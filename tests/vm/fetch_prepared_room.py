#!/usr/bin/env python3
"""Explicit same-repository prepared-base transport; no latest or cold fallback.

The caller supplies a trusted receipt digest and reviewed producer commit/run.
Only GitHub API requests receive GITHUB_TOKEN. Signed blob redirects never do.
No QEMU invocation occurs here; prepared_room.select and the warm launcher retain
all content, current-source, qcow2 and live-enforcement checks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import prepared_room as prepared

REPOSITORY = 'matuto-ai/ultimate-agent-sandbox'
WORKFLOW = '.github/workflows/room-prepare.yml'
API = 'https://api.github.com/repos/' + REPOSITORY
MAX_ZIP = prepared.MAX_BASE + prepared.MAX_POOL + 16 * 1024**2
MAX_ENTRIES = 600
TIMEOUT = 300


class TransportError(ValueError):
    pass


def error_code(error):
    # Only fixed codes leave this process; never exception text or signed URLs.
    allowed = {'metadata_mismatch', 'receipt_mismatch_rebuild_required',
               'artifact_missing_or_expired', 'transport_timeout'}
    if isinstance(error, TransportError) and str(error) in allowed: return str(error)
    if isinstance(error, urllib.error.HTTPError):
        return {401:'read_permission_denied',403:'read_permission_denied',
                404:'artifact_missing_or_expired',410:'artifact_missing_or_expired'}.get(error.code, 'artifact_http_failure')
    if isinstance(error, TimeoutError): return 'transport_timeout'
    if isinstance(error, urllib.error.URLError): return 'artifact_connection_failure'
    if isinstance(error, zipfile.BadZipFile): return 'artifact_archive_invalid'
    if isinstance(error, ValueError): return 'artifact_validation_failed'
    return 'artifact_transport_failed'


def require(value, message):
    if not value: raise ValueError(message)


def selection(run_id, artifact_id, commit, receipt):
    require(all(type(v) is str and re.fullmatch('[1-9][0-9]{0,19}', v)
                for v in (run_id, artifact_id)), 'explicit run and artifact IDs required')
    require(type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit), 'exact producer commit required')
    prepared.hex_digest(receipt)
    return {'run_id':run_id, 'artifact_id':artifact_id, 'commit':commit, 'receipt':receipt}


def verify_metadata(run, artifact, chosen):
    require(type(run) is dict and type(artifact) is dict, 'API metadata required')
    require(run.get('id') == int(chosen['run_id'])
            and run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and run.get('event') in ('workflow_dispatch', 'pull_request')
            and run.get('path', '').split('@')[0] == WORKFLOW,
            'producer run differs or is not successful')
    producer_head = run.get('head_sha')
    require(type(producer_head) is str and re.fullmatch('[0-9a-f]{40}', producer_head), 'invalid run head')
    selected = producer_head == chosen['commit']
    if run.get('event') == 'pull_request':
        pulls = run.get('pull_requests', [])
        require(type(pulls) is list and len(pulls) <= 16, 'bounded producer PR association required')
        selected = selected or any(type(pr) is dict and pr.get('head', {}).get('sha') == chosen['commit']
                    and pr.get('head', {}).get('repo', {}).get('id') == run.get('repository', {}).get('id')
                    for pr in pulls)
    require(selected, 'reviewed producer checkout differs')
    repository = run.get('repository', {})
    require(repository.get('full_name') == REPOSITORY and type(repository.get('id')) is int
            and run.get('head_repository', {}).get('id') == repository['id'], 'foreign producer repository')
    require(run.get('actor', {}).get('login') == 'puglab-reviewer'
            and run.get('triggering_actor', {}).get('login') == 'puglab-reviewer', 'producer actor differs')
    require(artifact.get('id') == int(chosen['artifact_id']) and artifact.get('expired') is False
            and artifact.get('name') == 'room-prepared-' + chosen['run_id']
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_ZIP,
            'artifact identity, expiry or size differs')
    binding = artifact.get('workflow_run', {})
    require(binding.get('id') == int(chosen['run_id']) and binding.get('head_sha') == producer_head
            and binding.get('repository_id') == repository['id']
            and binding.get('head_repository_id') == repository['id'], 'artifact producer binding differs')
    digest = artifact.get('digest')
    require(type(digest) is str and re.fullmatch('sha256:[0-9a-f]{64}', digest), 'artifact digest required')
    return digest[7:]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def api_request(path, token):
    require(path.startswith('/actions/') and not any(c in path for c in ('?', '#', '\\')), 'fixed API path required')
    require(type(token) is str and token and not any(c in token for c in ('\r','\n')), 'built-in read token required')
    return urllib.request.Request(API + path, headers={'Accept':'application/vnd.github+json',
             'Authorization':'Bearer ' + token, 'X-GitHub-Api-Version':'2022-11-28'})


def json_api(opener, path, token):
    with opener.open(api_request(path, token), timeout=30) as response:
        require(response.status == 200, 'GitHub metadata request failed')
        raw = response.read(1024**2 + 1)
        require(len(raw) <= 1024**2, 'GitHub metadata oversized')
    return json.loads(raw, object_pairs_hook=prepared.unique)


def signed_blob_url(value):
    parsed = urllib.parse.urlsplit(value)
    host = parsed.hostname or ''
    require(parsed.scheme == 'https' and parsed.username is None and parsed.password is None
            and parsed.port in (None,443) and not parsed.fragment
            and (host.endswith('.blob.core.windows.net') or host.endswith('.actions.githubusercontent.com')
                 or host.endswith('.githubusercontent.com')), 'untrusted artifact redirect')
    return value


def download(opener, chosen, token, destination, expected, expected_size):
    request = api_request('/actions/artifacts/' + chosen['artifact_id'] + '/zip', token)
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        try:
            if error.code != 302: raise
            url = signed_blob_url(error.headers.get('Location', ''))
        finally:
            error.close()
    else:
        response.close()
        raise ValueError('artifact download redirect required')
    # A fresh Request deliberately has NO Authorization header. Further redirects
    # are rejected by the same opener instead of forwarding credentials or loops.
    started, count, digest = time.monotonic(), 0, hashlib.sha256()
    with opener.open(urllib.request.Request(url), timeout=30) as response, Path(destination).open('xb') as stream:
        require(response.status == 200, 'artifact blob request failed')
        while True:
            if time.monotonic() - started > TIMEOUT: raise TransportError('transport_timeout')
            data = response.read(1024**2)
            if not data: break
            count += len(data)
            require(count <= MAX_ZIP and count <= expected_size, 'artifact download byte budget exceeded')
            digest.update(data); stream.write(data)
    require(count == expected_size and digest.hexdigest() == expected, 'artifact archive digest or size differs')


def entry_limit(name):
    if name == 'receipt.json': return prepared.MAX_RECEIPT
    if name == 'base.qcow2': return prepared.MAX_BASE
    if name == 'pool/fedora-44.asc': return 1024**2
    if re.fullmatch(r'pool/rpms/[A-Za-z0-9._+~^%-]{1,240}\.rpm', name): return 128*1024**2
    if re.fullmatch(r'pool/rpms/repodata/[A-Za-z0-9._-]{1,240}', name): return 8*1024**2
    raise ValueError('unexpected prepared archive member')


def extract(archive, destination):
    destination = Path(destination)
    require(destination.is_absolute() and destination.parent.resolve() == destination.parent
            and not destination.exists() and not destination.is_symlink(), 'new canonical extraction directory required')
    started = time.monotonic()
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        require(0 < len(entries) <= MAX_ENTRIES, 'prepared archive entry bound exceeded')
        seen, total = set(), 0
        for entry in entries:
            if time.monotonic() - started > TIMEOUT: raise TransportError('transport_timeout')
            name = entry.filename
            require(type(name) is str and len(name) <= 300 and '\\' not in name and '\x00' not in name
                    and not name.startswith('/') and all(p not in ('','.','..') for p in name.rstrip('/').split('/'))
                    and name not in seen and not entry.flag_bits & 1, 'unsafe or duplicate archive member')
            seen.add(name)
            mode = entry.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG), 'archive links/special nodes forbidden')
            if entry.is_dir():
                require(name in ('pool/','pool/rpms/','pool/rpms/repodata/') and entry.file_size == 0, 'unexpected archive directory')
                continue
            maximum = entry_limit(name)
            require(0 < entry.file_size <= maximum, 'prepared archive member oversized')
            total += entry.file_size
        require({'base.qcow2','receipt.json','pool/fedora-44.asc'} <= seen
                and total <= prepared.MAX_BASE + prepared.MAX_POOL + prepared.MAX_RECEIPT,
                'prepared archive inventory or total bound differs')
        destination.mkdir(mode=0o700)
        # Contents remain in this owned temporary extraction directory on failure;
        # outer TemporaryDirectory cleanup never adopts an existing user directory.
        for entry in entries:
            if entry.is_dir(): continue
            path = destination / entry.filename
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            count = 0
            with source.open(entry) as old, path.open('xb') as new:
                while True:
                    if time.monotonic() - started > TIMEOUT: raise TransportError('transport_timeout')
                    data = old.read(min(1024**2, entry.file_size - count + 1))
                    if not data: break
                    count += len(data)
                    require(count <= entry.file_size, 'archive expanded beyond declared size')
                    new.write(data)
            require(count == entry.file_size, 'archive member truncated')
            path.chmod(0o600)


def fetch(chosen, output, repository_root, token):
    output = Path(output)
    require(output.is_absolute() and output.parent.resolve() == output.parent
            and not output.exists() and not output.is_symlink(), 'new canonical output directory required')
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'same repository execution required')
    opener = urllib.request.build_opener(NoRedirect)
    run = json_api(opener, '/actions/runs/' + chosen['run_id'], token)
    artifact = json_api(opener, '/actions/artifacts/' + chosen['artifact_id'], token)
    if artifact.get('expired') is True:
        raise TransportError('artifact_missing_or_expired')
    try:
        digest = verify_metadata(run, artifact, chosen)
    except ValueError as error:
        raise TransportError('metadata_mismatch') from error
    with tempfile.TemporaryDirectory(prefix='uas-prepared-download-', dir=output.parent) as owned:
        owned = Path(owned)
        archive, staging = owned / 'artifact.zip', owned / 'prepared'
        download(opener, chosen, token, archive, digest, artifact['size_in_bytes'])
        extract(archive, staging)
        try:
            receipt = prepared.select(staging, chosen['receipt'], Path(repository_root))
        except ValueError as error:
            raise TransportError('receipt_mismatch_rebuild_required') from error
        if receipt['producer'] != {'commit':chosen['commit'], 'run_id':chosen['run_id']}:
            raise TransportError('receipt_mismatch_rebuild_required')
        # Reserve the output ourselves; no overwrite/adoption of a raced path.
        output.mkdir(mode=0o700)
        for name in ('base.qcow2','pool','receipt.json'):
            (staging / name).rename(output / name)
        prepared.select(output, chosen['receipt'], Path(repository_root))
    print(json.dumps({'status':'prepared_artifact_verified', 'run_id':chosen['run_id'],
                      'artifact_id':chosen['artifact_id'], 'commit':chosen['commit'],
                      'receipt_sha256':chosen['receipt'], 'qualification':'NOT_RUN'}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    for field in ('producer-run-id','artifact-id','producer-commit','receipt-sha256'):
        parser.add_argument('--' + field)
    parser.add_argument('--selection-file')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.selection_file:
        require(not any((args.producer_run_id,args.artifact_id,args.producer_commit,args.receipt_sha256)),
                'choose one explicit selection route')
        path = Path(args.selection_file)
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4096, 'bounded selection file required')
        value = json.loads(path.read_bytes(), object_pairs_hook=prepared.unique)
        require(type(value) is dict and set(value) == {'run_id','artifact_id','commit','receipt'}, 'explicit selection schema required')
        chosen = selection(value['run_id'],value['artifact_id'],value['commit'],value['receipt'])
    else:
        chosen = selection(args.producer_run_id, args.artifact_id, args.producer_commit, args.receipt_sha256)
    fetch(chosen, args.output, Path(__file__).resolve().parents[2], os.environ.get('GITHUB_TOKEN',''))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # HTTPError messages can contain signed blob URLs. Never log the request,
        # response headers, token or raw exception text in hosted diagnostics.
        print('Prepared artifact transport failed: ' + error_code(error), flush=True)
        raise SystemExit(1) from None
