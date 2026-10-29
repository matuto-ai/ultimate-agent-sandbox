"""Bounded public Docker-save transport, not installation or runtime evidence."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import time
import uuid
from urllib.parse import quote

from .docker_exec_api import _UnixHTTP, API

CAPS = {'combined-image.tar': 2 * 1024**3, 'hub-image.tar': 1024**3}
RESERVE = 512 * 1024**2


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _document(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'duplicate archive JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def validate_archive(path, image_id, deadline):
    """Inspect one Docker-save config binding, never extract or execute layers."""
    archive_size = Path(path).stat().st_size
    with tarfile.open(path, mode='r:') as archive:
        members = {}
        for member in archive:
            require(time.monotonic() < deadline, 'archive validation deadline')
            name = member.name
            require(len(members) < 4096 and name not in members and len(name) <= 1024
                    and name and not name.startswith('/') and '\\' not in name
                    and '..' not in PurePosixPath(name).parts
                    and (member.isfile() or member.isdir()) and not member.issparse()
                    and 0 <= member.size and member.offset_data + member.size <= archive_size,
                    'unsafe or oversized Docker-save inventory')
            members[name] = member
        def read(name, limit):
            member = members.get(name)
            require(member is not None and member.isfile() and 0 < member.size <= limit,
                    'bounded Docker-save metadata required')
            raw = archive.extractfile(member).read(limit + 1)
            require(len(raw) == member.size, 'truncated Docker-save metadata')
            return raw
        manifest = _document(read('manifest.json', 65536))
        require(type(manifest) is list and len(manifest) == 1 and type(manifest[0]) is dict,
                'exactly one saved image required')
        entry = manifest[0]
        require(type(entry.get('Config')) is str and type(entry.get('Layers')) is list
                and 0 < len(entry['Layers']) <= 256
                and all(type(name) is str and name in members and members[name].isfile()
                        for name in entry['Layers'])
                and len(set(entry['Layers'])) == len(entry['Layers']), 'saved layer inventory required')
        raw = read(entry['Config'], 1024 * 1024)
        require('sha256:' + hashlib.sha256(raw).hexdigest() == image_id, 'saved config differs from readback image')
        config = _document(raw)
        require(type(config) is dict and config.get('os') == 'linux' and config.get('architecture') == 'amd64',
                'saved image platform differs')
        require(time.monotonic() < deadline, 'archive validation deadline')


def export_archive(image_id, directory, *, artifact_name, max_bytes, readback,
                   timeout=120, socket_path='/var/run/docker.sock'):
    """Export exact observed image once; retain only complete verified transport.

    Closing HTTP on error stops this reader; it does not assert daemon-side
    export cancellation. No image mutation or retry is performed.
    """
    require(type(image_id) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', image_id), 'exact image ID required')
    require(artifact_name in CAPS and type(max_bytes) is int and 0 < max_bytes <= CAPS[artifact_name],
            'archive budget invalid')
    require(type(timeout) is int and 1 <= timeout <= 120, 'archive deadline invalid')
    require(type(readback) is dict and readback.get('image_id') == image_id
            and type(readback.get('source_revision')) is str
            and re.fullmatch(r'[0-9a-f]{40}', readback['source_revision']), 'exact readback binding required')
    evidence = canonical(readback)
    require(len(evidence) <= 65536, 'readback evidence budget')
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'owned artifact directory required')
    require(shutil.disk_usage(directory).free >= max_bytes + RESERVE, 'archive disk reserve unavailable')
    target = directory / artifact_name
    metadata = target.with_suffix('.json')
    require(not target.exists() and not target.is_symlink() and not metadata.exists() and not metadata.is_symlink(),
            'archive target already exists')
    nonce = uuid.uuid4().hex
    partial = directory / ('.' + artifact_name + '-' + nonce)
    partial_metadata = directory / ('.' + metadata.name + '-' + nonce)
    connection = None
    published = []
    owned_partials = []
    complete = False
    deadline = time.monotonic() + timeout
    try:
        connection = _UnixHTTP(socket_path, min(timeout, 10))
        connection.request('GET', API + '/images/' + quote(image_id, safe='') + '/get?platform=' + quote(canonical({'os': 'linux', 'architecture': 'amd64'}).decode(), safe=''))
        response = connection.getresponse()
        require(response.status == 200, 'image archive unavailable')
        digest = hashlib.sha256()
        size = 0
        with partial.open('xb') as output:
            owned_partials.append(partial)
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'image archive read deadline')
                if connection.sock is not None:
                    connection.sock.settimeout(min(10, remaining))
                block = response.read1(min(65536, max_bytes - size + 1))
                if not block:
                    break
                size += len(block)
                require(size <= max_bytes, 'image archive exceeds budget')
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        connection.close()
        connection = None
        require(size > 0, 'empty image archive')
        validate_archive(partial, image_id, deadline)
        record = {'version': 1, 'format': 'docker-save', 'artifact': artifact_name,
                  'image_id': image_id, 'archive_sha256': digest.hexdigest(), 'size': size,
                  'readback': _document(evidence), 'readback_sha256': hashlib.sha256(evidence).hexdigest(),
                  'restore_verification': 'required-before-use', 'registry_reference': None}
        with partial_metadata.open('xb') as output:
            owned_partials.append(partial_metadata)
            output.write(canonical(record))
            output.flush()
            os.fsync(output.fileno())
        require(time.monotonic() < deadline, 'archive publication deadline')
        # link is atomic and refuses an existing destination; no replace/race overwrite.
        os.link(partial, target)
        published.append(target)
        os.link(partial_metadata, metadata)
        published.append(metadata)
        complete = True
        return record
    finally:
        primary = sys.exc_info()[1]
        cleanup_errors = []
        if connection is not None:
            try: connection.close()
            except BaseException as error: cleanup_errors.append(error)
        for path in ([] if complete else list(reversed(published))) + owned_partials:
            try: path.unlink(missing_ok=True)
            except BaseException as error: cleanup_errors.append(error)
        if cleanup_errors and complete:
            # No successful return if partial cleanup failed after publication.
            # Remove only our published names; report any unsuccessful removal.
            for path in reversed(published):
                try: path.unlink(missing_ok=True)
                except BaseException as error: cleanup_errors.append(error)
        if cleanup_errors:
            if primary is not None:
                primary.add_note('Archive cleanup incomplete: ' + ','.join(type(e).__name__ for e in cleanup_errors))
            else:
                raise cleanup_errors[0]
