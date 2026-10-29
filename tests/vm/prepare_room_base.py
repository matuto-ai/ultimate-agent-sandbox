#!/usr/bin/env python3
"""Deliberate expensive preparation only; never runs or reports qualification.

Output is a standalone cold disk plus exact signed pool. A caller must approve
and pin the producer run/commit and receipt SHA before selecting it in run_room.
No network artifact discovery, credential changes, or automatic rebuild exists.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

import prepared_room as prepared
import run_room


def parse_prepared(text, nonce, key):
    run_room._nonce(nonce)
    marker = 'UAS_ROOM_PREPARED:' + nonce + ':'
    rows = [line.strip() for line in text.splitlines() if line.strip().startswith('UAS_ROOM_PREPARED:')]
    prepared.require(len(rows) == 1 and rows[0].startswith(marker), 'exact fresh prepared report required')
    prepared.require(len(rows[0]) <= prepared.MAX_RECEIPT, 'prepared report size exceeded')
    value = json.loads(rows[0][len(marker):], object_pairs_hook=prepared.unique)
    return prepared.validate_guest_receipt(value, key)


def failure_logs(directory):
    """Best effort diagnostics must never replace the primary preparation error."""
    for name in run_room.LOG_FILES:
        path = directory / name
        try:
            if path.is_file() and not path.is_symlink():
                with path.open('rb') as stream:
                    stream.seek(max(0, path.stat().st_size - 8192))
                    detail = stream.read(8192).decode(errors='replace')
                print('Room preparation failure log:', json.dumps({'file':name,'tail':detail}), flush=True)
        except OSError:
            pass


def build(output):
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux'
            or os.geteuid() == 0 or os.environ.get('UAS_ROOM_VM_PROFILE') != prepared.PROFILE):
        raise RuntimeError('explicit unprivileged hosted Room preparation profile required')
    # Identity is an auditable binding, not independent authorization. The
    # consumer separately requires a trusted receipt digest from this producer.
    producer = {'commit':os.environ.get('UAS_ROOM_PRODUCER_COMMIT',''), 'run_id':os.environ.get('GITHUB_RUN_ID','')}
    import re
    prepared.require(re.fullmatch('[0-9a-f]{40}', producer['commit']) and
                     re.fullmatch('[1-9][0-9]{0,19}', producer['run_id']), 'exact producer identity required')
    output = Path(output)
    prepared.require(output.is_absolute() and output.parent.resolve() == output.parent
                     and output.parent.is_dir() and not output.exists() and not output.is_symlink(),
                     'new owned output directory required')
    # Publication starts only after cold shutdown, flattening,
    # inventory and every content hash succeed. Failed partial work stays owned
    # by TemporaryDirectory and is never an eligible artifact.
    with tempfile.TemporaryDirectory(prefix='uas-room-prepare-', dir=output.parent) as temporary:
        directory = Path(temporary)
        nonce = uuid.uuid4().hex
        lock = json.loads((run_room.HERE / 'fedora-image.json').read_bytes())
        try:
            image = run_room.feasibility.fetch_image(lock, directory)
            payload = run_room.build_payload(directory, run_room.ROOT, nonce,
                                            source_paths=run_room.SOURCES, profile=prepared.PROFILE)
            payload_root = payload.parent / 'payload'
            raw = (payload_root / 'manifest.json').read_bytes()
            manifest = json.loads(raw, object_pairs_hook=prepared.unique)
            contract = prepared.foundation(manifest)
            key = prepared.digest(contract)
            overlay, quota = directory / 'guest.qcow2', directory / 'quota.raw'
            run_room.feasibility.command(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(image),str(overlay)])
            with quota.open('xb') as stream: stream.truncate(2 * 1024**3)
            seed = run_room.seed(directory, nonce, hashlib.sha256(raw).hexdigest(), payload_root=payload_root,
                                 mode='prepare', base_key=key)
            guest, seconds = run_room.boot(directory, run_room.arguments(directory, overlay, seed, payload, quota), nonce,
                                report_parser=lambda text, observed:parse_prepared(text, observed, key))
            artifact = directory / 'artifact'
            artifact.mkdir()
            base = artifact / 'base.qcow2'
            run_room.feasibility.command(['qemu-img','convert','-f','qcow2','-O','qcow2',str(overlay),str(base)], timeout=180)
            prepared.standalone_info(json.loads(run_room.feasibility.command(['qemu-img','info','--output=json',str(base)])))
            prepared.copy_pool(payload_root, artifact / 'pool', contract['pool'], source_has_payload=True)
            receipt = {'version':prepared.VERSION, 'profile':prepared.PROFILE, 'base_key':key,
                       'foundation':contract, 'base':prepared.hash_file(base, prepared.MAX_BASE),
                       'guest_receipt':guest, 'producer':producer, 'qualification':'NOT_RUN', 'created_at':int(time.time())}
            (artifact / 'receipt.json').write_bytes(prepared.canonical(receipt) + b'\n')
            expected = prepared.hash_file(artifact / 'receipt.json', prepared.MAX_RECEIPT)['sha256']
            prepared.select(artifact, expected, run_room.ROOT)
            # A preexisting output is never adopted/overwritten, including a race.
            prepared.require(not output.exists() and not output.is_symlink(), 'output appeared during preparation')
            # mkdir reserves an owned empty destination; rename into its fixed child
            # would change the artifact contract. renameat2 NOREPLACE is not portable;
            # publish via exclusive owned directory and copy verified fixed files.
            output.mkdir(mode=0o700)
            try:
                for name in ('base.qcow2','pool','receipt.json'):
                    (artifact / name).rename(output / name)
            except BaseException:
                # Leave a clearly ineligible partial artifact, never delete someone
                # else's directory or print a successful receipt.
                raise
            print('Room prepared artifact:', json.dumps({'directory':str(output), 'receipt_sha256':expected,
                  'producer':producer, 'base_key':key, 'prepare_seconds':seconds, 'qualification':'NOT_RUN'}), flush=True)
            return receipt
        except BaseException:
            failure_logs(directory)
            raise



if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2: raise SystemExit('usage: prepare_room_base.py NEW_ABSOLUTE_OUTPUT_DIRECTORY')
    build(sys.argv[1])
