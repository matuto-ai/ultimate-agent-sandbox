#!/usr/bin/env python3
"""Deliberate manual-only artifacts qualification; not ordinary CI or deploy."""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid

import run as feasibility
from prepare_payload import build_payload
from run_workstation import arguments, LOG_FILES, BOOT_TIMEOUT, SILENT_BOOT_TIMEOUT, IDLE_SERIAL_TIMEOUT

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
REQUIRED={'payload','confinement','committed_source','hub_adjudication','native_filter',
          'held_identity','mutation_loss','resource_limits','two_rooms','owned_cleanup','guest_cleanup'}
SOURCES=(
    'uas/__init__.py','uas/config.py','uas/gate_policy.py','uas/context.py','uas/forge.py','uas/ledger.py',
    'uas/lifecycle.py','uas/launch.py','uas/peer.py','uas/participant.py','uas/checkouts.py',
    'uas/artifact_protocol.py','uas/artifact_target.py','uas/artifact_helper.py','uas/gate_evaluation.py',
    'uas/docker_exec_api.py','uas/kernel_origin.py','uas/workstation_exec.py','uas/workstation_probe.py',
    'uas/forge_audit.py','uas/run_admission.py','uas/forge_assignment.py','uas/github_assignment.py',
    'uas/github_read.py','uas/github_pr.py',
    'tests/vm/fedora-image.json','tests/vm/boundary_fixture.go','tests/vm/guest_boundary.py',
    'tests/vm/guest_workstation.py','tests/vm/native_rootfs.py','tests/vm/native_trust.py',
    'tests/vm/guest_artifacts.py','tests/vm/artifact_supervisor.py','tests/vm/artifact_hub.py',
    'tests/vm/artifact_diagnostics.py',
    'tests/vm/artifact_room_probe.py','tests/vm/artifact_confinement_probe.c','tests/vm/artifact_quota_probe.py',
    'tests/fixtures/two-rooms.json','runtime/workstation/artifact_protocol.h',
    'runtime/workstation/artifact_bootstrap.c','runtime/workstation/artifact_evaluator.c')


def seed(directory,nonce,digest):
    payload={'disable_root':True,'ssh_pwauth':False,'users':[],
        'write_files':[{'path':'/run/'+name,'permissions':'0600','encoding':'b64',
            'content':base64.b64encode((HERE/name).read_bytes()).decode()}
            for name in ('guest_artifacts.py','guest_boundary.py','guest_workstation.py')]+
            [{'path':'/run/uas-vm-fixture','permissions':'0600','content':nonce}],
        'runcmd':[['python3','/run/guest_artifacts.py',nonce,digest]],
        'power_state':{'mode':'poweroff','delay':'now','timeout':30,'condition':True}}
    (directory/'user-data').write_text('#cloud-config\n'+json.dumps(payload))
    (directory/'meta-data').write_text(json.dumps({'instance-id':'uas-artifacts-'+nonce,'local-hostname':'uas-artifacts'}))
    result=directory/'seed.iso';feasibility.command(['cloud-localds',str(result),str(directory/'user-data'),str(directory/'meta-data')]);return result


def parse_report(serial,nonce):
    prefix='UAS_ARTIFACT_REPORT:'+nonce+':'
    lines=[line[len(prefix):] for line in serial.splitlines() if line.startswith(prefix)]
    if len(lines)!=1 or len(lines[0])>65536:raise RuntimeError('one bounded exact artifacts boot report required')
    value=json.loads(lines[0])
    if (value.get('version')!=1 or value.get('nonce')!=nonce or value.get('production_enabled') is not False
            or 'failure' in value or set(value.get('checks',{}))!=REQUIRED
            or any(v.get('status')!='passed' for v in value['checks'].values())):
        raise RuntimeError('artifacts native proof failed: '+json.dumps(value))
    return value


def boot(directory,argv,nonce):
    started=last_progress=last_activity=time.monotonic();serial=directory/'serial.log';previous=0
    with (directory/'qemu.log').open('x') as log:
        process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            while process.poll() is None:
                now=time.monotonic();elapsed=now-started;size=serial.stat().st_size if serial.exists() else 0
                if elapsed>BOOT_TIMEOUT:raise RuntimeError('bounded artifact VM deadline exceeded')
                if elapsed>SILENT_BOOT_TIMEOUT and size==0:raise RuntimeError('artifact VM boot silent')
                if size!=previous:last_activity=now;previous=size
                if now-last_activity>IDLE_SERIAL_TIMEOUT:raise RuntimeError('artifact VM serial stalled')
                if now-last_progress>=30:
                    print('Artifacts VM progress:',json.dumps({'elapsed_seconds':round(elapsed),'serial_bytes':size}),flush=True);last_progress=now
                for name in LOG_FILES:
                    path=directory/name
                    if path.exists() and path.stat().st_size>feasibility.LOG_LIMIT:raise RuntimeError('artifact VM log bound')
                time.sleep(1)
            if process.returncode:raise RuntimeError('artifact VM abnormal exit')
            return parse_report(serial.read_text(errors='replace'),nonce),round(time.monotonic()-started,3)
        finally:feasibility.stop_process(process)


def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.geteuid()==0:
        raise RuntimeError('explicit disposable GitHub manual job required')
    started=time.monotonic();directory=None
    try:
        with tempfile.TemporaryDirectory(prefix='uas-artifacts-vm-') as temporary:
            directory=Path(temporary);nonce=uuid.uuid4().hex
            try:
                lock=json.loads((HERE/'fedora-image.json').read_text());image=feasibility.fetch_image(lock,directory)
                payload=build_payload(directory,ROOT,nonce,source_paths=SOURCES,profile='artifacts-v1-source')
                manifest=payload.parent/'payload/manifest.json';digest=hashlib.sha256(manifest.read_bytes()).hexdigest()
                overlay=directory/'guest.qcow2';quota=directory/'quota.raw'
                feasibility.command(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(image),str(overlay)])
                with quota.open('xb') as stream:stream.truncate(2*1024**3)
                report,seconds=boot(directory,arguments(directory,overlay,seed(directory,nonce,digest),payload,quota),nonce)
                print('Artifacts VM:',json.dumps({'guest':report,'image_sha256':lock['sha256'],
                    'payload_manifest_sha256':digest,'boot_seconds':seconds,'no_guest_NIC':True,
                    'qualification_reused_from_Pi':False,'production_enabled':False},sort_keys=True),flush=True)
            except BaseException:
                for name in LOG_FILES:
                    path=directory/name
                    if path.exists():
                        with path.open('rb') as stream:
                            stream.seek(max(0,path.stat().st_size-131072));print(name+' tail:',stream.read(131072).decode(errors='replace'),flush=True)
                raise
    finally:
        print('Artifacts VM cleanup:',json.dumps({'owned_temporary_directory_removed':directory is None or not directory.exists(),
            'elapsed_seconds':round(time.monotonic()-started,3)}),flush=True)


if __name__=='__main__':
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    main()
