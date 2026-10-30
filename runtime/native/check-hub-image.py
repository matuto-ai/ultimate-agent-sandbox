#!/usr/bin/env python3
"""Deliberate fixed Hub build/readback only: never start, push or install."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from uas.native_hub_image import dockerfile, source_inventory, validate_payload, COMMAND, MANIFEST
from uas.native_image_package import canonical
from uas.native_image_archive import export_archive

# Reuse stopped-file parsing, bounded command execution and exact ownership
# cleanup from the Workstation checker, rather than another Engine protocol.
SPEC = importlib.util.spec_from_file_location('native_image_check_common', Path(__file__).with_name('check-image.py'))
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--retain-image-archive', action='store_true', help='retain bounded public Docker image archive after readback')
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(exist_ok=False)
    selection = COMMON.document(Path(args.selection).read_bytes())
    recipe = dockerfile(selection)
    revision = COMMON.command(['git','rev-parse','HEAD'],cwd=ROOT,output=True).decode().strip()
    COMMON.require(re.fullmatch(r'[0-9a-f]{40}', revision), 'exact source revision required')
    COMMON.require(not COMMON.command(['git','status','--porcelain','--untracked-files=no'],cwd=ROOT,output=True).strip(),
                   'clean tracked source required')
    report = {'version':1,'source_revision':revision,'selection':selection,'status':'running',
              'stage':'build','build_execution':'not-started','archive_export':'not-started' if args.retain_image_archive else 'not-requested','native_lifecycle':'not-run',
              'installation_envelopes':'not-created-no-published-reference'}
    container_name = None
    create_confirmed = False
    image_id = None
    owner = uuid.uuid4().hex
    config = out / 'docker-config'; config.mkdir()
    docker = ['docker','--config',str(config),'--host','unix:///var/run/docker.sock']
    artifacts = out / 'artifacts'; artifacts.mkdir()
    (artifacts / 'selection.json').write_bytes(canonical(selection))
    (artifacts / 'Dockerfile.hub-check').write_text(recipe)
    cleanup_error = None
    try:
        with tempfile.TemporaryDirectory(prefix='uas-hub-check-') as temporary:
            work = Path(temporary); context = work / 'context'; context.mkdir()
            archive = work / 'source.tar'
            COMMON.command(['git','archive','--format=tar','--output='+str(archive),revision],cwd=ROOT)
            with tarfile.open(archive) as stream: stream.extractall(context,filter='data')
            sources = source_inventory(context)
            (context / 'Dockerfile.hub-check').write_text(recipe)
            report['build_execution'] = 'running'
            COMMON.command(docker+['build','--platform=linux/amd64','--iidfile='+str(out/'image-id'),
                                  '-f','Dockerfile.hub-check','.'],cwd=context,timeout=600)
            report['build_execution'] = 'completed'
            image_id = (out/'image-id').read_text().strip()
            COMMON.require(re.fullmatch(r'sha256:[0-9a-f]{64}',image_id),'observed Hub image ID required')
            image = json.loads(COMMON.command(docker+['image','inspect',image_id],output=True))[0]
            cfg = image['Config']
            COMMON.require(image['Id']==image_id and image['Os']=='linux' and image['Architecture']=='amd64'
                and cfg['User']=='65531:65531' and cfg['Entrypoint']==COMMAND[:1] and cfg['Cmd']==COMMAND[1:]
                and cfg['WorkingDir']=='/' and 'PYTHONPATH=/opt/uas' in cfg.get('Env',[])
                and 'PYTHONDONTWRITEBYTECODE=1' in cfg.get('Env',[]), 'Hub image identity/platform/config differs')
            report.update(image_id=image_id,stage='create')
            container_name = 'uas-image-check-'+owner
            container = COMMON.command(docker+['create','--network=none','--read-only','--name='+container_name,
                '--label=io.uas.image-check='+owner,'--entrypoint=/uas-readback-never-start',image_id],output=True).decode().strip()
            COMMON.require(re.fullmatch(r'[0-9a-f]{64}',container),'owned stopped Hub container ID required')
            create_confirmed = True
            state = json.loads(COMMON.command(docker+['inspect',container],output=True))[0]
            COMMON.require(state['Image']==image_id and state['State']['Status']=='created'
                           and state['State']['Running'] is False,'Hub readback identity/state differs')
            report['stage'] = 'readback'
            value = COMMON.document(COMMON.read_file(container,MANIFEST)['data'])
            report['hub_payload'] = validate_payload(value,sources,selection['python_version'],
                                                     lambda p: COMMON.read_file(container,p))
            (artifacts/'hub-payload.json').write_bytes(canonical(value))
            if args.retain_image_archive:
                report.update(stage='archive',archive_export='running')
                report['image_archive']=export_archive(image_id,artifacts,artifact_name='hub-image.tar',
                    max_bytes=1024**3,readback={'source_revision':revision,'image_id':image_id,'hub_payload':report['hub_payload']})
                report['archive_export']='complete'
            report.update(status='passed',stage='complete')
    except BaseException as error:
        notes = getattr(error, '__notes__', ())
        if notes: report['error_notes'] = [str(note)[:500] for note in notes[:8]]
        if report['archive_export']=='running':report['archive_export']='failed'
        report.update(status='failed',error=type(error).__name__+': '+str(error)[:1000])
        if report['build_execution']=='running':
            report['build_execution']='unknown-daemon-outcome' if isinstance(error,subprocess.TimeoutExpired) else 'failed'
    finally:
        if container_name:
            try: COMMON.cleanup_container(docker,container_name,owner,image_id,uncertain=not create_confirmed)
            except BaseException as error: cleanup_error=type(error).__name__+': '+str(error)[:1000]
        report['container_cleanup']='failed' if cleanup_error else ('complete' if container_name else 'not-created')
        if cleanup_error: report.update(cleanup_error=cleanup_error,status='failed')
        (out/'report.json').write_bytes(canonical(report))
        print(canonical(report).decode())
    return 0 if report['status']=='passed' else 1


if __name__ == '__main__': raise SystemExit(main())
