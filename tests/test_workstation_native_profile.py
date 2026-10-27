"""Pure fixed native-profile contracts; no listener, payload build or guest run."""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from uas.kernel_origin import OriginDenied
from uas.workstation_service import configuration

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests/vm'))
import guest_workstation as guest
import run_workstation as runner


class NativeProfileTests(unittest.TestCase):
    def metadata(self):
        return {'version':1,'challenge':'a'*64,'supervisor_identity':[1,2],
            'mapping_digest':'b'*64,'room_id':'alpha','room_instance':'instance','run_id':'native-run',
            'seats':[{'participant_id':'alice','actor_id':'actor-a','profile_id':'native-pi-v1'},
                     {'participant_id':'bob','actor_id':'actor-b','profile_id':'native-pi-v1'}]}

    def test_fixed_hub_metadata_retains_distinct_actor_and_receiver_mapping(self):
        metadata,seats=configuration(json.dumps(self.metadata()).encode())
        self.assertEqual([s.actor_id for s in seats],['actor-a','actor-b'])
        self.assertTrue(all((s.receiver.uid,s.receiver.gid)==(65532,65532) for s in seats))
        self.assertTrue(all(s.capabilities==('peer-traffic',) for s in seats))

    def test_extra_claims_duplicate_actor_and_oversized_startup_rejected(self):
        value=self.metadata();value['engine_socket']='/run/docker.sock'
        with self.assertRaises(OriginDenied):configuration(json.dumps(value).encode())
        value=self.metadata();value['seats'][1]['actor_id']='actor-a'
        with self.assertRaises(OriginDenied):configuration(json.dumps(value).encode())
        with self.assertRaises(OriginDenied):configuration(b'x'*8193)

    def test_deliberate_workflow_has_no_automatic_trigger_and_fixed_node(self):
        source=(ROOT/'.github/workflows/workstation-native.yml').read_text()
        self.assertIn('  workflow_dispatch:',source)
        self.assertIn('types: [labeled]',source);self.assertNotIn('  push:',source)
        self.assertNotIn('synchronize',source)
        self.assertIn("github.event.label.name == 'qualify-native-workstation'",source)
        self.assertIn("github.event.sender.login == 'puglab-reviewer'",source)
        self.assertIn('github.event.pull_request.head.repo.full_name == github.repository',source)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha || github.sha }}',source)
        self.assertIn("node-version: '24.22.1'",source)
        self.assertIn('cc -static',source)
        self.assertIn('tests/vm/run_workstation.py',source)

    def test_actual_process_status_projection_and_hub_failclosed_before_connect(self):
        from uas import workstation_probe, workstation_service
        raw='CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n'
        with patch.object(workstation_probe.Path,'read_text',return_value=raw):
            status=workstation_probe.process_status()
        self.assertEqual(status,{'CapEff':'0000000000000000','CapBnd':'0000000000000000','NoNewPrivs':'1','Seccomp':'2'})
        for key,bad in (('CapEff','1'),('CapBnd','1'),('NoNewPrivs','0'),('Seccomp','0')):
            with self.subTest(key=key),patch.object(workstation_service.sys,'argv',['fixed-hub']), \
                 patch.object(workstation_service.os,'getuid',return_value=65531), \
                 patch.object(workstation_service.os,'getgid',return_value=65531), \
                 patch.object(workstation_service,'probe'), \
                 patch.object(workstation_service,'process_status',return_value={**status,key:bad}), \
                 patch.object(workstation_service.socket,'socket') as connect:
                with self.assertRaisesRegex(OriginDenied,'capabilities/NNP/seccomp'):
                    workstation_service.main()
                connect.assert_not_called()

    def test_fixed_connector_service_and_probe_share_endpoint_path(self):
        from uas.workstation_service import PEER
        self.assertEqual(PEER,'/uas/peer/pi.sock')
        self.assertIn('#define UAS_ENDPOINT "'+PEER+'"',
                      (ROOT/'runtime/workstation/pi_connector.c').read_text())
        self.assertIn("connect('"+PEER+"')",(ROOT/'uas/workstation_probe.py').read_text())

    def test_source_allowlist_is_complete_and_not_implicit_whole_repository(self):
        self.assertEqual(len(runner.SOURCES),len(set(runner.SOURCES)))
        for path in runner.SOURCES:self.assertTrue((ROOT/path).is_file(),path)
        self.assertIn('tests/vm/native_supervisor.py',runner.SOURCES)
        self.assertIn('tests/pi/handoff-probe.py',runner.SOURCES)
        self.assertIn('uas/workstation_service.py',runner.SOURCES)
        self.assertNotIn('uas/claude_runtime.py',runner.SOURCES)
        self.assertEqual(guest.REQUIRED,runner.REQUIRED)

    def test_staged_source_closure_in_isolated_python_without_broker(self):
        # The imported runner is used ONLY to enumerate the explicit source
        # allowlist. The child gets no repository path, PYTHONPATH or site libs.
        code = r'''import json, sys, tempfile
from pathlib import Path
stage = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(stage))
class NoProviderImports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {'uas.github_read', 'uas.provider', 'uas.providers'}:
            raise AssertionError('provider module reached: ' + fullname)
sys.meta_path.insert(0, NoProviderImports())
from uas import workstation_service, workstation_control, workstation_hub, workstation_peer
from uas import docker_exec_api, workstation_exec, workstation_admission, pi_runtime
from uas.forge import ReadOnlyForgeBroker
from uas.ledger import RoomLedger, Origin
from uas.peer import FixturePeerHub, FixtureParticipant, Message, WorkRequest

def forbidden_broker(*args, **kwargs):
    raise AssertionError('Broker construction is unavailable in native profile')
ReadOnlyForgeBroker.__init__ = forbidden_broker
metadata = {'version': 1, 'challenge': 'a'*64, 'supervisor_identity': [1,2],
    'mapping_digest': 'b'*64, 'room_id': 'alpha', 'room_instance': 'instance', 'run_id': 'native-run',
    'seats': [{'participant_id': 'alice', 'actor_id': 'actor-a', 'profile_id': 'native-pi-v1'},
              {'participant_id': 'bob', 'actor_id': 'actor-b', 'profile_id': 'native-pi-v1'}]}
_, seats = workstation_service.configuration(json.dumps(metadata).encode())
assert all(seat.capabilities == ('peer-traffic',) for seat in seats)
with tempfile.TemporaryDirectory(dir=stage) as directory:
    ledger = RoomLedger(Path(directory)/'room.db', 'alpha')
    try:
        hub = FixturePeerHub(ledger)
        hub.configure('configure', tuple(FixtureParticipant(s.participant_id,s.actor_id) for s in seats), 'native-run')
        connection = hub.connect('connect', 'alice', 'incarnation-a', object())
        origin = Origin('actor-a', 'alice', 'incarnation-a', 'native-source-smoke', ('peer-traffic',))
        message = Message('staged-message', 'native-run', 1, 'bob', 'staged source closure')
        receipt = hub.submit(connection, message, origin=origin, authorize=lambda: True)
        assert hub.submit(connection, message, origin=origin, authorize=lambda: True) == receipt
        assert ledger.snapshot()['state']['peer_traffic']['traffic']['staged-message']['actor_id'] == 'actor-a'
        request = WorkRequest('staged-request', 'native-run', 1, 'bob', 'staged request closure')
        hub.submit(connection, request, origin=origin, authorize=lambda: True)
        recipient = hub.connect('connect-bob', 'bob', 'incarnation-b', object())
        assert {item['id'] for item in hub._pending(recipient)} == {'staged-message', 'staged-request'}
        assert not hasattr(hub, 'broker') and not hasattr(hub, 'provider_for_actor')
    finally:
        ledger.close()
assert 'uas.github_read' not in sys.modules
assert not any(name.startswith(('uas.provider', 'uas.providers')) for name in sys.modules)
loaded = {name: str(Path(module.__file__).resolve()) for name,module in sys.modules.items()
          if name == 'uas' or name.startswith('uas.')}
assert all(Path(path).is_relative_to(stage) for path in loaded.values()), loaded
print(json.dumps({'modules': sorted(loaded), 'broker_constructed': False, 'provider_loaded': False}))
'''
        with tempfile.TemporaryDirectory(prefix='uas-native-selected-source-') as temporary:
            stage = Path(temporary)
            for relative in runner.SOURCES:
                if relative.startswith('uas/'):
                    target = stage/relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT/relative, target)
            args = [sys.executable, '-I', '-S', '-B', '-c', code, str(stage)]
            result = subprocess.run(args, cwd=stage, env={'PATH':os.defpath,'HOME':str(stage)},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertIn('uas.forge', report['modules'])
            self.assertFalse(report['broker_constructed']);self.assertFalse(report['provider_loaded'])
            self.assertFalse((stage/'uas/github_read.py').exists())
            # A missing reached file really fails; no full checkout fallback.
            (stage/'uas/forge.py').unlink()
            missing = subprocess.run(args, cwd=stage, env={'PATH':os.defpath,'HOME':str(stage)},
                                     capture_output=True, text=True, timeout=10)
            self.assertNotEqual(missing.returncode,0)
            self.assertIn("No module named 'uas.forge'",missing.stderr)

    def test_fixed_container_roles_do_not_expose_engine_or_hub_store_to_workstation(self):
        paths={name:Path('/owned')/name for name in ('peer','control','hub','workstation')}
        paths['nonce']='a'*32
        for kind in ('hub','workstation','sibling'):
            with self.subTest(kind=kind),patch.object(guest,'run',return_value='b'*64) as run:
                self.assertEqual(guest.create('sha256:'+'c'*64,'owned-name',kind,paths),'b'*64)
                args=run.call_args.args
                self.assertIn('--read-only',args);self.assertIn('ALL',args)
                self.assertIn('no-new-privileges=true',args)
                self.assertIn('/opt/uas/bin/tini',args)
                self.assertIn('none',args)
                self.assertFalse(any('docker.sock' in arg for arg in args))
                if kind=='hub':
                    self.assertIn('65531:65531',args)
                    self.assertIn('uas.workstation_service',args)
                else:
                    self.assertFalse(any('dst=/uas/hub' in arg or 'dst=/uas/control' in arg for arg in args))
                    self.assertIn('65532:65532',args)
                self.assertFalse(any('unconfined' in arg or 'label=disable' in arg for arg in args))

    def test_report_requires_every_native_check_without_synthetic_substitution(self):
        nonce='a'*32
        report={'version':1,'nonce':nonce,'checks':{key:{'status':'passed'} for key in runner.REQUIRED}}
        line='UAS_WORKSTATION_REPORT:'+nonce+':'+json.dumps(report)
        self.assertEqual(runner.parse_report(line,nonce),report)
        report['checks'].pop('socket_policy')
        with self.assertRaises(RuntimeError):runner.parse_report('UAS_WORKSTATION_REPORT:'+nonce+':'+json.dumps(report),nonce)
