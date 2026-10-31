"""Cheap persistent Hub contracts; no kernel, process or Docker execution."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uas import workstation_service as service
from uas import local_hub_host as host
from uas.kernel_origin import OriginDenied
from uas.native_qualification import QualificationError

class LocalHubTests(unittest.TestCase):
    def value(self):
        return {'version':1,'challenge':'a'*64,'supervisor_identity':[1,2],
                'mapping_digest':'b'*64,'room_id':'alpha','room_instance':'instance',
                'profile':'local-hub-v1','seats':[
                    {'participant_id':'alice','actor_id':'actor-a','profile_id':'native-pi-v1'},
                    {'participant_id':'bob','actor_id':'actor-b','profile_id':'native-claude-v1'}]}

    def test_profile_is_explicit_and_separate(self):
        value=self.value();self.assertEqual(len(service.configuration(json.dumps(value).encode(),persistent=True)[1]),2)
        with self.assertRaises(OriginDenied):service.configuration(json.dumps(value).encode())
        value['run_id']='not-an-idle-run'
        with self.assertRaises(OriginDenied):service.configuration(json.dumps(value).encode(),persistent=True)
        del value['profile'];service.configuration(json.dumps(value).encode())

    def test_idle_does_not_configure_run(self):
        hub=Mock();value,seats=service.configuration(json.dumps(self.value()).encode(),persistent=True)
        service.initialize_hub(hub,seats,value,persistent=True);hub.configure.assert_not_called()
        value['run_id']='actual-qualification'
        service.initialize_hub(hub,seats,value,persistent=False)
        self.assertEqual(hub.configure.call_args.args[-1],'actual-qualification')

    def test_persistent_loop_uses_owner_not_clock(self):
        loop=Mock();loop.step.side_effect=[None,OriginDenied('owner gone')]
        ledger=Mock();ledger.snapshot.return_value={'room_seq':0};lease=Mock()
        with patch.object(service.time,'monotonic',side_effect=AssertionError('no lifetime clock')),patch.object(service,'report') as report:
            with self.assertRaisesRegex(OriginDenied,'owner gone'):service.serve_loop(loop,ledger,lease,persistent=True)
        report.assert_called_once_with(ledger,summary=True)
        self.assertEqual(lease.require.call_count,2)

    def test_qualification_keeps_deadline(self):
        with patch.object(service.time,'monotonic',side_effect=[10,191]):
            with self.assertRaisesRegex(OriginDenied,'lifetime expired'):service.serve_loop(Mock(),Mock(),Mock())

    def test_summary_bounded_and_real(self):
        ledger=Mock();ledger.snapshot.return_value={'room_seq':42,'state':{'real': 'x'*2000000}}
        with tempfile.TemporaryDirectory() as tmp,patch.object(service,'STORE',Path(tmp)):
            service.report(ledger,summary=True)
            result=json.loads((Path(tmp)/'report.json').read_text())
            self.assertLess((Path(tmp)/'report.json').stat().st_size,200)
            self.assertEqual(result['room_seq'],42);self.assertFalse(result['configured'])

    def test_host_metadata_has_no_run(self):
        room={'id':'alpha','seats':[{'participant':'alice','actor':'actor-a','profile':'native-pi-v1'},
                                  {'participant':'bob','actor':'actor-b','profile':'native-claude-v1'}]}
        result=host.metadata(room,{'mapping_digest':'b'*64,'instance':'instance'},[1,2],'a'*64)
        self.assertNotIn('run_id',result);self.assertEqual(result['profile'],'local-hub-v1')

    def test_parent_eof_releases_retainer(self):
        origin=SimpleNamespace(revoked=False,pidfd=12);control=object()
        with patch.object(host,'alive',return_value=True),patch.object(host.select,'select',return_value=([9],[],[])),patch.object(host.os,'read',return_value=b''):
            host.retain(control,origin,9)

    def test_hub_loss_is_not_ready(self):
        origin=SimpleNamespace(revoked=False,pidfd=12);control=object()
        with patch.object(host,'alive',return_value=True),patch.object(host.select,'select',return_value=([12],[],[])):
            with self.assertRaisesRegex(QualificationError,'OWNER_LOST'):host.retain(control,origin,9)

    def test_root_cannot_claim_supervisor_identity(self):
        with patch.object(host.os,'getuid',return_value=0),patch.object(host.os,'getgid',return_value=0):
            with self.assertRaisesRegex(QualificationError,'FIXED_OWNER'):host.run(b'{}',0)

    def test_handshake_binds_ready_and_never_retries_start(self):
        from contextlib import ExitStack
        from uas import native_session as session
        startup=self.value();resources={'hub_id':'owned-id','control_path':'/owned/hub.sock'}
        control=Mock();control.send.return_value=len(service.RELEASE);listener=Mock();listener.accept.return_value=(control,None)
        record1=SimpleNamespace(data=b'HUB1'+bytes.fromhex(startup['challenge']),credentials=(42,session.HUB_UID,session.HUB_UID))
        ready={'version':1,'kind':'HUB_READY','controller':'controller','room_id':'alpha','room_instance':'instance','observation':{}}
        record2=SimpleNamespace(data=json.dumps(ready).encode())
        def record(value):
            result=Mock();result.__enter__=Mock(return_value=value);result.__exit__=Mock(return_value=False);return result
        engine=Mock();budget=Mock();budget.remaining.return_value=5;phases=[];handoff=Mock()
        with patch.object(session,'EndpointLease'),patch.object(session,'enable'),patch.object(session,'HeldOrigin'),patch.object(session,'receive',side_effect=[record(record1),record(record2)]),ExitStack() as stack:
            result=session.start_hub_channel(engine,resources,startup,listener,stack,budget,progress=phases.append,library_handoff=handoff)
            self.assertEqual(result[2],ready);engine.start_hub.assert_called_once_with('owned-id')
            self.assertEqual(phases,['hub-attach','hub-start','hub-write','hub-connect','hub-origin','hub-release','hub-library-handoff','hub-ready'])
            handoff.assert_called_once_with(control)
        engine=Mock();engine.start_hub.side_effect=TimeoutError('uncertain start');phases=[]
        with patch.object(session,'EndpointLease'),ExitStack() as stack:
            with self.assertRaises(TimeoutError):session.start_hub_channel(engine,resources,startup,listener,stack,budget,progress=phases.append)
        engine.start_hub.assert_called_once_with('owned-id');engine.attach_hub.return_value.close.assert_called_once()
        self.assertEqual(phases,['hub-attach','hub-start'])
        self.assertEqual(host.failure_receipt(phases[-1],TimeoutError('private'))['phase'],'hub-start')

    def test_startup_rejects_alias_descriptors(self):
        value={'version':1,'room':{},'resources':{'hub_id':'owned','instance':'instance','control_path':'/owned/hub.sock',
                'mapping_digest':'b'*64,'control_fd':9,'peer_fd':9}}
        with self.assertRaisesRegex(QualificationError,'STARTUP_RESOURCES'):host.startup_document(json.dumps(value).encode())

    def test_host_preserves_public_project_policy_without_run(self):
        room={'id':'alpha','project':{'id':'project','repository':'matuto-ai/ultimate-agent-sandbox'},
              'profiles':[{'id':'pi','capabilities':['forge-read']}],
              'seats':[{'participant':'alice','actor':'actor-a','profile':'pi'},
                       {'participant':'bob','actor':'actor-b','profile':'pi'}]}
        result=host.metadata(room,{'mapping_digest':'b'*64,'instance':'instance'},[1,2],'a'*64)
        self.assertNotIn('run_id',result)
        self.assertEqual(result['seats'][0]['capabilities'],['forge-read','peer-traffic'])
        self.assertEqual(result['forge']['repository'],room['project']['repository'])
    def test_failure_receipt_is_closed_and_never_contains_exception_text(self):
        for error,kind in ((OriginDenied('secret/path'),'origin-denied'),
                           (QualificationError('secret/token'),'qualification'),
                           (PermissionError('secret'),'permission'),
                           (TimeoutError('secret'),'timeout'),(ValueError('secret'),'other')):
            self.assertEqual(host.failure_receipt('library-root',error),
                {'version':1,'status':'unknown','phase':'library-root','error':kind})
        self.assertEqual(host.failure_receipt('private/path',ValueError()).get('phase'),'bootstrap')
    def test_main_emits_safe_failure_then_terminates(self):
        from io import BytesIO
        output=BytesIO()
        def fail(raw,fd,*,phase):
            phase('hub-startup');raise OriginDenied('private model/config text')
        with patch.object(host.sys,'argv',['fixed']),patch.object(host.os,'read',side_effect=[b'{',b'}',b'\n']),patch.object(host,'run',side_effect=fail),patch.object(host.sys,'stdout',SimpleNamespace(buffer=output)):
            with self.assertRaises(OriginDenied):host.main()
        value=json.loads(output.getvalue())
        self.assertEqual(value,{'version':1,'status':'unknown','phase':'hub-startup','error':'origin-denied'})
