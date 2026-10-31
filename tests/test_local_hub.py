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
    def test_local_entrypoint_emits_only_fixed_flushed_phases_and_import_order(self):
        import builtins
        from uas import local_hub
        output=Mock()
        with patch.object(local_hub.sys,'stderr',output):
            for phase in sorted(local_hub.PHASES):local_hub.progress(phase)
            for bad in ('secret\nprobe-done','unknown',None,[]):
                with self.assertRaises(ValueError):local_hub.progress(bad)
        self.assertEqual(output.flush.call_count,len(local_hub.PHASES))
        self.assertEqual([call.args[0] for call in output.write.call_args_list],
            ['UAS_LOCAL_HUB_PHASE '+phase+'\n' for phase in sorted(local_hub.PHASES)])
        events=[];original=builtins.__import__
        def importing(name,*args,**kwargs):
            if name=='workstation_service':events.append('actual-import')
            return original(name,*args,**kwargs)
        with patch.object(local_hub,'progress',side_effect=events.append),patch.object(builtins,'__import__',side_effect=importing),patch.object(service,'run_service',return_value='done') as run:
            self.assertEqual(local_hub.main(),'done')
        self.assertEqual(events,['import-start','actual-import','import-done'])
        self.assertTrue(run.call_args.kwargs['persistent'])
        self.assertIn('progress',run.call_args.kwargs)

    def test_preconnect_phases_preserve_guard_order_and_propagate_failure(self):
        from io import BytesIO
        import hashlib
        mapping={'uid_map':'0 100000 65536\n','gid_map':'0 100000 65536\n','overflow_uid':65534,'overflow_gid':65534}
        value=self.value();value['mapping_digest']=hashlib.sha256(json.dumps(mapping,sort_keys=True).encode()).hexdigest()
        def read(path):
            return str(mapping[{'overflowuid':'overflow_uid','overflowgid':'overflow_gid'}.get(path.name,path.name)])
        class ConnectReached(Exception):pass
        channel=Mock();channel.connect.side_effect=ConnectReached
        phases=[]
        with patch.object(service.sys,'argv',['fixed']),patch.object(service.os,'getuid',return_value=65531),patch.object(service.os,'getgid',return_value=65531),patch.object(service.os,'umask'),patch.object(service,'probe') as probe,patch.object(service,'process_status',return_value={'CapEff':'0000000000000000','CapBnd':'0000000000000000','NoNewPrivs':'1','Seccomp':'2'}),patch.object(service.sys,'stdin',SimpleNamespace(buffer=BytesIO(json.dumps(value).encode()+b'\n'))),patch.object(service.Path,'read_text',read),patch.object(service,'EndpointLease'),patch.object(service.socket,'socket',return_value=channel),patch.object(service,'enable'):
            with self.assertRaises(ConnectReached):service.run_service(persistent=True,progress=phases.append)
        self.assertEqual(phases,['entrypoint-validated','probe-start','probe-done','metadata-wait','metadata-read','metadata-parsed','mapping-validated','paths-validated','control-connect'])
        probe.assert_called_once();channel.send.assert_not_called()
        with patch.object(service.sys,'argv',['fixed']),patch.object(service.os,'getuid',return_value=0),patch.object(service,'probe') as probe:
            with self.assertRaises(OriginDenied):service.run_service(persistent=True,progress=lambda _:self.fail('phase before guard'))
        probe.assert_not_called()
        with patch.object(service.sys,'argv',['fixed']),patch.object(service.os,'getuid',return_value=65531),patch.object(service.os,'getgid',return_value=65531),patch.object(service,'probe') as probe:
            with self.assertRaisesRegex(RuntimeError,'phase failure'):
                service.run_service(persistent=True,progress=Mock(side_effect=RuntimeError('phase failure')))
        probe.assert_not_called()
    def test_cold_configuration_does_not_load_unneeded_broker_or_human_authority(self):
        import subprocess
        import sys
        value=self.value()
        value['forge']={'project_id':'project','repository':'owner/repository','host':'github.com'}
        value['library']={'project':{'id':'project','repository':'owner/repository',
            'roots':{'reference':'/owned/reference'}},'source_identity':'source'}
        script="""import sys,json
sys.path.insert(0,sys.argv[1])
from uas.workstation_service import configuration
value=json.loads(sys.argv[2]);observed,seats=configuration(json.dumps(value).encode(),persistent=True)
assert observed==value and len(seats)==2
assert 'uas.forge' not in sys.modules
assert 'uas.manager_actions' not in sys.modules
from uas import library
binding=library.project_binding(value['library']['project'],source_identity='source')
try:library.human_scope(object(),binding=binding,kind='drain')
except library.LibraryError as error:assert error.code=='LIBRARY_AUTHENTICATION_REQUIRED'
else:raise AssertionError('fake human accepted')
assert 'uas.manager_actions' in sys.modules
"""
        result=subprocess.run([sys.executable,'-I','-S','-B','-c',script,
            str(Path(__file__).resolve().parents[1]),json.dumps(value)],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
