"""Persistent resource custody contracts without socket/process execution."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from uas import local_runtime_resources as resources
from uas.native_qualification import QualificationError

class LocalRuntimeResourcesTests(unittest.TestCase):
    def plan(self):
        return SimpleNamespace(room={'id':'alpha','project':{'id':'project','repository':'matuto-ai/example'}},
                               config={'deployment':{'id':'deployment'}},installation={},require_unchanged=Mock())
    def test_missing_bindings_are_distinct_from_malformed_credentials(self):
        plan=self.plan()
        with patch.object(resources,'broker_selection',return_value={'credential_path':'/private/token'}),patch('pathlib.Path.lstat',side_effect=FileNotFoundError):
            self.assertEqual(resources.missing_bindings(plan),['forge-credential'])
        bad=SimpleNamespace(st_mode=0o100644,st_uid=165534,st_nlink=1)
        with patch.object(resources,'broker_selection',return_value={'credential_path':'/private/token'}),patch('pathlib.Path.lstat',return_value=bad),patch('pathlib.Path.resolve',return_value=Path('/private/token')):
            with self.assertRaisesRegex(QualificationError,'INVALID'):
                resources.missing_bindings(plan)

    def test_public_configuration_preserves_existing_broker_scope(self):
        plan=self.plan();selection={'version':1,'credential_path':'/private/token','gh_executable':'/usr/bin/gh','gh_sha256':'a'*64}
        value=resources.forge_configuration(plan,'instance',Path('/private/broker'),selection)
        self.assertEqual(value['supervisor_uid'],165533)
        self.assertEqual(value['credential_path'],'/private/token');self.assertNotIn('version',value)
        self.assertEqual(value['room_instance'],'instance')
        git=resources.git_configuration(plan,'instance',Path('/private/git'),{'version':1,'credentials':[]})
        self.assertEqual(git['binding']['repository'],'matuto-ai/example')
    def test_unknown_spawn_is_retained_and_not_repeatable(self):
        owner=resources.LocalRuntimeBrokers(self.plan(),'instance',{},8)
        host,service=Mock(),Mock();service.fileno.return_value=11
        with patch.object(resources.socket,'socketpair',return_value=(host,service)),patch.object(resources.subprocess,'Popen',side_effect=TimeoutError) as spawn:
            with self.assertRaises(TimeoutError):owner._spawn('forge','uas.forge_read_service',{},20)
            with self.assertRaisesRegex(QualificationError,'SELECTION'):owner._spawn('forge','uas.forge_read_service',{},20)
            spawn.assert_called_once()
        self.assertIs(owner.close(),False);host.close.assert_called_once();service.close.assert_called_once()
    def test_spawn_fixed_identity_and_lock_then_one_public_write(self):
        owner=resources.LocalRuntimeBrokers(self.plan(),'instance',{},8)
        host,service,process=Mock(),Mock(),Mock();service.fileno.return_value=11
        with patch.object(resources.socket,'socketpair',return_value=(host,service)),patch.object(resources.subprocess,'Popen',return_value=process) as spawn,patch.object(resources,'write_startup') as write:
            owner._spawn('git','uas.git_service',{'public':'metadata'},20)
        self.assertEqual(spawn.call_args.kwargs['user'],165534)
        self.assertEqual(spawn.call_args.kwargs['extra_groups'],[])
        self.assertEqual(spawn.call_args.kwargs['pass_fds'],(11,8))
        write.assert_called_once_with(process.stdin,b'{"public":"metadata"}\n',20)
    def test_close_does_not_claim_live_broker_fenced(self):
        owner=resources.LocalRuntimeBrokers(self.plan(),'instance',{},8)
        process=Mock();process.wait.side_effect=TimeoutError
        owner.records['forge']={'process':process,'host':Mock(),'service':Mock()}
        self.assertIs(owner.close(),False)
    def test_local_handoff_does_not_override_finite_handlers(self):
        from uas.native_checkout_handoff import RootCheckoutHandoff,MAX_REQUESTS
        self.assertIs(resources.LocalRootCheckoutHandoff.serve_one,RootCheckoutHandoff.serve_one)
        self.assertIsNot(resources.LocalRootCheckoutHandoff.operation,RootCheckoutHandoff.operation)
        self.assertEqual(MAX_REQUESTS,8)
    def test_epoch_reuses_existing_handler_not_deadline_reset(self):
        server=object.__new__(resources.LocalCheckoutServer)
        handler=Mock();server.epochs={'run-abc':handler};server._state=lambda:{}
        with patch('uas.local_successor_checkout.local_request'):
            self.assertIs(server._epoch({'kind':'OBSERVE','run_id':'run-abc'}),handler)
    def test_successor_epoch_requires_previous_verified_completion(self):
        server=object.__new__(resources.LocalCheckoutServer)
        server.epochs={'run-before':Mock()};server._state=lambda:{'runs':{'run-before':{'status':'OPEN'}}}
        with patch('uas.local_successor_checkout.local_request'):
            with self.assertRaisesRegex(QualificationError,'PREVIOUS_EPOCH_UNRESOLVED'):
                server._epoch({'kind':'ALLOCATE','run_id':'run-next'})
    def test_gate_requires_existing_canonical_epoch(self):
        server=object.__new__(resources.LocalCheckoutServer);server.epochs={}
        server._state=lambda:{'gate_evaluations':{'evaluation':{'scope':{'run_id':'run'}}}}
        with patch('uas.local_successor_checkout.local_request'):
            with self.assertRaisesRegex(QualificationError,'EPOCH_REQUIRED'):
                server._epoch({'kind':'GATE_QUOTA','evaluation_id':'evaluation'})
    def test_checkout_rejects_other_kernel_sender_before_dispatch(self):
        from contextlib import contextmanager
        from uas import kernel_origin
        server=object.__new__(resources.LocalCheckoutServer)
        server.closed=False;server.child=Mock();server.child.pid=123;server.child.poll.return_value=None
        server.pidfd=9;server.identity=(1,2);server.channel=Mock();server._epoch=Mock()
        server.resources=SimpleNamespace(plan=self.plan())
        @contextmanager
        def incoming(_channel):
            yield SimpleNamespace(credentials=(456,165533,165533),pidfd=10,data=b'{}')
        with patch.object(kernel_origin,'alive',return_value=True),patch.object(kernel_origin,'receive',incoming):
            with self.assertRaisesRegex(QualificationError,'HOST_MISMATCH'):server.serve_one()
        server._epoch.assert_not_called()
    def test_existing_manifest_mismatch_never_replaced(self):
        import stat
        from uas import native_qualification_backend
        info=SimpleNamespace(st_mode=stat.S_IFREG|0o400,st_nlink=1,st_uid=165533,st_size=2)
        with patch.object(resources.os.path,'lexists',return_value=True),patch.object(resources.os,'open',return_value=9),patch.object(resources.os,'fstat',return_value=info),patch.object(resources.os,'read',return_value=b'{}'),patch.object(resources.os,'close'),patch.object(native_qualification_backend,'copy_public_manifest') as copy:
            with self.assertRaisesRegex(QualificationError,'MANIFEST_CHANGED'):
                resources.retained_manifest({'path':'/public/source','sha256':'a'*64},'/public/retained')
        copy.assert_not_called()
