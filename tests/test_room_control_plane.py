"""Pure persistence/authorization tests, not native service/runtime evidence."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from lifecycle_support import FileFixtureBackend
from uas.lifecycle import FixtureSpec, LifecycleError, Supervisor
from uas.room_control_plane import RoomControlPlane, ServiceLease
from uas.room_remote_start import RemoteStart, StartCertificateBindings


class RoomFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / 'project'; self.project.mkdir()
        self.backend = FileFixtureBackend(self.root / 'resources')
        self.allowed = True
        self.supervisor = self.reopen()
        self.spec = FixtureSpec('alpha','project',(str(self.project),),'sha256:'+'a'*64,'sha256:'+'b'*64,'sha256:'+'c'*64)
        self.started = self.supervisor.start(self.spec)

    def reopen(self):
        return Supervisor(self.root/'control','alpha',self.backend,
                          authorize=lambda *_: self.allowed,revoke=self.backend.revoke)


class RoomControlPlaneTests(RoomFixture):
    def test_hosted_fixture_unix_paths_are_short_and_guarded_before_bind(self):
        import ast
        source = (Path(__file__).parent/'linux/room_control_smoke.py').read_text()
        tree = ast.parse(source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        temporary = next(node for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == 'TemporaryDirectory')
        options = {node.arg: ast.literal_eval(node.value) for node in temporary.keywords}
        self.assertEqual({'prefix':'r61-', 'dir':'/tmp'}, options)
        self.assertIn("directory=instance_dir/'data'/(name+'-e')", source)
        self.assertIn("endpoint=directory/'s'", source)
        self.assertIn("Supervisor(root/'c','alpha'", source)
        guard = source.index("require(len(os.fsencode(endpoint)) <= 107")
        self.assertLess(guard, source.index('listener.bind(str(endpoint))'))
        for name in ('hub','forge','git'):
            path = Path('/tmp')/('r61-'+'x'*8)/'c'/'alpha'/'instances'/('a'*32)/'data'/(name+'-e')/'s'
            self.assertLessEqual(len(str(path).encode()), 107)

    def test_stream_identity_is_persistent_and_callback_cannot_certify_missing_services(self):
        owner = RoomControlPlane(self.supervisor)
        identity = owner.status()['stream_id']
        reopened = self.reopen(); restored = RoomControlPlane(reopened)
        self.assertEqual(identity, restored.status()['stream_id'])
        self.assertEqual('destroy_failed', reopened.destroy()['phase'])
        self.assertEqual('running', self.backend.inspect(self.supervisor._read(),'container')['running'] and 'running')
        self.assertTrue(self.project.exists())

    def test_reopened_supervisor_does_not_accept_legacy_revoker(self):
        RoomControlPlane(self.supervisor)
        self.backend.calls.clear()
        result = self.reopen().destroy()
        self.assertEqual('destroy_failed',result['phase'])
        self.assertNotIn('revoke-all',self.backend.calls)
        self.assertFalse(any(call.startswith('remove') for call in self.backend.calls))

    def test_duplicate_owner_refused_without_replacing_store(self):
        owner = RoomControlPlane(self.supervisor); before = owner.path.read_bytes()
        with self.assertRaises(LifecycleError): RoomControlPlane(self.supervisor)
        self.assertEqual(before,owner.path.read_bytes())

    def test_wrong_service_handle_refused(self):
        owner = RoomControlPlane(self.supervisor)
        with self.assertRaises(LifecycleError): owner.attach(lambda: True)
        self.assertEqual('registering',owner.status()['phase'])

    def test_corrupt_store_blocks_restoration(self):
        owner = RoomControlPlane(self.supervisor)
        value = json.loads(owner.path.read_text()); value['phase'] = 'revoked'
        owner.path.write_text(json.dumps(value))
        with self.assertRaises(LifecycleError): RoomControlPlane(self.reopen())

    def test_local_start_and_reconcile_require_persisted_control_plane_readiness(self):
        RoomControlPlane(self.supervisor)
        reopened = self.reopen()
        self.backend.calls.clear()
        self.assertEqual('start_failed',reopened.start(self.spec)['phase'])
        self.assertNotIn('admit',self.backend.calls)
        self.assertEqual('start_failed',reopened.reconcile()['phase'])
        self.assertNotIn('admit',self.backend.calls)

    def test_missing_registry_does_not_downgrade_to_legacy_empty_callback(self):
        owner = RoomControlPlane(self.supervisor); owner.path.unlink()
        reopened = self.reopen()
        self.assertEqual('start_failed',reopened.start(self.spec)['phase'])
        self.assertEqual('destroy_failed',reopened.destroy()['phase'])
        with self.assertRaises(LifecycleError): RoomControlPlane(reopened)

    def test_large_hub_snapshot_has_bounded_status_summary(self):
        from uas.room_hub import status_summary
        summary = status_summary({'room_seq':123,'state':{'peer_traffic':{},'history':'x'*100000}})
        self.assertLess(len(json.dumps(summary)),300)
        self.assertGreater(summary['state_bytes'],65536)
        self.assertTrue(summary['configured'])

    def test_active_provider_operation_refuses_revocation_without_kernel_effect(self):
        import threading
        owner = RoomControlPlane(self.supervisor)
        owner.document['services']['git'] = {'identity':[1,2],'uid':65532,'gid':65532,
            'endpoints':[],'exited':False,'revoked':False}
        owner._save()
        lock = threading.Lock(); lock.acquire()
        owner._clients['git'] = SimpleNamespace(closed=False,_stream_lock=lock)
        try:
            self.assertFalse(owner.revoke_locked(self.supervisor._read(),'all'))
            self.assertIn({'kind':'authority','name':owner.instance+':git','reason':'SERVICE_OPERATION_ACTIVE'},owner.leftovers)
        finally: lock.release()

    def test_stale_owner_cannot_overwrite_newer_registry(self):
        first = RoomControlPlane(self.supervisor)
        second = RoomControlPlane(self.reopen())
        first.document['phase'] = 'revoking'; first._save()
        second.document['phase'] = 'registering'
        with self.assertRaises(LifecycleError) as error: second._save()
        self.assertEqual('CONTROL_PLANE_OWNER_STALE',error.exception.code)
        self.assertEqual('revoking',json.loads(first.path.read_text())['phase'])

    def test_revoked_owner_allows_tombstone_retry_after_instance_removal(self):
        from unittest.mock import patch
        import shutil
        owner = RoomControlPlane(self.supervisor)
        # Pure durable-proof model, not process-runtime evidence.
        owner.document['phase'] = 'revoked'
        state = self.supervisor._read(); state.update(authority='all-revoked')
        shutil.rmtree(owner.directory)
        self.assertTrue(owner.revoke_locked(state,'all'))


class RemoteStartContractTests(RoomFixture):
    def setUp(self):
        super().setUp()
        self.supervisor.stop()
        self.bindings = StartCertificateBindings({'a'*64:('human','alpha',self.started['instance_id'])})
        self.remote = RemoteStart(self.supervisor,self.bindings)
        # Deliberate pure unit substitute; native/mTLS integration is separate.
        self.supervisor._control_plane = SimpleNamespace(document={'phase':'ready'},require_ready_locked=lambda:True)
        self.principal = next(iter(self.bindings.bindings.values()))
        self.request = {'version':1,'kind':'start','operation_id':'start-one',
                        'observed_revision':self.supervisor._read()['observation_revision']}

    def test_exact_start_and_receipt_replay_do_not_repeat_effect(self):
        first = self.remote._start(self.principal,self.request)
        calls = list(self.backend.calls)
        self.assertEqual('running',first['phase'])
        self.assertEqual(first,self.remote._start(self.principal,self.request))
        self.assertEqual(calls,self.backend.calls)

    def test_stale_observation_refused_before_intent(self):
        self.request['observed_revision'] -= 1
        with self.assertRaises(LifecycleError) as error: self.remote._start(self.principal,self.request)
        self.assertEqual('START_STALE_OBSERVATION',error.exception.code)
        self.assertEqual('stopped',self.supervisor._read()['phase'])

    def test_certificate_role_does_not_allow_payload_identity_or_spec(self):
        for key in ('human','room_id','spec','argv'):
            request = {**self.request,key:'injected'}
            with self.assertRaises(LifecycleError): self.remote._start(self.principal,request)
        with self.assertRaises(LifecycleError): self.remote._start(('other',*self.principal[1:]),self.request)

    def test_current_authorization_required_even_for_cached_result(self):
        self.remote._start(self.principal,self.request); self.allowed = False
        with self.assertRaises(LifecycleError) as error: self.remote._start(self.principal,self.request)
        self.assertEqual('FORBIDDEN',error.exception.code)

    def test_reused_operation_with_changed_revision_conflicts(self):
        self.remote._start(self.principal,self.request)
        with self.assertRaises(LifecycleError) as error:
            self.remote._start(self.principal,{**self.request,'observed_revision':self.request['observed_revision']+1})
        self.assertEqual('START_IDEMPOTENCY_CONFLICT',error.exception.code)


class ManagerOwnershipTests(RoomFixture):
    def setUp(self):
        super().setUp()
        from uas.manager_host import RoomManagerWorker
        from uas.manager_stream import RoomIdentity
        from unittest.mock import patch
        self.owner=RoomControlPlane(self.supervisor)
        self.identity=RoomIdentity('demo','alpha',self.owner.document['stream_id'])
        self.worker=RoomManagerWorker(self.root/'ledger.db',self.identity,'{}',lambda **_:None)
        # Pure attachment contract only: no kernel services or thread launch.
        with patch.object(self.owner,'require_ready_locked',return_value=True), patch.object(self.worker,'start') as start:
            self.owner.attach_manager_worker(self.worker)
            self.assertEqual(1,start.call_count)

    def test_worker_identity_persisted_before_start_and_stop_retains_it(self):
        from unittest.mock import patch
        self.assertEqual(self.worker.worker_id,self.owner.document['manager']['worker_id'])
        with patch.object(self.owner,'require_ready_locked',return_value=True):
            self.assertTrue(self.owner.revoke_locked(self.supervisor._read(),'participants'))
        self.assertFalse(self.worker.status()['stop_requested'])

    def test_pending_worker_blocks_cleanup_until_actual_terminal(self):
        class LiveThread:
            ident=1
            def is_alive(self): return True
        self.worker._phase='running'; self.worker._thread=LiveThread()
        self.assertFalse(self.owner._stop_exporter_locked())
        self.assertEqual('MANAGER_EXPORTER_STOP_PENDING',self.owner.leftovers[-1]['reason'])
        self.assertFalse(self.owner.document['manager']['terminated'])
        self.worker._thread=None; self.worker._done.set()
        self.assertTrue(self.owner._stop_exporter_locked())
        self.assertTrue(self.owner.document['manager']['terminated'])

    def test_lost_owner_and_new_worker_with_same_stream_do_not_certify_old_worker(self):
        from uas.manager_host import RoomManagerWorker
        self.owner._manager_worker=None
        self.assertFalse(self.owner._stop_exporter_locked())
        self.assertEqual('MANAGER_EXPORTER_OWNER_UNKNOWN',self.owner.leftovers[-1]['reason'])
        other=RoomManagerWorker(self.root/'ledger.db',self.identity,'{}',lambda **_:None)
        other.request_stop()
        with self.assertRaises(LifecycleError):self.owner.recover_manager_worker(other)
        self.worker.request_stop()
        self.owner.recover_manager_worker(self.worker)
        self.assertTrue(self.owner._stop_exporter_locked())
