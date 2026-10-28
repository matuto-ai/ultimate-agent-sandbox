"""Pure fixture diagnostics: no VM, native process, socket or kernel evidence."""
import ast
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import tempfile
from contextlib import ExitStack

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
try:
    import room_service
    import guest_room
    from room_service import ObservedAuthority, require_help_reply
finally:
    sys.path.pop(0)


class DiagnosticsTests(unittest.TestCase):
    def test_first_help_refusal_is_terminal_before_second_request(self):
        checks = {}
        with self.assertRaisesRegex(RuntimeError, 'mounted help refused'):
            require_help_reply(None, checks, 0)
        self.assertEqual([None], checks['help_replies'])

    def test_help_success_and_nonhelp_refusal(self):
        checks = {}
        require_help_reply({'code': 0, 'status': 'OK', 'stdout': b'not retained'}, checks, 0)
        require_help_reply(None, checks, 1)
        self.assertEqual([{'code': 0, 'status': 'OK'}, None], checks['help_replies'])
        with self.assertRaisesRegex(RuntimeError, 'non-help unexpectedly admitted'):
            require_help_reply({'code': 0, 'status': 'OK'}, {}, 1)
        with self.assertRaisesRegex(RuntimeError, 'mounted help refused'):
            require_help_reply({'code': 128, 'status': 'ERROR'}, {}, 0)

    def test_bind_denial_keeps_original_exception_and_first_failure(self):
        original = RuntimeError('lineage admission deadline exceeded')
        delegate = Mock(); delegate.bind.side_effect = original
        checks = {}; observed = ObservedAuthority(delegate, checks, lambda: None)
        with self.assertRaises(RuntimeError) as caught: observed.bind('record')
        self.assertIs(original, caught.exception)
        self.assertEqual({'operation':'bind', 'phase':'lineage', 'error_type':'RuntimeError',
                          'message':str(original)}, checks['authority_failure'])
        delegate.current.side_effect = ValueError('later')
        with self.assertRaises(ValueError): observed.current()
        self.assertEqual('bind', checks['authority_failure']['operation'])
        delegate.bind.assert_called_once_with('record')

    def test_admitted_binding_still_rechecks_and_closes_same_authority(self):
        binding = SimpleNamespace(origin=object(), current=Mock(return_value=True),
                                  require=Mock(return_value=True), close=Mock())
        delegate = SimpleNamespace(bind=Mock(return_value=binding), close=Mock())
        checks = {}; observed = ObservedAuthority(delegate, checks, lambda: None)
        admitted = observed.bind('record')
        self.assertIs(binding.origin, admitted.origin)
        self.assertTrue(admitted.current()); self.assertTrue(admitted.require('next'))
        admitted.close(); observed.close()
        binding.current.assert_called_once_with(); binding.require.assert_called_once_with('next')
        binding.close.assert_called_once_with(); delegate.close.assert_called_once_with()
        self.assertNotIn('authority_failure', checks)
        self.assertEqual(3, len({key.split('.')[0] for key in checks['authority_phases']}))

    def test_current_denial_bounded_without_replacing_exception(self):
        error = RuntimeError('x' * 1000)
        checks = {}; binding = Mock(); binding.current.side_effect = error
        with self.assertRaises(RuntimeError) as caught: ObservedAuthority(binding, checks, lambda: None).current()
        self.assertIs(error, caught.exception)
        self.assertEqual(256, len(checks['authority_failure']['message']))
        self.assertEqual('current', checks['authority_failure']['operation'])

    def test_stage_and_partial_evidence_are_assigned_before_effects(self):
        text = (VM/'room_service.py').read_text()
        self.assertLess(text.index("checks['stage'] = 'help_accept'"), text.index('select.select([listener, launch.channel]'))
        self.assertLess(text.index('require_help_reply(replies[-1]'), text.index("control({'kind': 'HELP_ONLY_PROVED'})"))
        self.assertIn('launch.origin.require(record)', text)
        guest = (VM/'guest_room.py').read_text()
        self.assertLess(guest.index("checks['endpoint_service'] = {}"), guest.index("prove_service(supervisors['alpha']"))
        self.assertIn("checks=checks['endpoint_service']", guest)
        self.assertIn("checks.update(status='failed', error_type=type(error).__name__)", text)

    def test_bootstrap_error_report_does_not_export_exception_text(self):
        tree = ast.parse((VM.parent.parent/'uas/room_probe.py').read_text())
        handlers = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)
                    and "'BOOTSTRAP_FAILED'" in ast.unparse(n)]
        self.assertEqual(1, len(handlers))
        text = ast.unparse(handlers[0])
        self.assertIn("'stage': stage", text)
        self.assertIn("'error_type': type(error).__name__[:64]", text)
        self.assertNotIn('str(error)', text)
        self.assertIsInstance(handlers[0].body[-1], ast.Raise)

    def test_failure_sender_holds_for_bounded_authenticated_ack(self):
        probe = (VM.parent.parent/'uas/room_probe.py').read_text()
        start = probe.index("'kind': 'BOOTSTRAP_FAILED'")
        tail = probe[start:probe.index('except Exception:', start)]
        self.assertLess(tail.index('channel.settimeout(5)'), tail.index('with receive(channel)'))
        self.assertLess(tail.index('peer.require(record)'), tail.index("'BOOTSTRAP_FAILURE_RECORDED'"))
        service = (VM/'room_service.py').read_text()
        start = service.index('if launch.channel in ready:')
        tail = service[start:service.index("raise RuntimeError('bootstrap ended", start)]
        self.assertLess(tail.index('launch.origin.require(record)'), tail.index("checks['bootstrap_failure'] = value"))
        self.assertLess(tail.index("checks['bootstrap_failure'] = value"), tail.index("'BOOTSTRAP_FAILURE_RECORDED'"))


    def test_service_closer_attempts_every_owner_and_backend_and_keeps_first_failure(self):
        names = ('authority', 'launch', 'provenance', 'broker')
        for failing in names + ('backend_fd', 'all'):
            with self.subTest(failing=failing):
                checks, calls = {}, []
                originals = {name: OSError(name) for name in names + ('backend_fd',)}
                def close(name):
                    calls.append(name)
                    if failing in (name, 'all'): raise originals[name]
                owners = [(name, SimpleNamespace(close=lambda name=name: close(name))) for name in names]
                with patch.object(room_service.os, 'close', side_effect=lambda fd: close('backend_fd')):
                    error = room_service.close_service_resources(checks, owners, 99)
                self.assertEqual(list(names)+['backend_fd'], calls)
                self.assertIs(error, originals['authority' if failing == 'all' else failing])
                self.assertEqual('failed', checks['cleanup']['status'])
                self.assertEqual(calls, checks['cleanup']['attempted'])
                self.assertEqual(5 if failing == 'all' else 1, len(checks['cleanup']['errors']))
                self.assertNotIn('message', str(checks))

    def test_broker_constructor_rollback_closes_every_owned_handle_without_masking_startup(self):
        import uas.kernel_origin as origin
        import uas.git_service as service
        primary = RuntimeError('startup failed')
        for phase in ('enable_parent', 'enable_child', 'fork', 'child_close', 'pidfd', 'client', 'require'):
            with self.subTest(phase=phase), ExitStack() as stack:
                parent, child = Mock(), Mock()
                parent.close.side_effect = OSError('parent cleanup')
                directory = Mock(); root = Mock(); root.__truediv__ = Mock(return_value=directory)
                root.lstat.return_value = SimpleNamespace(st_mode=0o40755, st_uid=0)
                checks = {}
                stack.enter_context(patch.object(room_service, 'BROKER_ROOT', root))
                stack.enter_context(patch.object(room_service, 'fixed_executable', return_value=(91, 'a'*64)))
                stack.enter_context(patch.object(room_service.os, 'chown'))
                stack.enter_context(patch.object(room_service.os, 'close'))
                stack.enter_context(patch.object(room_service.signal, 'getsignal', return_value=room_service.signal.SIG_DFL))
                stack.enter_context(patch.object(room_service.socket, 'socketpair', return_value=(parent, child)))
                enable = stack.enter_context(patch.object(origin, 'enable'))
                if phase.startswith('enable_'): enable.side_effect = [primary] if phase == 'enable_parent' else [None, primary]
                stack.enter_context(patch.object(room_service.os, 'fork', side_effect=primary if phase=='fork' else None, return_value=100))
                if phase == 'child_close': child.close.side_effect = primary
                stack.enter_context(patch.object(room_service.os, 'pidfd_open', side_effect=primary if phase=='pidfd' else None, return_value=92))
                stack.enter_context(patch.object(service, 'GitBrokerClient', side_effect=primary if phase=='client' else None))
                stack.enter_context(patch.object(room_service.BrokerProcess, 'require', side_effect=primary if phase=='require' else None))
                cleanup = stack.enter_context(patch.object(room_service.BrokerProcess, 'close', side_effect=ValueError('broker cleanup')))
                with self.assertRaises(RuntimeError) as caught:
                    room_service.BrokerProcess(object(), 'owned-instance', checks=checks)
                self.assertIs(primary, caught.exception); cleanup.assert_called_once()
                self.assertEqual(['parent_channel','child_channel','broker'], checks['cleanup']['attempted'])
                self.assertTrue(child.close.called)
                self.assertEqual('failed', checks['cleanup']['status'])

    def test_actual_prove_service_preserves_primary_and_records_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = SimpleNamespace(directory=Path(temporary), _read=lambda:{
                'phase':'running', 'room_id':'alpha', 'instance_id':'owned'})
            primary = RuntimeError('Broker observation failed')
            broker = SimpleNamespace(observe=Mock(side_effect=primary), close=Mock(side_effect=OSError('close')))
            checks = {}
            with patch.object(room_service, 'BrokerProcess', return_value=broker):
                with self.assertRaises(RuntimeError) as caught:
                    room_service.prove_service(supervisor, object(), SimpleNamespace(listeners=[object()]),
                        'owned-container', run=Mock(), checks=checks)
            self.assertIs(primary, caught.exception); broker.close.assert_called_once()
            self.assertEqual('failed', checks['status'])
            self.assertEqual({'owner':'broker','error_type':'OSError'}, checks['cleanup']['errors'][0])

    def test_guest_cleanup_fault_matrix_keeps_attempting_all_owned_resources(self):
        names = ('destroy', 'listener0', 'listener1', 'responder', 'veth', 'netns', 'public', 'image', 'storage')
        for failure in names + ('all',):
            with self.subTest(failure=failure):
                calls, checks = [], {}
                def effect(name):
                    calls.append(name)
                    if failure in (name, 'all'): raise OSError('synthetic cleanup fault')
                    return {'phase':'destroyed'}
                supervisor = SimpleNamespace(destroy=lambda:effect('destroy'))
                endpoint = SimpleNamespace(listeners=[SimpleNamespace(close=lambda:effect('listener0')),
                    SimpleNamespace(close=lambda:effect('listener1'))])
                command_names = iter(('veth','netns','public','image','storage'))
                with patch.object(guest_room, 'stop_child', side_effect=lambda p:effect('responder')), \
                        patch.object(guest_room, 'run', side_effect=lambda *args:effect(next(command_names))):
                    errors = guest_room.cleanup_owned({'alpha':supervisor}, {'alpha':endpoint}, [object()],
                        {'veth','netns','public-host','storage'}, 'sha256:owned', Path('/owned'), checks)
                self.assertEqual(list(names), calls)
                self.assertEqual(9 if failure=='all' else 1, len(errors))
                self.assertEqual('failed', checks['guest_cleanup']['status'])
                self.assertTrue(checks['guest_cleanup']['outer_disposable_vm_removal_remains_mandatory'])


    def network_case(self, *, public_error=None, failed_address=None, admission_at=None, decoy_error=None):
        checks, calls, admissions = {}, [], [0]
        primary = RuntimeError('fresh containment failed')
        def admit(state):
            admissions[0] += 1
            if admission_at == admissions[0]: raise primary
        backends = {name:SimpleNamespace(admit=admit, _firewall=lambda state:'fixed-firewall') for name in ('alpha','beta')}
        def probe(room, mode, address):
            calls.append(address)
            if address == failed_address: return {'error':'OK'}
            return {'error':'ENETUNREACH' if address.startswith('[') else 'TIMEOUT'}
        def public(*args):
            calls.append('public')
            if public_error: raise public_error
            return {'certificate_hostname_verified':True}
        with patch.object(guest_room, 'wait_decoys', side_effect=decoy_error), \
                patch.object(guest_room.boundary, 'denial_counter', side_effect=range(8)), \
                patch.object(guest_room.boundary, 'require_sibling_denial', return_value={'exact':'synthetic'}):
            error = None
            try: guest_room.prove_network(probe, public, backends, {'alpha':{},'beta':{}},
                {'beta':'owned'}, [], checks)
            except BaseException as caught: error = caught
        return checks, calls, error, primary

    def test_public_failure_keeps_every_independent_deny_observation_and_first_error(self):
        primary = RuntimeError('public HTTPS unavailable')
        checks, calls, error, _ = self.network_case(public_error=primary)
        self.assertIs(primary, error); self.assertEqual('failed', checks['status'])
        self.assertEqual('failed', checks['observations']['public_https']['status'])
        self.assertEqual({'host-private','host-public','LAN','metadata','sibling'}, set(checks['denied']))
        self.assertTrue(all(checks['observations'][name]['status']=='passed' for name in checks['denied']))
        self.assertEqual('passed', checks['observations']['ipv6']['status'])
        self.assertEqual(6, len(calls))

    def test_one_deny_failure_preserves_its_raw_counters_and_later_independent_results(self):
        checks, _, error, _ = self.network_case(failed_address='10.89.1.1:5000')
        self.assertIsNotNone(error); self.assertEqual('failed', checks['status'])
        observation = checks['observations']['host-private']
        self.assertEqual({'error':'OK'}, observation['result'])
        self.assertEqual((0,1), (observation['before'],observation['after']))
        self.assertNotIn('host-private',checks['denied'])
        self.assertEqual('passed',checks['observations']['host-public']['status'])
        self.assertEqual('passed',checks['observations']['sibling']['status'])

    def test_fresh_admission_failure_blocks_all_later_workload_probes_and_preserves_prior_error(self):
        for fail_at in (1,5,9):
            with self.subTest(fail_at=fail_at):
                primary = RuntimeError('first public failure')
                checks, calls, error, admission = self.network_case(public_error=primary, admission_at=fail_at)
                self.assertIs(error, admission if fail_at==1 else primary)
                blocked = [entry for entry in checks['observations'].values() if entry['status']=='blocked']
                self.assertTrue(blocked)
                self.assertTrue(all(entry['reason']=='fresh_room_admission_failed' for entry in blocked))
                self.assertNotIn('[2606:4700:4700::1111]:5000', calls)
                if fail_at==1: self.assertEqual([], calls)

    def test_decoy_failure_blocks_only_dependent_denies_not_public_sibling_or_ipv6(self):
        primary = RuntimeError('decoy failed')
        checks, calls, error, _ = self.network_case(decoy_error=primary)
        self.assertIs(error, primary)
        self.assertEqual(['public','[2606:4700:4700::1111]:5000'], calls)
        for name in ('host-private','host-public','LAN','metadata'):
            self.assertEqual({'status':'blocked','reason':'live_decoy_positive_control_failed'}, checks['observations'][name])
        for name in ('public_https','sibling','ipv6'): self.assertEqual('passed',checks['observations'][name]['status'])

    def test_network_success_still_requires_conjunction_of_all_observations(self):
        checks, _, error, _ = self.network_case()
        self.assertIsNone(error); self.assertEqual('passed',checks['status'])
        self.assertEqual(8,len(checks['observations']))
        self.assertTrue(all(item['status']=='passed' for item in checks['observations'].values()))

    def test_decoy_readiness_has_one_absolute_deadline_and_nonreaping_child_check(self):
        for mode in ('success','false','timeout','exit','late_success'):
            with self.subTest(mode=mode):
                now, deadlines, attempts = [0.0], [], []
                def connect(address, *, deadline):
                    attempts.append(address); deadlines.append(deadline)
                    now[0] += 2.1 if mode=='late_success' else (2 if mode=='timeout' else .01)
                    if mode=='timeout': raise TimeoutError('synthetic timeout')
                    return mode != 'false'
                def sleep(seconds): now[0] += seconds
                with patch.object(guest_room.time,'monotonic',side_effect=lambda:now[0]), \
                        patch.object(guest_room.time,'sleep',side_effect=sleep), \
                        patch.object(guest_room.os,'waitid',return_value=object() if mode=='exit' else None) as waitid, \
                        patch.object(guest_room.boundary,'connect',side_effect=connect):
                    if mode=='success': guest_room.wait_decoys([SimpleNamespace(pid=123)])
                    else:
                        with self.assertRaisesRegex(AssertionError, 'deadline|exited'):
                            guest_room.wait_decoys([SimpleNamespace(pid=123)])
                self.assertTrue(all(value==guest_room.DECOY_TIMEOUT for value in deadlines))
                self.assertLessEqual(now[0],guest_room.DECOY_TIMEOUT+.4)
                self.assertTrue(all(call.args==(guest_room.os.P_PID,123,
                    guest_room.os.WEXITED|guest_room.os.WNOHANG|guest_room.os.WNOWAIT) for call in waitid.call_args_list))
                if mode=='exit': self.assertEqual([],attempts)

    def test_decoy_connect_shares_deadline_across_connect_and_receive_without_changing_default(self):
        channel=Mock();channel.__enter__=Mock(return_value=channel);channel.__exit__=Mock(return_value=False)
        channel.recv.return_value=b'uas-boundary-ok\n'
        with patch.object(guest_room.boundary.socket,'create_connection',return_value=channel) as connect, \
                patch.object(guest_room.time,'monotonic',side_effect=[7,7.75,7.9]):
            self.assertTrue(guest_room.boundary.connect('93.184.216.34',deadline=8))
        connect.assert_called_once_with(('93.184.216.34',5000),timeout=1)
        channel.settimeout.assert_called_once_with(.25)
        channel.settimeout.reset_mock()
        with patch.object(guest_room.boundary.socket,'create_connection',return_value=channel) as connect:
            self.assertTrue(guest_room.boundary.connect('93.184.216.34'))
        connect.assert_called_once_with(('93.184.216.34',5000),timeout=2)
        channel.settimeout.assert_not_called()


    def test_report_under_limit_is_unchanged_and_escaped_overflow_is_never_a_pass(self):
        report = {'version':1,'nonce':'a'*32,'profile':guest_room.PROFILE,'production_enabled':False,
                  'checks':{name:{'status':'passed'} for name in guest_room.REQUIRED}}
        self.assertEqual(json.dumps(report,sort_keys=True),guest_room.encode_report(report))
        report['checks']['network']['synthetic_diagnostic'] = '\u0000' * 11000
        encoded = guest_room.encode_report(report); compact = json.loads(encoded)
        self.assertLessEqual(len(encoded.encode()),65536)
        self.assertTrue(compact['report_overflow'] and compact['evidence_omitted'])
        self.assertEqual({'error_type':'ReportBudgetExceeded'},compact['failure'])
        self.assertGreater(compact['original_report_bytes'],65536)
        self.assertTrue(compact['checks']['guest_cleanup']['outer_disposable_vm_removal_remains_mandatory'])

    def test_report_overflow_preserves_primary_and_all_fixed_cleanup_failures(self):
        report = {'version':1,'nonce':'a'*32,'profile':guest_room.PROFILE,'production_enabled':False,
            'failure':{'error_type':'RuntimeError'}, 'checks':{
                'network':{'status':'failed','synthetic_diagnostic':'\u0000'*11000},
                'guest_cleanup':{'status':'failed','errors':['OSError:listener:alpha:0']},
                'endpoint_service':{'status':'failed','authority_failure':{'operation':'bind','phase':'lineage',
                    'error_type':'RuntimeError','message':'\u0000'*256},
                    'cleanup':{'status':'failed','errors':[{'owner':'broker','error_type':'OSError'}]},
                    'broker':{'cleanup':{'status':'failed','errors':[{'owner':'parent_channel','error_type':'OSError'}]}},
                    'foreign_room_mcs':{'label_restore':{'status':'failed','error_type':'PermissionError'}}}}}
        encoded = guest_room.encode_report(report); compact = json.loads(encoded)
        self.assertLessEqual(len(encoded.encode()),65536)
        self.assertEqual(report['failure'],compact['primary_failure'])
        self.assertEqual('failed',compact['checks']['guest_cleanup']['status'])
        self.assertEqual(report['checks']['guest_cleanup']['errors'],compact['checks']['guest_cleanup']['errors'])
        service = compact['checks']['endpoint_service']
        self.assertEqual('OSError',service['cleanup']['errors'][0]['error_type'])
        self.assertEqual('OSError',service['broker_cleanup']['errors'][0]['error_type'])
        self.assertEqual('PermissionError',service['label_restore']['error_type'])
        self.assertEqual('RuntimeError',service['authority_failure']['error_type'])

    def test_pathname_restore_failure_never_masks_probe_failure_or_allows_endpoint_reuse(self):
        endpoint = SimpleNamespace(parent=Path('/owned/git'), leases=[SimpleNamespace(path=Path('/owned/git/request.sock'))],
            listeners=[SimpleNamespace(fileno=lambda:91)], require=Mock())
        good = {'returncode':0,'timeout':False,'status':'observed','cleanup_errors':[],
            'stdout':{'truncated':False},'stderr':{'truncated':False},'decoded':{'connected':False,'error':'EACCES'}}
        for probe_fails in (False, True):
            with self.subTest(probe_fails=probe_fails):
                checks={}; endpoint.require.reset_mock(); primary=RuntimeError('probe failed'); restore=OSError('restore failed')
                probe=Mock(side_effect=primary if probe_fails else None, return_value=good)
                with patch.object(guest_room,'run',side_effect=['',restore]), \
                        patch.object(guest_room.os,'getxattr',return_value=b'synthetic-fixed-label'):
                    with self.assertRaises((RuntimeError,OSError)) as caught:
                        guest_room.prove_foreign_pathname(endpoint,probe,checks)
                self.assertIs(primary if probe_fails else restore,caught.exception)
                self.assertEqual({'status':'failed','error_type':'OSError'},checks['label_restore'])
                endpoint.require.assert_not_called()
                if not probe_fails: self.assertEqual(good,checks['raw_probe'])

    def test_recovery_preserves_completed_steps_and_stops_after_failed_ownership_gate(self):
        import uas.guest_fixture as fixture
        good_resume={'phase':'running','observed':{'container':{'id':'owned'}}}
        good_refusal={'phase':'start_failed','observed':{'container':{'running':False}}}
        for failure in ('stop','resume','stop_for_drift','drift_refusal','repair','reconcile',None):
            with self.subTest(failure=failure):
                checks={}; supervisor=Mock()
                supervisor.stop.side_effect=[{'phase':'wrong' if failure=='stop' else 'stopped'},
                    {'phase':'wrong' if failure=='stop_for_drift' else 'stopped'}]
                supervisor.start.side_effect=[{'phase':'failed'} if failure=='resume' else good_resume,
                    {'phase':'running'} if failure=='drift_refusal' else good_refusal]
                supervisor.reconcile.return_value={'phase':'failed' if failure=='reconcile' else 'running'}
                command=Mock(side_effect=[None,OSError('synthetic repair failure')] if failure=='repair' else None)
                with patch.object(fixture,'command',command), patch.object(fixture,'network_names',return_value=('owned','bridge','table')), \
                        patch.object(fixture,'firewall_document',return_value={'fixed':'fixture'}):
                    if failure:
                        with self.assertRaises((AssertionError,OSError)):
                            guest_room.prove_recovery(supervisor,object(),{},'owned','a'*32,checks)
                    else: guest_room.prove_recovery(supervisor,object(),{},'owned','a'*32,checks)
                observed=checks['observations']
                self.assertIn('stop',observed)
                self.assertEqual('passed' if failure is None else 'incomplete',checks['status'])
                if failure in ('stop','resume','stop_for_drift'):command.assert_not_called()
                if failure in ('stop','resume','stop_for_drift','drift_refusal','repair'):supervisor.reconcile.assert_not_called()
                if failure=='repair':
                    self.assertEqual('start_failed',observed['drift_refusal']['phase'])
                    self.assertFalse(observed['drift_refusal']['container']['running'])
                if failure is None:
                    self.assertEqual({'stop','resume','stop_for_drift','drift_refusal','reconcile'},set(observed))
                    self.assertFalse(checks['persistent_participant_service_restart'])

    def test_scenario_retains_observed_limits_when_later_service_and_listener_cleanup_fail(self):
        import native_rootfs
        import uas.guest_fixture as fixture
        import uas.lifecycle as lifecycle
        import uas.room_fixture as room_fixture
        # Proc labels/status/maps match the recorded run40729545828 report.
        # Cgroup/quota values below model this fixture's configured limits;
        # they are not represented as newly captured target observations.
        primary=RuntimeError('synthetic later service failure'); checks={}; calls=[]
        listeners={room:Mock() for room in ('alpha','beta')}
        listeners['alpha'].close.side_effect=OSError('synthetic listener failure')
        endpoints={room:SimpleNamespace(listeners=[listeners[room]]) for room in listeners}
        supervisors={room:Mock() for room in listeners}
        backends={room:Mock() for room in listeners}
        for room in listeners:
            supervisors[room].start.return_value={'phase':'running','observed':{'container':{'id':room}}}
            supervisors[room].destroy.return_value={'phase':'destroyed'}
            supervisors[room]._read.return_value={}
            backends[room].admit.return_value={'HostConfig':{'LogConfig':{'Type':'local'}},'Mounts':[]}
        def run(*args,**kwargs):
            calls.append(args)
            if args[:2]==('docker','version'):return '29.8.2'
            if args[0]=='blockdev':return str(2*1024**3)
            if args[:2]!=('docker','exec'):return ''
            room=args[2]; mode=args[4] if args[3]=='/fixture' else args[6]
            if mode=='observe':
                value={'uid':65532,'gid':65532,'files':{
                    '/proc/self/status':'CapEff: 0000000000000000\nCapBnd: 0000000000000000\nNoNewPrivs: 1\nSeccomp: 2\n',
                    '/proc/self/attr/current':'system_u:system_r:container_t:'+fixture.ROOMS[room][3]+'\0',
                    '/proc/self/uid_map':'0     100000      65536','/proc/self/gid_map':'0     100000      65536',
                    '/sys/fs/cgroup/memory.max':'100663296','/sys/fs/cgroup/pids.max':'24',
                    '/sys/fs/cgroup/cpu.max':'75000 100000'}}
            elif mode=='attributes':value={'clear_inherit':'EPERM','change_project':'EPERM',
                'initial_project':fixture.ROOMS[room][0],'after_change_project':fixture.ROOMS[room][0],'after_clear_inherit':True}
            elif mode=='private':value={'endpoint_unlink':'EROFS','/var/run/docker.sock':'ENOENT'}
            elif mode=='write':value={'error':'EROFS' if args[5].endswith('/references') else 'OK'}
            else:raise AssertionError('unexpected dependent probe '+mode)
            return json.dumps(value)
        def service(*args,checks,**kwargs):checks.update(status='failed');raise primary
        with ExitStack() as stack:
            for owner,name,value in ((guest_room,'run',run),(native_rootfs,'build_room_rootfs',Mock(return_value={})),
                    (guest_room.boundary,'start_engine',Mock()),(guest_room.boundary,'attribute_positive_control',Mock(return_value={})),
                    (guest_room,'import_image',Mock(return_value='sha256:owned')),
                    (room_service,'endpoint',lambda room,run:endpoints[room]),(room_service,'prove_service',service),
                    (fixture,'prepare_storage',Mock()),(fixture,'command',Mock(return_value='#101 0 0 8192\n#102 0 0 8192\n')),
                    (lifecycle,'Supervisor',lambda control,room,*args,**kwargs:supervisors[room]),
                    (room_fixture,'RoomLaunchFixtureBackend',lambda nonce,room,**kwargs:backends[room])):
                stack.enter_context(patch.object(owner,name,value))
            stack.enter_context(patch.object(Path,'mkdir'))
            stack.enter_context(patch.object(Path,'exists',return_value=True))
            stack.enter_context(patch.object(Path,'iterdir',return_value=[]))
            archive=Mock();archive.__enter__=Mock(return_value=archive);archive.__exit__=Mock(return_value=False)
            stack.enter_context(patch.object(guest_room.tarfile,'open',return_value=archive))
            stack.enter_context(patch.object(sys,'path',list(sys.path)))
            with self.assertRaises(RuntimeError) as caught:guest_room.scenario('a'*32,{}, {},checks)
        self.assertIs(primary,caught.exception)
        self.assertEqual('blocked',checks['limits']['status'])
        self.assertEqual('endpoint_service',checks['limits']['blocked_by'])
        for room in listeners:
            self.assertEqual('100663296',checks['limits']['observed'][room]['memory'])
            self.assertIn('actual_xfs_b',checks['limits']['observed'][room])
            listeners[room].close.assert_called_once();supervisors[room].destroy.assert_called_once()
        self.assertEqual('failed',checks['guest_cleanup']['status'])
        self.assertIn(('docker','image','rm','sha256:owned'),calls)
        self.assertIn(('umount',str(fixture.STORAGE)),calls)
        self.assertNotIn('network',checks)


    def test_recovery_projection_does_not_duplicate_recorded_mounts_or_large_synthetic_state(self):
        import uas.guest_fixture as fixture
        # Exact Alpha Mounts from UAS_ROOM_REPORT in run40729545828/job122961802589.
        # Other lifecycle fields and the oversized annotation are synthetic.
        recorded_mounts = [{'Destination': '/state', 'Driver': 'local', 'Mode': 'z', 'Name': 'uas-fixture-06e264cc3f5f4d62a079f00f1a8511bc-state', 'Propagation': '', 'RW': True, 'Source': '/var/lib/docker/100000.100000/volumes/uas-fixture-06e264cc3f5f4d62a079f00f1a8511bc-state/_data', 'Type': 'volume'}, {'Destination': '/uas/git', 'Mode': '', 'Propagation': 'rprivate', 'RW': False, 'Source': '/run/uas-room-endpoints/alpha/git', 'Type': 'bind'}, {'Destination': '/mnt/uas-boundary/alpha/checkouts', 'Mode': '', 'Propagation': 'rprivate', 'RW': True, 'Source': '/mnt/uas-boundary/alpha/checkouts', 'Type': 'bind'}, {'Destination': '/mnt/uas-boundary/alpha/references', 'Mode': '', 'Propagation': 'rprivate', 'RW': False, 'Source': '/mnt/uas-boundary/alpha/references', 'Type': 'bind'}, {'Destination': '/mnt/uas-boundary/alpha/repository', 'Mode': '', 'Propagation': 'rprivate', 'RW': True, 'Source': '/mnt/uas-boundary/alpha/repository', 'Type': 'bind'}, {'Destination': '/mnt/uas-boundary/alpha/workspace', 'Mode': '', 'Propagation': 'rprivate', 'RW': True, 'Source': '/mnt/uas-boundary/alpha/workspace', 'Type': 'bind'}]
        base={'room_id':'alpha','instance_id':'owned','desired':'running','fixture_only':True,
            'production_launch':'unqualified','authority':'active','error':None,'leftovers':[],
            'observed':{'container':{'id':'owned','running':False,'Mounts':recorded_mounts,
                'synthetic_annotation':'x'*70000}},'pending_spec':None}
        def result(phase,running):
            return {**base,'phase':phase,'observed':{'container':{**base['observed']['container'],'running':running}}}
        supervisor=Mock();supervisor.stop.side_effect=[result('stopped',False),result('stopped',False)]
        supervisor.start.side_effect=[result('running',True),result('start_failed',False)]
        supervisor.reconcile.return_value=result('running',True)
        checks={}
        with patch.object(fixture,'command'),patch.object(fixture,'network_names',return_value=('owned','bridge','table')), \
                patch.object(fixture,'firewall_document',return_value={}):
            guest_room.prove_recovery(supervisor,{}, {},'owned','a'*32,checks)
        self.assertEqual('passed',checks['status']);self.assertLess(len(json.dumps(checks)),2048)
        self.assertNotIn('Mounts',json.dumps(checks));self.assertNotIn('synthetic_annotation',json.dumps(checks))


    def test_report_overflow_keeps_cli_and_foreign_listener_cleanup_uncertainty(self):
        report={'version':1,'nonce':'a'*32,'profile':guest_room.PROFILE,'production_enabled':False,
            'failure':{'error_type':'TimeoutError'},'checks':{'endpoint_service':{'status':'failed',
                'oversized_synthetic_output':'\u0000'*11000,
                'bind_cleanup':{'attempted':True,'closed':False,'error_type':'OSError','message':'not retained'},
                'unrelated_task':{'status':'failed','stage':'accept','error_type':'TimeoutError',
                    'cleanup':{'kill_attempted':True,'reaped':False,
                        'errors':[{'operation':'wait','error_type':'TimeoutExpired'}]}},
                'foreign_listener_admission':{'status':'failed','cleanup_errors':['OSError'],
                    'original_lease_restored':False}},'guest_cleanup':{'status':'failed','errors':['OSError:responder']}}}
        compact=json.loads(guest_room.encode_report(report));service=compact['checks']['endpoint_service']
        self.assertEqual({'error_type':'TimeoutError'},compact['primary_failure'])
        self.assertEqual({'attempted':True,'closed':False,'error_type':'OSError'},service['bind_cleanup'])
        self.assertFalse(service['unrelated_task']['cleanup']['reaped'])
        self.assertEqual('TimeoutExpired',service['unrelated_task']['cleanup']['errors'][0]['error_type'])
        self.assertEqual(['OSError'],service['foreign_listener_admission']['cleanup_errors'])
        self.assertFalse(service['foreign_listener_admission']['original_lease_restored'])
        self.assertLessEqual(len(json.dumps(compact).encode()),65536)

    def test_decoy_deadline_crossing_before_sleep_never_passes_negative_sleep(self):
        with patch.object(guest_room.time,'monotonic',side_effect=[0,0,0,0,0,7.99,8.01]), \
                patch.object(guest_room.time,'sleep') as sleep, \
                patch.object(guest_room.boundary,'connect',return_value=False):
            with self.assertRaisesRegex(AssertionError,'readiness deadline'):
                guest_room.wait_decoys([])
        sleep.assert_not_called()
