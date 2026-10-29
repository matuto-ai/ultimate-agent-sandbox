"""Pure contracts for the fixed Room payload and from-boot network runner.

These cases perform file-only staging or inert policy checks, never native
commands, sockets, containers, package installation, kernel probes or a VM.
"""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from contextlib import redirect_stdout
import io

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
try:
    import prepare_room_payload as stage
    import room_profile
    import run_boundary  # Loaded while its sibling imports have their path.
    import run_room as runner
finally:
    sys.path.pop(0)


class RoomVMSourceTests(unittest.TestCase):
    def test_checkpoints_are_bounded_diagnostics_not_qualification(self):
        import guest_room
        checks = {'payload': {'status': 'passed', 'secret': 'never exported'},
                  'network': {'status': 'incomplete'}}
        output = io.StringIO()
        with redirect_stdout(output), patch.object(guest_room.time, 'monotonic', side_effect=[10, 12, 15]):
            emit = guest_room.checkpoint_writer('a'*32, checks)
            emit('rootfs', 'end'); emit('network', 'begin')
        self.assertNotIn('secret', output.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            serial = Path(directory)/'serial.log'
            serial.write_text(output.getvalue())
            got = runner.last_checkpoint(serial, 'a'*32)
            self.assertEqual(('network', 'begin', 2, 5),
                (got['stage'], got['event'], got['sequence'], got['elapsed_seconds']))
            self.assertEqual(['payload'], got['completed_checks'])
            self.assertIs(got['terminal'], False)
            self.assertIsNone(runner.last_checkpoint(serial, 'b'*32))
            with self.assertRaises(RuntimeError): runner.parse_report(serial.read_text(), 'a'*32)
            good = output.getvalue()
            for change in ({'terminal': True}, {'sequence': 41}, {'elapsed_seconds': float('nan')},
                           {'stage': 'injected'}, {'completed_checks': ['unexpected']}, {'extra':'secret'}):
                bad = dict(got); bad.update(change)
                serial.write_text(good + 'UAS_ROOM_CHECKPOINT:'+'a'*32+':'+json.dumps(bad)+'\n')
                self.assertEqual(got, runner.last_checkpoint(serial, 'a'*32))
            serial.write_text('UAS_ROOM_CHECKPOINT:'+'a'*32+':'+('x'*2048)+'\n')
            self.assertIsNone(runner.last_checkpoint(serial,'a'*32))
            serial.write_text(good + 'x'*65536)
            self.assertIsNone(runner.last_checkpoint(serial,'a'*32))

    def report(self):
        value = {'version': 1, 'nonce': 'a' * 32, 'profile': room_profile.PROFILE,
                 'production_enabled': False, 'checks': {key: {'status': 'passed'} for key in runner.REQUIRED}}
        value['checks']['network'].update(real_public_https=True, denied=sorted(runner.DENIED))
        return value

    def line(self, value):
        return 'UAS_ROOM_REPORT:' + 'a' * 32 + ':' + json.dumps(value)

    def seed_input(self, root):
        payload = root / 'payload'; payload.mkdir()
        source = payload / 'repo/tests/vm'; source.mkdir(parents=True)
        entries = []
        for name in runner.BOOTSTRAP_SOURCES:
            raw = ('# fixture copy of ' + name + '\n').encode()
            (source / name).write_bytes(raw)
            entries.append({'file': 'tests/vm/' + name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        encoded = json.dumps({'nonce': 'a' * 32, 'profile': room_profile.PROFILE, 'source': entries,
            'packages': [dict(name=name, **dict(zip(('epoch','version','release','arch'), values)))
                         for name, values in room_profile.PACKAGE_PROFILE.items()]}).encode()
        (payload / 'manifest.json').write_bytes(encoded)
        return payload, hashlib.sha256(encoded).hexdigest()

    def staging_input(self, root):
        payload = root / 'payload'; payload.mkdir()
        source = payload / 'repo/uas'; source.mkdir(parents=True)
        for name in stage.ROOM_MODULES:
            (source / (name + '.py')).write_text('# inert ' + name + '\n')
        return payload, source

    def test_room_staging_closes_eager_and_exercised_journey_imports(self):
        from test_staged_source_closure import missing_imports
        paths = set(runner.SOURCES)
        self.assertEqual([], missing_imports(paths))
        # Lifecycle writes Manager projection v2 even with no journey events;
        # that path imports this passive module before returning unavailable.
        self.assertIn('manager_journey', stage.ROOM_MODULES)
        self.assertIn('uas/manager_journey.py', paths)
        self.assertEqual(len(runner.SOURCES), len(paths))
        self.assertLessEqual(len(paths), 64)
        self.assertLessEqual(sum((VM.parent.parent/name).stat().st_size for name in paths), 4*1024*1024)

    def test_network_is_fixed_from_boot_with_no_forwarding_or_shared_host_paths(self):
        root = Path('/owned-fixture')
        args = runner.arguments(root, root/'guest.qcow2', root/'seed.iso', root/'payload.iso', root/'quota.raw')
        self.assertEqual(1, args.count('-netdev'))
        self.assertEqual('user,id=room-egress,ipv6=off,net=10.0.2.0/24,host=10.0.2.2', args[args.index('-netdev')+1])
        self.assertIn('virtio-net-pci,netdev=room-egress,mac=' + room_profile.MAC, args)
        self.assertNotIn('-nic', args)
        self.assertEqual('none', args[args.index('-monitor')+1])
        self.assertEqual('tcg,thread=multi', args[args.index('-accel')+1])
        self.assertEqual(4, args.count('-drive'))
        for forbidden in ('hostfwd=', 'guestfwd=', 'tap,', 'bridge,', '-qmp', '-virtfs', '-fsdev', '/dev/kvm', 'docker.sock', 'ssh'):
            self.assertFalse(any(forbidden in item for item in args), forbidden)

    def test_seed_binds_immutable_copies_network_and_private_profile_markers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload, digest = self.seed_input(root)
            with patch.object(runner.feasibility, 'command') as command:
                result = runner.seed(root, 'a'*32, digest, payload_root=payload)
            self.assertEqual(root/'seed.iso', result)
            self.assertEqual(['cloud-localds', '--network-config='+str(root/'network-config'),
                str(result), str(root/'user-data'), str(root/'meta-data')], command.call_args.args[0])
            self.assertEqual(room_profile.network_config(), json.loads((root/'network-config').read_text()))
            value = json.loads((root/'user-data').read_text().split('\n',1)[1])
            self.assertEqual([], value['users']); self.assertIs(value['disable_root'], True)
            self.assertIs(value['ssh_pwauth'], False); self.assertIs(value['package_update'], False)
            self.assertIs(value['package_upgrade'], False)
            self.assertEqual([['python3','/run/guest_room.py','a'*32,digest]],value['runcmd'])
            files = {item['path']:item for item in value['write_files']}
            self.assertTrue(all(item['permissions']=='0600' for item in files.values()))
            self.assertEqual(room_profile.marker('a'*32),json.loads(files[str(room_profile.MARKER)]['content']))
            self.assertEqual('a'*32,files['/run/uas-vm-fixture']['content'])
            self.assertEqual((payload/'repo/tests/vm/guest_room.py').read_bytes(),
                base64.b64decode(files['/run/guest_room.py']['content']))

    def test_seed_rejects_changed_or_missing_copied_source_before_cloud_localds(self):
        for broken in ('digest','source','scope','missing','manifest_type'):
            with self.subTest(broken=broken),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);payload,digest=self.seed_input(root)
                if broken=='digest':digest='f'*64
                elif broken=='source':(payload/'repo/tests/vm/guest_room.py').write_text('# replaced\n')
                elif broken=='missing':(payload/'repo/tests/vm/guest_room.py').unlink()
                else:
                    data=json.loads((payload/'manifest.json').read_text())
                    if broken=='manifest_type':data=[]
                    else:data['profile']='native-pi-v1'
                    raw=json.dumps(data).encode();(payload/'manifest.json').write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
                with patch.object(runner.feasibility,'command') as command:
                    with self.assertRaises((ValueError,OSError)):runner.seed(root,'a'*32,digest,payload_root=payload)
                command.assert_not_called()

    def test_staging_is_exact_python_only_readonly_and_never_runs_or_fetches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);payload,_=self.staging_input(root)
            command=Mock(side_effect=AssertionError('command forbidden'));fetch=Mock(side_effect=AssertionError('fetch forbidden'))
            result=stage.stage_native(root,payload,command,fetch)
            command.assert_not_called();fetch.assert_not_called()
            self.assertEqual(room_profile.PROFILE,result['profile'])
            self.assertEqual(['python3','tini','glibc','libstdc++'],result['rpm_roots'])
            self.assertEqual(['git-core','openssh','openssh-clients','openssh-server'],result['guest_rpm_roots'])
            self.assertTrue(result['help_only'] and result['runtime_python_only'])
            self.assertFalse(result['production_enabled'] or result['rpm_scriptlets'])
            self.assertEqual(len(stage.ROOM_MODULES),result['file_count'])
            listing=json.loads((payload/'room-files.json').read_text())
            self.assertEqual(room_profile.PROFILE,listing['profile'])
            self.assertTrue(all(item['mode']==0o444 for item in listing['files']))
            with tarfile.open(payload/'room-runtime.tar') as archive:
                self.assertEqual({'opt/uas/uas/'+name+'.py' for name in stage.ROOM_MODULES},set(archive.getnames()))
                self.assertTrue(all(item.isfile() and item.mode==0o444 and item.uid==item.gid==0
                                    and item.mtime==0 for item in archive.getmembers()))

    def test_staging_rejects_missing_extra_symlink_and_reused_output(self):
        for broken in ('missing','extra','symlink','reused'):
            with self.subTest(broken=broken),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);payload,source=self.staging_input(root)
                if broken=='missing':(source/'room_probe.py').unlink()
                elif broken=='extra':(source/'pi_runtime.py').write_text('# not selected\n')
                elif broken=='symlink':
                    (source/'room_probe.py').unlink();(source/'room_probe.py').symlink_to(source/'__init__.py')
                else:(root/'room-root/opt/uas/uas').mkdir(parents=True)
                command=Mock();fetch=Mock()
                with self.assertRaises((ValueError,OSError)):stage.stage_native(root,payload,command,fetch)
                command.assert_not_called();fetch.assert_not_called()

    def test_report_requires_current_profile_every_gate_real_public_and_each_deny(self):
        report=self.report()
        self.assertEqual(report,runner.parse_report(self.line(report),'a'*32))
        changes = [lambda r:r.update(version=True),lambda r:r.update(profile='native-pi-v1'),
            lambda r:r.update(production_enabled=True),lambda r:r.update(failure='failed'),
            lambda r:r['checks'].pop('endpoint_service'),lambda r:r['checks']['limits'].update(status='not_run'),
            lambda r:r['checks']['network'].update(real_public_https=False),
            lambda r:r['checks']['network'].update(denied=['host-private']*5)]
        for change in changes:
            value=copy.deepcopy(report);change(value)
            with self.assertRaises(RuntimeError):runner.parse_report(self.line(value),'a'*32)
        with self.assertRaises(RuntimeError):runner.parse_report(self.line(report)+'\n'+self.line(report),'a'*32)
        with self.assertRaises(ValueError):
            runner.parse_report(self.line(report).replace('"version": 1','"version": 1, "version": 1'),'a'*32)

    def test_runner_requires_explicit_hosted_profile_before_any_effect(self):
        settings = ({}, {'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux'},
            {'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','UAS_ROOM_VM_PROFILE':'native-pi-v1'})
        for environment in settings:
            with self.subTest(environment=environment),patch.dict(runner.os.environ,environment,clear=True), \
                    patch.object(runner.os,'geteuid',return_value=1000), \
                    patch.object(runner.tempfile,'TemporaryDirectory') as temporary:
                with self.assertRaises(RuntimeError):runner.main()
                temporary.assert_not_called()
        with patch.dict(runner.os.environ,{'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','UAS_ROOM_VM_PROFILE':runner.PROFILE},clear=True), \
                patch.object(runner.os,'geteuid',return_value=0), \
                patch.object(runner.feasibility,'fetch_image') as fetch:
            with self.assertRaises(RuntimeError):runner.main()
            fetch.assert_not_called()

    def test_allowlist_budget_and_owned_cleanup_remain_explicit(self):
        self.assertLessEqual(len(runner.SOURCES),64)
        self.assertEqual(len(runner.SOURCES),len(set(runner.SOURCES)))
        self.assertIn('tests/vm/room_service.py',runner.SOURCES)
        self.assertIn('tests/vm/guest_room.py',runner.SOURCES)
        self.assertIn('uas/room_probe.py',runner.SOURCES)
        self.assertFalse(any('/pi/' in path or path.endswith(('pi_runtime.py','claude_runtime.py')) for path in runner.SOURCES))
        tree=ast.parse((VM/'run_room.py').read_text())
        boot=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='boot')
        tries=[node for node in ast.walk(boot) if isinstance(node,ast.Try)]
        self.assertTrue(any('feasibility.stop_process(process)' in ast.unparse(node.finalbody) for node in tries))
        self.assertIn("path.stat().st_size > feasibility.LOG_LIMIT",ast.unparse(boot))
        self.assertEqual(180,runner.SILENT_BOOT_TIMEOUT)
        self.assertEqual(300,runner.IDLE_SERIAL_TIMEOUT)


    def test_seed_rejects_missing_ambiguous_and_wrong_exact_package_roots_before_commands(self):
        for broken in ('missing', 'duplicate', 'epoch', 'version', 'release', 'arch'):
            with self.subTest(broken=broken), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); payload, _ = self.seed_input(root)
                data = json.loads((payload/'manifest.json').read_text())
                if broken == 'missing': data['packages'].pop()
                elif broken == 'duplicate': data['packages'].append(dict(data['packages'][0]))
                else: data['packages'][0][broken] = 'wrong'
                raw = json.dumps(data).encode(); (payload/'manifest.json').write_bytes(raw)
                with patch.object(runner.feasibility, 'command') as command:
                    with self.assertRaisesRegex(AssertionError, 'exact native root'):
                        runner.seed(root, 'a'*32, hashlib.sha256(raw).hexdigest(), payload_root=payload)
                command.assert_not_called()

    def boot_case(self, steps, *, stop_error=None, parse_error=None, final_clock=0):
        # Every subprocess/clock is inert. Actual temporary regular files model
        # the serial/log observations; there is no QEMU, sleep, or signaling.
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name); current = [0.0]
        process = SimpleNamespace(returncode=None)
        iterator = iter(steps)
        def poll():
            seconds, code, logs = next(iterator)
            current[0] = seconds; process.returncode = code
            for name, value in logs.items():
                if isinstance(value, int):
                    with (directory/name).open('wb') as stream: stream.truncate(value)
                else: (directory/name).write_text(value)
            return code
        process.poll = Mock(side_effect=poll)
        parsed = Mock(side_effect=parse_error, return_value=self.report())
        stop = Mock(side_effect=stop_error); output = io.StringIO()
        def clock(): return current[0] + final_clock
        with patch.object(runner.subprocess, 'Popen', return_value=process) as popen, \
                patch.object(runner.time, 'monotonic', side_effect=clock), \
                patch.object(runner.time, 'sleep') as sleep, \
                patch.object(runner.feasibility, 'stop_process', stop), \
                patch.object(runner, 'parse_report', parsed), redirect_stdout(output):
            result, error = None, None
            try: result = runner.boot(directory, ['inert-qemu'], 'a'*32)
            except BaseException as caught: error = caught
        popen.assert_called_once(); stop.assert_called_once_with(process)
        return result, error, parsed, sleep, output.getvalue()

    def test_outer_timeout_retains_latest_checkpoint_but_never_calls_report_parser(self):
        value = {'version': 1, 'sequence': 20, 'stage': 'endpoint-service', 'event': 'begin',
                 'elapsed_seconds': 150, 'completed_checks': ['confinement', 'mounts', 'payload'],
                 'terminal': False}
        line = 'UAS_ROOM_CHECKPOINT:'+'a'*32+':'+json.dumps(value)+'\n'
        result, error, parsed, _, output = self.boot_case([(1201, None, {'serial.log': line})])
        self.assertIsNone(result); self.assertIn('exceeded budget', str(error))
        parsed.assert_not_called()
        self.assertIn('diagnostic, not qualification', output)
        self.assertIn('"stage": "endpoint-service"', output)
        self.assertIn('"terminal": false', output)

    def test_boot_behavioral_clock_serial_exit_and_log_budget_matrix(self):
        cases = (
            ('silent', [(181, None, {})], 'no serial boot output'),
            ('idle', [(1, None, {'serial.log':'boot'}), (302, None, {})], 'serial output stalled'),
            ('active_overall', [(1201, None, {'serial.log':'new output'})], 'exceeded budget'),
            ('exit_overall', [(1201, 0, {'serial.log':'report'})], 'exceeded budget'),
            ('abnormal', [(2, 7, {'serial.log':'boot'})], 'abnormal exit'),
            ('live_log', [(1, None, {'serial.log':'boot', 'firmware.log':runner.feasibility.LOG_LIMIT+1})], 'log budget'),
            ('final_log', [(1, 0, {'serial.log':'report', 'qemu.log':runner.feasibility.LOG_LIMIT+1})], 'final log budget'),
            ('missing_serial', [(1, 0, {})], None),
        )
        for name, steps, message in cases:
            with self.subTest(name=name):
                result, error, parsed, _, _ = self.boot_case(steps)
                self.assertIsNone(result); self.assertIsNotNone(error); parsed.assert_not_called()
                if message is None: self.assertIsInstance(error, FileNotFoundError)
                else: self.assertIn(message, str(error))

    def test_boot_serial_activity_refreshes_idle_only_and_exact_bound_is_allowed(self):
        result, error, parsed, sleep, output = self.boot_case([
            (180, None, {'serial.log':'first'}), (480, None, {'serial.log':'next larger'}),
            (780, None, {'serial.log':'another larger output'}),
            (1080, None, {'serial.log':'yet another larger output'}),
            (1200, 0, {'serial.log':'complete report'})])
        self.assertIsNone(error); self.assertEqual(1200, result[1]); self.assertEqual(4, sleep.call_count)
        parsed.assert_called_once_with('complete report', 'a'*32)
        self.assertIn('Room VM progress:', output)

    def test_boot_cleanup_cannot_mask_parser_failure_or_become_success(self):
        primary, cleanup = ValueError('first report failure'), OSError('cleanup')
        result, error, parsed, _, output = self.boot_case([(1, 0, {'serial.log':'bad'})],
            parse_error=primary, stop_error=cleanup)
        self.assertIs(error, primary); self.assertIsNone(result); parsed.assert_called_once()
        self.assertIn('Room QEMU cleanup:', output)
        self.assertIn('OSError', primary.__notes__[0])
        result, error, _, _, _ = self.boot_case([(1, 0, {'serial.log':'good'})], stop_error=cleanup)
        self.assertIs(error, cleanup); self.assertIsNone(result)


    def test_boot_launch_failure_has_no_unacquired_process_cleanup(self):
        primary=OSError('synthetic launch failure')
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(runner.subprocess,'Popen',side_effect=primary), \
                patch.object(runner.feasibility,'stop_process') as stop:
            with self.assertRaises(OSError) as caught:runner.boot(Path(temporary),['inert-qemu'],'a'*32)
        self.assertIs(primary,caught.exception);stop.assert_not_called()

    def test_boot_cancellation_preserves_primary_when_owned_cleanup_also_fails(self):
        primary=KeyboardInterrupt()
        _,error,_,_,output=self.boot_case([(1,0,{'serial.log':'report'})],
            parse_error=primary,stop_error=OSError('synthetic cleanup'))
        self.assertIs(primary,error);self.assertIn('Room QEMU cleanup:',output)
