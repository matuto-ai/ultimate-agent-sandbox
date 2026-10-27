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
        encoded = json.dumps({'nonce': 'a' * 32, 'profile': room_profile.PROFILE, 'source': entries}).encode()
        (payload / 'manifest.json').write_bytes(encoded)
        return payload, hashlib.sha256(encoded).hexdigest()

    def staging_input(self, root):
        payload = root / 'payload'; payload.mkdir()
        source = payload / 'repo/uas'; source.mkdir(parents=True)
        for name in stage.ROOM_MODULES:
            (source / (name + '.py')).write_text('# inert ' + name + '\n')
        return payload, source

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
            self.assertEqual(['git-core','openssh-clients'],result['guest_rpm_roots'])
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
