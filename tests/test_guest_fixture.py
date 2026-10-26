"""Offline contracts only. Real kernel enforcement is mandatory in VM CI."""
import importlib.util
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from uas import guest_fixture as guest
from uas.docker_fixture import DockerFixtureBackend
from uas.lifecycle import BackendUnknown, LifecycleError, OwnershipConflict

sys.path.insert(0, str(Path(__file__).parent / 'vm'))
SPEC = importlib.util.spec_from_file_location('boundary_runner', Path(__file__).parent / 'vm/run_boundary.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
sys.path.pop(0)
GUEST_SPEC = importlib.util.spec_from_file_location('guest_boundary_script', Path(__file__).parent / 'vm/guest_boundary.py')
guest_script = importlib.util.module_from_spec(GUEST_SPEC)
GUEST_SPEC.loader.exec_module(guest_script)
NONCE = 'a' * 32
STATE = {'instance_id': 'b' * 32, 'room_id': 'alpha', 'spec': {
    'config_digest': 'sha256:' + 'c' * 64, 'profile_digest': 'sha256:' + 'd' * 64,
    'project_paths': [str(guest.STORAGE / 'alpha' / name) for name in ('repository', 'workspace', 'checkouts', 'references')]}}


class GuestFixtureTests(unittest.TestCase):
    def test_no_accidental_host_execution_or_selinux_relaxation(self):
        with patch.object(guest.os, 'geteuid', return_value=1000), patch.object(guest, 'command') as command:
            with self.assertRaises(LifecycleError) as caught:
                guest.guard(NONCE)
            self.assertEqual('DISPOSABLE_GUEST_REQUIRED', caught.exception.code)
            command.assert_not_called()
        with patch.object(guest.os, 'geteuid', return_value=0), patch.object(Path, 'read_text', return_value=NONCE), patch.object(guest, 'command', return_value='Permissive'):
            with self.assertRaises(LifecycleError) as caught:
                guest.guard(NONCE)
            self.assertEqual('GUEST_SELINUX_REQUIRED', caught.exception.code)

    def test_fixed_policy_blocks_all_host_addresses_private_metadata_and_ipv6(self):
        document = guest.firewall_document(STATE, NONCE)
        objects = [item['add'] for item in document['nftables']]
        rules = [item['rule'] for item in objects if 'rule' in item]
        self.assertEqual(3, len(rules))
        self.assertEqual('input', rules[0]['chain'])
        self.assertEqual(3, len(rules[0]['expr']))  # iif + counter + drop, no private-only host filter.
        self.assertEqual('ipv6', rules[1]['expr'][1]['match']['right'])
        self.assertIn('169.254.0.0/16', guest.DENIED_V4)
        self.assertIn('10.0.0.0/8', guest.DENIED_V4)
        self.assertIn('192.168.0.0/16', guest.DENIED_V4)
        self.assertTrue(all(item['chain']['prio'] == -100 for item in objects if 'chain' in item))
        self.assertTrue(all(item['expr'][-1] == {'drop': None} for item in rules))
        changed = json.loads(json.dumps(document))
        changed['nftables'][-1]['add']['rule']['expr'][-1] = {'accept': None}
        self.assertNotEqual(guest.canonical_firewall(document), guest.canonical_firewall(changed))

    def test_firewall_normalization_ignores_only_runtime_handles_counters(self):
        expected = guest.firewall_document(STATE, NONCE)
        observed = {'nftables': [{'metainfo': {'version': 'fixture'}}] + [item['add'] for item in json.loads(json.dumps(expected))['nftables']]}
        for item in observed['nftables'][1:]:
            value = next(iter(item.values())); value['handle'] = 42
            for expression in value.get('expr', []):
                if 'counter' in expression:
                    expression['counter'] = {'packets': 123, 'bytes': 456}
        self.assertEqual(guest.canonical_firewall(expected), guest.canonical_firewall(observed))
        observed['nftables'].pop()
        self.assertNotEqual(guest.canonical_firewall(expected), guest.canonical_firewall(observed))

    def test_denied_prefix_union_is_already_canonical_for_nft_interval_merging(self):
        networks = [ipaddress.ip_network(value) for value in guest.DENIED_V4]
        self.assertEqual(networks, list(ipaddress.collapse_addresses(networks)))
        self.assertEqual([ipaddress.ip_network('224.0.0.0/3')], list(ipaddress.collapse_addresses(
            [ipaddress.ip_network('224.0.0.0/4'), ipaddress.ip_network('240.0.0.0/4')])))
        for address in ('224.0.0.0', '239.255.255.255', '240.0.0.0', '255.255.255.255'):
            self.assertTrue(any(ipaddress.ip_address(address) in network for network in networks))
        self.assertFalse(any(ipaddress.ip_address('93.184.216.34') in network for network in networks))

    def test_default_docker_fixture_remains_network_none_read_only_no_extra_labels(self):
        backend = DockerFixtureBackend()
        self.assertEqual('none', backend._network_name(STATE))
        self.assertEqual({}, backend._volume_options(STATE))
        self.assertEqual(['no-new-privileges=true'], backend._security_options(STATE))
        self.assertFalse(backend._project_writable(STATE, '/fixture'))
        enhanced = guest.GuestBoundaryBackend(NONCE, 'alpha')
        self.assertTrue(enhanced._project_writable(STATE, str(enhanced.root / 'repository')))
        self.assertFalse(enhanced._project_writable(STATE, str(enhanced.root / 'references')))
        self.assertNotIn('label=disable', enhanced._security_options(STATE))
        with self.assertRaises(LifecycleError):
            guest.GuestBoundaryBackend(NONCE, 'user-project')

    def test_firewall_precedes_container_creation_and_volume_is_cleanup_anchor(self):
        backend = guest.GuestBoundaryBackend(NONCE, 'alpha')
        events = []
        with patch.object(guest, 'guard'), patch.object(backend, '_quota'), patch.object(backend, '_project_paths'), patch.object(backend, '_runtime'), patch.object(backend, '_ensure_network', side_effect=lambda *_: events.append('enforce')), patch.object(DockerFixtureBackend, 'create', side_effect=lambda *_: events.append('create')):
            backend.create(STATE, 'container')
        self.assertEqual(['enforce', 'create'], events)
        with patch.object(backend, '_inspect_object', return_value=None), patch.object(backend, '_run') as command:
            with self.assertRaises(BackendUnknown):
                backend._ensure_network(STATE)
            command.assert_not_called()

    def test_quota_requires_enabled_block_and_inode_limits_and_project_inheritance(self):
        backend = guest.GuestBoundaryBackend(NONCE, 'alpha')
        def command(*args):
            selector = args[3]
            if selector == 'state -p':
                return 'Accounting: ON\nEnforcement: ON'
            return '#101 2 0 ' + ('8192' if '-b' in selector else '128') + ' 00 [--------]\n'
        with patch.object(backend, '_storage'), patch.object(guest, 'command', side_effect=command), patch.object(guest, 'project_attributes', return_value=(101, True)):
            backend._quota()
            with patch.object(guest, 'project_attributes', return_value=(0, False)), self.assertRaises(LifecycleError):
                backend._quota()
        for values in ('Accounting: ON\nEnforcement: OFF', '#101 0 0 0 00 [--------]'):
            with patch.object(backend, '_storage'), patch.object(guest, 'command', return_value=values), self.assertRaises(LifecycleError):
                backend._quota()

    def test_volume_anchor_precedes_runtime_effects_and_mkdir_intent_recovers(self):
        backend = guest.GuestBoundaryBackend(NONCE, 'alpha')
        events = []
        with patch.object(guest, 'guard'), patch.object(backend, '_quota'), patch.object(backend, '_project_paths'), patch.object(DockerFixtureBackend, 'create', side_effect=lambda *_: events.append('anchor')), patch.object(backend, '_runtime', side_effect=lambda *a, **k: events.append('runtime')):
            backend.create(STATE, 'volume')
        self.assertEqual(['anchor', 'runtime'], events)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); backend.root = root / 'alpha'
            path = backend._runtime_path(STATE); path.parent.mkdir(parents=True)
            with patch.object(guest, 'CONTROL', root), patch.object(backend, '_storage'), patch.object(backend, '_inspect_object', return_value={'owned': True}), patch.object(guest, 'command'), patch.object(guest.os, 'chown'), patch.object(guest, 'WORKSTATION_HOST_UID', os.getuid()):
                guest.publish(backend._runtime_intent(STATE), backend._intent_value(STATE))
                path.mkdir()  # Simulate SIGKILL after actual mkdir and before marker.
                self.assertEqual(path, backend._runtime(STATE, create=True))
                self.assertTrue(backend._runtime_marker(STATE).exists())
                backend._remove_runtime(STATE)
                self.assertFalse(path.exists())
                self.assertFalse(backend._runtime_intent(STATE).exists())
                self.assertFalse(backend._runtime_marker(STATE).exists())

    def test_record_publication_reconciles_completed_pending_not_foreign_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'owned.json'; pending = path.with_suffix('.pending')
            value = {'owned': 'fixture'}
            pending.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
            guest.publish(path, value)
            self.assertEqual(value, json.loads(path.read_text()))
            self.assertFalse(pending.exists())
            path.unlink(); pending.write_text('partial')
            with self.assertRaises(OwnershipConflict): guest.publish(path, value)

    def test_runtime_identity_swap_is_not_adopted(self):
        backend = guest.GuestBoundaryBackend(NONCE, 'alpha')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); backend.root = root / 'alpha'
            path = backend._runtime_path(STATE); path.mkdir(parents=True)
            marker = root / (STATE['instance_id'] + '.runtime.json')
            intent = root / (STATE['instance_id'] + '.intent.json')
            expected = backend._intent_value(STATE)
            intent.write_text(json.dumps(expected))
            marker.write_text(json.dumps({**expected, 'identity': guest.identity(path)}))
            with patch.object(guest, 'CONTROL', root), patch.object(backend, '_storage'):
                self.assertEqual(path, backend._runtime(STATE))
                path.rename(path.with_name('retained-original')); path.mkdir()
                with self.assertRaises(OwnershipConflict):
                    backend._runtime(STATE)

    def test_dangling_runtime_and_record_symlinks_retain_anchor_and_evidence(self):
        for position in range(5):
            with self.subTest(position=position), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                backend = guest.GuestBoundaryBackend(NONCE, 'alpha'); backend.root = root / 'alpha'
                runtime = backend._runtime_path(STATE); runtime.mkdir(parents=True)
                with patch.object(guest, 'CONTROL', root):
                    expected = backend._intent_value(STATE)
                    marker, intent = backend._runtime_marker(STATE), backend._runtime_intent(STATE)
                    marker.write_text(json.dumps({**expected, 'identity': guest.identity(runtime)}))
                    intent.write_text(json.dumps(expected))
                    artifact = backend._runtime_artifacts(STATE)[position]
                    if artifact.is_dir(): artifact.rmdir()
                    elif artifact.exists(): artifact.unlink()
                    artifact.symlink_to(root / 'missing-target')
                    with patch.object(guest, 'guard'), patch.object(backend, '_storage'), patch.object(backend, 'inspect', return_value=None), patch.object(backend, '_network', return_value=None), patch.object(backend, '_firewall', return_value=None), patch.object(DockerFixtureBackend, 'remove') as remove:
                        with self.assertRaises(OwnershipConflict): backend.remove(STATE, 'volume')
                        remove.assert_not_called()
                        with self.assertRaises(OwnershipConflict): backend._runtime(STATE)
                    self.assertTrue(artifact.is_symlink())
                    self.assertTrue(os.path.lexists(marker)); self.assertTrue(os.path.lexists(intent))

    def test_orphan_pending_records_and_dangling_links_are_not_clean_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backend = guest.GuestBoundaryBackend(NONCE, 'alpha'); backend.root = root / 'alpha'
            backend._runtime_path(STATE).parent.mkdir(parents=True)
            with patch.object(guest, 'CONTROL', root), patch.object(DockerFixtureBackend, 'inspect', return_value=None), patch.object(backend, '_network', return_value=None), patch.object(backend, '_firewall', return_value=None):
                for artifact in backend._runtime_artifacts(STATE):
                    for symlink in (False, True):
                        if symlink: artifact.symlink_to(root / 'missing-target')
                        else: artifact.write_text('partial publication')
                        with self.assertRaises(BackendUnknown): backend.inspect(STATE, 'volume')
                        artifact.unlink()
                self.assertIsNone(backend.inspect(STATE, 'volume'))

    def test_publication_never_replaces_dangling_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'owned.json'
            for artifact in (path, path.with_suffix('.pending')):
                artifact.symlink_to(Path(temporary) / 'missing-target')
                with self.assertRaises(OwnershipConflict): guest.publish(path, {'owned': 'fixture'})
                self.assertTrue(artifact.is_symlink())
                artifact.unlink()

    def test_missing_volume_with_owned_network_is_unknown_not_clean_absence(self):
        backend = guest.GuestBoundaryBackend(NONCE, 'alpha')
        with patch.object(DockerFixtureBackend, 'inspect', return_value=None), patch.object(backend, '_network', return_value={'Id': 'owned'}):
            with self.assertRaises(BackendUnknown):
                backend.inspect(STATE, 'volume')
        with patch.object(DockerFixtureBackend, 'inspect', return_value=None), patch.object(backend, '_network', return_value=None), patch.object(backend, '_firewall', return_value=None):
            self.assertIsNone(backend.inspect(STATE, 'volume'))

    def test_partial_destroy_retains_volume_anchor_and_project_data(self):
        backend = guest.GuestBoundaryBackend(NONCE, 'alpha')
        with patch.object(guest, 'guard'), patch.object(backend, '_storage'), patch.object(backend, 'inspect', return_value=None), patch.object(backend, '_network', return_value={'Id': 'owned-network'}), patch.object(backend, '_run', side_effect=BackendUnknown), patch.object(DockerFixtureBackend, 'remove') as remove:
            with self.assertRaises(BackendUnknown):
                backend.remove(STATE, 'volume')
            remove.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); backend.root = root / 'alpha'; runtime = backend._runtime_path(STATE); runtime.mkdir(parents=True)
            (runtime / 'cache').write_text('Room-owned'); project = root / 'Project-data'; project.write_text('keep')
            (runtime / 'link').symlink_to(project)
            with patch.object(guest, 'CONTROL', root):
                expected = backend._intent_value(STATE)
                backend._runtime_intent(STATE).write_text(json.dumps(expected))
                backend._runtime_marker(STATE).write_text(json.dumps({**expected, 'identity': guest.identity(runtime)}))
                with patch.object(guest, 'guard'), patch.object(backend, '_storage'), patch.object(backend, 'inspect', return_value=None), patch.object(backend, '_network', return_value=None), patch.object(backend, '_firewall', return_value=None), patch.object(DockerFixtureBackend, 'remove') as remove:
                    backend.remove(STATE, 'volume')
            self.assertFalse(runtime.exists())
            self.assertEqual('keep', project.read_text())
            remove.assert_called_once_with(STATE, 'volume')

    def test_ci_runner_has_no_nic_only_owned_images_and_complete_nonce_report(self):
        root = Path('/tmp/owned-vm')
        args = runner.arguments(root, root / 'guest.qcow2', root / 'seed.iso', root / 'payload.iso', root / 'quota.raw')
        self.assertEqual('none', args[args.index('-nic') + 1])
        devices = [args[i+1] for i, arg in enumerate(args) if arg == '-device']
        self.assertEqual(['virtio-blk-pci,drive=os,bootindex=1', 'virtio-blk-pci,drive=seed',
                          'virtio-blk-pci,drive=payload', 'virtio-blk-pci,drive=quota,serial=uas-quota',
                          'isa-debugcon,iobase=0x402,chardev=firmware'], devices)
        self.assertEqual('strict=on,menu=off', args[args.index('-boot') + 1])
        self.assertTrue(all('if=none,id=' in args[i+1] for i, arg in enumerate(args) if arg == '-drive'))
        self.assertEqual('file,id=firmware,path=/tmp/owned-vm/firmware.log', args[args.index('-chardev') + 1])
        self.assertFalse(any(value in args for value in ('-netdev', '-virtfs', '-fsdev', '-enable-kvm')))
        self.assertTrue(all(value.startswith('file=/tmp/owned-vm/') for i, value in enumerate(args) if i and args[i-1] == '-drive'))
        report = {'version': 1, 'nonce': NONCE, 'checks': {name: {'status': 'passed'} for name in runner.REQUIRED}}
        line = 'UAS_BOUNDARY_REPORT:' + NONCE + ':' + json.dumps(report)
        self.assertEqual(report, runner.parse_report(line, NONCE))
        for bad in ('', line + '\n' + line, line.replace('passed', 'failed'), line.replace(NONCE, 'c'*32)):
            with self.assertRaises(RuntimeError): runner.parse_report(bad, NONCE)
        with patch.dict('os.environ', {}, clear=True), patch.object(runner, 'build_payload') as prepare:
            with self.assertRaises(RuntimeError): runner.main()
            prepare.assert_not_called()

    def test_silent_firmware_boot_fails_early_and_stops_only_owned_qemu(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            process = Mock(); process.poll.return_value = None
            with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner.time, 'monotonic', side_effect=[0, 181]), patch.object(runner.feasibility, 'stop_process') as stop:
                with self.assertRaisesRegex(RuntimeError, 'no serial boot output'):
                    runner.boot(directory, ['unused-offline-placeholder'], NONCE)
                stop.assert_called_once_with(process)
            self.assertEqual(('qemu.log', 'serial.log', 'firmware.log'), runner.LOG_FILES)

    def test_native_guest_solver_installs_roots_not_union_of_conflicting_providers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); marker = root / 'boot'; marker.write_text(NONCE)
            def mapped_path(value):
                return marker if value == '/run/uas-vm-fixture' else root / 'repositories' if value == '/run/uas-repositories' else Path(value)
            manifest = {'packages': [{'file': 'systemd.rpm'}, {'file': 'systemd-standalone-sysusers.rpm'}]}
            with patch.object(guest_script, 'Path', side_effect=mapped_path), patch.object(guest_script, 'PAYLOAD', root / 'payload'), patch.object(guest_script.os, 'geteuid', return_value=0), patch.object(guest_script, 'run', return_value='Enforcing') as run:
                guest_script.install_packages(NONCE, manifest)
            commands = [call.args for call in run.call_args_list]
            dnf = next(args for args in commands if args[0] == 'dnf')
            self.assertEqual(guest_script.REQUIRED_PACKAGES, dnf[dnf.index('install') + 1:])
            self.assertIn('--disable-repo=*', dnf); self.assertIn('--enable-repo=uas-offline', dnf)
            self.assertNotIn('--allowerasing', dnf); self.assertNotIn('--nogpgcheck', dnf)
            self.assertTrue(any('systemd-standalone-sysusers.rpm' in argument for args in commands if args[0] == 'rpmkeys' for argument in args))
            config = (root / 'repositories/uas.repo').read_text()
            self.assertIn('gpgcheck=1\n', config); self.assertIn('baseurl=file://', config)
            self.assertNotIn('http', config)

    def test_package_install_requires_disposable_guest_before_effects(self):
        with patch.object(guest_script.os, 'geteuid', return_value=1000), patch.object(guest_script, 'run') as run:
            with self.assertRaisesRegex(AssertionError, 'not this disposable boot'):
                guest_script.install_packages(NONCE, {'packages': []})
            run.assert_not_called()

    def test_fedora_service_owns_selinux_flag_and_actual_engine_enforcement_is_required(self):
        self.assertNotIn('selinux-enabled', guest_script.DOCKER_CONFIGURATION)
        self.assertEqual('uas-remap', guest_script.DOCKER_CONFIGURATION['userns-remap'])
        self.assertEqual('overlay2', guest_script.DOCKER_CONFIGURATION['storage-driver'])
        with patch.object(guest_script, 'run', side_effect=['Enforcing', '["name=selinux", "name=userns"]']):
            guest_script.require_engine_security()
        for options in ('[]', '["name=selinux"]', '["name=userns"]', '{}'):
            with patch.object(guest_script, 'run', side_effect=['Enforcing', options]), self.assertRaises(AssertionError):
                guest_script.require_engine_security()
        with patch.object(guest_script, 'run', return_value='Permissive'), self.assertRaises(AssertionError):
            guest_script.require_engine_security()

    def test_guest_verifies_local_repository_metadata_before_package_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); metadata = root / 'rpms/repodata/repomd.xml'
            metadata.parent.mkdir(parents=True); metadata.write_bytes(b'original')
            (root / 'fixture').write_bytes(b'fixture'); (root / 'fedora-44.asc').write_bytes(b'key')
            def entry(path):
                return {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            manifest = {'version': 1, 'nonce': NONCE, 'source': [], 'packages': [],
                        'repository_metadata': [{'file': 'repodata/repomd.xml', **entry(metadata)}],
                        'fixture': entry(root / 'fixture'), 'key': entry(root / 'fedora-44.asc')}
            raw = json.dumps(manifest).encode(); (root / 'manifest.json').write_bytes(raw)
            with patch.object(guest_script, 'PAYLOAD', root):
                self.assertEqual(manifest, guest_script.verify_payload(NONCE, hashlib.sha256(raw).hexdigest()))
                metadata.write_bytes(b'tampered')
                with self.assertRaisesRegex(AssertionError, 'digest mismatch'):
                    guest_script.verify_payload(NONCE, hashlib.sha256(raw).hexdigest())
