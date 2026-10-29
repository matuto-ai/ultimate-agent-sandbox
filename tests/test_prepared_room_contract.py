"""File/pure contracts for explicit prepared Room bases; no native execution."""
import copy
from contextlib import ExitStack, redirect_stdout
import io
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, Mock, mock_open
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent / 'vm'))
try:
    import prepared_room as prepared
    import run_room as runner
    import prepare_room_base as producer
    import guest_room as guest_runner
finally:
    sys.path.pop(0)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


class PreparedRoomContractTests(unittest.TestCase):
    def fixture(self, root):
        repo = root / 'repo'; repo.mkdir()
        artifact = root / 'prepared'; artifact.mkdir()
        pool = artifact / 'pool'; (pool / 'rpms/repodata').mkdir(parents=True)
        package = b'signed RPM fixture bytes'
        metadata = b'repodata fixture bytes'
        certificate = b'certificate fixture bytes'
        (pool / 'fedora-44.asc').write_bytes(certificate)
        (pool / 'rpms/tool-1-1.x86_64.rpm').write_bytes(package)
        (pool / 'rpms/repodata/repomd.xml').write_bytes(metadata)
        source = []
        for name in prepared.BASE_SOURCES:
            data = ('source fixture ' + name).encode()
            path = repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            source.append({'file': name, **identity(data)})
        manifest = {'version': 1, 'profile': prepared.PROFILE, 'release': '44',
                    'signing_fingerprint': 'A'*40, 'nonce': 'a'*32, 'source': source,
                    'key': {'file': 'fedora-44.asc', **identity(certificate)},
                    'packages': [{'file': 'tool-1-1.x86_64.rpm', 'name': 'tool', 'epoch': '0',
                                  'version': '1', 'release': '1', 'arch': 'x86_64',
                                  'signature_verified': True, **identity(package)}],
                    'repository_metadata': [{'file': 'repodata/repomd.xml', **identity(metadata)}]}
        contract = prepared.foundation(manifest)
        key = prepared.digest(contract)
        base = b'standalone disk fixture bytes'; (artifact / 'base.qcow2').write_bytes(base)
        receipt = {'version': 1, 'profile': prepared.PROFILE, 'base_key': key, 'foundation': contract,
                   'base': identity(base), 'qualification': 'NOT_RUN', 'created_at': int(time.time()),
                   'producer': {'commit': 'b'*40, 'run_id': '123'},
                   'guest_receipt': {'version': 1, 'base_key': key, 'inventory': 'tool-0:1-1.x86_64\n',
                                     'kernel': '6.1.2-x86_64', 'clean': True, 'scenario_started': False}}
        digest = self.write_receipt(artifact, receipt)
        return repo, artifact, manifest, receipt, digest

    def write_receipt(self, artifact, receipt):
        raw = prepared.canonical(receipt) + b'\n'
        (artifact / 'receipt.json').write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def test_exact_receipt_pool_and_setup_are_accepted_without_a_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, artifact, _, expected, digest = self.fixture(Path(temporary))
            result = prepared.select(artifact, digest, repo)
            self.assertEqual(expected, result)
            self.assertEqual('NOT_RUN', result['qualification'])
            self.assertFalse(result['guest_receipt']['scenario_started'])

    def test_nonce_and_current_runtime_source_do_not_invalidate_os_foundation(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, manifest, _, _ = self.fixture(Path(temporary))
            expected = prepared.digest(prepared.foundation(manifest))
            manifest['nonce'] = 'c'*32
            manifest['source'].append({'file': 'uas/runtime.py', **identity(b'new runtime')})
            manifest['native_runtime'] = {'sha256': 'd'*64}
            self.assertEqual(expected, prepared.digest(prepared.foundation(manifest)))

    def test_setup_and_signed_package_pool_changes_invalidate_foundation(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, manifest, _, _ = self.fixture(Path(temporary))
            expected = prepared.digest(prepared.foundation(manifest))
            for section, field in [('source', 'sha256'), ('packages', 'sha256'),
                                   ('packages', 'version'), ('repository_metadata', 'sha256')]:
                changed = copy.deepcopy(manifest)
                changed[section][0][field] = 'f'*64 if field == 'sha256' else '2'
                with self.subTest(section=section, field=field):
                    self.assertNotEqual(expected, prepared.digest(prepared.foundation(changed)))

    def test_receipt_digest_is_external_and_cannot_be_self_authorized(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, artifact, _, receipt, digest = self.fixture(Path(temporary))
            receipt['producer']['run_id'] = '456'; self.write_receipt(artifact, receipt)
            with self.assertRaisesRegex(ValueError, 'receipt digest differs'):
                prepared.select(artifact, digest, repo)

    def test_each_artifact_file_mutation_and_extra_file_is_rejected(self):
        for relative in ('base.qcow2', 'pool/fedora-44.asc', 'pool/rpms/tool-1-1.x86_64.rpm',
                         'pool/rpms/repodata/repomd.xml', 'pool/unexpected', 'unexpected'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                repo, artifact, _, _, digest = self.fixture(Path(temporary))
                (artifact / relative).write_bytes(b'changed')
                with self.assertRaises(ValueError): prepared.select(artifact, digest, repo)

    def test_setup_change_is_a_bounded_miss_not_silent_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, artifact, _, _, digest = self.fixture(Path(temporary))
            (repo / prepared.BASE_SOURCES[0]).write_bytes(b'new setup')
            with self.assertRaisesRegex(ValueError, 'explicit rebuild required'):
                prepared.select(artifact, digest, repo)

    def test_missing_or_symlinked_pool_file_never_passes(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                repo, artifact, _, _, digest = self.fixture(Path(temporary))
                target = artifact / 'pool/fedora-44.asc'
                data = target.read_bytes(); target.unlink()
                if symlink:
                    other = Path(temporary) / 'certificate'; other.write_bytes(data); target.symlink_to(other)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    prepared.select(artifact, digest, repo)

    def test_duplicate_json_keys_and_cached_qualification_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, artifact, _, receipt, _ = self.fixture(Path(temporary))
            receipt['qualification'] = 'PASSED'
            with self.assertRaisesRegex(ValueError, 'not a clean prepared base'):
                prepared.select(artifact, self.write_receipt(artifact, receipt), repo)
            raw = b'{"version":1,"version":1}'
            (artifact / 'receipt.json').write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                prepared.select(artifact, hashlib.sha256(raw).hexdigest(), repo)

    def test_bad_or_dirty_guest_receipt_is_not_acceptance(self):
        mutations = ({'clean': False}, {'scenario_started': True}, {'base_key': 'd'*64},
                     {'inventory': ''}, {'kernel': '../host'}, {'unexpected': True})
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                repo, artifact, _, receipt, _ = self.fixture(Path(temporary))
                receipt['guest_receipt'].update(mutation)
                with self.assertRaises(ValueError):
                    prepared.select(artifact, self.write_receipt(artifact, receipt), repo)

    def test_pool_rejects_unsigned_duplicate_and_path_traversal_records(self):
        mutations = ({'signature_verified': False}, {'file': '../tool.rpm'}, {'bytes': True},
                     {'sha256': 'not-a-hash'}, {'arch': 'i686'})
        with tempfile.TemporaryDirectory() as temporary:
            _, _, manifest, _, _ = self.fixture(Path(temporary))
            for mutation in mutations:
                changed = copy.deepcopy(manifest); changed['packages'][0].update(mutation)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError): prepared.pool_contract(changed)
            changed = copy.deepcopy(manifest); changed['packages'] *= 2
            with self.assertRaises(ValueError): prepared.pool_contract(changed)

    def test_pool_copy_is_exact_and_never_adopts_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, artifact, manifest, _, _ = self.fixture(Path(temporary))
            target = Path(temporary) / 'new-pool'
            prepared.copy_pool(artifact / 'pool', target, prepared.pool_contract(manifest))
            prepared.verify_pool(target, prepared.pool_contract(manifest))
            with self.assertRaises(FileExistsError):
                prepared.copy_pool(artifact / 'pool', target, prepared.pool_contract(manifest))

    def test_external_backing_and_data_files_are_rejected(self):
        good = {'format': 'qcow2', 'virtual-size': 1024**3}
        prepared.standalone_info(good)
        for mutation in ({'backing-filename': 'other.qcow2'}, {'full-backing-filename': '/host/image'},
                         {'data-file': '/host/data'}, {'format-specific': {'data': {'data-file': '/host/data'}}},
                         {'format': 'raw'}, {'virtual-size': 65*1024**3}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                prepared.standalone_info({**good, **mutation})

    def test_expired_future_and_noninteger_receipts_fail_without_refresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, artifact, _, receipt, _ = self.fixture(Path(temporary))
            now = 2000000000
            for created in (now - 7*24*3600 - 1, now + 1, str(now), True):
                receipt['created_at'] = created
                with self.subTest(created=created), patch.object(prepared.time, 'time', return_value=now):
                    with self.assertRaisesRegex(ValueError, 'expired|future|preparation'):
                        prepared.select(artifact, self.write_receipt(artifact, receipt), repo)
            receipt['created_at'] = now - 7*24*3600
            with patch.object(prepared.time, 'time', return_value=now):
                self.assertEqual(receipt, prepared.select(artifact, self.write_receipt(artifact, receipt), repo))

    def test_preparation_report_requires_exact_nonce_key_and_single_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, receipt, _ = self.fixture(Path(temporary))
            value = receipt['guest_receipt']; key = receipt['base_key']
            line = 'UAS_ROOM_PREPARED:' + 'a'*32 + ':' + json.dumps(value)
            self.assertEqual(value, producer.parse_prepared(line, 'a'*32, key))
            for text, nonce, expected in ((line, 'b'*32, key), (line, 'a'*32, 'b'*64),
                                           (line+'\n'+line, 'a'*32, key),
                                           (line.replace('UAS_ROOM_PREPARED:', 'UAS_ROOM_REPORT:'), 'a'*32, key)):
                with self.subTest(nonce=nonce, text=text[:50]), self.assertRaises(ValueError):
                    producer.parse_prepared(text, nonce, expected)

    def test_producer_refuses_existing_output_and_unknown_identity_before_fetch(self):
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
                       'UAS_ROOM_VM_PROFILE': prepared.PROFILE,
                       'UAS_ROOM_PRODUCER_COMMIT': 'a'*40, 'GITHUB_RUN_ID': '42'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / 'already-there'; existing.mkdir()
            (existing / 'human-file').write_text('preserve me')
            for destination, changes in ((existing, {}), (root/'new', {'GITHUB_RUN_ID': 'latest'}),
                                          (root/'new', {'UAS_ROOM_PRODUCER_COMMIT': ''}), (root/'new', {'GITHUB_ACTIONS': 'false'})):
                with self.subTest(destination=destination, changes=changes), \
                     patch.dict(producer.os.environ, {**environment, **changes}, clear=True), \
                     patch.object(producer.os, 'geteuid', return_value=1000), \
                     patch.object(runner.feasibility, 'fetch_image') as fetch, \
                     patch.object(runner, 'build_payload') as payload, patch.object(runner, 'boot') as boot:
                    with self.assertRaises((ValueError, RuntimeError)): producer.build(destination)
                    for method in (fetch, payload, boot): method.assert_not_called()
            self.assertEqual('preserve me', (existing / 'human-file').read_text())
            self.assertFalse((root/'new').exists())

    def test_failure_diagnostic_read_or_write_error_preserves_primary(self):
        for failing in ('read','write'):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary)
                (directory/'serial.log').write_bytes(b'bounded diagnostic')
                original=RuntimeError('primary preparation failure')
                with ExitStack() as stack:
                    if failing == 'read': stack.enter_context(patch.object(Path,'open',side_effect=OSError('diagnostic read')))
                    else: stack.enter_context(patch('builtins.print',side_effect=OSError('diagnostic write')))
                    with self.assertRaises(RuntimeError) as caught:
                        try: raise original
                        except RuntimeError:
                            producer.failure_logs(directory)
                            raise
                    self.assertIs(original,caught.exception)

    def producer_case(self, root, *, failure=None, race=False):
        repo, source_artifact, manifest, template, _ = self.fixture(root)
        output = root / 'result'
        calls = []
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
                       'UAS_ROOM_VM_PROFILE': prepared.PROFILE,
                       'UAS_ROOM_PRODUCER_COMMIT': 'a'*40, 'GITHUB_RUN_ID': '42'}
        (repo / 'tests/vm/fedora-image.json').write_text('{}')
        # Keep every setup identity current after replacing the synthetic image lock.
        manifest['source'] = [{'file': item['file'], **identity((repo/item['file']).read_bytes())}
                              for item in manifest['source']]
        guest = {**template['guest_receipt'], 'base_key': prepared.digest(prepared.foundation(manifest))}

        def effect(name):
            calls.append(name)
            if failure == name: raise RuntimeError('injected ' + name)

        def fetch(lock, directory):
            effect('fetch'); image = directory/'image.qcow2'; image.write_bytes(b'official base fixture'); return image

        def payload(directory, repository, nonce, **kwargs):
            effect('payload')
            self.assertEqual(repo, repository)
            folder = directory/'payload-build'; folder.mkdir()
            (folder/'payload').mkdir()
            for source in (source_artifact/'pool').rglob('*'):
                target = folder/'payload'/source.relative_to(source_artifact/'pool')
                if source.is_dir(): target.mkdir()
                else: target.write_bytes(source.read_bytes())
            current = copy.deepcopy(manifest); current['nonce'] = nonce
            (folder/'payload/manifest.json').write_bytes(prepared.canonical(current))
            iso = folder/'payload.iso'; iso.write_bytes(b'ISO fixture'); return iso

        def command(arguments, **kwargs):
            if arguments[:2] == ['qemu-img', 'create']:
                effect('overlay'); Path(arguments[-1]).write_bytes(b'fresh overlay fixture'); return ''
            if arguments[:2] == ['qemu-img', 'convert']:
                effect('convert'); Path(arguments[-1]).write_bytes(b'flattened clean base fixture'); return ''
            if arguments[:2] == ['qemu-img', 'info']:
                effect('info'); return json.dumps({'format': 'qcow2', 'virtual-size': 1024**3})
            if '--version' in arguments:
                effect('tool-version'); return 'prepared tool fixture version 1'
            self.fail('unexpected native command boundary: ' + str(arguments[0]))

        def seed(directory, nonce, digest, **kwargs):
            effect('seed')
            self.assertEqual('prepare', kwargs['mode'])
            self.assertEqual(guest['base_key'], kwargs['base_key'])
            self.assertEqual(hashlib.sha256((kwargs['payload_root']/'manifest.json').read_bytes()).hexdigest(), digest)
            return directory/'seed.iso'

        def boot(directory, arguments, nonce, *, report_parser):
            effect('boot')
            self.assertEqual([], arguments)
            value = report_parser('UAS_ROOM_PREPARED:' + nonce + ':' + json.dumps(guest), nonce)
            if race:
                output.mkdir(); (output/'human').write_text('do not replace')
            return value, 12.5

        actual_copy, actual_select, actual_rename = prepared.copy_pool, prepared.select, Path.rename
        def rename(path, target):
            if failure == 'publish-pool' and path.name == 'pool':
                raise OSError('injected publication failure')
            return actual_rename(path, target)
        def copy_pool(*args, **kwargs):
            effect('copy'); return actual_copy(*args, **kwargs)
        def select(*args, **kwargs):
            effect('select'); return actual_select(*args, **kwargs)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(producer.os.environ, environment, clear=True))
            stack.enter_context(patch.object(producer.os, 'geteuid', return_value=1000))
            for owner, name, value in ((runner, 'ROOT', repo), (runner, 'HERE', repo/'tests/vm'),
                    (runner.feasibility, 'fetch_image', fetch), (runner.feasibility, 'command', command),
                    (runner, 'build_payload', payload), (runner, 'seed', seed), (runner, 'boot', boot),
                    (runner, 'arguments', lambda *args: []), (prepared, 'copy_pool', copy_pool),
                    (prepared, 'select', select), (Path, 'rename', rename)):
                stack.enter_context(patch.object(owner, name, value))
            qualification = stack.enter_context(patch.object(runner, 'parse_report'))
            log = stack.enter_context(redirect_stdout(io.StringIO()))
            if failure or race:
                with self.assertRaises((RuntimeError, ValueError, OSError)): producer.build(output)
                self.assertNotIn('Room prepared artifact:', log.getvalue())
            else:
                receipt = producer.build(output)
                raw = (output/'receipt.json').read_bytes()
                self.assertEqual(receipt, actual_select(output, hashlib.sha256(raw).hexdigest(), repo))
                self.assertEqual('NOT_RUN', receipt['qualification'])
                self.assertEqual(guest, receipt['guest_receipt'])
                self.assertEqual({'base.qcow2','pool','receipt.json'}, {p.name for p in output.iterdir()})
                self.assertIn('Room prepared artifact:', log.getvalue())
            qualification.assert_not_called()
        self.assertFalse(list(root.glob('uas-room-prepare-*')))
        if race: self.assertEqual('do not replace', (output/'human').read_text())
        elif failure == 'publish-pool':
            self.assertTrue(output.is_dir())
            self.assertTrue((output/'base.qcow2').exists())
            self.assertFalse((output/'receipt.json').exists())
            with self.assertRaises((ValueError, FileNotFoundError)):
                actual_select(output, 'a'*64, repo)
        elif failure: self.assertFalse(output.exists())
        return calls

    def test_mocked_producer_publishes_only_after_clean_boot_flatten_and_full_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = self.producer_case(Path(temporary))
        phases = [name for name in calls if name != 'tool-version']
        self.assertEqual(['fetch','payload','overlay','seed','boot','convert','info','copy','select'], phases)

    def test_mocked_producer_failure_matrix_never_publishes_and_cleans_owned_temp(self):
        for failure in ('fetch','payload','overlay','seed','boot','convert','info','copy','select'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                self.producer_case(Path(temporary), failure=failure)

    def test_mocked_producer_preserves_output_that_appears_during_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.producer_case(Path(temporary), race=True)

    def test_partial_publication_is_not_an_eligible_artifact_or_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.producer_case(Path(temporary), failure='publish-pool')

    def test_prepare_guest_main_never_runs_scenario_or_reports_qualification(self):
        manifest = {'profile': prepared.PROFILE}
        report = {'clean': True, 'scenario_started': False}
        events = []
        serial = mock_open()
        with patch.object(guest_runner.sys, 'argv', ['guest_room.py','a'*32,'b'*64,'prepare','c'*64]), \
             patch.object(guest_runner, 'install', side_effect=lambda *args, **kwargs: (events.append('install') or (manifest, {}))) as install, \
             patch.object(prepared, 'seal_guest', side_effect=lambda *args: (events.append('seal') or report)) as seal, \
             patch.object(guest_runner, 'scenario') as scenario, patch('builtins.open', serial):
            guest_runner.main()
        self.assertEqual(['install', 'seal'], events)
        install.assert_called_once_with('a'*32,'b'*64,mode='prepare',base_key='c'*64)
        seal.assert_called_once_with(manifest,'c'*64,guest_runner.boundary,guest_runner.room_profile)
        scenario.assert_not_called()
        serial.assert_called_once_with('/dev/ttyS0','w')
        written = ''.join(call.args[0] for call in serial().write.call_args_list)
        self.assertIn('UAS_ROOM_PREPARED:'+'a'*32+':',written)
        self.assertNotIn('UAS_ROOM_REPORT:',written)
        self.assertNotIn('passed',written)

    def test_warm_install_repeats_fresh_guards_and_stages_current_source_without_provision(self):
        events = []; manifest = {'profile': prepared.PROFILE}; network = {'fresh': True}
        def run(*args, **kwargs):
            if args == ('getenforce',): events.append('selinux'); return 'Enforcing'
            if args[0] == 'mount':
                self.assertEqual(('mount','-o','ro,nodev,nosuid,noexec','/dev/disk/by-label/UAS_PAYLOAD',str(guest_runner.boundary.PAYLOAD)),args)
                events.append('mount'); return ''
            if args[:2] == ('rpm','-V'): events.append('verify-'+args[-1]); return ''
            self.fail('unexpected guest native boundary')
        with patch.object(guest_runner.room_profile,'guest_guard',side_effect=lambda *args, **kwargs: (events.append('guard') or network)), \
             patch.object(guest_runner,'run',side_effect=run), patch.object(Path,'mkdir',side_effect=lambda *args, **kwargs: events.append('mkdir')), \
             patch.object(guest_runner.boundary,'verify_payload',side_effect=lambda *args: (events.append('payload') or manifest)) as verify, \
             patch.object(prepared,'consume_guest',side_effect=lambda *args: events.append('consume')) as consume, \
             patch.object(prepared,'provision') as provision, \
             patch.object(guest_runner.shutil,'copytree',side_effect=lambda *args: events.append('source')) as source, \
             patch.object(guest_runner.shutil,'copyfile',side_effect=lambda *args: events.append('fixture')) as fixture, \
             patch.object(Path,'chmod',side_effect=lambda *args: events.append('fixture-mode')):
            self.assertEqual((manifest,network),guest_runner.install('a'*32,'b'*64,mode='warm',base_key='c'*64))
        self.assertEqual(['guard','selinux','mkdir','mount','payload','consume','verify-git-core',
                          'verify-openssh-clients','source','fixture','fixture-mode'],events)
        verify.assert_called_once_with('a'*32,'b'*64)
        consume.assert_called_once_with(manifest,'c'*64,guest_runner.boundary,guest_runner.room_profile)
        provision.assert_not_called()
        source.assert_called_once_with(guest_runner.boundary.PAYLOAD/'repo',guest_runner.boundary.ROOT)
        fixture.assert_called_once_with(guest_runner.boundary.PAYLOAD/'fixture',guest_runner.boundary.ROOT/'fixture')

    def test_failed_warm_consumption_never_stages_source_or_provisions(self):
        with patch.object(guest_runner.room_profile,'guest_guard',return_value={}), \
             patch.object(guest_runner,'run',return_value='Enforcing'), patch.object(Path,'mkdir'), \
             patch.object(guest_runner.boundary,'verify_payload',return_value={'profile':prepared.PROFILE}), \
             patch.object(prepared,'consume_guest',side_effect=ValueError('mismatch')), \
             patch.object(prepared,'provision') as provision, patch.object(guest_runner.shutil,'copytree') as source, \
             patch.object(guest_runner.shutil,'copyfile') as fixture, patch.object(Path,'chmod') as chmod:
            with self.assertRaisesRegex(ValueError,'mismatch'):
                guest_runner.install('a'*32,'b'*64,mode='warm',base_key='c'*64)
            for effect in (provision,source,fixture,chmod): effect.assert_not_called()

    def consume_case(self, root, failure=None):
        _, _, manifest, receipt, _ = self.fixture(root)
        value = receipt['guest_receipt']; configuration = {'userns-remap':'uas-remap'}
        fixed = {'/etc/subuid':'uas-remap:100000:65536\n', '/etc/subgid':'uas-remap:100000:65536\n',
                 '/etc/docker/daemon.json': json.dumps(configuration)}
        if failure == 'configuration': fixed['/etc/docker/daemon.json'] = '{}'
        if failure == 'subuid': fixed['/etc/subuid'] = 'uas-remap:0:65536\n'
        def path(name):
            node = Mock()
            node.read_text.return_value = fixed.get(name,'')
            node.exists.return_value = failure == 'runtime' and name == '/var/lib/docker'
            node.is_dir.return_value = True; node.iterdir.return_value = iter(['old state'])
            return node
        def run(*args, **kwargs):
            if args == ('uname','-r'): return 'other-kernel' if failure == 'kernel' else value['kernel']
            if args == ('getenforce',): return 'Permissive' if failure == 'selinux' else 'Enforcing'
            if args[0] == 'rpmkeys':
                if failure == 'signature': raise ValueError('bad signature')
                return ''
            if args[:2] == ('rpm','-q'): return '0:1-1.x86_64\n'
            if args[:2] == ('rpm','-V'): return 'changed executable' if failure == 'executable' else ''
            if args[:2] == ('systemctl','show'):
                if args[-1] in ('docker.service','docker.socket','containerd.service'):
                    return 'ActiveState=active\nUnitFileState=enabled\n' if failure == 'runtime-active' else 'ActiveState=inactive\nUnitFileState=disabled\n'
                return 'ActiveState=active\nUnitFileState=enabled\n' if failure == 'ssh' else 'ActiveState=inactive\nUnitFileState=masked\n'
            self.fail('unexpected installed-state boundary')
        boundary = SimpleNamespace(run=Mock(side_effect=run), ROOT=Mock(), PAYLOAD=Path('/mnt/uas-payload'),
                                   require_installed_roots=Mock(), DOCKER_CONFIGURATION=configuration, REQUIRED_PACKAGES=('moby-engine','docker-cli','shadow-utils'))
        boundary.ROOT.exists.return_value = failure == 'source-state'
        profile = SimpleNamespace(PACKAGE_PROFILE={},guest_package_roots=lambda manifest:{'git-core':('0','1','1','x86_64')})
        guest_receipt = Mock()
        guest_receipt.stat.return_value = SimpleNamespace(st_uid=1 if failure == 'owner' else 0,
                                                         st_mode=0o644 if failure == 'mode' else 0o600)
        guest_receipt.read_bytes.return_value = prepared.canonical(value)
        with patch.object(prepared,'GUEST_RECEIPT',guest_receipt), patch.object(prepared,'hash_file',return_value={}), \
             patch.object(prepared,'inventory',return_value='wrong' if failure == 'inventory' else value['inventory']), \
             patch.object(prepared,'Path',side_effect=path):
            if failure:
                with self.assertRaises(ValueError): prepared.consume_guest(manifest,receipt['base_key'],boundary,profile)
            else:
                prepared.consume_guest(manifest,receipt['base_key'],boundary,profile)
        if failure in ('owner','mode','inventory','kernel','signature'):
            boundary.require_installed_roots.assert_not_called()
        else: boundary.require_installed_roots.assert_called_once_with({})
        if not failure:
            self.assertTrue(any(call.args[0] == 'rpmkeys' for call in boundary.run.call_args_list))
            self.assertTrue(any(call.args == ('getenforce',) for call in boundary.run.call_args_list))

    def test_warm_consumer_rechecks_inventory_kernel_signatures_config_and_live_security(self):
        with tempfile.TemporaryDirectory() as temporary: self.consume_case(Path(temporary))

    def test_warm_consumer_rejects_each_dirty_or_mismatched_guest_before_scenario(self):
        for failure in ('owner','mode','inventory','kernel','signature','configuration','subuid','executable','ssh',
                        'source-state','selinux','runtime','runtime-active'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                self.consume_case(Path(temporary),failure)

    def seal_case(self, root, failure=None):
        _, _, manifest, receipt, _ = self.fixture(root)
        events = []; value = receipt['guest_receipt']
        def event(name):
            events.append(name)
            if failure == name: raise ValueError('injected '+name)
        def run(*args, **kwargs):
            if args[:2] == ('systemctl','stop'): event('stop-'+args[-1]); return ''
            if args[:2] == ('systemctl','disable'): event('disable-'+args[-1]); return ''
            if args[:2] == ('systemctl','show'):
                event('observe-'+args[-1]); return 'ActiveState=inactive\nUnitFileState=disabled\n'
            if args == ('uname','-r'): event('kernel'); return value['kernel']
            if args[0] == 'umount': event('unmount'); return ''
            if args[0] == 'cloud-init':
                self.assertEqual(('cloud-init','clean','--logs','--seed','--machine-id'),args)
                event('reset-identity'); return ''
            self.fail('unexpected seal native boundary')
        boundary = SimpleNamespace(run=Mock(side_effect=run), ROOT=Mock(), PAYLOAD=Mock())
        boundary.ROOT.exists.return_value = failure == 'source-residue'
        boundary.PAYLOAD.rmdir.side_effect = lambda: event('remove-mountpoint')
        hostkey = Mock(); hostkey.is_file.return_value = True; hostkey.is_symlink.return_value = False
        hostkey.unlink.side_effect = lambda: event('remove-host-key')
        def path(name):
            node = Mock(); node.exists.return_value = failure == 'runtime-residue' and name == '/var/lib/docker'
            node.is_dir.return_value = True; node.iterdir.return_value = iter(['old runtime'])
            if name == '/etc/ssh': node.glob.return_value = [hostkey]
            return node
        writer = mock_open()
        writer.return_value.write.side_effect = lambda content: event('write-receipt')
        guest_receipt = Mock(); guest_receipt.exists.return_value = False
        guest_receipt.open.side_effect = lambda *args: (event('open-receipt') or writer(*args))
        guest_receipt.chmod.side_effect = lambda mode: (self.assertEqual(0o600,mode),event('protect-receipt'))
        with patch.object(prepared,'validate_installed',side_effect=lambda *args: event('validate-installed')), \
             patch.object(prepared,'inventory',side_effect=lambda *args: (event('inventory') or value['inventory'])), \
             patch.object(prepared,'GUEST_RECEIPT',guest_receipt), patch.object(prepared,'Path',side_effect=path):
            if failure:
                with self.assertRaises(ValueError): prepared.seal_guest(manifest,receipt['base_key'],boundary,object())
            else:
                observed = prepared.seal_guest(manifest,receipt['base_key'],boundary,object())
                self.assertEqual(value,observed)
                writer.assert_called_once_with('x')
                raw = writer.return_value.write.call_args.args[0]
                self.assertEqual(value,json.loads(raw))
        if failure and failure not in ('write-receipt','protect-receipt'):
            writer.return_value.write.assert_not_called()
        return events

    def test_seal_cleans_only_pre_scenario_state_before_writing_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            events = self.seal_case(Path(temporary))
        self.assertEqual(['validate-installed','stop-docker.service','disable-docker.service','stop-docker.socket','disable-docker.socket',
                          'stop-containerd.service','disable-containerd.service',
                          'observe-docker.service','observe-docker.socket','observe-containerd.service','inventory','kernel','unmount','remove-mountpoint','reset-identity','remove-host-key',
                          'open-receipt','write-receipt','protect-receipt'],events)

    def test_seal_residue_and_each_cleanup_failure_never_returns_eligible_receipt(self):
        for failure in ('validate-installed','source-residue','runtime-residue','stop-docker.service',
                        'stop-docker.socket','stop-containerd.service','disable-docker.service','disable-docker.socket',
                        'disable-containerd.service','observe-docker.service','observe-docker.socket','observe-containerd.service','inventory','kernel','unmount',
                        'remove-mountpoint','reset-identity','remove-host-key','open-receipt','write-receipt','protect-receipt'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                self.seal_case(Path(temporary),failure)

    def test_guest_prepare_failure_cannot_emit_successful_prepared_receipt(self):
        with patch.object(guest_runner.sys,'argv',['guest_room.py','a'*32,'b'*64,'prepare','c'*64]), \
             patch.object(guest_runner,'install',return_value=({},{})), \
             patch.object(prepared,'seal_guest',side_effect=ValueError('cleanup failed')), \
             patch.object(guest_runner,'scenario') as scenario, patch('builtins.open') as serial:
            with self.assertRaisesRegex(ValueError,'cleanup failed'): guest_runner.main()
            scenario.assert_not_called(); serial.assert_not_called()

    def test_mocked_warm_main_uses_fresh_overlay_quota_nonce_source_and_normal_report_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, artifact, manifest, receipt, receipt_digest = self.fixture(root)
            here = root/'lock'; here.mkdir(); (here/'fedora-image.json').write_text(json.dumps({'sha256':'d'*64}))
            original_base = (artifact/'base.qcow2').read_bytes()
            environment = {'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','UAS_ROOM_VM_PROFILE':prepared.PROFILE,
                           'UAS_ROOM_EXECUTION':'warm','UAS_ROOM_PREPARED_DIR':str(artifact),
                           'UAS_ROOM_PREPARED_SHA256':receipt_digest}
            nonces = []; owned = []; events = []
            def command(arguments, **kwargs):
                if arguments[:2] == ['qemu-img','info']:
                    self.assertEqual(str(artifact/'base.qcow2'),arguments[-1]); events.append('inspect-base')
                    return json.dumps({'format':'qcow2','virtual-size':1024**3})
                if arguments[:2] == ['qemu-img','create']:
                    self.assertEqual(str(artifact/'base.qcow2'),arguments[-2]); events.append('fresh-overlay')
                    Path(arguments[-1]).write_bytes(b'fresh overlay')
                    return ''
                self.fail('unexpected warm native command')
            def payload(directory, repository, nonce, **kwargs):
                self.assertEqual(repo,repository); self.assertEqual(artifact,kwargs['prepared_directory'])
                self.assertEqual(receipt_digest,kwargs['prepared_sha256'])
                nonces.append(nonce); owned.append(directory); events.append('fresh-payload')
                folder = directory/'payload-build'; (folder/'payload').mkdir(parents=True)
                current = copy.deepcopy(manifest); current['nonce']=nonce
                current['source'].append({'file':'uas/current.py',**identity(b'new runtime code')})
                (folder/'payload/manifest.json').write_bytes(prepared.canonical(current))
                iso=folder/'payload.iso'; iso.write_bytes(b'fresh ISO'); return iso
            def seed(directory,nonce,digest,**kwargs):
                self.assertEqual('warm',kwargs['mode']); self.assertEqual(receipt['base_key'],kwargs['base_key'])
                self.assertEqual(nonces[-1],nonce)
                self.assertEqual(hashlib.sha256((kwargs['payload_root']/'manifest.json').read_bytes()).hexdigest(),digest)
                events.append('fresh-seed'); return directory/'seed.iso'
            def arguments(directory,overlay,seed_file,payload_file,quota):
                self.assertEqual(2*1024**3,quota.stat().st_size)
                self.assertEqual(b'fresh overlay',overlay.read_bytes())
                self.assertEqual(directory/'quota.raw',quota)
                events.append('fresh-quota'); return ['mock-guest']
            # No optional parser is accepted: warm qualification must use boot's
            # ordinary current-report route, never the producer receipt parser.
            def boot(directory, arguments, nonce):
                self.assertEqual(['mock-guest'],arguments); self.assertEqual(nonces[-1],nonce)
                events.append('normal-report-route'); return {'test_fixture':True},1.0
            with patch.dict(runner.os.environ,environment,clear=True), patch.object(runner.os,'geteuid',return_value=1000), \
                 patch.object(runner,'ROOT',repo), patch.object(runner,'HERE',here), \
                 patch.object(runner.feasibility,'fetch_image') as fetch, \
                 patch.object(runner.feasibility,'command',side_effect=command), \
                 patch.object(runner,'build_payload',side_effect=payload), patch.object(runner,'seed',side_effect=seed), \
                 patch.object(runner,'arguments',side_effect=arguments), patch.object(runner,'boot',side_effect=boot), \
                 redirect_stdout(io.StringIO()):
                runner.main(); runner.main()
                fetch.assert_not_called()
            self.assertEqual(2,len(set(nonces)))
            self.assertEqual(2,len(set(owned)))
            self.assertTrue(all(not directory.exists() for directory in owned))
            self.assertEqual(original_base,(artifact/'base.qcow2').read_bytes())
            self.assertEqual(['inspect-base','fresh-payload','fresh-overlay','fresh-seed','fresh-quota','normal-report-route']*2,events)

    def test_missing_explicit_warm_artifact_fails_before_payload_qemu_or_cold_fetch(self):
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
                       'UAS_ROOM_VM_PROFILE': prepared.PROFILE, 'UAS_ROOM_EXECUTION': 'warm',
                       'UAS_ROOM_PREPARED_DIR': '', 'UAS_ROOM_PREPARED_SHA256': ''}
        with patch.dict(runner.os.environ, environment, clear=True), patch.object(runner.os, 'geteuid', return_value=1000), \
             patch.object(runner.feasibility, 'fetch_image') as fetch, \
             patch.object(runner.feasibility, 'command') as command, \
             patch.object(runner, 'build_payload') as payload, patch.object(runner, 'boot') as boot:
            with self.assertRaises(ValueError): runner.main()
            for method in (fetch, command, payload, boot): method.assert_not_called()


if __name__ == '__main__': unittest.main()
