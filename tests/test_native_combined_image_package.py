"""Finite source/layout contracts only: no build, native process or image engine."""
import copy
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
import unittest
from unittest.mock import patch
from uas import native_git_resources as RESOURCES
from uas.native_image_package import dockerfile, git_envelope
from uas.native_git_resources import FIXED_ARTIFACTS, LOADER
from uas.kernel_origin import OriginDenied

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('combined_image_build_source', ROOT / 'runtime/native/prepare-git.py')
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class NativeCombinedImagePackageTests(unittest.TestCase):
    def setUp(self):
        # Deliberately synthetic identities/versions: render tests never build.
        self.args = {'node_image': 'node:24.22.1-bookworm-slim@sha256:' + 'a'*64,
                     'compiler_image': 'gcc:14-bookworm@sha256:' + 'b'*64}
        self.packages = {'python_package': '3.11.2-fixture', 'git_package': '1:2.39-fixture',
                         'python_version': '3.11.2'}
        self.entries = json.loads((ROOT / 'runtime/git/public-entries.json').read_text())

    def test_legacy_mode_unchanged_and_combined_requires_explicit_selection(self):
        legacy = dockerfile(**self.args)
        self.assertNotIn('apt-get', legacy)
        source = dockerfile(**self.args, git_packages=self.packages)
        self.assertIn('python3.11=3.11.2-fixture git=1:2.39-fixture', source)
        self.assertIn('/usr/bin/python3.11 -I /build/prepare-git.py 3.11.2', source)
        self.assertIn('git-worker-connector; do', source)
        self.assertIn('FROM scratch AS git-backend-export', source)
        final = source.split('FROM payload AS combined')[1]
        self.assertIn('RUN rm -rf /build', final)
        self.assertNotIn('COPY', final)
        self.assertIn('USER 65532:65532', final)
        self.assertNotIn('artifact-bootstrap', source)
        self.assertNotIn('tini', source)

    def test_partial_unpinned_or_shell_selectors_rejected(self):
        for selected in ({}, {'python_package': '3.11'}, {**self.packages, 'extra': 'x'},
                         {**self.packages, 'git_package': '1;id'},
                         {**self.packages, 'git_package': 'latest'},
                         {**self.packages, 'python_package': '3.11\nRUN evil'},
                         {**self.packages, 'python_version': '3.12.1'},
                         {**self.packages, 'python_version': True}):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                dockerfile(**self.args, git_packages=selected)

    def test_layout_has_every_fixed_asset_and_all_regular_aliases(self):
        layout = BUILD.layout(self.entries)
        supplied_elsewhere = {'/usr/bin/python3.11', '/opt/uas/bin/git-worker-connector'}
        self.assertFalse(FIXED_ARTIFACTS - set(layout) - supplied_elsewhere)
        for prefix in ('/opt/uas/bin', '/usr/bin', '/usr/lib/git-core'):
            for name in self.entries:
                self.assertEqual(layout[prefix + '/' + name], ('launcher.py', 0o555))
        self.assertEqual({p.rsplit('/', 1)[1] for p in layout if p.startswith('/usr/lib/git-core/')},
                         set(self.entries))
        self.assertEqual(layout['/opt/uas/git-hooks/reference-transaction'], ('reference-transaction.py', 0o555))
        for source, mode in layout.values():
            self.assertTrue((ROOT / 'runtime/git' / source).is_file())
            self.assertFalse(mode & 0o022)

    def test_invalid_inventory_fails_before_layout(self):
        for values in ([], ['git', '../git'], ['git', 'git'], ['git-z', 'git'], ['git', 4]):
            with self.assertRaises(ValueError): BUILD.layout(values)

    def test_actual_source_closure_is_complete_without_importing_runtime(self):
        source = {p.stem: p.read_text() for p in (ROOT / 'uas').glob('*.py')}
        closure = BUILD.source_closure(source)
        self.assertTrue({'__init__', 'git_launcher', 'git_worker', 'git_policy', 'kernel_origin'} <= set(closure))
        self.assertLessEqual(len(closure), 192)
        del source['git_policy']
        with self.assertRaises(ValueError): BUILD.source_closure(source)

    def test_closure_rejects_unknown_relative_and_absolute_package_edges(self):
        base = dict.fromkeys(('__init__', 'git_launcher', 'git_worker', 'git_worker_native', 'git_transaction'), '')
        for body in ('from ..escape import x', 'from . import x', 'from uas import x', 'import uas'):
            with self.assertRaises(ValueError): BUILD.source_closure({**base, 'git_worker': body})

    def test_closure_follows_flat_absolute_package_edges(self):
        source = dict.fromkeys(('__init__', 'git_launcher', 'git_worker', 'git_worker_native', 'git_transaction'), '')
        source.update(git_worker='from uas.extra import x', extra='import uas.leaf', leaf='')
        self.assertTrue({'extra', 'leaf'} <= set(BUILD.source_closure(source)))

    def test_abi_parser_accepts_only_resolved_selected_library_paths(self):
        output = 'linux-vdso.so.1 (0x123)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x456)\n/lib64/ld-linux-x86-64.so.2 (0x789)\n'
        self.assertEqual(BUILD.dependency_paths(output), {LOADER, '/lib/x86_64-linux-gnu/libc.so.6'})
        for text in ('', 'libc.so.6 => not found', '/usr/local/lib/libpython.so (0x123)',
                     '/lib/../tmp/evil (0x123)', 'statically linked', output + 'unknown line'):
            with self.assertRaises(ValueError): BUILD.dependency_paths(text)

    def selected(self):
        return {'version': 1, 'profile': 'native-git-primary-v1', 'python_version': '3.11.2',
                'artifacts': dict.fromkeys(FIXED_ARTIFACTS, 'a'*64),
                'abi_artifacts': {LOADER: 'b'*64, '/lib/x86_64-linux-gnu/libc.so.6': 'c'*64},
                'uas_tree_sha256': 'd'*64, 'backend_sha256': 'e'*64}

    def test_external_envelope_consumes_existing_git_selection_contract(self):
        payload = self.selected()
        before = copy.deepcopy(payload)
        result = git_envelope(payload, image_reference='registry/native@sha256:'+'f'*64,
                              image_id='sha256:'+'1'*64, nonce='2'*32)
        self.assertEqual(result['backend_path'], '/mnt/uas-native/'+'2'*32+'/git-backend')
        self.assertEqual(payload, before)
        self.assertNotIn('image_id', payload)
        self.assertEqual(result['artifacts'], payload['artifacts'])

    def test_envelope_rejects_partial_or_synthetic_success_assertions(self):
        for delta in ({'qualified': True}, {'artifacts': {}}, {'abi_artifacts': {}},
                      {'python_version': '3.12.1'}, {'version': True}):
            with self.assertRaises((ValueError, OriginDenied)):
                git_envelope({**self.selected(), **delta}, image_reference='registry/native@sha256:'+'f'*64,
                             image_id='sha256:'+'1'*64, nonce='2'*32)

    def test_generated_layout_passes_canonical_readback_and_detects_alias_drift(self):
        layout = BUILD.layout(self.entries)
        payload = self.selected()
        records = {}
        for target, (source, mode) in layout.items():
            raw = (ROOT / 'runtime/git' / source).read_bytes()
            records[target] = {'kind': 'file', 'uid': 0, 'mode': mode,
                               'sha256': hashlib.sha256(raw).hexdigest(), 'data': raw}
        for path in FIXED_ARTIFACTS - set(records):
            records[path] = {'kind': 'file', 'uid': 0, 'mode': 0o555, 'sha256': 'a'*64}
        payload['artifacts'] = {p: records[p]['sha256'] for p in FIXED_ARTIFACTS}
        payload['uas_tree_sha256'] = hashlib.sha256(BUILD.canonical({'__init__.py': 'd'*64})).hexdigest()
        for path, digest in payload['abi_artifacts'].items():
            records[path] = {'kind': 'file', 'uid': 0, 'mode': 0o555, 'sha256': digest}
        records['/usr/bin/python3'] = {'kind': 'link', 'target': 'python3.11'}
        records['/opt/uas/git-helpers'] = {'kind': 'directory', 'uid': 0, 'mode': 0o755}
        records['/opt/uas/git-helpers/git'] = {'kind': 'link', 'target': '/proc/self/fd/19'}
        records['/opt/uas/git-hooks'] = {'kind': 'directory', 'uid': 65530, 'mode': 0o500}
        records['/opt/uas/uas'] = {'kind': 'directory', 'uid': 0, 'mode': 0o755}
        records['/opt/uas/uas/__init__.py'] = {'kind': 'file', 'uid': 0, 'mode': 0o444, 'sha256': 'd'*64}
        for path in ('/opt/uas/bin', '/usr/lib/git-core'):
            records[path] = {'kind': 'directory', 'uid': 0, 'mode': 0o755}
        class Reader:
            def __init__(self, *args): pass
            def single(self, name, **kwargs):
                if name not in records: raise OriginDenied('required archive absent')
                return records[name]
            def archive(self, name):
                parent = name.rsplit('/', 1)[0] + '/'
                return {p[len(parent):]: r for p, r in records.items() if p == name or p.startswith(name + '/')}
        selected = git_envelope(payload, image_reference='registry/native@sha256:'+'f'*64,
                                image_id='sha256:'+'1'*64, nonce='2'*32)
        with patch.object(RESOURCES, '_ImageReader', Reader):
            observed = RESOURCES.verify_engine_payload(object(), '3'*64, selected, deadline=1)
            self.assertEqual(observed['image_id'], selected['image_id'])
            records['/usr/bin/git-push']['sha256'] = '0'*64
            with self.assertRaises(OriginDenied):
                RESOURCES.verify_engine_payload(object(), '3'*64, selected, deadline=1)

            records['/usr/bin/git-push']['sha256'] = payload['artifacts']['/opt/uas/bin/git']
            del records['/opt/uas/bin/git-worker-connector']
            with self.assertRaises(OriginDenied):
                RESOURCES.verify_engine_payload(object(), '3'*64, selected, deadline=1)

    def test_abi_producer_records_all_hops_and_consumer_resolves_them(self):
        libc = '/lib/x86_64-linux-gnu/libc.so.6'
        target = '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
        observed = {LOADER: ('a'*64, '../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'),
                    target: ('a'*64, None), libc: ('b'*64, None)}
        abi = BUILD.abi_records({LOADER, libc}, observed.__getitem__)
        self.assertEqual(set(abi), set(observed))
        reader = RESOURCES._ImageReader.__new__(RESOURCES._ImageReader)
        reader.allowed = set(abi)
        def archive(name):
            digest, link = observed[name]
            record = {'kind': 'link', 'target': link} if link else {'kind': 'file', 'sha256': digest}
            return {name.rsplit('/', 1)[1]: record}
        reader.archive = archive
        self.assertEqual(reader.single(LOADER, follow=True)['sha256'], 'a'*64)
        for wrong in ('/tmp/loader', '/usr/local/lib/loader', LOADER):
            with self.assertRaises(ValueError):
                BUILD.abi_records({LOADER, libc}, {**observed, LOADER: ('a'*64, wrong)}.__getitem__)
        with self.assertRaises(ValueError): BUILD.abi_records({libc}, observed.__getitem__)

    def test_only_verified_dependency_free_extension_allows_empty_ldd_inventory(self):
        raw = bytearray(256)
        raw[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', raw, 16, 3, 62, 1)
        struct.pack_into('<Q', raw, 32, 64)
        struct.pack_into('<HH', raw, 54, 56, 2)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0, 0, 256, 256, 4096)
        struct.pack_into('<IIQQQQQQ', raw, 120, 2, 4, 192, 0, 0, 32, 32, 8)
        self.assertTrue(BUILD.dependency_free_extension(bytes(raw)))
        self.assertEqual(BUILD.dependency_paths('statically linked', dependency_free=True), set())
        struct.pack_into('<qQ', raw, 192, 1, 10)
        self.assertFalse(BUILD.dependency_free_extension(bytes(raw)))
        for output in ('', 'libx => not found', '/usr/local/lib/libx (0x1)'):
            with self.assertRaises(ValueError): BUILD.dependency_paths(output, dependency_free=True)
        for at, format, value in ((16, '<H', 2), (18, '<H', 3), (64, '<I', 3), (152, '<Q', 4096)):
            bad = bytearray(raw); struct.pack_into(format, bad, at, value)
            with self.assertRaises(ValueError): BUILD.dependency_free_extension(bytes(bad))
        struct.pack_into('<qQ', raw, 208, 1, 10)
        with self.assertRaises(ValueError): BUILD.dependency_free_extension(bytes(raw))
