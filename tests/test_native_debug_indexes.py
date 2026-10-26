"""Pure exact ncurses debug-index exceptions; no RPM commands are executed."""
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('debug_index_rootfs', Path(__file__).parent / 'vm/native_rootfs.py')
rootfs = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(rootfs)
INDEXES = {
    'usr/lib/.build-id/47/437b4066718b825b28e816f46c58ab30a3f7cf': 'usr/lib64/libncurses++w.so.6.6',
    'usr/lib/.build-id/f0/1d24b6f5c772ff3f9a9e452bac67d356a96a31': 'usr/lib64/libncurses++.so.6.6',
}


class NativeDebugIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'usr/lib64').mkdir(parents=True)
        self.header = 'ncurses-libs\t0:6.6-1.fc44.x86_64\n'
        for key, target in INDEXES.items():
            path = self.root / key; path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to('../../../../' + target)
            self.header += '/' + key + '\t41471\t../../../../' + target + '\t0\n'

    def evidence(self, text=None):
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            self.assertEqual(args[:4], ('rpm', '--root', str(self.root), '-q'))
            self.assertEqual(args[-1], 'ncurses-libs')
            self.assertEqual(kwargs, {'timeout': 30})
            return self.header if text is None else text
        result = rootfs.installed_ncurses_indexes(self.root, run=run)
        self.assertEqual(len(calls), 1)
        return result

    def test_exact_two_missing_indexes_are_explicit_owner_evidenced_facts(self):
        evidence = self.evidence()
        self.assertEqual(set(evidence), set(INDEXES))
        result = rootfs.fingerprint(self.root, debug_indexes=evidence)
        for item in result['manifest']['entries']:
            if item['path'] in INDEXES:
                fact = item['debug_index']
                self.assertEqual(fact['status'], 'unresolved-optional-debug-index')
                self.assertEqual(fact['owner'], 'ncurses-libs-0:6.6-1.fc44.x86_64')
                self.assertEqual(fact['header_sha256'], hashlib.sha256(self.header.encode()).hexdigest())
                self.assertEqual(fact['missing_target'], INDEXES[item['path']])
                self.assertFalse((self.root / fact['missing_target']).exists())
                self.assertNotIn('runtime_exists', fact)

    def test_without_signed_owner_evidence_dangling_indices_remain_rejected(self):
        with self.assertRaises(FileNotFoundError): rootfs.fingerprint(self.root)
        incomplete = self.evidence(); incomplete.pop(next(iter(INDEXES)))
        with self.assertRaises(FileNotFoundError): rootfs.fingerprint(self.root, debug_indexes=incomplete)

    def test_wrong_owner_arch_known_target_type_flags_duplicates_and_malformed_header(self):
        row = self.header.splitlines()[1]
        for invalid in (self.header.replace('ncurses-libs', 'other-package'),
                        self.header.replace('x86_64', 'aarch64'),
                        self.header.replace('41471', '33188'),
                        self.header.replace('\t0\n', '\t64\n'),
                        self.header.replace('libncurses++w.so.6.6', 'elsewhere'),
                        self.header + row + '\n', self.header + 'malformed\n', 'x' * 65537):
            with self.subTest(header=invalid[:100]), self.assertRaises(ValueError): self.evidence(invalid)

    def test_changed_path_malformed_id_and_arbitrary_dangling_not_allowed(self):
        evidence = self.evidence()
        for key in ('usr/lib/.build-id/47/not-hex', 'usr/lib/.build-id/00/' + '0' * 38,
                    'usr/lib64/runtime-link'):
            with self.subTest(path=key):
                link = self.root / key; link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to('/absent')
                try:
                    forged = deepcopy(evidence); forged[key] = next(iter(evidence.values()))
                    with self.assertRaises(FileNotFoundError): rootfs.fingerprint(self.root, debug_indexes=forged)
                finally: link.unlink()

    def test_unlisted_or_mutated_header_path_cannot_authorize_existing_index(self):
        first = next(iter(INDEXES))
        for replacement in ('usr/lib/.build-id/47/not-hex', 'usr/lib/.build-id/00/' + '0' * 38):
            with self.subTest(path=replacement):
                evidence = self.evidence(self.header.replace(first, replacement))
                self.assertNotIn(first, evidence)
                with self.assertRaises(FileNotFoundError):
                    rootfs.fingerprint(self.root, debug_indexes=evidence)

    def test_actual_target_mutation_escape_or_prefix_redirect_rejected(self):
        evidence = self.evidence(); key = next(iter(INDEXES)); link = self.root / key
        for target in ('../../../../usr/lib64/other.so', '../../../../../../outside'):
            link.unlink(); link.symlink_to(target)
            with self.subTest(target=target), self.assertRaises((ValueError, FileNotFoundError)):
                rootfs.fingerprint(self.root, debug_indexes=evidence)
        link.unlink(); link.symlink_to('../../../../' + INDEXES[key])
        (self.root / 'usr/lib64').rmdir(); (self.root / 'usr/lib64').symlink_to('../../outside')
        with self.assertRaises((ValueError, FileNotFoundError)):
            rootfs.fingerprint(self.root, debug_indexes=evidence)

    def test_forged_owner_hash_target_or_missing_target_evidence_rejected(self):
        evidence = self.evidence(); key = next(iter(INDEXES))
        for field, wrong in [('owner', 'other-0:6.6-1.fc44.x86_64'), ('header_sha256', 'not-a-hash'),
                             ('target', '/elsewhere'), ('missing_target', 'usr/lib64/elsewhere')]:
            invalid = deepcopy(evidence); invalid[key][field] = wrong
            with self.subTest(field=field), self.assertRaises(FileNotFoundError):
                rootfs.fingerprint(self.root, debug_indexes=invalid)

    def test_present_targets_are_ordinary_resolved_links_not_unresolved_exceptions(self):
        for target in INDEXES.values(): (self.root / target).write_bytes(b'ordinary fixture, not native ELF proof')
        result = rootfs.fingerprint(self.root, debug_indexes=self.evidence())
        for item in result['manifest']['entries']:
            if item['path'] in INDEXES:
                self.assertEqual(item['kind'], 'symlink')
                self.assertNotIn('debug_index', item)


if __name__ == '__main__': unittest.main()
