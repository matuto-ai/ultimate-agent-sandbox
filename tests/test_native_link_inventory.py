"""Bounded diagnostic inventory never authorizes unresolved runtime links."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

SPEC = importlib.util.spec_from_file_location('link_inventory_rootfs', Path(__file__).parent / 'vm/native_rootfs.py')
rootfs = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(rootfs)


class NativeLinkInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def links(self, count):
        for index in range(count):
            (self.root / ('link-%02d' % index)).symlink_to('missing-%02d' % index)

    def inventory(self, **kwargs):
        with self.assertRaises(FileNotFoundError) as caught:
            rootfs.fingerprint(self.root, **kwargs)
        prefix = 'unresolved rootfs links: '
        message = str(caught.exception)
        self.assertTrue(message.startswith(prefix))
        self.assertNotIn(str(self.root), message)
        return json.loads(message[len(prefix):])

    def test_collects_multiple_failures_without_returning_manifest(self):
        self.links(3)
        owner = Mock(return_value={'status': 'observed', 'owners': []})
        value = self.inventory(unresolved_owner=owner)
        self.assertEqual((value['count'], value['retained'], value['truncated']), (3, 3, False))
        self.assertEqual([item['link'] for item in value['links']], ['link-00', 'link-01', 'link-02'])
        for index, item in enumerate(value['links']):
            self.assertEqual(item['target'], 'missing-%02d' % index)
            self.assertEqual(item['missing'], item['target'])
        self.assertEqual(owner.call_count, 3)
        self.assertNotIn('manifest', value)

    def test_count_limit_still_counts_all_no_callbacks_after_sixteen(self):
        self.links(23); owner = Mock(return_value={'status': 'no-exact-file-row'})
        value = self.inventory(unresolved_owner=owner)
        self.assertEqual((value['count'], value['retained'], value['truncated']), (23, 16, True))
        self.assertEqual(owner.call_count, 16)
        self.assertEqual(owner.call_args.args, ('link-15',))

    def test_byte_budget_stops_owner_callbacks_and_still_fails(self):
        self.links(10); owner = Mock(return_value={'observed': 'é' * 12000})
        value = self.inventory(unresolved_owner=owner)
        self.assertEqual(value['count'], 10)
        self.assertEqual(value['retained'], 0)
        self.assertTrue(value['truncated'])
        self.assertEqual(owner.call_count, 1)
        self.assertLess(len(json.dumps(value).encode()), 65536)

    def test_owner_query_is_fixed_and_exact_file_rows_only(self):
        text = ('OWNER\tcoreutils-0:9.11-2.fc44.x86_64\n'
                'FILE\t/usr/bin/unrelated\t41471\tother\t0\n'
                'FILE\t/usr/bin/target\t41471\t../libexec/coreutils\t0\n')
        run = Mock(return_value=text)
        value = rootfs.installed_link_owner(self.root, 'usr/bin/target', run=run)
        args = run.call_args.args
        self.assertEqual(args[:5], ('rpm', '--root', str(self.root), '-qf', '/usr/bin/target'))
        self.assertEqual(args[5], '--qf'); self.assertEqual(run.call_args.kwargs, {'timeout': 10})
        self.assertEqual(run.call_count, 1)
        self.assertEqual(value['status'], 'observed')
        self.assertEqual(value['owners'], [{'owner': 'coreutils-0:9.11-2.fc44.x86_64',
            'path': '/usr/bin/target', 'mode': '41471', 'target': '../libexec/coreutils', 'flags': '0'}])
        self.assertEqual(value['header_sha256'], hashlib.sha256(text.encode()).hexdigest())

    def test_owner_query_failures_limits_and_no_exact_row_are_diagnostic_only(self):
        cases = [(Mock(side_effect=RuntimeError('secret output')), 'query-failed'),
                 (Mock(return_value='x' * (4 * 1024 * 1024 + 1)), 'metadata-too-large'),
                 (Mock(return_value='OWNER\towner\nFILE\t/other\t41471\tmissing\t0\n'), 'no-exact-file-row'),
                 (Mock(return_value='FILE\t/link-00\t41471\tmissing\t0\n'), 'ambiguous-or-excessive-owners')]
        self.links(1)
        for run, status in cases:
            with self.subTest(status=status):
                value = self.inventory(unresolved_owner=lambda key: rootfs.installed_link_owner(self.root, key, run=run))
                fact = value['links'][0]['installed_owner']
                self.assertEqual(fact['status'], status)
                self.assertNotIn('secret output', json.dumps(fact))

    def test_owner_path_traversal_rejected_before_query(self):
        run = Mock()
        for path in ('../outside', '/absolute', 'a/../outside'):
            with self.assertRaises(ValueError): rootfs.installed_link_owner(self.root, path, run=run)
        run.assert_not_called()

    def test_runtime_owner_does_not_exempt_dangling_link(self):
        (self.root / 'runtime').symlink_to('absent-runtime')
        value = self.inventory(unresolved_owner=lambda key: {'status': 'observed',
            'owners': [{'owner': 'coreutils-0:9.11-2.fc44.x86_64', 'path': '/' + key, 'target': 'absent-runtime'}]})
        self.assertEqual(value['count'], 1)
        self.assertEqual(value['links'][0]['link'], 'runtime')

    def test_escape_loop_and_special_file_are_immediate_not_inventory(self):
        for kind in ('escape', 'loop', 'special'):
            with self.subTest(kind=kind):
                path = self.root / 'a-first'
                if kind == 'escape': path.symlink_to('../outside')
                elif kind == 'loop': path.symlink_to('a-first')
                else: os.mkfifo(path)
                (self.root / 'z-later').symlink_to('missing')
                owner = Mock()
                try:
                    with self.assertRaises(ValueError): rootfs.fingerprint(self.root, unresolved_owner=owner)
                    owner.assert_not_called()
                finally:
                    path.unlink(); (self.root / 'z-later').unlink()


if __name__ == '__main__': unittest.main()
