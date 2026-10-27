"""Complete artifact Gate definitions through the public configuration boundary."""
from copy import deepcopy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from uas.config import ConfigError, load


class GatePolicyTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(Path('tests/fixtures/two-rooms.json').read_text())
        self.policy = self.document['rooms'][0]['policies'][0]
        self.gate = self.policy['gates'][0]

    def compile(self):
        return load(io.StringIO(json.dumps(self.document)))['rooms'][0]['policies'][0]

    def refuses(self, suffix):
        with self.assertRaises(ConfigError) as caught:
            self.compile()
        self.assertTrue(caught.exception.field.endswith(suffix), caught.exception.field)

    def test_compiles_exact_dependencies_and_conjunction_without_execution(self):
        before = deepcopy(self.document)
        with patch('subprocess.run', side_effect=AssertionError('no evaluator execution')):
            compiled = self.compile()
        gate = compiled['gates'][0]
        self.assertEqual('supervisor-one-shot-helper', gate['source'])
        self.assertEqual('exact-head-tree', gate['scope'])
        self.assertEqual('dependency-changes', gate['freshness'])
        self.assertEqual(['run-id', 'run-generation', 'policy-id', 'policy-version', 'repository', 'head-sha'], gate['dependencies'])
        self.assertEqual(['complete', 'submit-for-review'], gate['guarded_operations'])
        self.assertNotIn('verdict', gate)
        self.assertNotIn('evaluation', gate)
        self.assertEqual(before, self.document)

    def test_artifact_order_normalizes_without_changing_guards(self):
        self.gate['config']['items'].append({'path': 'LICENSE', 'type': 'file', 'nonempty': False})
        first = self.compile()
        self.gate['config']['items'].reverse()
        self.assertEqual(first, self.compile())

    def test_complete_fixture_policy_contains_no_review_or_human_merge_placeholder(self):
        compiled = self.compile()
        self.assertEqual(['fixture-artifacts'], [g['id'] for g in compiled['gates']])
        self.assertEqual({'submit-for-review': ['fixture-artifacts'], 'complete': ['fixture-artifacts']}, compiled['protected_operations'])

    def test_incomplete_definitions_refused(self):
        for missing in ('evaluator', 'config'):
            with self.subTest(missing=missing):
                original = self.gate.pop(missing)
                self.refuses('.' + missing)
                self.gate[missing] = original

    def test_unimplemented_kinds_never_degrade_to_artifact_checks(self):
        for kind in ('attestation', 'decision', 'unknown'):
            with self.subTest(kind=kind):
                self.gate['kind'] = kind
                self.refuses('.kind')

    def test_unimplemented_or_superseded_evaluators_are_refused(self):
        for evaluator in ('command', 'diff-claims', 'forge-state', 'findings-clear', 'plugin'):
            with self.subTest(evaluator=evaluator):
                self.gate['evaluator'] = evaluator
                self.refuses('.evaluator')

    def test_participant_selected_authority_scope_or_freshness_cannot_enter_config(self):
        for key, value in (('source', 'participant'), ('scope', 'run'), ('freshness', 'forever'),
                           ('max_age', 300), ('guarded_operations', []), ('optional', True)):
            with self.subTest(key=key):
                self.gate[key] = value
                self.refuses('.' + key)
                del self.gate[key]

    def test_empty_and_oversize_artifact_lists_refused(self):
        self.gate['config']['items'] = []
        self.refuses('.items')
        self.gate['config']['items'] = [{'path': str(i), 'type': 'file', 'nonempty': True} for i in range(129)]
        self.refuses('.items')

    def test_unsafe_or_nonspecific_paths_refused(self):
        for path in ('/etc/passwd', '../README', 'a/../b', './README', 'a//b', 'a/',
                     'a\\b', '*.py', 'a?b', '[ab]', '.git/config', 'a/.GIT/HEAD', '', 'x' * 1025):
            with self.subTest(path=path):
                self.gate['config']['items'][0]['path'] = path
                self.refuses('.path')

    def test_unicode_component_bytes_and_path_depth_match_artifacts_profile(self):
        for path in ('a' * 256, '\U0001f642' * 64, '/'.join(['a'] * 33)):
            with self.subTest(path=path):
                self.gate['config']['items'][0]['path'] = path
                self.refuses('.path')
        for path in ('a' * 255, '\U0001f642' * 63, '/'.join(['a'] * 32)):
            with self.subTest(path=path):
                self.gate['config']['items'][0]['path'] = path
                self.assertEqual(path, self.compile()['gates'][0]['config']['items'][0]['path'])

    def test_duplicate_paths_and_unknown_item_fields_refused(self):
        item = self.gate['config']['items'][0]
        self.gate['config']['items'].append(deepcopy(item))
        self.refuses('.path')
        self.gate['config']['items'].pop()
        item['shell'] = 'true'
        self.refuses('.shell')

    def test_artifact_types_and_nonempty_are_strict(self):
        item = self.gate['config']['items'][0]
        item['type'] = 'symlink'
        self.refuses('.type')
        item['type'] = 'directory'
        self.assertEqual('directory', self.compile()['gates'][0]['config']['items'][0]['type'])
        for flag in (1, 'true', None):
            item['nonempty'] = flag
            self.refuses('.nonempty')

    def test_unknown_guard_and_dangling_references_refused(self):
        self.policy['protected_operations']['merge'] = ['fixture-artifacts']
        self.refuses('.merge')
        del self.policy['protected_operations']['merge']
        self.policy['protected_operations']['complete'] = ['missing']
        self.refuses('.complete[0]')

    def test_duplicate_gate_and_unmapped_gate_refused(self):
        self.policy['gates'].append(deepcopy(self.gate))
        self.refuses('.id')
        self.policy['gates'][1]['id'] = 'unused'
        self.refuses('.id')

    def test_empty_guard_cannot_silently_remove_required_checks(self):
        self.policy['protected_operations']['complete'] = []
        self.refuses('.complete')
