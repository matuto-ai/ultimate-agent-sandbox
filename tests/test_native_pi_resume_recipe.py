"""Pure exact-session recipe tests; native effects must be guarded by the runner."""
from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from uas.native_pi_recipe import NativePiResume, NativeRecipeError
from uas.runtime_provider import ProviderAuthReference
import test_native_pi_recipe as recipe_fixture


class NativePiResumeRecipeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = recipe_fixture.NativePiRecipeTests()
        self.fixture.setUp()
        self.auth = ProviderAuthReference('pi', 'chosen', 'subscription', 'pi-oauth-json')
        self.file = '/runtime/room/seat-a/contexts/2/sessions/old-session.jsonl'
        self.resume = NativePiResume(self.file, 'exact-prior-session')

    def recipe(self, **changes):
        return self.fixture.recipe(provider_auth=self.auth, **changes)

    def test_resume_facts_are_immutable_and_non_authoritative(self):
        with self.assertRaises(FrozenInstanceError):
            self.resume.session_id = 'changed'
        self.assertEqual(set(self.resume.__dict__), {'session_file', 'session_id'})

    def test_only_exact_same_context_file_is_consumed(self):
        recipe = self.recipe(resume=self.resume)
        self.assertIs(recipe.resume, self.resume)
        self.assertEqual(recipe.exec_spec()['Cmd'][-3:], [recipe.auth_path, self.file, 'exact-prior-session'])
        self.assertEqual(recipe.scope, self.fixture.scope)
        self.assertEqual(recipe.checkout, self.fixture.kw['checkout'])

    def test_no_filesystem_read_occurs_during_resume_recipe_construction(self):
        with patch('os.open', side_effect=AssertionError('unexpected filesystem open')):
            self.recipe(resume=self.resume)

    def test_resume_identity_binds_file_and_session_without_changing_initial_shape(self):
        fresh = self.recipe()
        self.assertEqual(fresh.identity, self.recipe(resume=None).identity)
        self.assertNotIn('resume', fresh.identity)
        resumed = self.recipe(resume=self.resume)
        self.assertEqual(set(fresh.identity), set(resumed.identity))
        self.assertNotEqual(fresh.identity['recipe_sha256'], resumed.identity['recipe_sha256'])
        changed_id = self.recipe(resume=NativePiResume(self.file, 'another-session'))
        changed_file = self.recipe(resume=NativePiResume(self.file.replace('old-', 'other-'), 'exact-prior-session'))
        self.assertNotEqual(resumed.identity['recipe_sha256'], changed_id.identity['recipe_sha256'])
        self.assertNotEqual(resumed.identity['recipe_sha256'], changed_file.identity['recipe_sha256'])

    def test_wrong_context_nested_file_untyped_facts_and_missing_auth_fail(self):
        for resume in (NativePiResume(self.file.replace('/2/', '/1/'), 'prior'),
                       NativePiResume(self.file.replace('/old-', '/nested/old-'), 'prior'),
                       {'session_file': self.file, 'session_id': 'prior'}):
            with self.subTest(resume=resume), self.assertRaises(NativeRecipeError):
                self.recipe(resume=resume)
        with self.assertRaises(NativeRecipeError):
            self.fixture.recipe(resume=self.resume)

    def test_invalid_resume_fields_fail_without_fallback(self):
        for file in ('relative.jsonl', '/x/../session.jsonl', '/x/session', '/x/session.jsonl/'):
            with self.subTest(file=file), self.assertRaises(NativeRecipeError):
                NativePiResume(file, 'prior')
        for session_id in ('', '../other', 'session/id', 'provider:id', True, 'x' * 129):
            with self.subTest(session_id=session_id), self.assertRaises(NativeRecipeError):
                NativePiResume(self.file, session_id)
