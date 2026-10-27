"""Pure admission tests for optional trusted Actor Git authorship."""
import io
import json
from pathlib import Path
import unittest

from uas.config import ConfigError, load
from uas.git_policy import GitIdentity
from uas.git_provenance import actor_git_identity
from uas.ledger import LedgerError


class GitIdentityConfigTests(unittest.TestCase):
    def setUp(self):
        self.value = json.loads((Path(__file__).parent / 'fixtures/two-rooms.json').read_text())

    def load(self):
        return load(io.StringIO(json.dumps(self.value)))

    def test_absent_identity_retains_old_config_but_cannot_select_git_identity(self):
        actor = self.load()['deployment']['actors'][0]
        with self.assertRaises(LedgerError) as raised:
            actor_git_identity(actor)
        self.assertEqual('GIT_IDENTITY_UNAVAILABLE', raised.exception.code)

    def test_identity_is_canonical_actor_scoped_and_not_a_credential_grant(self):
        self.value['deployment']['actors'][0]['git_identity'] = {'name': 'Alice Canonical', 'email': 'alice@example.invalid'}
        result = self.load()
        identity = actor_git_identity(result['deployment']['actors'][0])
        self.assertEqual(GitIdentity('alice', 'Alice Canonical', 'alice@example.invalid'), identity)
        self.assertEqual('unavailable', result['rooms'][0]['seats'][0]['resolved']['credential_status'])
        self.assertEqual('not-evaluated', result['rooms'][0]['seats'][0]['resolved']['activation'])

    def test_invalid_identity_shape_rejects_without_silent_fallback(self):
        for identity in (None, [], 'Alice', {}, {'name': 'Alice'}, {'name': 'Alice', 'email': 'a@b', 'actor': 'bob'}):
            with self.subTest(identity=identity):
                self.value['deployment']['actors'][0]['git_identity'] = identity
                with self.assertRaises(ConfigError):
                    self.load()

    def test_canonical_fields_are_bounded_unambiguous_text(self):
        bad = ('', ' Alice', 'Alice ', 'Al\nice', 'Al\rice', 'Al\0ice', 'Al\tice', 'Al\x7fice', 'Al\x85ice', 'A<lice', 'Alice>', True, None)
        for field in ('name', 'email'):
            for value in (*bad, 'x' * (257 if field == 'name' else 255)):
                with self.subTest(field=field, value=value):
                    self.value['deployment']['actors'][0]['git_identity'] = {'name': 'Alice', 'email': 'a@b', field: value}
                    with self.assertRaises(ConfigError) as raised:
                        self.load()
                    self.assertEqual('$.deployment.actors[0].git_identity.' + field, raised.exception.field)

    def test_email_has_no_whitespace_and_unicode_name_is_preserved(self):
        for email in ('alice @example.invalid', 'alice\u00a0@example.invalid', 'unqualified',
                      'alice@@example.invalid', '@example.invalid', 'alice@', 'alice@exámple.invalid'):
            self.value['deployment']['actors'][0]['git_identity'] = {'name': 'Élodie', 'email': email}
            with self.assertRaises(ConfigError):
                self.load()
        self.value['deployment']['actors'][0]['git_identity'] = {'name': 'Élodie', 'email': 'elodie@example.invalid'}
        self.assertEqual('Élodie', actor_git_identity(self.load()['deployment']['actors'][0]).name)

    def test_name_uses_shared_byte_bound_and_rejects_unicode_control_categories(self):
        for name in ('é' * 129, 'Al\u2028ice', 'Al\u2029ice', 'Al\u200dice', 'Al\ud800ice'):
            self.value['deployment']['actors'][0]['git_identity'] = {'name': name, 'email': 'a@b'}
            with self.assertRaises(ConfigError) as raised:
                self.load()
            self.assertEqual('$.deployment.actors[0].git_identity.name', raised.exception.field)

    def test_source_dictionary_and_another_actor_do_not_share_identity(self):
        self.value['deployment']['actors'][0]['git_identity'] = {'name': 'Alice', 'email': 'a@b'}
        result = self.load()
        result['deployment']['actors'][0]['git_identity']['name'] = 'Changed'
        self.assertEqual('Alice', self.value['deployment']['actors'][0]['git_identity']['name'])
        with self.assertRaises(LedgerError):
            actor_git_identity(result['deployment']['actors'][1])


if __name__ == '__main__':
    unittest.main()
