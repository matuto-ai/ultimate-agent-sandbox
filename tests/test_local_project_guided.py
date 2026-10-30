"""Pure guided input/schema composition; no accounts, credentials or host effects."""
from copy import deepcopy
from io import StringIO
import json
import unittest
from unittest.mock import patch, Mock
from uas.config import ConfigError, load
from uas.local_project_guided import project_intent, materialize
from uas.native_qualification import validate_runtime_pair, native_review_configuration, QualificationError
from uas.manager_host import RoomManagerExport
from uas.manager_stream import RoomStream, RoomIdentity, StreamError


class GuidedProjectTests(unittest.TestCase):
    def intent(self, **extra):
        args=dict(pi_actor='builder',claude_actor='reviewer',pi_github_id=122,reviewer_github_id=123,
                  pi_auth_ref='pi-login',claude_auth_ref='claude-login',
                  pi_git_name='Build Agent',pi_git_email='builder@example.com',
                  claude_git_name='Review Agent',claude_git_email='reviewer@example.com')
        args.update(extra)
        return project_intent('demo','https://github.com/org/project.git',**args)
    def raw(self):return materialize(self.intent(),'sha256:'+'a'*64,'/var/lib/uas')
    def test_image_independent_intent_and_raw_roundtrip(self):
        intent=self.intent(pi_model='chosen-model')
        self.assertNotIn('images',intent)
        raw=materialize(intent,'sha256:'+'b'*64,'/var/lib/uas')
        parsed=load(StringIO(json.dumps(raw)))
        seats=validate_runtime_pair(parsed,parsed['rooms'][0])
        self.assertEqual(123,native_review_configuration(parsed,seats,[456])['reviewers'][0]['github_user_id'])
        self.assertEqual('chosen-model',next(p for p in parsed['deployment']['providers'] if p['runtime']=='pi')['model'])
        self.assertNotIn('model',next(p for p in parsed['deployment']['providers'] if p['runtime']=='claude'))
        for seat in parsed['rooms'][0]['seats']:
            self.assertEqual('unavailable',seat['resolved']['credential_status'])
            self.assertEqual('not-evaluated',seat['resolved']['activation'])
        self.assertNotIn('resolved',raw['rooms'][0])
        self.assertEqual('org/project',intent['repository'])
    def test_no_fake_image_or_model_auth_credentials(self):
        with self.assertRaises(ConfigError):materialize(self.intent(),'latest','/var/lib/uas')
        self.assertEqual({'id','kind'},set(self.intent()['credentials'][0]))
        self.assertNotIn('model',self.intent()['providers'][0])
        raw=self.raw();raw['deployment']['providers'][0].pop('auth')
        parsed=load(StringIO(json.dumps(raw)))
        with self.assertRaisesRegex(QualificationError,'RUNTIME_AUTH_REFERENCE_REQUIRED'):
            validate_runtime_pair(parsed,parsed['rooms'][0])
    def test_rehashed_unknown_mutated_role_is_not_accepted(self):
        for mutate in (lambda i:i.update(secret='x'), lambda i:i['actors'][0].update(extra_authority=True),
                       lambda i:i['providers'][0].update(runtime='claude'),lambda i:i.update(profile='idle')):
            i=self.intent();mutate(i)
            with self.assertRaises(ConfigError):materialize(i,'sha256:'+'a'*64,'/var/lib/uas')
    def test_real_distinct_identity_and_refs_required(self):
        for change in ({'claude_actor':'builder'},{'reviewer_github_id':0},{'pi_github_id':123},{'pi_auth_ref':'reviewer-forge'},
                       {'pi_git_email':'not email'},{'pi_git_name':' bad'}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.intent(**change)
    def test_manager_null_requires_explicit_local_mode(self):
        raw=self.raw()
        for mode in (None,'remote','invalid'):
            changed=deepcopy(raw)
            if mode is None:changed['deployment'].pop('mode')
            else:changed['deployment']['mode']=mode
            with self.assertRaises(ConfigError):load(StringIO(json.dumps(changed)))
    def test_local_without_manager_cannot_export_or_resolve_credentials(self):
        raw=self.raw();source=Mock(spec=RoomStream)
        # Actual type check remains, use uninitialized typed stream: only identity
        # is needed before the expected no-Manager refusal.
        source=RoomStream.__new__(RoomStream)
        source.identity=RoomIdentity('demo','demo','epoch')
        resolver=Mock()
        with self.assertRaisesRegex(StreamError,'MANAGER_NOT_CONFIGURED'):
            RoomManagerExport.from_configuration(source,StringIO(json.dumps(raw)),resolver)
        resolver.assert_not_called()

    def test_remote_manager_trio_preserved_and_partial_rejected(self):
        selected=dict(manager_url='https://manager.example.com',manager_client_ref='manager-client',manager_trust_ref='manager-trust')
        intent=self.intent(**selected)
        raw=materialize(intent,'sha256:'+'a'*64,'/var/lib/uas')
        self.assertEqual('remote',raw['deployment']['mode'])
        self.assertEqual(selected['manager_url'],raw['deployment']['manager']['url'])
        self.assertEqual(8,len(raw['deployment']['credentials']))
        load(StringIO(json.dumps(raw)))
        for key in selected:
            missing=dict(selected);missing.pop(key)
            with self.subTest(key=key),self.assertRaises(ConfigError):self.intent(**missing)
        with self.assertRaises(ConfigError):self.intent(**dict(selected,manager_trust_ref='pi-login'))
