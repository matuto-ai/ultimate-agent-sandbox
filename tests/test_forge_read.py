from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read import ExternalReadBroker
from uas.ledger import LedgerError, Origin

class Provider:
    host = 'github.com'
    def __init__(self): self.calls=[]; self.result={'status':'OK','completeness':'complete','data':{'body':'PRIVATE_SOURCE_BODY'}}
    def read(self, route): self.calls.append(route.document()); return self.result

class ExternalReadTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.audit=ForgeAudit(self.root/'audit.db','deployment');self.addCleanup(self.audit.close)
        self.provider=Provider();self.actors=[]
        self.origin=Origin('actor','alice','inc-1','epoch-1',('forge-read',))
        self.binding=ForgeBinding('alpha','project','owner/repo')
        self.allowed=True;self.broker=self.reopen()
    def reopen(self):
        def provider(actor):self.actors.append(actor);return self.provider
        return ExternalReadBroker(self.binding,'instance-1',self.audit,provider,self.root/'results')
    def request(self, id='read-1', argv=None, origin=None):
        return self.broker.execute({'id':id,'kind':'forge-read','argv':argv or ['issue','view','1']},
            origin=origin or self.origin,authorize=lambda:self.allowed)
    def test_body_is_output_and_private_cache_but_never_canonical_audit(self):
        first=self.request();self.assertIn('PRIVATE_SOURCE_BODY',json.dumps(first))
        self.assertEqual(first,self.request());self.assertEqual(1,len(self.provider.calls));self.assertEqual(['actor'],self.actors)
        self.assertNotIn(b'PRIVATE_SOURCE_BODY',(self.root/'audit.db').read_bytes())
        for path in self.root.glob('audit.db*'):self.assertNotIn(b'PRIVATE_SOURCE_BODY',path.read_bytes())
        self.broker=self.reopen();self.assertEqual(first,self.request());self.assertEqual(1,len(self.provider.calls))
    def test_same_forge_read_is_not_an_additional_repository_allowlist(self):
        self.request(argv=['pr','view','42','-R','other/repo'])
        self.assertEqual('other/repo',self.provider.calls[0]['repository'])
    def test_authentication_and_full_origin_retry_before_any_provider_contact(self):
        self.allowed=False
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.request()
        self.assertFalse(self.provider.calls)
        self.allowed=True;self.request()
        for origin in [replace(self.origin,actor_id='other'),replace(self.origin,authority_version='epoch-2')]:
            with self.assertRaises(LedgerError):self.request(origin=origin)
        self.assertEqual(1,len(self.provider.calls))
    def test_denied_routes_are_audited_without_provider_contact_or_raw_argv(self):
        for n,argv in enumerate([['auth','token'],['api','SECRET_ARG'],['run','view','1','--log'],['issue','view','1','-R','https://evil.test/r']]):
            self.assertEqual('unknown',self.request(str(n),argv)['completeness'])
        self.assertFalse(self.provider.calls)
        for path in self.root.glob('audit.db*'):self.assertNotIn(b'SECRET_ARG',path.read_bytes())
    def test_help_is_generated_before_provider_contact(self):
        result=self.request(argv=['--help']);self.assertEqual('HELP',result['status']);self.assertIn('pr diff',result['text']);self.assertFalse(self.provider.calls)
    def test_terminal_audit_failure_fences_and_recovery_never_recontacts(self):
        commit=self.audit._commit;calls=[]
        def fail():
            calls.append(1)
            if len(calls)==2:raise sqlite3.OperationalError('failure')
            return commit()
        with patch.object(self.audit,'_commit',side_effect=fail):
            with self.assertRaisesRegex(LedgerError,'AUDIT_UNAVAILABLE'):self.request()
        self.assertEqual(1,len(self.provider.calls))
        with self.assertRaisesRegex(LedgerError,'AUDIT_UNAVAILABLE'):self.request('new')
        self.audit.close();self.audit=ForgeAudit(self.root/'audit.db','deployment');self.addCleanup(self.audit.close);self.broker=self.reopen()
        self.assertEqual('INTERRUPTED_OBSERVATION',self.request()['status']);self.assertEqual(1,len(self.provider.calls))
        self.broker.recover(lambda metadata:True)
        self.assertEqual('INTERRUPTED_OBSERVATION',self.request()['status']);self.assertEqual(1,len(self.provider.calls))
    def test_precontact_audit_failure_makes_no_provider_selection(self):
        with patch.object(self.audit,'_commit',side_effect=sqlite3.OperationalError()):
            with self.assertRaisesRegex(LedgerError,'AUDIT_UNAVAILABLE'):self.request()
        self.assertFalse(self.provider.calls);self.assertFalse(self.actors)
    def test_late_revocation_denies_output_but_preserves_terminal(self):
        original=self.provider.read
        def read(route):self.allowed=False;return original(route)
        self.provider.read=read
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.request()
        self.allowed=True;self.assertEqual('OK',self.request()['status']);self.assertEqual(1,len(self.provider.calls))
    def test_cache_corruption_never_recontacts_or_fabricates_original(self):
        self.request();next((self.root/'results').glob('*.json')).write_text('{}')
        self.assertEqual('RESULT_UNAVAILABLE',self.request()['status']);self.assertEqual(1,len(self.provider.calls))
    def test_raw_provider_exception_cannot_escape(self):
        self.provider.read=lambda _: (_ for _ in ()).throw(ValueError('SECRET_TOKEN'))
        self.assertEqual({'status':'PROVIDER_FAILURE','completeness':'unknown'},self.request())
    def test_provider_selection_failure_terminalizes_without_contact_or_secret(self):
        self.broker.providers=lambda _: (_ for _ in ()).throw(LedgerError('CREDENTIAL_UNAVAILABLE'))
        self.assertEqual({'status':'CREDENTIAL_UNAVAILABLE','completeness':'unknown'},self.request())
        self.assertEqual([],self.audit.pending_reads('alpha'));self.assertFalse(self.provider.calls)
        record=self.audit._connection().execute('SELECT result FROM read_terminals').fetchone()
        self.assertEqual('none',json.loads(record[0])['contact'])
        self.broker.providers=lambda _: (_ for _ in ()).throw(ValueError('SECRET_TOKEN'))
        self.assertEqual({'status':'PROVIDER_FAILURE','completeness':'unknown'},self.request('other'))
        for path in self.root.glob('audit.db*'):self.assertNotIn(b'SECRET_TOKEN',path.read_bytes())
    def test_denial_has_no_attacker_attribution(self):
        self.broker.denied('WRONG_PROCESS')
        records=self.audit._connection().execute('SELECT metadata FROM read_starts').fetchall()
        self.assertEqual('unauthenticated',json.loads(records[0][0])['actor_id']);self.assertFalse(self.provider.calls)
    def test_output_capacity_is_bounded_without_extra_contact(self):
        self.provider.result={'status':'OK','completeness':'complete','data':'x'*1040000}
        self.assertEqual('OUTPUT_LIMIT',self.request()['status'])
        with patch('uas.forge_read.MAX_CACHED',1):
            self.assertEqual('READ_CAPACITY',self.request('second')['status'])
            self.assertEqual([],self.audit.pending_reads('alpha'))
        self.assertEqual(1,len(self.provider.calls))
