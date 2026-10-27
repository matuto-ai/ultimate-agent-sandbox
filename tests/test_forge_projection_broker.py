"""Pure connected Hub/external Broker/audit fixtures, without kernel effects."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from test_github_reconciliation import RecoverableGitHub
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_mutations import ExternalMutationBroker
from uas.forge_projection_broker import ExternalProjectionBroker,hub_origin
from uas.github_mutations import GitHubMutationProvider
from uas.github_read import GitHubProject
from uas.ledger import LedgerError,Origin


class ProjectionBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'audit.db';self.audit=ForgeAudit(self.path,'deployment')
        self.addCleanup(lambda:self.audit.close())
        self.binding=ForgeBinding('room','project','owner/repo')
        self.fixture=RecoverableGitHub();self.fixture.issues[1]['assignees']=[{'id':41}]
        self.fixture.issues[1]['labels']=[{'name':'type:bug'},{'name':'run:paused'}]
        self.provider=GitHubMutationProvider(GitHubProject('owner/repo'),self.fixture)
        self.broker=ExternalProjectionBroker(self.binding,'instance',self.audit,'actor',41,lambda _:self.provider)
        self.origin=hub_origin('instance')
        self.intent={'room_id':'room','project_id':'project','repository':'owner/repo','run_id':'run',
            'generation':1,'issue_number':1,'issue_id':101,'github_user_id':41,
            'labels':['lifecycle:active','run:active'],'version':1,'reconcile_operation':None}

    def envelope(self,action,operation='op',observed=None,intent=None):
        value={'id':operation,'kind':'forge-projection','action':action,'intent':intent or deepcopy(self.intent)}
        if observed is not None:value['observed']=observed
        return value

    def call(self,action,operation='op',observed=None,*,intent=None,origin=None,authorize=lambda:True):
        return self.broker.execute(self.envelope(action,operation,observed,intent),
            origin=origin or self.origin,authorize=authorize)

    def test_observe_and_repair_only_owned_labels_preserve_work_and_authority(self):
        observed=self.call('observe','read')
        self.assertEqual('OK',observed['status']);self.assertEqual(['run:paused'],observed['labels'])
        result=self.call('repair','write',observed)
        self.assertEqual('OK',result['mutation']['status'])
        names={v['name'] for v in self.fixture.issues[1]['labels']}
        self.assertEqual({'type:bug','lifecycle:active','run:active'},names)
        calls=len(self.fixture.calls)
        self.assertEqual(result,self.call('repair','write',observed));self.assertEqual(calls,len(self.fixture.calls))
        self.assertEqual(self.intent['labels'],self.call('observe','after')['labels'])

    def test_participant_origin_and_target_work_label_changes_denied_before_contact(self):
        participant=Origin('actor','alice','inc','epoch',('forge-read','forge-write','forge-project'))
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.call('observe',origin=participant)
        for change in ({'repository':'other/repo'},{'room_id':'other'},{'labels':['type:bug','run:active']}):
            with self.assertRaises(LedgerError):self.call('observe',intent={**self.intent,**change})
        self.assertEqual([],self.fixture.calls)

    def test_external_assignment_remains_visible_no_mutation(self):
        self.fixture.issues[1]['assignees']=[{'id':88}]
        observed=self.call('observe')
        self.assertEqual(('CONFLICT',[88]),(observed['status'],observed['assignee_ids']))
        with self.assertRaisesRegex(LedgerError,'ASSIGNMENT_CONFLICT'):self.call('repair','write',observed)
        self.assertEqual([],self.fixture.effects)

    def test_permissions_and_incomplete_label_pages_stay_unknown(self):
        self.fixture.before=lambda m,p,b:self.fixture.response({},403) if '/labels?' in p else None
        observed=self.call('observe')
        self.assertEqual(('UNKNOWN','unknown',[]),(observed['status'],observed['completeness'],observed['labels']))
        self.assertEqual([],self.fixture.effects)

    def test_changed_identity_or_assignment_before_write_never_mutates(self):
        observed=self.call('observe','read')
        self.fixture.issues[1]['assignees']=[{'id':88}]
        result=self.call('repair','write',observed)
        self.assertEqual('PROVIDER_FAILURE',result['mutation']['status']);self.assertEqual([],self.fixture.effects)

    def test_partial_label_sequence_records_only_confirmed_steps(self):
        observed=self.call('observe','read')
        self.fixture.before=lambda m,p,b:self.fixture.response({},403) if m=='POST' and len(self.fixture.effects)==1 else None
        receipt=self.call('repair','write',observed)
        self.assertEqual('PARTIAL_MUTATION',receipt['mutation']['status'])
        record=self.audit.get_mutation(receipt['audit_reference'])
        self.assertEqual(1,len([s for s in record['steps'] if s['fields'] is not None]))
        self.assertEqual({'type:bug','run:paused','lifecycle:active'},set(v['name'] for v in self.fixture.issues[1]['labels']))

    def test_lost_response_reconciles_before_new_repair_without_repeating_step(self):
        observed=self.call('observe','read')
        def lost(method,path,body,response):
            if method!='GET':raise TimeoutError('lost')
        self.fixture.after=lost
        unknown=self.call('repair','write',observed)
        self.assertEqual('UNKNOWN_OUTCOME',unknown['mutation']['status'])
        self.fixture.after=None
        self.audit.close();self.audit=ForgeAudit(self.path,'deployment')
        self.broker=ExternalProjectionBroker(self.binding,'instance',self.audit,'actor',41,lambda _:self.provider)
        count=len(self.fixture.effects)
        self.assertEqual(unknown,self.call('repair','write',observed));self.assertEqual(count,len(self.fixture.effects))
        intent={**self.intent,'reconcile_operation':'write'}
        fresh=self.call('observe','read-next',intent=intent)
        self.assertEqual('OK',fresh['status']);self.assertEqual(count,len(self.fixture.effects))
        record=self.audit.get_mutation(unknown['audit_reference'])
        self.assertEqual('PARTIAL',record['reconciliations'][-1]['observation']['status'])
        repaired=self.call('repair','write-next',fresh,intent=intent)
        self.assertEqual('OK',repaired['mutation']['status'])
        calls=[b for m,p,b in self.fixture.effects if m=='POST']
        self.assertEqual(1,sum(b['labels']==['lifecycle:active'] for b in calls))

    def test_authority_loss_after_confirmed_label_is_known_partial_no_stale_disclosure(self):
        observed=self.call('observe','read-before-revoke')
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
            self.call('repair','revoked-between-labels',observed,
                authorize=lambda:len(self.fixture.effects)<1)
        record=self.audit.get_mutation(self.broker._key('revoked-between-labels'))
        self.assertEqual('PARTIAL_MUTATION',record['result']['status'])
        self.assertEqual(['add-label'],record['result']['confirmed_fields'])
        self.assertEqual(1,len(record['steps']))
        self.assertIsNotNone(record['steps'][0]['fields'])
        self.assertEqual(1,len(self.fixture.effects))
        before=len(self.fixture.calls)
        self.assertEqual(record['result'],self.call('repair','revoked-between-labels',observed)['mutation'])
        self.assertEqual(before,len(self.fixture.calls))

    def test_new_generation_reconciles_old_plan_without_discarding_reference(self):
        observed=self.call('observe','before')
        def lost(method,path,body,response):
            if method!='GET':raise TimeoutError('lost')
        self.fixture.after=lost
        unknown=self.call('repair','old-generation-write',observed)
        self.fixture.after=None
        self.assertEqual('UNKNOWN_OUTCOME',unknown['mutation']['status'])
        newer={**self.intent,'generation':2,'version':2,'reconcile_operation':'old-generation-write',
            'labels':['lifecycle:attention','run:paused']}
        observation=self.call('observe','new-generation-read',intent=newer)
        self.assertEqual('OK',observation['status'])
        self.assertEqual('PARTIAL',self.audit.get_mutation(unknown['audit_reference'])['reconciliations'][-1]['observation']['status'])
        receipt=self.call('repair','new-generation-write',observation,intent=newer)
        self.assertEqual('OK',receipt['mutation']['status'])
        self.assertEqual(set(newer['labels'])|{'type:bug'},set(v['name'] for v in self.fixture.issues[1]['labels']))

    def test_outbox_send_committed_before_broker_contact_does_not_invent_mutation(self):
        value=self.call('observe',intent={**self.intent,'reconcile_operation':'never-contacted'})
        self.assertEqual('OK',value['status']);self.assertEqual([],self.fixture.effects)
        self.assertIsNone(self.audit.get_mutation(self.broker._key('never-contacted')))

    def test_audit_start_failure_makes_zero_provider_contact(self):
        with patch.object(self.audit,'_commit',side_effect=sqlite3.OperationalError('disk')):
            with self.assertRaisesRegex(LedgerError,'AUDIT_UNAVAILABLE'):self.call('observe')
        self.assertEqual([],self.fixture.calls);self.assertTrue(self.broker.failed)

    def test_drift_is_detected_again_after_success_and_foreign_labels_retained(self):
        first=self.call('observe','read');self.call('repair','write',first)
        self.fixture.issues[1]['labels']=[{'name':'type:human'},{'name':'lifecycle:review'}]
        observed=self.call('observe','drift')
        self.assertEqual(['lifecycle:review'],observed['labels'])
        self.call('repair','repair-drift',observed)
        self.assertEqual({'type:human',*self.intent['labels']},set(v['name'] for v in self.fixture.issues[1]['labels']))


if __name__=='__main__':unittest.main()
