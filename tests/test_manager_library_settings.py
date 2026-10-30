"""T33 settings page's actual installation host/Hub/durable owner path."""
from copy import deepcopy
import sqlite3
import tempfile
from pathlib import Path
import unittest
from manager_settings_fixture import invoke
from uas import library
from uas.library_settings import SettingsOwner
from uas.manager_library_settings import canonical
import library_support as support


class SettingsTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.n=0
    def packet(self,request,ident=None,mode='execute'):
        self.n+=1
        return dict(version=1,operation_id=ident or 'op-'+str(self.n),mode=mode,request=request)
    def observe(self):
        return invoke(self.root,self.packet(dict(version=1,action='settings-observe',deployment='installation')))['result']
    def update(self):
        value=self.observe();value['shared']['limits']['coalesce_seconds']+=1
        return self.packet(dict(version=1,action='settings-update',deployment='installation',request_id='request-'+str(self.n),
            configuration_version=value['configuration_version'],settings_id=value['settings_id'],shared=value['shared']))
    def revision(self):
        with sqlite3.connect(self.root/'settings.db') as db:return db.execute('SELECT revision FROM active').fetchone()[0]
    def test_durable_success_exact_retry_reconcile_and_changed_payload(self):
        value=self.update();result=invoke(self.root,value)
        self.assertEqual(result['result']['outcome'],'CONFIGURED');self.assertEqual(self.revision(),2)
        self.assertEqual(invoke(self.root,value),result)
        self.assertEqual(invoke(self.root,{**value,'mode':'reconcile'}),result)
        changed=deepcopy(value);changed['request']['shared']['limits']['coalesce_seconds']+=1
        self.assertEqual(invoke(self.root,changed)['reason'],'ID_CONFLICT');self.assertEqual(self.revision(),2)
        changed['operation_id']='new-operation'
        self.assertEqual(invoke(self.root,changed)['reason'],'ID_CONFLICT');self.assertEqual(self.revision(),2)
    def test_unknown_after_commit_and_before_owner_are_distinct(self):
        value=self.update();self.assertEqual(invoke(self.root,value,'lost-after')['outcome'],'UNCONFIRMED')
        self.assertEqual(self.revision(),2)
        self.assertEqual(invoke(self.root,{**value,'mode':'reconcile'})['result']['outcome'],'CONFIGURED')
        value=self.update();self.assertEqual(invoke(self.root,value,'lost-before')['outcome'],'UNCONFIRMED')
        for mode in ('execute','reconcile'):
            self.assertEqual(invoke(self.root,{**value,'mode':mode})['reason'],'SETTINGS_OUTCOME_UNKNOWN')
        self.assertEqual(self.revision(),2)
    def test_project_only_and_revoked_never_read_or_write_receipts(self):
        value=self.update();invoke(self.root,value)
        for scenario in ('project-only','revoked'):
            for packet in (value,{**value,'mode':'reconcile'},self.packet(dict(version=1,action='settings-observe',deployment='installation'))):
                self.assertEqual(invoke(self.root,packet,scenario)['outcome'],'UNCONFIRMED')
        self.assertEqual(self.revision(),2)
    def test_stale_invalid_and_no_content_or_provider_routes(self):
        value=self.update();result=invoke(self.root,value,'stale')['result']
        self.assertEqual(result['reason'],'STALE_SETTINGS');self.assertEqual(self.revision(),2)
        value=self.update();value['request']['shared']['limits']['coalesce_seconds']=0
        self.assertEqual(invoke(self.root,value)['result']['outcome'],'REJECTED');self.assertEqual(self.revision(),2)
        for action in ('inspect','adjudicate','drain','settings-provider'):
            self.assertEqual(invoke(self.root,self.packet(dict(version=1,action=action,deployment='installation')))['outcome'],'UNCONFIRMED')
        value=self.update();value['request']['shared']['model']={'profile_ref':'changed'}
        self.assertEqual(invoke(self.root,value)['result']['outcome'],'REJECTED')
    def test_reconcile_unreserved_never_writes_and_metadata_only_ledger(self):
        value=self.update();self.assertEqual(invoke(self.root,{**value,'mode':'reconcile'})['reason'],'SETTINGS_OUTCOME_UNKNOWN')
        self.assertEqual(self.revision(),1);invoke(self.root,value)
        self.assertNotIn(b'coalesce_seconds',(self.root/'hub.db').read_bytes())
    def test_committed_settings_pin_inflight_and_new_operations(self):
        value=self.update();owner=SettingsOwner(self.root/'settings.db','installation',support.settings)
        before=owner()['limits']['coalesce_seconds']
        with owner.operation():
            invoke(self.root,value)
            self.assertEqual(owner()['limits']['coalesce_seconds'],before)
        self.assertEqual(owner()['limits']['coalesce_seconds'],before+1)
    def test_midflight_service_grant_and_host_connection_revocation(self):
        from uas.manager_library_settings import LibrarySettingsContact, ManagerLibrarySettingsHub, FieldNotesLibrarySettingsHost
        from uas.ledger import RoomLedger, Origin
        from uas.manager_actions import HumanSession
        for fence in ('service','host'):
            with self.subTest(fence=fence):
                value=self.update();active={'service':True,'host':True};reads=[]
                def authority():
                    reads.append(1)
                    if len(reads)==3:active[fence]=False
                    return support.settings()
                owner=SettingsOwner(self.root/'settings.db','installation',authority)
                principal=library.LocalHuman('human','actor','grant-1',lambda _,p,a:active['service'] and p is None,lambda:True)
                session=HumanSession('installation','room','instance','human',Origin('actor','human','inc','grant',()),lambda _,a:True,lambda:active['host'])
                with RoomLedger(self.root/('mid-'+fence+'.db'),'room') as ledger:
                    hub=ManagerLibrarySettingsHub(ledger,deployment_id='installation',room_id='room',instance_id='instance',contact=LibrarySettingsContact(owner,lambda _:principal))
                    host=FieldNotesLibrarySettingsHost(hub,lambda _:session)
                    self.assertEqual(host.handle(canonical(value),object())['outcome'],'UNCONFIRMED')
                self.assertEqual(self.revision(),1)
