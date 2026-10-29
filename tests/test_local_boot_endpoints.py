"""Endpoint reboot custody; only inert file/receipt/owner doubles."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

from uas import local_boot_endpoints as endpoint
from uas.local_host_profile import HostProfileError, digest

A='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
B='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
C='cccccccc-cccc-cccc-cccc-cccccccccccc'


class Receipt:
    def __init__(self):
        self.fd=20;self.plan={'plan_id':'a'*64,'operations':[{'kind':'prepare-owned-endpoints','path':'/run/owned'}]}
        self.records={'xfs-identity-policy.json':{'version':3,'plan_id':'a'*64,'uuid':A}}
        self.status='not-started';self.baseline=None
    def _guard(self):pass
    def _read(self,name):return deepcopy(self.records.get(name))
    def _append(self,name,value):
        if name in self.records:
            if self.records[name]!=value:raise HostProfileError('HOST_RECEIPT_CONFLICT')
            return False
        self.records[name]=deepcopy(value);return True
    def state(self,index):return {'state':self.status,**({'evidence':deepcopy(self.baseline)} if self.status=='confirmed' else {})}
    def intent(self,index):self.status='unknown';return True
    def confirm(self,index,evidence):self.status='confirmed';self.baseline=deepcopy(evidence)


class World:
    def __init__(self):
        self.receipt=Receipt();self.boot=A;self.directory=None;self.creates=0
        self.fail=None;self.next_identity=[10,22]
    def lstat(self,*args):
        if self.directory is None:raise FileNotFoundError('absent')
        return N()
    def mkdir(self,target,*,plan_id,operation,owner_uid,mode,create):
        assert str(target)=='/run/owned' and plan_id=='a'*64 and operation=='prepare-owned-endpoints'
        assert owner_uid==0 and mode==0o711
        if create:
            assert self.receipt._read(f'endpoints-0-boot-{self.boot}.intent.json') is not None
            assert self.directory is None
            self.creates+=1
            if self.fail=='before':raise TimeoutError('unknown mkdir')
            self.directory={'identity':self.next_identity[:],'observed_sha256':digest(self.next_identity)}
            if self.fail=='after':raise TimeoutError('lost mkdir success')
        if self.directory is None:raise FileNotFoundError('absent')
        if self.fail=='foreign':raise HostProfileError('HOST_APPLY_MARKER_CHANGED')
        return deepcopy(self.directory)
    def installed(self):
        stack=ExitStack()
        stack.enter_context(patch.object(endpoint.os,'geteuid',return_value=0))
        @contextmanager
        def scan(fd):yield iter(N(name=name) for name in self.receipt.records)
        stack.enter_context(patch.object(endpoint.os,'scandir',side_effect=scan))
        stack.enter_context(patch.object(endpoint,'boot_id',side_effect=lambda:self.boot))
        stack.enter_context(patch.object(Path,'lstat',side_effect=self.lstat))
        return stack
    def prepare(self):return endpoint.prepare_endpoints(self.receipt,0,self.mkdir)


class BootEndpointTests(unittest.TestCase):
    def test_initial_then_sameboot_repeat_never_recreates(self):
        w=World()
        with w.installed():
            result=w.prepare();self.assertEqual(w.prepare(),result)
        self.assertEqual(w.creates,1);self.assertEqual(w.receipt.baseline,result)
    def test_sameboot_unknown_missing_is_not_retried(self):
        w=World();w.fail='before'
        with w.installed():
            with self.assertRaises(TimeoutError):w.prepare()
            w.fail=None
            with self.assertRaises(FileNotFoundError):w.prepare()
        self.assertEqual(w.creates,1);self.assertEqual(w.receipt.status,'unknown')
    def test_lost_success_reconciles_owned_directory_without_second_mkdir(self):
        w=World();w.fail='after'
        with w.installed():
            with self.assertRaises(TimeoutError):w.prepare()
            w.fail=None;w.prepare()
        self.assertEqual(w.creates,1);self.assertEqual(w.receipt.status,'confirmed')
    def test_sameboot_missing_confirmed_directory_refuses(self):
        w=World()
        with w.installed():
            w.prepare();w.directory=None
            with self.assertRaises(FileNotFoundError):w.prepare()
        self.assertEqual(w.creates,1)
    def test_newboot_completed_predecessor_permits_one_new_directory(self):
        w=World()
        with w.installed():
            first=w.prepare();w.boot=B;w.directory=None;w.next_identity=[11,33]
            second=w.prepare();self.assertEqual(second,w.prepare())
        self.assertNotEqual(first,second);self.assertEqual(w.receipt.baseline,first)
        self.assertEqual(w.creates,2)
    def test_newboot_existing_owned_directory_reused_only_with_durable_evidence(self):
        w=World()
        with w.installed():
            first=w.prepare();w.boot=B
            self.assertEqual(w.prepare(),first)
        self.assertEqual(w.creates,1)
        self.assertIn(f'endpoints-0-boot-{B}.confirmed.json',w.receipt.records)
    def test_newboot_unknown_predecessor_does_not_authorize_recreation(self):
        w=World();w.fail='before'
        with w.installed():
            with self.assertRaises(TimeoutError):w.prepare()
            w.fail=None;w.boot=B
            with self.assertRaisesRegex(HostProfileError,'ENDPOINT_RECREATE_NOT_PROVEN'):w.prepare()
        self.assertEqual(w.creates,1)
    def test_newboot_unknown_generation_not_reissued_with_completed_older_generation(self):
        w=World()
        with w.installed():
            w.prepare();w.boot=B;w.directory=None;w.fail='before'
            with self.assertRaises(TimeoutError):w.prepare()
            w.fail=None
            with self.assertRaises(FileNotFoundError):w.prepare()
        self.assertEqual(w.creates,2)
    def test_foreign_existing_or_replaced_directory_never_adopted(self):
        for preexisting in (True,False):
            w=World()
            with w.installed():
                if not preexisting:w.prepare();w.boot=B
                w.directory={'identity':[80,90],'observed_sha256':'b'*64}
                with self.assertRaisesRegex(HostProfileError,'ENDPOINT_FOREIGN_DIRECTORY'):w.prepare()
            self.assertEqual(w.creates,0 if preexisting else 1)
    def test_sameboot_replaced_directory_refuses_confirmation(self):
        w=World()
        with w.installed():
            w.prepare();w.directory={'identity':[80,90],'observed_sha256':'b'*64}
            with self.assertRaisesRegex(HostProfileError,'ENDPOINT_CONFIRMED_DRIFT'):w.prepare()
        self.assertEqual(w.creates,1)
    def test_missing_or_foreign_marker_refusal_is_preserved(self):
        w=World()
        with w.installed():
            w.prepare();w.boot=B;w.fail='foreign'
            with self.assertRaisesRegex(HostProfileError,'HOST_APPLY_MARKER_CHANGED'):w.prepare()
        self.assertEqual(w.creates,1)
    def test_no_policy_or_existing_legacy_operation_not_upgraded(self):
        for kind in ('no-policy','legacy'):
            w=World()
            if kind=='no-policy':del w.receipt.records['xfs-identity-policy.json']
            else:w.receipt.status='confirmed';w.receipt.baseline={'identity':[1,2],'observed_sha256':'b'*64}
            with w.installed(),self.assertRaises(HostProfileError):w.prepare()
            self.assertEqual(w.creates,0)
    def test_foreign_generation_scope_or_orphan_confirmation_refuses(self):
        for record,value in [('intent',{'plan_id':'b'*64,'step':'foreign','operation':'b'*64}),
                             ('confirmed',{'identity':[1,2],'observed_sha256':'a'*64})]:
            w=World();w.receipt.records[f'endpoints-0-boot-{C}.{record}.json']=value
            with w.installed(),self.assertRaisesRegex(HostProfileError,'ENDPOINT_GENERATION_SCOPE'):w.prepare()
            self.assertEqual(w.creates,0)
    def test_bad_generation_name_or_receipt_count_refuses(self):
        w=World();w.receipt.records['endpoints-0-bad.json']={}
        with w.installed(),self.assertRaisesRegex(HostProfileError,'ENDPOINT_GENERATION_NAME'):w.prepare()
        w=World();w.receipt.records.update({f'unrelated-{i}':{} for i in range(4096)})
        with w.installed(),self.assertRaisesRegex(HostProfileError,'ENDPOINT_RECEIPT_BOUND'):w.prepare()
    def test_firstgeneration_baseline_recovered_after_confirmation_response_loss(self):
        w=World()
        with w.installed():
            first=w.prepare();w.receipt.status='unknown';w.receipt.baseline=None
            w.boot=B;w.directory=None;w.next_identity=[11,33]
            w.prepare()
        self.assertEqual(w.receipt.baseline,first);self.assertEqual(w.creates,2)

    def test_real_append_only_receipt_retains_initial_baseline_across_generations(self):
        import os, tempfile, uuid
        from uas.local_host_receipt import PreparationReceipt
        plan={'operations':[{'kind':'prepare-owned-endpoints','path':'/run/owned'}]}
        plan['plan_id']=digest(plan)
        with tempfile.TemporaryDirectory() as root:
            with PreparationReceipt(root,plan,owner_uid=os.getuid()) as receipt:
                receipt._append('xfs-identity-policy.json',{'version':3,'plan_id':plan['plan_id'],
                    'uuid':str(uuid.UUID(hex=plan['plan_id'][:32]))})
                current=[None];boot=[A];creates=[];real_lstat=Path.lstat
                def lstat(path,*args,**kwargs):
                    if str(path)=='/run/owned':
                        if current[0] is None:raise FileNotFoundError('absent')
                        return N()
                    return real_lstat(path,*args,**kwargs)
                def directory(path,**kwargs):
                    if kwargs['create']:
                        creates.append(boot[0]);current[0]={'identity':[10,len(creates)],'observed_sha256':digest(boot[0])}
                    if current[0] is None:raise FileNotFoundError('absent')
                    return deepcopy(current[0])
                with patch.object(endpoint.os,'geteuid',return_value=0),patch.object(endpoint,'boot_id',side_effect=lambda:boot[0]),patch.object(Path,'lstat',lstat):
                    first=endpoint.prepare_endpoints(receipt,0,directory)
                    baseline_raw=(Path(root)/'0.confirmed.json').read_bytes()
                    boot[0]=B;current[0]=None
                    second=endpoint.prepare_endpoints(receipt,0,directory)
                    self.assertNotEqual(first,second)
                    self.assertEqual((Path(root)/'0.confirmed.json').read_bytes(),baseline_raw)
                    self.assertEqual(receipt.state(0)['evidence'],first)
                    self.assertEqual(endpoint.prepare_endpoints(receipt,0,directory),second)
                self.assertEqual(creates,[A,B])
