"""Explicit bootstrap contracts, no host tools or privileged mutations."""
from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uas import local_engine_prepare as engine
from uas.local_host_profile import HostProfileError,digest
from uas.local_host_receipt import PreparationReceipt
from tests.test_local_host_plan import profile


def observation():
    return {'version':1,'complete':True,'engine_version':'29.8.2','ipv4_forwarding':'1','units':{},'socket_parent':{'path':'/run','identity':[1,2]},'blockers':[],'tools':{},'accounts':{'passwd':[],'group':[]},'subuid':[],'subgid':[]}


def selected(root='/var/lib/uas-engine-prepare'):
    p=profile('owned');p['engine'].update(data_root='/var/lib/uas-engine',exec_root='/run/uas-engine',socket='/run/uas-engine.sock')
    return engine.plan(p,observation(),receipt_root=root,account_uid=981,account_gid=982)


class EnginePlanTests(unittest.TestCase):
    def test_exact_config_unit_and_declared_admission_profile(self):
        p=selected();a=p['artifacts'];config=a['config']
        self.assertEqual(config['hosts'],['unix:///run/uas-engine.sock'])
        self.assertFalse(config['ip-forward']);self.assertTrue(config['selinux-enabled'])
        self.assertFalse(config['features']['containerd-snapshotter']);self.assertEqual(config['group'],'root')
        self.assertIn('Restart=no',a['service']);self.assertNotIn('containerd.service',a['service'])
        expected=deepcopy(p['profile']);expected['mode']='reuse';self.assertEqual(a['admission_profile'],expected)
        engine._verify_plan(p)
    def test_foreign_accounts_ranges_and_ambiguous_host_refuse(self):
        cases=[('blockers',['ROOT_DOCKER']),('subuid',[{'user':'podman','offset':100001,'size':65536}]),
            ('subgid',[{'user':'podman','offset':99999,'size':5}])]
        for key,value in cases:
            o=observation();o[key]=value
            with self.subTest(key=key),self.assertRaises(HostProfileError):engine.plan(profile('owned'),o,receipt_root='/var/lib/prepare',account_uid=981,account_gid=982)
        for kind,row in [('passwd',{'name':'other','uid':981}),('group',{'name':'other','gid':982})]:
            o=observation();o['accounts'][kind]=[row]
            with self.assertRaises(HostProfileError):engine.plan(profile('owned'),o,receipt_root='/var/lib/prepare',account_uid=981,account_gid=982)
    def test_nonoverlapping_rootless_ranges_preserved(self):
        o=observation();o['subuid']=o['subgid']=[{'user':'podman','offset':300000,'size':65536}]
        value=engine.plan(profile('owned'),o,receipt_root='/var/lib/prepare',account_uid=981,account_gid=982)
        self.assertEqual(value['observed']['subuid'],o['subuid'])
    def test_rehashed_arbitrary_unit_or_operation_cannot_be_applied(self):
        for change in ('unit','operation'):
            p=selected()
            if change=='unit':p['artifacts']['service']+='ExecStart=/bin/false\n'
            else:p['operations'][0]['kind']='foreign-delete'
            p['plan_id']=digest({k:v for k,v in p.items() if k!='plan_id'})
            with self.assertRaisesRegex(HostProfileError,'PLAN_CHANGED'):engine._verify_plan(p)
    def test_exact_account_commands_never_autoselect_ids_or_overwrite(self):
        p=selected()
        with patch.object(engine,'run_fixed') as command,patch.object(engine,'_socket_parent_guard'):
            for kind in ('group','account','subuid','subgid','enable','start'):engine._effect(p,kind)
        args=[c.args[0] for c in command.call_args_list]
        self.assertEqual(args[0],['/usr/sbin/groupadd','--system','--gid','982',p['account']['name']])
        self.assertIn('--uid',args[1]);self.assertIn('981',args[1]);self.assertIn('SUB_UID_COUNT=0',args[1])
        self.assertEqual(args[2][1:3],['--add-subuids','100000-165535'])
        self.assertNotIn('--force',sum(args,[]));self.assertIn('--no-block',args[-1])
    def test_other_accounts_or_ranges_changed_refuse_before_effect(self):
        p=selected()
        with patch.object(engine,'_account_snapshot',return_value={'passwd':[{'name':'new','uid':33}],'group':[]}):
            with self.assertRaisesRegex(HostProfileError,'DATABASE_CHANGED'):engine._accounts_guard(p)
        with patch.object(engine,'_account_snapshot',return_value={'passwd':[],'group':[]}),patch.object(engine,'read_text',return_value='other:300000:65536'):
            with self.assertRaisesRegex(HostProfileError,'DATABASE_CHANGED'):engine._accounts_guard(p)


class EngineApplyReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700);self.plan=selected(str(self.root))
        self.done=set();self.effects=[];self.fail=None
    def effect(self,value,kind):
        self.effects.append(kind)
        if self.fail==kind:raise OSError('effect outcome unknown')
        self.done.add(kind)
    def observe(self,value,kind):
        if kind not in self.done:raise HostProfileError('ENGINE_EFFECT_UNCONFIRMED')
        return {'identity':[0,0],'observed_sha256':digest(kind)}
    def stack(self):
        stack=ExitStack()
        # Keep real append-only receipt files; only host boundaries are doubled.
        original=PreparationReceipt
        stack.enter_context(patch.object(engine,'PreparationReceipt',side_effect=lambda r,p,owner_uid:original(r,p,owner_uid=os.getuid())))
        stack.enter_context(patch.object(engine.os,'geteuid',return_value=0))
        stack.enter_context(patch('uas.local_host_apply.owned_directory'))
        stack.enter_context(patch.object(engine,'_guard'))
        stack.enter_context(patch.object(engine,'_effect',side_effect=self.effect))
        stack.enter_context(patch.object(engine,'_observe_step',side_effect=self.observe))
        stack.enter_context(patch.object(engine,'_unit_state',return_value={'FragmentPath':self.plan['artifacts']['unit_path'],'ActiveState':'active'}))
        return stack
    def test_complete_then_repeated_apply_does_not_repeat_effects(self):
        with self.stack():
            first=engine.apply(self.plan);second=engine.apply(self.plan)
        self.assertEqual(first,second);self.assertEqual(self.effects,[r['kind'] for r in self.plan['operations']])
        self.assertEqual(first['profile'],self.plan['artifacts']['admission_profile'])
    def test_unknown_account_effect_stops_then_observes_without_retry(self):
        self.fail='account'
        with self.stack():
            with self.assertRaises(OSError):engine.apply(self.plan)
            with self.assertRaisesRegex(HostProfileError,'UNCONFIRMED'):engine.apply(self.plan)
            self.done.add('account');self.fail=None
            engine.apply(self.plan)
        self.assertEqual(self.effects.count('account'),1)
    def test_unknown_start_is_not_issued_twice(self):
        self.fail='start'
        with self.stack():
            with self.assertRaises(OSError):engine.apply(self.plan)
            self.done.add('start');self.fail=None;engine.apply(self.plan)
        self.assertEqual(self.effects.count('start'),1)
    def test_confirmed_result_cannot_be_replaced_by_changed_evidence(self):
        with self.stack():
            engine.apply(self.plan)
            with patch.object(engine,'_observe_step',return_value={'identity':[1,2],'observed_sha256':'a'*64}):
                with self.assertRaisesRegex(HostProfileError,'CONFIRMED_DRIFT'):engine.apply(self.plan)
