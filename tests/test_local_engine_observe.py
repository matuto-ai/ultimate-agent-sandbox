import hashlib
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from uas import local_engine_observe as m
from uas.local_host_profile import HostProfileError, LocalHostProfile


def profile():
    return LocalHostProfile('a'*32, 'owned', '/run/uas-engine.sock', '/var/lib/uas-engine',
                            '/run/uas-engine', 'uasengine', 500000, 65536).document()


def tool(path): return {'path': path, 'identity': [1, 2], 'sha256': 'a'*64}


def command(argv, **kw):
    if argv[0].endswith('dockerd'): return 'Docker version 29.8.2, build abc123'
    if argv[0].endswith('systemctl'):
        return 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nFragmentPath=/usr/lib/systemd/system/'+argv[2]
    if argv[0].endswith('nft'): return '{"nftables":[]}'
    return '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT'


class ObserverTests(unittest.TestCase):
    def harness(self):
        stack = ExitStack(); self.addCleanup(stack.close)
        mocks = {}
        for name, value in [('_tool', None), ('run_fixed', None), ('_processes', []),
                             ('_accounts', {'passwd': [], 'group': []}), ('_footprints', []),
                             ('_entries', []), ('socket_parent',{'path':'/run','identity':[1,2]}), ('read_text', '')]:
            mocks[name] = stack.enter_context(patch.object(m, name, return_value=value))
        mocks['read_text'].side_effect=lambda p:'1' if str(p)=='/proc/sys/net/ipv4/ip_forward' else ''
        mocks['_tool'].side_effect = tool
        mocks['run_fixed'].side_effect = command
        return mocks

    def test_pristine_and_fixed_commands_only(self):
        mocks=self.harness(); out=m.inspect_exclusive(profile())
        self.assertEqual(out['blockers'], []); self.assertTrue(out['complete'])
        self.assertEqual(out['engine_version'], '29.8.2')
        self.assertTrue(all(call.kwargs['limit']==m.LIMIT for call in mocks['run_fixed'].call_args_list))

    def test_real_writable_tmp_ancestor_is_not_a_socket_namespace(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            selected=profile();selected['engine']['socket']=str(Path(root)/'engine.sock')
            with self.assertRaises(HostProfileError):m.socket_parent(LocalHostProfile.parse(selected))

    def test_forwarding_is_a_prerequisite_never_changed(self):
        mocks=self.harness();mocks['read_text'].side_effect=lambda p:'0' if str(p)=='/proc/sys/net/ipv4/ip_forward' else ''
        self.assertIn('ENGINE_IPV4_FORWARDING_PREREQUISITE',m.inspect_exclusive(profile())['blockers'])

    def test_missing_tool_not_absence(self):
        mocks=self.harness(); mocks['_tool'].side_effect=FileNotFoundError()
        out=m.inspect_exclusive(profile())
        self.assertFalse(out['complete']); self.assertIn('ENGINE_TOOL_UNAVAILABLE', out['blockers'])
        mocks['run_fixed'].assert_not_called()

    def test_wrong_version(self):
        mocks=self.harness()
        mocks['run_fixed'].side_effect=lambda argv,**kw: 'Docker version 28.0.0, build abc' if argv[0].endswith('dockerd') else command(argv,**kw)
        self.assertIn('ENGINE_VERSION',m.inspect_exclusive(profile())['blockers'])

    def test_root_daemon_foreign_and_raw_evidence_retained(self):
        mocks=self.harness(); rows=[{'pid':32,'exe':'/usr/bin/containerd'}]
        mocks['_processes'].return_value=rows
        out=m.inspect_exclusive(profile()); self.assertIn('ENGINE_FOREIGN_PROCESS',out['blockers'])
        self.assertEqual(out['root_processes'],rows)

    def test_process_access_denial_blocks(self):
        mocks=self.harness(); mocks['_processes'].side_effect=PermissionError()
        self.assertFalse(m.inspect_exclusive(profile())['complete'])

    def test_active_socket_blocks(self):
        mocks=self.harness(); mocks['run_fixed'].side_effect=lambda argv,**kw: command(argv,**kw).replace('ActiveState=inactive','ActiveState=active')
        self.assertIn('ENGINE_FOREIGN_UNIT',m.inspect_exclusive(profile())['blockers'])

    def test_disabled_service_but_enabled_socket_blocks(self):
        mocks=self.harness(); mocks['run_fixed'].side_effect=lambda argv,**kw: command(argv,**kw).replace('UnitFileState=disabled','UnitFileState=enabled') if 'docker.socket' in argv else command(argv,**kw)
        self.assertIn('ENGINE_FOREIGN_UNIT',m.inspect_exclusive(profile())['blockers'])

    def test_empty_package_config_directory_is_observed_without_mutation(self):
        import tempfile
        from pathlib import Path
        import os
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);before=list(p.iterdir())
            with patch('uas.local_host_observe.canonical_node',return_value=type('Info',(),{'st_uid':0,'st_mode':0o40700,'st_dev':p.stat().st_dev,'st_ino':p.stat().st_ino})()):
                self.assertTrue(m._empty_config_directory(p))
                self.assertEqual(list(p.iterdir()),before)
                (p/'foreign.json').write_text('keep')
                self.assertFalse(m._empty_config_directory(p))
                self.assertEqual((p/'foreign.json').read_text(),'keep')

    def test_foreign_directory_blocks_even_without_process(self):
        mocks=self.harness(); mocks['_footprints'].return_value=[{'path':'/var/lib/docker'}]
        self.assertIn('ENGINE_FOREIGN_FOOTPRINT',m.inspect_exclusive(profile())['blockers'])

    def test_firewall_ipv6_and_nft_detected(self):
        self.harness()
        def cmd(argv):
            if argv[0].endswith('nft'): return '{"nftables":[{"table":{"name":"docker-bridges"}}]}'
            return '*filter\n:DOCKER - [0:0]\nCOMMIT'
        rows=m._networks(cmd)
        self.assertEqual({r['kind'] for r in rows},{'ipv4','ipv6','nft'})
        self.assertFalse(any('DOCKER' in str(r) for r in rows))

    def test_rootless_podman_ranges_retained(self):
        mocks=self.harness(); mocks['read_text'].side_effect=lambda p:'1' if str(p)=='/proc/sys/net/ipv4/ip_forward' else 'alice:100000:65536\n'
        out=m.inspect_exclusive(profile()); self.assertEqual(out['blockers'],[])
        self.assertEqual(out['subuid'],[{'user':'alice','offset':100000,'size':65536}])

    def test_arbitrary_owned_dict_is_not_authority(self):
        self.harness(); out=m.inspect_exclusive(profile(),owned={})
        self.assertFalse(out['complete']); self.assertIn('ENGINE_OWNED_PROFILE',out['blockers'])

    def test_receipt_missing_blocks_owned_reconciliation(self):
        self.harness()
        with patch.object(m,'_receipt_states',side_effect=FileNotFoundError()):
            out=m.inspect_exclusive(profile(),owned={'profile':profile()})
        self.assertFalse(out['complete']); self.assertIn('ENGINE_OWNED_OBSERVATION',out['blockers'])

    def test_account_parser_never_returns_password_fields(self):
        with patch.object(m,'read_text',side_effect=['alice:secret:1000:1000:Private:/home/alice:/bin/bash','alice:secret:1000:alice']):
            out=m._accounts()
        self.assertNotIn('secret',str(out)); self.assertNotIn('Private',str(out))

    def test_nonroot_process_ignored(self):
        with patch.object(m,'_entries',return_value=['1']), patch.object(m,'read_text',return_value='Uid:\t1000\t1000\t1000\t1000\n'), patch.object(m.os,'readlink') as link:
            self.assertEqual(m._processes(),[]); link.assert_not_called()

    def test_process_stat_cpu_changes_not_identity_changes(self):
        stat='5 (dockerd) S ' + ' '.join(['0']*18+['123']+['0']*4)
        values={'status':'Uid:\t0\t0\t0\t0\n','comm':'dockerd\n','stat':stat,'cmdline':'/usr/bin/dockerd\0--config-file=/owned/config\0','cgroup':'0::/system.slice/owned.service'}
        with patch.object(m,'_entries',return_value=['5']), patch.object(m,'read_text',side_effect=lambda path:values[path.name]), patch.object(m.os,'readlink',side_effect=lambda path:'net:[1]' if path.name=='net' else '/usr/bin/dockerd'):
            rows=m._processes()
        self.assertEqual(rows[0]['arguments'],{'--config-file':'/owned/config'})
        self.assertEqual(rows[0]['starttime'],123)

class OwnedTests(unittest.TestCase):
    def setUp(self):
        self.p=LocalHostProfile.parse(profile())
        self.value={'profile':profile(),'plan_id':'f'*64,'account':{'name':'uasengine','uid':400,'gid':400,'home':'/nonexistent','shell':'/usr/sbin/nologin'},
                    'artifacts':{'config_path':'/receipt/daemon.json','config':{},'unit_path':'/etc/systemd/system/owned.service','unit':'owned.service','service':'exact'},
                    'observed':{'accounts':{'passwd':[],'group':[]},'subuid':[],'subgid':[]}}
        self.states={k:{'state':'not-started'} for k in ('directories','config','unit','account','group','subuid','subgid','start')}
        self.out={'accounts':{'passwd':[],'group':[]},'subuid':[],'subgid':[], 'root_processes':[],
                  'tools':{p:tool(p) for p in m.TOOLS},'docker_footprints':[], 'docker_networks':[], 'blockers':[]}
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(m,'_receipt_states',return_value=self.states))
        self.exists=self.stack.enter_context(patch.object(m.os.path,'lexists',return_value=False))
        self.owned=self.stack.enter_context(patch('uas.local_host_apply.owned_directory',return_value={'identity':[1,2]}))
        self.file=self.stack.enter_context(patch('uas.local_engine_prepare._file',return_value=[1,2]))

    def test_prestart_empty(self):
        m._reconcile_owned(self.p,self.value,self.out,lambda _:self.fail('command'))
        self.assertFalse(self.out['owned_evidence']['daemon_verified'])

    def test_partial_directory_requires_marker(self):
        self.states['directories']={'state':'unknown'}
        self.exists.side_effect=lambda path:path==self.p.data_root
        self.out['docker_footprints']=[{'path':self.p.data_root}]; self.out['blockers']=['ENGINE_FOREIGN_FOOTPRINT']
        m._reconcile_owned(self.p,self.value,self.out,lambda _:self.fail('command'))
        self.owned.assert_called_once();self.assertEqual(self.out['blockers'],[])

    def test_directory_marker_denied_not_exempted(self):
        self.states['directories']={'state':'unknown'};self.exists.side_effect=lambda path:path==self.p.data_root
        self.owned.side_effect=HostProfileError('FOREIGN')
        with self.assertRaises(HostProfileError):m._reconcile_owned(self.p,self.value,self.out,None)

    def test_account_without_intent(self):
        self.out['accounts']['passwd']=[self.value['account']]
        with self.assertRaisesRegex(HostProfileError,'ENGINE_UNOWNED_ACCOUNT'):m._reconcile_owned(self.p,self.value,self.out,None)

    def test_exact_account_with_intent(self):
        self.states['account']={'state':'unknown'};self.out['accounts']['passwd']=[self.value['account']]
        m._reconcile_owned(self.p,self.value,self.out,None)

    def test_confirmed_artifact_inode_changed(self):
        self.states['config']={'state':'confirmed','evidence':{'identity':[1,999]}}
        self.exists.side_effect=lambda p:p=='/receipt/daemon.json'
        with self.assertRaisesRegex(HostProfileError,'ENGINE_ARTIFACT_CHANGED'):m._reconcile_owned(self.p,self.value,self.out,None)

    def daemon(self):
        args=['/usr/bin/dockerd','--config-file=/receipt/daemon.json']
        self.out['root_processes']=[{'pid':100,'exe':'/usr/bin/dockerd','arguments':{'--config-file':'/receipt/daemon.json'},
                                    'arguments_sha256':hashlib.sha256('\0'.join(args).encode()).hexdigest(),
                                    'uid':[0]*4,'cgroup':'0::/system.slice/owned.service','netns':'net:[3]'}]
        self.out['root_processes'].append({'pid':101,'exe':'/usr/bin/containerd', 'arguments':{'--config':self.p.exec_root+'/containerd/containerd.toml'}, 'arguments_sha256':hashlib.sha256('\0'.join(['containerd','--config',self.p.exec_root+'/containerd/containerd.toml']).encode()).hexdigest(), 'uid':[0]*4,'cgroup':'0::/system.slice/owned.service','netns':'net:[3]'})
        self.states['start']={'state':'unknown'}
        from types import SimpleNamespace
        import stat
        self.stack.enter_context(patch.object(m.os,'readlink',return_value='net:[3]'))
        self.stack.enter_context(patch.object(m.os,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=0)))
        return lambda _: 'FragmentPath=/etc/systemd/system/owned.service\nActiveState=active\nUnitFileState=enabled\nMainPID=100\nControlGroup=/system.slice/owned.service\nDropInPaths='

    def test_owned_daemon_known_chains_only(self):
        cmd=self.daemon(); self.out['docker_networks']=[{'kind':'ipv4','exclusive_candidate':True}]
        self.out['blockers']=['ENGINE_FOREIGN_PROCESS','ENGINE_FOREIGN_NETWORK']
        m._reconcile_owned(self.p,self.value,self.out,cmd)
        self.assertEqual(self.out['blockers'],[])

    def test_other_chain_remains_blocked(self):
        cmd=self.daemon();self.out['docker_networks']=[{'kind':'netdev','name':'docker0'}]
        self.out['blockers']=['ENGINE_FOREIGN_NETWORK']
        m._reconcile_owned(self.p,self.value,self.out,cmd)
        self.assertEqual(self.out['blockers'],['ENGINE_FOREIGN_NETWORK'])

    def test_same_pid_wrong_cgroup_refuses(self):
        cmd=self.daemon();self.out['root_processes'][0]['cgroup']='0::/foreign.service'
        with self.assertRaisesRegex(HostProfileError,'ENGINE_OWNED_CGROUP'):m._reconcile_owned(self.p,self.value,self.out,cmd)

    def test_added_daemon_argument_refuses(self):
        cmd=self.daemon();self.out['root_processes'][0]['arguments_sha256']='0'*64
        with self.assertRaisesRegex(HostProfileError,'ENGINE_OWNED_DAEMON'):m._reconcile_owned(self.p,self.value,self.out,cmd)

    def test_firewall_classification(self):
        self.assertTrue(m._docker_rule('-A FORWARD -j DOCKER-USER'))
        self.assertFalse(m._docker_rule('-A unrelated -j DOCKER'))
        self.assertFalse(m._docker_rule(':MY-docker - [0:0]'))
        self.assertTrue(m._docker_nft({'chain':{'family':'ip','table':'filter','name':'DOCKER'}}))
        self.assertFalse(m._docker_nft({'chain':{'family':'ip','table':'custom','name':'DOCKER'}}))

class BoundaryTests(unittest.TestCase):
    def test_enumeration_is_bounded(self):
        from types import SimpleNamespace
        class Entries:
            def __enter__(self):return iter([SimpleNamespace(name=str(i)) for i in range(4)])
            def __exit__(self,*args):pass
        with patch.object(m.os,'scandir',return_value=Entries()):
            with self.assertRaisesRegex(HostProfileError,'ENGINE_INVENTORY_BOUND'):m._entries('/not-real',3)

    def test_receipt_read_does_not_call_append_constructor(self):
        from types import SimpleNamespace
        from uas.local_host_receipt import PreparationReceipt
        value={'receipt_root':'/receipt','plan_id':'f'*64,'operations':[{'kind':'group'},{'kind':'start'}]}
        states=[{'state':'confirmed','evidence':{}},{'state':'not-started'}]
        with patch('uas.local_engine_prepare._verify_plan'), patch('uas.local_host_apply.owned_directory'), \
             patch.object(m.os,'open',return_value=91), patch.object(m.os,'fstat',return_value=SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_mode=0o40700)), \
             patch.object(PreparationReceipt,'_read',return_value=value), patch.object(PreparationReceipt,'state',side_effect=states), \
             patch.object(PreparationReceipt,'close'), patch.object(PreparationReceipt,'_append',side_effect=AssertionError('write')):
            result=m._receipt_states(value)
        self.assertEqual(result['start']['state'],'not-started')

    def test_orphan_later_intent_refused(self):
        from types import SimpleNamespace
        from uas.local_host_receipt import PreparationReceipt
        value={'receipt_root':'/receipt','plan_id':'f'*64,'operations':[{'kind':'group'},{'kind':'start'}]}
        with patch('uas.local_engine_prepare._verify_plan'), patch('uas.local_host_apply.owned_directory'), \
             patch.object(m.os,'open',return_value=91), patch.object(m.os,'fstat',return_value=SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_mode=0o40700)), \
             patch.object(PreparationReceipt,'_read',return_value=value), patch.object(PreparationReceipt,'state',side_effect=[{'state':'unknown'},{'state':'unknown'}]), \
             patch.object(PreparationReceipt,'close'):
            with self.assertRaisesRegex(HostProfileError,'ENGINE_RECEIPT_ORDER'):m._receipt_states(value)
