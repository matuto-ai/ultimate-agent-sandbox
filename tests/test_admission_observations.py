"""File/mock-only admission observations, not native boundary qualification."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas import guest_fixture as guest, room_fixture as room
from uas.lifecycle import BackendUnknown, LifecycleError, OwnershipConflict
import test_docker_fixture


class AdmissionObservationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.control = Path(temporary) / 'control'; self.control.mkdir()
        endpoint = object.__new__(room.RoomEndpoint)
        endpoint.room, endpoint.kind = 'alpha', 'git'
        endpoint.parent = room.ENDPOINT_ROOT / 'alpha/git'
        endpoint.leases = (Mock(expected=(1, 2, 3, 4)),)
        self.backend = room.RoomLaunchFixtureBackend('a'*32, 'alpha',
            limits=room.RoomFixtureLimits(), endpoints=(endpoint,))
        self.backend.root = Path(temporary) / 'alpha'; self.backend.root.mkdir()
        for name in ('repository', 'workspace', 'checkouts', 'references', 'runtime'):
            (self.backend.root / name).mkdir()
        self.state = {'room_id':'alpha', 'instance_id':'b'*32,
                      'spec':self.backend.fixture_spec('sha256:'+'c'*64).document()}
        runtime = self.backend._runtime_path(self.state); runtime.mkdir()
        manifest = {'nonce':self.backend.nonce, 'room':'alpha', 'project':101,
                    'root':guest.identity(self.backend.root), 'quota':[8192,128],
                    'paths':{name:guest.identity(self.backend.root/name) for name in
                             ('repository','workspace','checkouts','references','runtime')}}
        (self.control/'alpha.json').write_text(json.dumps(manifest))
        self.stack.enter_context(patch.object(guest, 'CONTROL', self.control))
        intent = self.backend._intent_value(self.state)
        self.backend._runtime_intent(self.state).write_text(json.dumps(intent))
        self.backend._runtime_marker(self.state).write_text(json.dumps({**intent,'identity':guest.identity(runtime)}))
        helper = test_docker_fixture.DockerFixtureContractTests(); helper.backend = self.backend; helper.state = self.state
        helper.project = self.backend.root/'repository'
        self.resource = helper.admitted_object(running=True); self.resource['State']['Pid']=12345
        host = self.resource['HostConfig']
        host['SecurityOpt']=self.backend._security_options(self.state)
        host['NetworkMode']=self.backend._network_name(self.state)
        host['LogConfig']=self.backend._log_config(self.state)
        self.resource['NetworkSettings']['Networks']={host['NetworkMode']:{}}
        self.resource['Mounts'] = self.resource['Mounts'][:1] + [
            {'Type':'bind','Source':path,'Destination':path,
             'RW':self.backend._project_writable(self.state,path),'Propagation':'rprivate'}
            for path in self.state['spec']['project_paths']]
        self.resource['Mounts'].append({'Type':'bind','Source':str(endpoint.parent),
            'Destination':'/uas/git','RW':False,'Propagation':'rprivate'})
        self.resource['ProcessLabel']='system_u:system_r:container_t:'+self.backend.level
        self.resource['MountLabel']='system_u:object_r:container_file_t:'+self.backend.level
        self.volume = helper.volume_object(); self.volume['Options']=self.backend._volume_options(self.state)
        name, bridge, _ = guest.network_names(self.state)
        labels=self.backend._labels(self.state,'volume');labels[self.backend.LABEL+'.kind']='network'
        self.network={'Name':name,'Labels':labels,'Driver':'bridge','Internal':False,'EnableIPv6':False,
            'Options':{'com.docker.network.bridge.name':bridge,
                       'com.docker.network.bridge.enable_ip_masquerade':'true',
                       'com.docker.network.bridge.gateway_mode_ipv4':'nat'},
            'IPAM':{'Config':[{'Subnet':self.backend.subnet,'Gateway':self.backend.gateway}]}}
        self.firewall={'nftables':[entry['add'] for entry in guest.firewall_document(self.state,self.backend.nonce)['nftables']]}
        self.info={'SecurityOptions':['name=selinux','name=userns','name=seccomp,profile=builtin'],
                   'DockerRootDir':'/var/lib/docker/100000.100000'}
        self.enforcement='Enforcing'; self.sysfs='1'; self.nonce=self.backend.nonce
        self.events=[]; self.commands=[]; self.fail=None
        self.stack.enter_context(patch.object(guest.os,'geteuid',return_value=0))
        self.stack.enter_context(patch.object(guest,'WORKSTATION_HOST_UID',os.getuid()))
        self.stack.enter_context(patch.object(guest,'project_attributes',return_value=(101,True)))
        self.stack.enter_context(patch.object(room,'probe',side_effect=lambda:self.events.append('probe')))
        self.stack.enter_context(patch.object(room.RoomEndpoint,'require',side_effect=lambda _:self.events.append('endpoint'), autospec=True))
        # All command boundaries are intercepted; no actual Docker/ip/nft/XFS.
        self.stack.enter_context(patch.object(guest,'command',side_effect=self.command))
        self.stack.enter_context(patch.object(room,'command',side_effect=self.command))
        self.stack.enter_context(patch.object(self.backend,'_run',side_effect=self.docker))
        read_text=Path.read_text; lstat=Path.lstat
        def read(path,*args,**kwargs):
            value=str(path)
            if value=='/run/uas-vm-fixture':self.events.append('nonce');return self.nonce
            if value=='/sys/fs/selinux/enforce':self.events.append('sysfs');return self.sysfs
            if value in ('/etc/subuid','/etc/subgid'):return 'uas-remap:100000:65536\n'
            if value in ('/proc/12345/uid_map','/proc/12345/gid_map'):return '0 100000 65536\n'
            if value=='/run/uas-room-network-profile':return json.dumps({'version':1,'nonce':self.backend.nonce,**room.EGRESS_PROFILE})
            if value=='/sys/class/net/uas-egress/address':return room.EGRESS_PROFILE['mac']
            return read_text(path,*args,**kwargs)
        def node(path,*args,**kwargs):
            if str(path)=='/run/uas-room-network-profile':
                return SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=200)
            return lstat(path,*args,**kwargs)
        self.stack.enter_context(patch.object(Path,'read_text',read))
        self.stack.enter_context(patch.object(Path,'lstat',node))

    def record(self, args):
        self.commands.append(tuple(args)); self.events.append(tuple(args))
        if self.fail==len(self.commands):raise BackendUnknown('mock command unavailable')

    def command(self,*args,**kwargs):
        self.record(args)
        if args==('getenforce',):return self.enforcement
        if args[0]=='ip':
            if args[2:4]==('link','show'):return json.dumps([{'ifname':'uas-egress','address':room.EGRESS_PROFILE['mac']}])
            if args[2:4]==('-4','address'):return json.dumps([{'ifname':'uas-egress','addr_info':[{'family':'inet','local':'10.0.2.15','prefixlen':24}]}])
            if args[2:4]==('-4','route'):return json.dumps([{'dev':'uas-egress','gateway':'10.0.2.2'}])
            if args[2:4]==('-6','route'):return '[]'
        if args[0]=='xfs_quota':
            if args[3]=='state -p':return 'Accounting: ON\nEnforcement: ON'
            return '#101 0 0 '+('8192' if '-b' in args[3] else '128')
        if args[:4]==('nft','-j','list','tables'):return json.dumps({'nftables':[self.firewall['nftables'][0]]})
        if args[:4]==('nft','-j','list','table'):return json.dumps(self.firewall)
        raise AssertionError(('unexpected command',args))

    def docker(self,args,**kwargs):
        self.record(('docker',*args))
        if args[0]=='info':
            if args[-1]=='{{.DockerRootDir}}':return self.info['DockerRootDir']
            if args[-1]=='{{json .SecurityOptions}}':return json.dumps(self.info['SecurityOptions'])
            return json.dumps(self.info)
        if args[:2]==['network','ls']:return self.network['Name']+'\n'
        if args[:2]==['network','inspect']:return json.dumps([self.network])
        if args[:3]==['inspect','--type','volume']:return json.dumps([self.volume])
        if args[:3]==['inspect','--type','container']:return json.dumps([self.resource])
        raise AssertionError(('unexpected docker',args))

    def admit(self):
        return self.backend.admit(self.state)

    def test_full_admission_has_fifteen_commands_and_retains_all_guard_sites(self):
        self.assertEqual(self.resource,self.admit())
        self.assertEqual(15,len(self.commands))
        self.assertEqual(['getenforce','ip','ip','ip','ip','xfs_quota','xfs_quota','xfs_quota',
                          'docker','docker','nft','nft','docker','docker','docker'],[v[0] for v in self.commands])
        self.assertEqual(5,self.events.count('nonce'));self.assertEqual(5,self.events.count('sysfs'))
        self.assertEqual(2,self.events.count('endpoint'));self.assertEqual(1,self.events.count('probe'))
        infos=[c for c in self.commands if c[:2]==('docker','info')]
        self.assertEqual([('docker','info','--format','{"SecurityOptions":{{json .SecurityOptions}},"DockerRootDir":{{json .DockerRootDir}}}')],infos)
        self.assertFalse(any('observation' in key or 'guard' in key or 'cache' in key for key in vars(self.backend)))

    def test_each_command_failure_denies_without_later_commands(self):
        for position in range(1,16):
            with self.subTest(position=position):
                self.commands.clear();self.fail=position
                with self.assertRaises((LifecycleError, BackendUnknown, OwnershipConflict)):self.admit()
                self.assertEqual(position,len(self.commands))

    def test_projected_info_missing_wrong_types_and_security_fail_closed(self):
        original=copy.deepcopy(self.info)
        values=[None,[],{}, {'SecurityOptions':original['SecurityOptions']},
                {'DockerRootDir':original['DockerRootDir']}, {**original,'extra':1}]
        for field in original:
            for value in (None,True,0,{},[],['name=selinux'],original['DockerRootDir']):
                if value==original[field]:continue
                values.append({**original,field:value})
        values += [{**original,'SecurityOptions':[v for v in original['SecurityOptions'] if v!=missing]}
                   for missing in original['SecurityOptions']]
        values += [{**original,'SecurityOptions':original['SecurityOptions']+[1]},
                   {**original,'DockerRootDir':'/var/lib/docker'}]
        for value in values:
            with self.subTest(value=value):
                self.info=value
                with self.assertRaises((LifecycleError, BackendUnknown, OwnershipConflict)):self.admit()
        self.info=original

    def test_every_next_admission_observes_changes_without_reusing_success(self):
        mutations=[lambda:setattr(self,'enforcement','Permissive'),lambda:setattr(self,'sysfs','0'),
            lambda:setattr(self,'nonce','f'*32),lambda:self.info.update(DockerRootDir='/elsewhere'),
            lambda:self.info['SecurityOptions'].remove('name=seccomp,profile=builtin'),
            lambda:self.firewall['nftables'][0]['table'].update(comment='foreign'),
            lambda:self.firewall['nftables'][-1]['rule']['expr'].pop(),
            lambda:self.network.update(Internal=True),lambda:self.volume.update(Driver='other'),
            lambda:self.resource['HostConfig'].update(Privileged=True)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                originals=copy.deepcopy((self.info,self.firewall,self.network,self.volume,self.resource))
                self.assertEqual(self.resource,self.admit());mutation()
                with self.assertRaises((LifecycleError, BackendUnknown, OwnershipConflict)):self.admit()
                self.info,self.firewall,self.network,self.volume,self.resource=originals
                self.enforcement='Enforcing';self.sysfs='1';self.nonce=self.backend.nonce

    def test_standalone_helpers_keep_fresh_full_guard(self):
        calls=[lambda:self.backend._storage(),lambda:self.backend._quota(),
               lambda:self.backend._runtime(self.state),lambda:self.backend._project_paths(self.state),
               lambda:self.backend._preflight(self.state)]
        for call in calls:
            with self.subTest(call=call):
                self.commands.clear();call()
                self.assertEqual(1,sum(c==('getenforce',) for c in self.commands))
                self.enforcement='Permissive'
                with self.assertRaisesRegex(LifecycleError,'SELINUX_REQUIRED'):call()
                self.enforcement='Enforcing'

    def test_repeated_nonce_and_sysfs_checks_can_deny_mid_admission(self):
        original=self.backend._quota_checked
        for field,value in [('nonce','f'*32),('sysfs','0')]:
            with self.subTest(field=field):
                def changed():original();setattr(self,field,value)
                with patch.object(self.backend,'_quota_checked',side_effect=changed):
                    with self.assertRaises((LifecycleError, BackendUnknown, OwnershipConflict)):self.admit()
                self.nonce=self.backend.nonce;self.sysfs='1'

    def test_malformed_json_is_unknown_and_public_api_accepts_no_evidence(self):
        original=self.docker
        def malformed(args,**kwargs):
            if args[0]=='info':return '{invalid'
            return original(args,**kwargs)
        with patch.object(self.backend,'_run',side_effect=malformed):
            with self.assertRaises(BackendUnknown):self.admit()
        with self.assertRaises(TypeError):self.backend.admit(self.state, evidence=self.info)

    def test_all_three_storage_manifests_and_project_paths_are_rechecked(self):
        with patch.object(self.backend,'_storage_checked',wraps=self.backend._storage_checked) as storage, \
                patch.object(self.backend,'_project_paths_checked',wraps=self.backend._project_paths_checked) as paths:
            self.admit()
            self.assertEqual(3,storage.call_count);paths.assert_called_once_with(self.state)
        path=self.control/'alpha.json';manifest=json.loads(path.read_text())
        manifest['root'][1]+=1;path.write_text(json.dumps(manifest))
        with self.assertRaises(OwnershipConflict):self.admit()

    def test_root_is_rechecked_and_standalone_guest_admit_starts_fresh(self):
        with patch.object(guest.os,'geteuid',side_effect=[0,0,1]):
            with self.assertRaisesRegex(LifecycleError,'DISPOSABLE_GUEST_REQUIRED'):self.admit()
        self.commands.clear();self.events.clear()
        self.assertEqual(self.resource,guest.GuestBoundaryBackend.admit(self.backend,self.state))
        self.assertEqual(11,len(self.commands));self.assertEqual(4,self.events.count('nonce'))
        self.enforcement='Disabled'
        with self.assertRaisesRegex(LifecycleError,'SELINUX_REQUIRED'):
            guest.GuestBoundaryBackend.admit(self.backend,self.state)

    def test_missing_network_and_firewall_never_reach_daemon_or_resources(self):
        for name in ('_network','_firewall'):
            with self.subTest(name=name),patch.object(self.backend,name,return_value=None):
                self.commands.clear()
                with self.assertRaisesRegex(LifecycleError,'GUEST_NETWORK_MISSING'):self.admit()
                self.assertFalse(any(c[:2]==('docker','info') or c[:2]==('docker','inspect') for c in self.commands))
