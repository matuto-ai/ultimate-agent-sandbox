"""Explicit inert checks of fixed Room profile/probe/service admission.

Mocks below are policy inputs only, never kernel/container or Broker evidence.
"""
import ast
from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import socket
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas import room_probe
from uas.forge import ForgeBinding
from uas.kernel_origin import OriginDenied

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
try:
    import room_profile
    import prepare_room_payload
    import room_service
    import native_rootfs
    import guest_workstation as native_guest
finally: sys.path.pop(0)


class RoomProfileTests(unittest.TestCase):
    def test_boot_guard_requires_exact_observed_nic_and_no_ipv6_route(self):
        from uas.room_fixture import EGRESS_PROFILE
        self.assertEqual({key:value for key,value in room_profile.marker('a'*32).items()
                          if key not in ('version','nonce')}, EGRESS_PROFILE)
        marker = room_profile.marker('a'*32)
        def check(*, interfaces=None, link=None, mac=None, address=None, route=None, ipv6=None, nonce='a'*32, mode=0o600):
            def read(path):
                if path == room_profile.MARKER: return json.dumps(marker)
                if path.name == 'uas-vm-fixture': return nonce
                return room_profile.MAC if mac is None else mac
            links=[{'ifname':room_profile.INTERFACE,'address':room_profile.MAC}]
            # Actual iproute2 IPv4-filtered shape: no link-layer address field.
            addresses=[{'ifname':room_profile.INTERFACE,
                        'addr_info':[{'family':'inet','local':'10.0.2.15','prefixlen':24}]}]
            routes=[{'gateway':room_profile.GATEWAY,'dev':room_profile.INTERFACE}]
            observations = {
                ('ip','-j','link','show','dev','uas-egress'): links if link is None else link,
                ('ip','-j','-4','address','show','dev','uas-egress'): addresses if address is None else address,
                ('ip','-j','-4','route','show','default'): routes if route is None else route,
                ('ip','-j','-6','route','show','default'): [] if ipv6 is None else ipv6,
            }
            run=Mock(side_effect=lambda *args, **kwargs: json.dumps(observations[args]))
            with patch.object(room_profile.os,'geteuid',return_value=0), \
                 patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|mode,
                       st_uid=0,st_nlink=1,st_size=300)),patch.object(Path,'read_text',read), \
                 patch.object(Path,'iterdir',return_value=[Path('/sys/class/net')/name for name in
                    (['lo','uas-egress'] if interfaces is None else interfaces)]):
                value=room_profile.guest_guard('a'*32,run=run)
                self.assertEqual(room_profile.PROFILE,value['profile'])
                self.assertEqual([
                    ('ip','-j','link','show','dev','uas-egress'),
                    ('ip','-j','-4','address','show','dev','uas-egress'),
                    ('ip','-j','-4','route','show','default'),
                    ('ip','-j','-6','route','show','default'),
                ], [call.args for call in run.call_args_list])
                self.assertTrue(all(call.kwargs == {'timeout':3} for call in run.call_args_list))
        check()
        for values in ({'interfaces':['lo']},{'interfaces':['lo','uas-egress','extra']},
                       {'link':[]},{'link':[{}]},{'link':[None]},
                       {'link':[{'ifname':'wrong','address':room_profile.MAC}]},
                       {'link':[{'ifname':'uas-egress','address':'52:54:00:62:00:02'}]},
                       {'link':[{'ifname':'uas-egress'}]},
                       {'link':[{'ifname':'uas-egress','address':room_profile.MAC}]*2},
                       {'mac':'52:54:00:62:00:02'},
                       {'address':[]},{'address':[None]},{'address':[{'ifname':'wrong'}]},
                       {'address':[{'ifname':'uas-egress','addr_info':[]}]},
                       {'address':[{'ifname':'uas-egress','addr_info':[{'family':'inet','local':'10.0.2.16','prefixlen':24}]}]},
                       {'route':[]},{'ipv6':[{'dev':'uas-egress'}]},
                       {'nonce':'b'*32},{'mode':0o644}):
            with self.subTest(values=values),self.assertRaises(RuntimeError):check(**values)

    def room_packages(self):
        return {'profile': room_profile.PROFILE, 'packages': [
            {'name': name, 'epoch': '0', 'version': '2.56.0' if name == 'git-core' else '10.2p1',
             'release': '1.fc44' if name == 'git-core' else '16.fc44',
             'arch': 'x86_64', 'signature_verified': True}
            for name in room_profile.GUEST_RPM_ROOTS]}

    def test_guest_package_family_is_complete_exact_and_signed_before_any_effect(self):
        import copy
        document = self.room_packages()
        selected = room_profile.guest_package_roots(document)
        self.assertEqual(list(room_profile.GUEST_RPM_ROOTS), list(selected))
        self.assertEqual(1, len({selected[name] for name in room_profile.OPENSSH_FAMILY}))
        for broken in ('missing_server', 'duplicate_server', 'mixed_server', 'mixed_core',
                       'unsigned', 'wrong_arch', 'malformed_version', 'wrong_profile'):
            value = copy.deepcopy(document)
            if broken == 'missing_server': value['packages'].pop()
            elif broken == 'duplicate_server': value['packages'].append(dict(value['packages'][-1]))
            elif broken == 'mixed_server': value['packages'][-1]['release'] = '7.fc44'
            elif broken == 'mixed_core': value['packages'][1]['epoch'] = '1'
            elif broken == 'unsigned': value['packages'][1]['signature_verified'] = False
            elif broken == 'wrong_arch': value['packages'][1]['arch'] = 'i686'
            elif broken == 'malformed_version': value['packages'][1]['version'] = 'bad\nversion'
            else: value['profile'] = 'native-pi-v1'
            with self.subTest(broken=broken):
                run = Mock()
                with self.assertRaises(RuntimeError): room_profile.guest_package_install(value, run=run)
                run.assert_not_called()

    def test_guest_package_transaction_keeps_ssh_disabled_and_checks_exact_installed_versions(self):
        document = self.room_packages()
        selected = room_profile.guest_package_roots(document)
        def observe(*args, **kwargs):
            if args[:2] == ('systemctl', 'show'):
                return 'ActiveState=inactive\nUnitFileState=masked\n'
            if args[:3] == ('rpm', '-q', '--queryformat'):
                epoch, version, release, arch = selected[args[-1]]
                return f'{epoch}:{version}-{release}.{arch}\n'
            return ''
        run = Mock(side_effect=observe)
        self.assertEqual(selected, room_profile.guest_package_install(document, run=run))
        calls = run.call_args_list
        self.assertEqual(('rpm','-q','openssh-server'), calls[0].args)
        self.assertEqual(('systemctl','mask','--now','sshd.service','sshd.socket'), calls[1].args)
        installs = [call for call in calls if call.args[0] == 'dnf']
        self.assertEqual(1, len(installs)); self.assertEqual({'timeout':180}, installs[0].kwargs)
        self.assertEqual(('dnf','-y','--setopt=reposdir=/run/uas-repositories','--disable-repo=*',
            '--enable-repo=uas-offline','--setopt=localpkg_gpgcheck=True',
            '--setopt=install_weak_deps=False','install',
            'git-core-0:2.56.0-1.fc44.x86_64','openssh-0:10.2p1-16.fc44.x86_64',
            'openssh-clients-0:10.2p1-16.fc44.x86_64','openssh-server-0:10.2p1-16.fc44.x86_64'), installs[0].args)
        self.assertEqual(4, len([call for call in calls if call.args[:2] == ('systemctl','show')]))
        for broken in ('server_absent','mask_failure','still_active','transaction_failure','wrong_installed','reactivated'):
            count = [0]
            def fail(*args, **kwargs):
                if broken == 'server_absent' and args == ('rpm','-q','openssh-server'): raise RuntimeError('absent')
                if broken == 'mask_failure' and args[:2] == ('systemctl','mask'): raise RuntimeError('mask')
                if args[:2] == ('systemctl','show'):
                    count[0] += 1
                    if broken == 'still_active' or (broken == 'reactivated' and count[0] == 3):
                        return 'ActiveState=active\nUnitFileState=masked\n'
                if broken == 'transaction_failure' and args[0] == 'dnf': raise RuntimeError('transaction')
                if broken == 'wrong_installed' and args[:3] == ('rpm','-q','--queryformat'): return '0:10.2p1-7.fc44.x86_64\n'
                return observe(*args, **kwargs)
            run = Mock(side_effect=fail)
            with self.subTest(broken=broken), self.assertRaises(RuntimeError):
                room_profile.guest_package_install(document, run=run)
            if broken in ('server_absent','mask_failure','still_active'):
                self.assertFalse(any(call.args[0] == 'dnf' for call in run.call_args_list))

    def test_room_resolver_validates_same_package_family_before_vm_and_keeps_rootfs_minimal(self):
        self.assertEqual(('python3','tini','glibc','libstdc++'),prepare_room_payload.ROOTFS_RPM_ROOTS)
        self.assertEqual(room_profile.GUEST_RPM_ROOTS,prepare_room_payload.GUEST_RPM_ROOTS)
        self.assertIs(room_profile.guest_package_roots,prepare_room_payload.guest_package_roots)
        source=(VM/'prepare_payload.py').read_text()
        check='native.guest_package_roots({**manifest, "profile": profile})'
        self.assertIn(check,source)
        self.assertLess(source.index(check),source.index('"createrepo_c"'))
        guest=(VM/'guest_room.py').read_text()
        self.assertIn('room_profile.guest_package_install(manifest, run=run)',guest)

    def test_distinct_rootfs_entrypoints_fail_before_common_assembly(self):
        manifest={'profile':room_profile.PROFILE,'native_runtime':{'profile':room_profile.PROFILE}}
        with patch.object(native_rootfs,'guest_guard') as old,patch.object(room_profile,'guest_guard') as new, \
             patch.object(native_rootfs,'_build_rootfs',return_value={'inert':True}) as build:
            with self.assertRaises(ValueError):native_rootfs.build_rootfs('a'*32,manifest,Path('/fixed'),run=Mock())
            old.assert_called_once();new.assert_not_called();build.assert_not_called()
            new.side_effect=RuntimeError('wrong NIC')
            with self.assertRaisesRegex(RuntimeError,'wrong NIC'):
                native_rootfs.build_room_rootfs('a'*32,manifest,Path('/fixed'),run=Mock())
            build.assert_not_called()
            new.side_effect=None
            result=native_rootfs.build_room_rootfs('a'*32,manifest,Path('/fixed'),run=Mock())
            self.assertEqual({'inert':True},result);self.assertEqual(1,build.call_count)

    def test_public_probe_is_fixed_verified_head_bounded_and_does_not_retain_body(self):
        raw,channel,context=Mock(),Mock(),Mock()
        raw.__enter__=Mock(return_value=raw);raw.__exit__=Mock(return_value=False)
        channel.__enter__=Mock(return_value=channel);channel.__exit__=Mock(return_value=False)
        context.wrap_socket.return_value=channel
        channel.recv.side_effect=[b'HTTP/1.1 200 OK\r\nServer: fixture\r\n\r\nDO_NOT_RETAIN_BODY']
        with patch.object(room_probe.socket,'socket',return_value=raw) as create, \
             patch.object(room_probe.ssl,'create_default_context',return_value=context) as verified, \
             patch.object(room_probe.time,'monotonic',return_value=10):
            result=room_probe.public_head()
        create.assert_called_once_with(socket.AF_INET,socket.SOCK_STREAM)
        verified.assert_called_once_with()
        raw.connect.assert_called_once_with(('1.1.1.1',443))
        context.wrap_socket.assert_called_once_with(raw,server_hostname='one.one.one.one')
        channel.sendall.assert_called_once_with(b'HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n')
        self.assertEqual(5,channel.settimeout.call_args.args[0])
        self.assertEqual(len(b'HTTP/1.1 200 OK\r\nServer: fixture\r\n\r\n'),result['response_header_bytes'])
        self.assertNotIn('DO_NOT_RETAIN',json.dumps(result))
        self.assertIs(result['certificate_hostname_verified'],True)

    def test_public_probe_rechecks_deadline_before_connect_and_every_receive(self):
        raw=Mock();raw.__enter__=Mock(return_value=raw);raw.__exit__=Mock(return_value=False)
        with patch.object(room_probe.socket,'socket',return_value=raw), \
             patch.object(room_probe.ssl,'create_default_context'), \
             patch.object(room_probe.time,'monotonic',side_effect=[10,16]):
            with self.assertRaisesRegex(RuntimeError,'deadline'):room_probe.public_head()
        raw.connect.assert_not_called()
        source=ast.parse((Path(__file__).parents[1]/'uas/room_probe.py').read_text())
        public=next(node for node in source.body if isinstance(node,ast.FunctionDef) and node.name=='public_head')
        loop=next(node for node in ast.walk(public) if isinstance(node,ast.While))
        self.assertIn('channel.settimeout(remaining())',ast.unparse(loop))
        self.assertIn('4096',ast.unparse(loop))
        self.assertNotIn('getaddrinfo',ast.unparse(public))

    def broker(self):
        broker=object.__new__(room_service.BrokerProcess)
        broker.binding=ForgeBinding('alpha','alpha','owner/repo');broker.instance='b'*32
        broker.pid,broker.pidfd=123,50
        broker.client=SimpleNamespace(closed=False,scope={**asdict(broker.binding),'room_instance':broker.instance},
            worker=SimpleNamespace(revoked=False,pidfd=51,identity=(2,3),credentials=(123,65531,65531)))
        return broker

    def test_broker_readiness_requires_same_live_retained_task_and_scope(self):
        from uas import kernel_origin
        with patch.object(kernel_origin,'alive',return_value=True),patch.object(kernel_origin,'_identity',return_value=(2,3)):
            self.assertTrue(self.broker().require())
            for kind in ('closed','revoked','wrong_scope','wrong_task','wrong_credentials'):
                broker=self.broker()
                if kind=='closed':broker.client.closed=True
                elif kind=='revoked':broker.client.worker.revoked=True
                elif kind=='wrong_scope':broker.client.scope['room_instance']='c'*32
                elif kind=='wrong_task':broker.client.worker.identity=(9,9)
                else:broker.client.worker.credentials=(124,65531,65531)
                with self.subTest(kind=kind),self.assertRaises(RuntimeError):broker.require()
        with patch.object(kernel_origin,'alive',return_value=False):
            with self.assertRaises(RuntimeError):self.broker().require()

    def test_broker_channel_close_failure_does_not_skip_owned_child_cleanup(self):
        broker=self.broker();broker.client=Mock();broker.client.close.side_effect=RuntimeError('close')
        with patch.object(room_service.signal,'pidfd_send_signal') as kill, \
             patch.object(room_service.os,'waitpid',return_value=(123,0)) as wait, \
             patch.object(room_service.os,'close') as close:
            with self.assertRaisesRegex(RuntimeError,'close'):broker.close()
        kill.assert_called_once_with(50,room_service.signal.SIGKILL)
        wait.assert_called_once_with(123,0);close.assert_called_once_with(50)
        self.assertIsNone(broker.pid);self.assertIsNone(broker.pidfd)

    def test_broker_authentication_options_precede_fork_and_preserve_sole_reaper(self):
        source=ast.parse((VM/'room_service.py').read_text())
        broker=next(node for node in source.body if isinstance(node,ast.ClassDef) and node.name=='BrokerProcess')
        init=next(node for node in broker.body if isinstance(node,ast.FunctionDef) and node.name=='__init__')
        text=ast.unparse(init)
        for option in ('enable(parent)', 'enable(child)'):
            self.assertLess(text.index(option),text.index('os.fork()'))
        self.assertLess(text.index('signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL'),
                        text.index('socket.socketpair('))
        self.assertNotIn('signal.signal(',text)

    def test_shared_listener_sets_exact_socket_sid_resets_and_preserves_process_label(self):
        for level in (native_guest.LEVEL,native_guest.SIBLING_LEVEL):
            events=[];listener=Mock();library=Mock()
            library.setsockcreatecon.side_effect=lambda value:events.append(('context',value)) or 0
            with patch.object(native_guest.ctypes,'CDLL',return_value=library), \
                 patch.object(Path,'read_text',return_value='system_u:system_r:unconfined_t:s0'), \
                 patch.object(native_guest.socket,'socket',side_effect=lambda *_:events.append(('socket',None)) or listener), \
                 patch.object(native_guest.os,'chown'),patch.object(native_guest.os,'chmod'), \
                 patch.object(native_guest,'run') as run:
                self.assertIs(listener,native_guest.labeled_listener(Path('/owned/request.sock'),165532,level=level))
            self.assertEqual([('context',('system_u:system_r:container_t:'+level).encode()),
                              ('socket',None),('context',None)],events)
            run.assert_called_once_with('chcon','-t','container_file_t','-l',level,'/owned/request.sock')
            listener.close.assert_not_called()
        self.assertEqual(native_guest.LEVEL,native_guest.labeled_listener.__kwdefaults__['level'])
        with patch.object(native_guest.ctypes,'CDLL') as native:
            with self.assertRaises(AssertionError):native_guest.labeled_listener(Path('/owned'),165532,level='s0')
            native.assert_not_called()

    def test_shared_listener_closes_on_reset_or_pathname_label_failure(self):
        for failure in ('reset','pathname'):
            listener=Mock();library=Mock()
            library.setsockcreatecon.side_effect=[0,-1 if failure=='reset' else 0]
            with patch.object(native_guest.ctypes,'CDLL',return_value=library), \
                 patch.object(Path,'read_text',return_value='system_u:system_r:unconfined_t:s0'), \
                 patch.object(native_guest.socket,'socket',return_value=listener), \
                 patch.object(native_guest.os,'chown'),patch.object(native_guest.os,'chmod'), \
                 patch.object(native_guest,'run',side_effect=RuntimeError('pathname label denied')):
                with self.assertRaises((OSError,RuntimeError)):
                    native_guest.labeled_listener(Path('/owned/request.sock'),165532)
            listener.close.assert_called_once()
            self.assertEqual((None,),library.setsockcreatecon.call_args_list[-1].args)

    def test_foreign_listener_admission_retains_original_lease_and_fails_uncertain_cleanup(self):
        source=ast.parse((VM/'room_service.py').read_text())
        negative=next(node for node in source.body if isinstance(node,ast.FunctionDef) and node.name=='prove_foreign_listener_admission')
        text=ast.unparse(negative)
        self.assertIn("level=ROOMS['beta'][3]",text)
        self.assertIn("run('chcon', '-t', 'container_file_t', '-l', ROOMS['alpha'][3], str(path))",text)
        self.assertIn("os.getxattr(foreign.fileno(), 'security.selinux')",text)
        self.assertNotIn('SO_PEERSEC', ast.unparse(negative))
        self.assertNotIn('foreign.accept()', text)
        self.assertIn('except ExecUnavailable:',text)
        self.assertIn("checks['original_lease'] = list(original)",text)
        self.assertIn("RoomEndpoint('alpha', 'git', (foreign,), (fresh,))",text)
        self.assertIn("str(error) == 'ROOM_FIXTURE_LISTENER_LABEL'",text)
        self.assertIn("checks['raw_probe_role'] = 'observational_only'",text)
        self.assertIn("checks['observed_connect'] = raw.get('decoded')",text)
        self.assertNotIn("checks['denied']",text)
        self.assertNotIn("EACCES",text)
        self.assertLess(text.index("checks['raw_probe'] = probe("),text.index("foreign listener raw observation incomplete"))
        cleanup=next(node.finalbody for node in ast.walk(negative)
                     if isinstance(node,ast.Try) and any(isinstance(child,ast.Assign) and
                        any(isinstance(target,ast.Name) and target.id=='cleanup_errors' for target in child.targets)
                        for child in node.finalbody))
        final=ast.unparse(cleanup)
        self.assertIn('(node.st_dev, node.st_ino) == foreign_inode',final)
        self.assertIn('(node.st_dev, node.st_ino) == original[2:]',final)
        self.assertIn('saved.rename(path)',final)
        self.assertIn('endpoint_.require()',final)
        self.assertIn('no further admission',final)
        scenario=(VM/'guest_room.py').read_text()
        self.assertLess(scenario.index("['held_bootstrap_exit_observed'] is True"),
                        scenario.index("prove_foreign_listener_admission(supervisors['alpha']"))
        self.assertLess(scenario.index("['foreign_listener_admission'] = {}"),
                        scenario.index("prove_foreign_listener_admission(supervisors['alpha']"))
        prove=next(node for node in source.body if isinstance(node,ast.FunctionDef) and node.name=='prove_service')
        self.assertIn('not alive(launch.origin.pidfd)',ast.unparse(prove))

    def test_foreign_listener_admission_restores_exact_lease_without_claiming_raw_denial(self):
        from contextlib import nullcontext
        from uas.workstation_exec import ExecUnavailable
        from uas.lifecycle import LifecycleError
        for fault in (None,'connected','other-result','close','helper','wrong-mcs','wrong-type','extra-nul','fd-read','diagnostic','timeout','nonzero','malformed','admission','other-admission-error','probe-error','capture-error','capture-cleanup','stdout-truncated','stderr-truncated'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary)/'alpha/git';directory.mkdir(parents=True)
                path=directory/'request.sock';path.write_bytes(b'original inert file')
                parent,node=directory.stat(),path.stat()
                original=(parent.st_dev,parent.st_ino,node.st_dev,node.st_ino)
                lease=SimpleNamespace(path=path,expected=original)
                def recheck():
                    now=path.stat()
                    if (now.st_dev,now.st_ino)!=original[2:]:raise ExecUnavailable('inert lease replaced')
                endpoint=SimpleNamespace(room='alpha',leases=(lease,),parent=directory,require=Mock(side_effect=recheck))
                foreign=Mock();foreign.fileno.return_value=123
                if fault=='close':foreign.close.side_effect=RuntimeError('inert close failure')
                def create(target,group,*,level):
                    self.assertEqual(165532,group);self.assertEqual(native_guest.SIBLING_LEVEL,level)
                    target.write_bytes(b'inert replacement')
                    if fault=='helper':raise RuntimeError('inert uncertain helper failure')
                    return foreign
                def label(target, attribute, **options):
                    self.assertEqual('security.selinux', attribute)
                    if target == 123:
                        self.assertEqual({}, options)
                        if fault == 'fd-read': raise OSError('inert fd label unavailable')
                        value = 'system_u:system_r:container_t:' + native_guest.SIBLING_LEVEL
                        if fault == 'wrong-mcs': value = 'system_u:system_r:container_t:' + native_guest.LEVEL
                        if fault == 'wrong-type': value = 'system_u:object_r:container_file_t:' + native_guest.SIBLING_LEVEL
                        if fault == 'extra-nul': value += '\0\0'
                        return value.encode()
                    self.assertEqual(path, target)
                    self.assertEqual({'follow_symlinks':False}, options)
                    return ('system_u:object_r:container_file_t:'+native_guest.LEVEL).encode()
                decoded={'connected':True} if fault=='connected' else {'connected':False,'error':'EACCES'}
                if fault=='other-result':decoded={'connected':False,'error':'ECONNREFUSED'}
                capture={'returncode':1 if fault=='nonzero' else 0,'timeout':fault=='timeout',
                         'cleanup_errors':['OSError'] if fault=='capture-cleanup' else [],
                         'stdout':{'output':'inert','bytes':5,'truncated':fault=='stdout-truncated'},
                         'stderr':{'output':'','bytes':0,'truncated':fault=='stderr-truncated'},
                         'decoded':None if fault=='malformed' else decoded}
                if fault=='capture-error':capture['status']='unavailable'
                probe=Mock(return_value=capture)
                if fault=='probe-error':probe.side_effect=OSError('inert probe exception')
                diagnostic=Mock(return_value={'status':'inert-read-only-diagnostic'})
                if fault=='diagnostic':diagnostic.side_effect=OSError('unavailable')
                checks={}
                with patch.object(native_guest,'labeled_listener',side_effect=create), \
                     patch.object(room_service.socket,'socket',side_effect=AssertionError('observer connection forbidden')), \
                     patch.object(room_service.os,'getxattr',side_effect=label), \
                     patch('uas.workstation_exec.EndpointLease') as fresh, \
                     patch('uas.room_fixture.RoomEndpoint',side_effect=None if fault=='admission' else LifecycleError('ROOM_FIXTURE_OTHER' if fault=='other-admission-error' else 'ROOM_FIXTURE_LISTENER_LABEL')) as admission:
                    action=lambda:room_service.prove_foreign_listener_admission(SimpleNamespace(_locked=nullcontext),endpoint,probe,run=Mock(),checks=checks,diagnostic=diagnostic)
                    if fault in ('wrong-mcs','wrong-type','extra-nul'):
                        with self.assertRaisesRegex(AssertionError,'actual SELinux label'):action()
                        probe.assert_not_called()
                    elif fault == 'fd-read':
                        with self.assertRaisesRegex(OSError,'fd label unavailable'):action()
                        probe.assert_not_called()
                    elif fault=='probe-error':
                        with self.assertRaisesRegex(OSError,'inert probe exception'):action()
                    elif fault not in (None,'diagnostic','connected','other-result'):
                        expected='inert uncertain helper failure' if fault=='helper' else ('cleanup failed' if fault=='close' else ('passed fresh canonical' if fault=='admission' else ('different admission invariant' if fault=='other-admission-error' else 'incomplete or unclean')))
                        with self.assertRaisesRegex(RuntimeError,expected):action()
                    else:
                        result=action();self.assertTrue(result['original_lease_restored'])
                        self.assertEqual(list(original),result['original_lease'])
                        self.assertEqual('system_u:system_r:container_t:'+native_guest.SIBLING_LEVEL,result['socket_object_label'])
                        self.assertEqual('held-listener-fd-security.selinux',result['socket_label_source'])
                        self.assertTrue(result['fresh_lease_foreign_listener_denied'])
                        self.assertTrue(result['replacement_lease_denied'])
                        self.assertEqual('observational_only',result['raw_probe_role'])
                        self.assertEqual(decoded,result['observed_connect'])
                        self.assertNotIn('denied',result)
                        self.assertEqual('passed',result['status'])
                        fresh.assert_called_once_with(path,owner=165533,group=165532)
                        admission.assert_called_once_with('alpha','git',(foreign,),(fresh.return_value,))
                        if fault=='diagnostic':self.assertEqual('unavailable',result['policy_diagnostic']['status'])
                if fault in ('timeout','nonzero','malformed','capture-error','capture-cleanup','stdout-truncated','stderr-truncated'):
                    self.assertEqual(capture,checks['raw_probe'])
                    self.assertEqual('failed',checks['status'])
                    self.assertTrue(checks['original_lease_restored'])
                if fault in ('admission','other-admission-error'):
                    probe.assert_not_called()
                    diagnostic.assert_not_called()
                if fault=='probe-error':
                    self.assertEqual('failed',checks['status'])
                    self.assertTrue(checks['original_lease_restored'])
                if fault=='helper':
                    self.assertEqual(b'original inert file',(directory.parent/'git-sid-negative/request.sock').read_bytes())
                    self.assertEqual(b'inert replacement',path.read_bytes())
                    probe.assert_not_called()  # Ownership uncertainty does not admit anything.
                else:
                    self.assertEqual(b'original inert file',path.read_bytes())
                    self.assertEqual(original[2:],(path.stat().st_dev,path.stat().st_ino))
                    self.assertFalse((directory.parent/'git-sid-negative').exists())

    def test_foreign_pathname_still_requires_complete_clean_actual_eacces(self):
        source=ast.parse((VM/'guest_room.py').read_text())
        gate=next(node for node in ast.walk(source) if isinstance(node,ast.Call)
                  and isinstance(node.func,ast.Name) and node.func.id=='require'
                  and len(node.args)==2 and isinstance(node.args[1],ast.Constant)
                  and node.args[1].value=='foreign Room MCS endpoint not denied')
        predicate=compile(ast.Expression(gate.args[0]),'<foreign pathname gate>','eval')
        for fault in (None,'connected','other-errno','malformed','nonzero','timeout',
                      'unavailable','cleanup','stdout-truncated','stderr-truncated'):
            with self.subTest(fault=fault):
                denied={'connected':False,'error':'EACCES'}
                if fault=='connected':denied={'connected':True}
                if fault=='other-errno':denied={'connected':False,'error':'ECONNREFUSED'}
                if fault=='malformed':denied=None
                raw={'returncode':1 if fault=='nonzero' else 0,'timeout':fault=='timeout',
                     'status':'unavailable' if fault=='unavailable' else 'observed',
                     'cleanup_errors':['OSError'] if fault=='cleanup' else [],
                     'stdout':{'truncated':fault=='stdout-truncated'},
                     'stderr':{'truncated':fault=='stderr-truncated'}}
                self.assertEqual(fault is None,eval(predicate,{'raw':raw,'denied':denied}))

    def test_service_uses_real_consumer_and_refuses_nonhelp_before_execution(self):
        source=ast.parse((VM/'room_service.py').read_text())
        prove=next(node for node in source.body if isinstance(node,ast.FunctionDef) and node.name=='prove_service')
        helper=next(node for node in source.body if isinstance(node,ast.ClassDef) and node.name=='RoomHelpOnlyCoordinator')
        method=next(node for node in helper.body if isinstance(node,ast.FunctionDef))
        self.assertIsInstance(method.body[0],ast.If)
        self.assertIn("!= 'help'",ast.unparse(method.body[0].test))
        self.assertIn("LedgerError('ROOM_FIXTURE_HELP_ONLY')",ast.unparse(method.body[0]))
        self.assertEqual('return super().request(request, authority)',ast.unparse(method.body[1]))
        text=ast.unparse(prove)
        for exact in ('GitChildAuthority((GitSeat(', 'serve_one(channel, service, authority, lifecycle_lock=supervisor._locked)',
                      'broker.require()', "{'kind': 'RELEASE_WORKLOAD'}", "same_uid_unrelated_task_refused=True"):
            self.assertIn(exact,text)
        self.assertLess(text.index('backend.admit(state)'),text.index("{'kind': 'RELEASE_WORKLOAD'}"))
        self.assertNotIn('GitSupervisor(',text)
        self.assertNotIn('type(\'Dummy',text)

    def test_actual_git_help_route_and_nonhelp_denial_never_reach_worker_or_provider(self):
        from contextlib import nullcontext
        from uas.git_policy import generated_help, GitPolicyError
        from uas.ledger import Origin, LedgerError
        service=object.__new__(room_service.RoomHelpOnlyCoordinator)
        service.failed=False;service.lifecycle_lock=nullcontext
        service.worker_factory=Mock(side_effect=AssertionError('worker forbidden'))
        service.broker=Mock(side_effect=AssertionError('provider forbidden'))
        authority=SimpleNamespace(current=Mock(return_value=True),
            origin=Origin('actor','participant','incarnation','epoch',('git-read',)))
        envelope={'kind':'git','id':'fixture-request','invoked_as':'git','argv':['--help'],'cwd':'/'}
        result=service.request(envelope,authority)
        self.assertEqual({'code':0,'status':'OK','stdout':generated_help().encode(),'stderr':b'','receipt':None},result)
        authority.current.assert_called_once()
        for argv in (['status'],['add','--','file'],['commit','-m','message'],['fetch'],['push'],['-c','alias.x=!bad','x']):
            with self.subTest(argv=argv),self.assertRaises((LedgerError,GitPolicyError)):
                service.request({**envelope,'argv':argv},authority)
        service.worker_factory.assert_not_called();self.assertEqual([],service.broker.mock_calls)
        authority.current.side_effect=OriginDenied('revoked')
        with self.assertRaises(OriginDenied):service.request(envelope,authority)

    def test_network_vm_is_deliberate_exact_review_only_and_preserves_quota_controls(self):
        workflow=(Path(__file__).parents[1]/'.github/workflows/room-launch.yml').read_text()
        self.assertEqual('  workflow_dispatch:\n  pull_request:\n    types: [labeled]',
                         workflow.split('\non:\n',1)[1].split('\npermissions:',1)[0].strip('\n'))
        for expected in ("github.event.label.name == 'qualify-room-launch'",
                         "github.event.sender.login == 'puglab-reviewer'",
                         'github.event.pull_request.head.repo.full_name == github.repository',
                         'persist-credentials: false', 'UAS_ROOM_VM_PROFILE: room-launch-ipv4-v1'):
            self.assertIn(expected,workflow)
        self.assertNotIn('pull_request_target',workflow);self.assertNotIn('secrets.',workflow)
        source=(VM/'guest_room.py').read_text()
        self.assertIn('attribute_positive_control(STORAGE)',source)
        self.assertIn('space.f_bavail * space.f_frsize > 64 * 1024 * 1024 and space.f_favail > 1000',source)
        self.assertIn('persistent_participant_service_restart=False',source)




    def test_public_probe_fragment_eof_size_status_and_operation_fault_matrix(self):
        # Synthetic HTTP fragments and faults exercise the fixed protocol only;
        # none of these observations claim actual public TLS reachability.
        cases = {
            'fragmented':([b'HTTP/1.1 20',b'0 OK\r\nX: y\r\n',b'\r\n'],None),
            'eof':([b'HTTP/1.1 200 OK\r\n',b''],'incomplete'),
            'oversized':([b'x'*512]*8,'budget'),
            'invalid':([b'HTTP/2 200 OK\r\n\r\n'],'invalid'),
            'status':([b'HTTP/1.1 500 Error\r\n\r\n'],'successfully'),
        }
        for name,(fragments,message) in cases.items():
            with self.subTest(name=name):
                raw,channel,context=Mock(),Mock(),Mock()
                for stream in (raw,channel):
                    stream.__enter__=Mock(return_value=stream);stream.__exit__=Mock(return_value=False)
                context.wrap_socket.return_value=channel;channel.recv.side_effect=fragments
                with patch.object(room_probe.socket,'socket',return_value=raw), \
                        patch.object(room_probe.ssl,'create_default_context',return_value=context), \
                        patch.object(room_probe.time,'monotonic',return_value=10):
                    if message:
                        with self.assertRaisesRegex(RuntimeError,message):room_probe.public_head()
                    else: self.assertTrue(room_probe.public_head()['certificate_hostname_verified'])
                raw.__exit__.assert_called_once();channel.__exit__.assert_called_once()
        for operation in ('connect','tls','send','recv'):
            with self.subTest(operation=operation):
                raw,channel,context=Mock(),Mock(),Mock()
                for stream in (raw,channel):
                    stream.__enter__=Mock(return_value=stream);stream.__exit__=Mock(return_value=False)
                context.wrap_socket.return_value=channel
                primary=OSError('synthetic '+operation)
                {'connect':raw.connect,'tls':context.wrap_socket,'send':channel.sendall,'recv':channel.recv}[operation].side_effect=primary
                with patch.object(room_probe.socket,'socket',return_value=raw), \
                        patch.object(room_probe.ssl,'create_default_context',return_value=context), \
                        patch.object(room_probe.time,'monotonic',return_value=10):
                    with self.assertRaises(OSError) as caught:room_probe.public_head()
                self.assertIs(primary,caught.exception);raw.__exit__.assert_called_once()
                if operation in ('send','recv'):channel.__exit__.assert_called_once()

    def test_public_probe_complete_final_header_after_deadline_is_rejected(self):
        raw,channel,context=Mock(),Mock(),Mock();now=[0.0]
        for stream in (raw,channel):
            stream.__enter__=Mock(return_value=stream);stream.__exit__=Mock(return_value=False)
        context.wrap_socket.return_value=channel
        def receive(_size):
            now[0]=5.01
            return b'HTTP/1.1 200 OK\r\n\r\n'
        channel.recv.side_effect=receive
        with patch.object(room_probe.socket,'socket',return_value=raw), \
                patch.object(room_probe.ssl,'create_default_context',return_value=context), \
                patch.object(room_probe.time,'monotonic',side_effect=lambda:now[0]):
            with self.assertRaisesRegex(RuntimeError,'deadline'):room_probe.public_head()
        raw.__exit__.assert_called_once();channel.__exit__.assert_called_once()


    def test_fixed_ready_probe_calls_real_launcher_only_after_exact_owned_release(self):
        import uas.git_launcher as launcher
        for fault in (None,'bad-release','extra-release','eof','no-ready','late-select','late-read','short-marker'):
            with self.subTest(fault=fault):
                calls=[];now=[0.0]
                def write(fd,data):
                    calls.append('marker');self.assertEqual((2,room_probe.DENIED_HELP_READY),(fd,data))
                    return 0 if fault=='short-marker' else len(data)
                def select(readers,writers,errors,timeout):
                    calls.append('wait');self.assertEqual([0],readers);self.assertEqual(5,timeout)
                    if fault=='late-select':now[0]=5
                    return ([] if fault=='no-ready' else [0]),[],[]
                def read(fd,limit):
                    calls.append('release');self.assertEqual((0,2),(fd,limit))
                    if fault=='late-read':now[0]=5
                    return {'bad-release':b'X','extra-release':b'GG','eof':b''}.get(fault,b'G')
                def git(args,*,invoked_as):
                    calls.append('git');self.assertEqual(['--help'],args);self.assertEqual('git',invoked_as);return 128
                with patch.object(room_probe.os,'write',side_effect=write), \
                        patch.object(room_probe.os,'read',side_effect=read), \
                        patch.object(room_probe.select,'select',side_effect=select), \
                        patch.object(room_probe.time,'monotonic',side_effect=lambda:now[0]), \
                        patch.object(launcher,'main',side_effect=git) as launch:
                    if fault:
                        with self.assertRaises(RuntimeError):room_probe.denied_help_ready()
                        launch.assert_not_called()
                    else:
                        self.assertEqual({'code':128},room_probe.denied_help_ready())
                        self.assertEqual(['marker','wait','release','git'],calls)


if __name__=='__main__':unittest.main()
