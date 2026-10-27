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
        def check(*, interfaces=None, address=None, route=None, ipv6=None, nonce='a'*32, mode=0o600):
            def read(path):
                if path == room_profile.MARKER: return json.dumps(marker)
                if path.name == 'uas-vm-fixture': return nonce
                return room_profile.MAC
            addresses=[{'ifname':room_profile.INTERFACE,'address':room_profile.MAC,
                        'addr_info':[{'family':'inet','local':'10.0.2.15','prefixlen':24}]}]
            routes=[{'gateway':room_profile.GATEWAY,'dev':room_profile.INTERFACE}]
            run=Mock(side_effect=[json.dumps(addresses if address is None else address),
                json.dumps(routes if route is None else route),json.dumps([] if ipv6 is None else ipv6)])
            with patch.object(room_profile.os,'geteuid',return_value=0), \
                 patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|mode,
                       st_uid=0,st_nlink=1,st_size=300)),patch.object(Path,'read_text',read), \
                 patch.object(Path,'iterdir',return_value=[Path('/sys/class/net')/name for name in
                    (['lo','uas-egress'] if interfaces is None else interfaces)]):
                value=room_profile.guest_guard('a'*32,run=run)
                self.assertEqual(room_profile.PROFILE,value['profile'])
                self.assertTrue(all(call.kwargs == {'timeout':3} for call in run.call_args_list))
        check()
        for values in ({'interfaces':['lo']},{'interfaces':['lo','uas-egress','extra']},
                       {'address':[]},{'route':[]},{'ipv6':[{'dev':'uas-egress'}]},
                       {'nonce':'b'*32},{'mode':0o644}):
            with self.subTest(values=values),self.assertRaises(RuntimeError):check(**values)

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

    def test_foreign_socket_sid_negative_retains_original_lease_and_fails_uncertain_cleanup(self):
        source=ast.parse((VM/'room_service.py').read_text())
        negative=next(node for node in source.body if isinstance(node,ast.FunctionDef) and node.name=='prove_foreign_socket_sid')
        text=ast.unparse(negative)
        self.assertIn("level=ROOMS['beta'][3]",text)
        self.assertIn("run('chcon', '-t', 'container_file_t', '-l', ROOMS['alpha'][3], str(path))",text)
        self.assertIn('observer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 1024)',text)
        self.assertIn('except ExecUnavailable:',text)
        self.assertIn("'original_lease': list(original)",text)
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
                        scenario.index("= prove_foreign_socket_sid("))
        prove=next(node for node in source.body if isinstance(node,ast.FunctionDef) and node.name=='prove_service')
        self.assertIn('not alive(launch.origin.pidfd)',ast.unparse(prove))

    def test_foreign_socket_sid_restores_exact_lease_on_success_and_probe_or_close_failure(self):
        from contextlib import nullcontext
        from uas.workstation_exec import ExecUnavailable
        for fault in (None,'probe','close','helper'):
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
                foreign=Mock();foreign.accept.return_value=(Mock(),None)
                if fault=='close':foreign.close.side_effect=RuntimeError('inert close failure')
                def create(target,group,*,level):
                    self.assertEqual(165532,group);self.assertEqual(native_guest.SIBLING_LEVEL,level)
                    target.write_bytes(b'inert replacement')
                    if fault=='helper':raise RuntimeError('inert uncertain helper failure')
                    return foreign
                observer=Mock();observer.__enter__=Mock(return_value=observer);observer.__exit__=Mock(return_value=False)
                observer.getsockopt.return_value=('system_u:system_r:container_t:'+native_guest.SIBLING_LEVEL).encode()
                probe=Mock(return_value={'connected':True} if fault=='probe' else {'connected':False,'error':'EACCES'})
                with patch.object(native_guest,'labeled_listener',side_effect=create), \
                     patch.object(room_service.socket,'socket',return_value=observer), \
                     patch.object(room_service.os,'getxattr',return_value=('system_u:object_r:container_file_t:'+native_guest.LEVEL).encode()):
                    action=lambda:room_service.prove_foreign_socket_sid(SimpleNamespace(_locked=nullcontext),endpoint,probe,run=Mock())
                    if fault:
                        with self.assertRaisesRegex(RuntimeError,'cleanup failed' if fault in ('close','helper') else 'not denied'):action()
                    else:
                        result=action();self.assertTrue(result['original_lease_restored'])
                        self.assertEqual(list(original),result['original_lease'])
                if fault=='helper':
                    self.assertEqual(b'original inert file',(directory.parent/'git-sid-negative/request.sock').read_bytes())
                    self.assertEqual(b'inert replacement',path.read_bytes())
                    probe.assert_not_called()  # Ownership uncertainty does not admit anything.
                else:
                    self.assertEqual(b'original inert file',path.read_bytes())
                    self.assertEqual(original[2:],(path.stat().st_dev,path.stat().st_ino))
                    self.assertFalse((directory.parent/'git-sid-negative').exists())

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
        self.assertIn("'persistent_participant_service_restart':False",source)


if __name__=='__main__':unittest.main()
