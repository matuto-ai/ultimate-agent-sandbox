"""Explicit pure launch-policy contracts, not kernel/container qualification."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from uas import room_fixture as room
from uas.docker_fixture import DockerFixtureBackend
from uas.lifecycle import LifecycleError
EGRESS = room.RoomLaunchFixtureBackend._egress


class RoomFixtureTests(unittest.TestCase):
    def setUp(self):
        self.egress_patch = patch.object(room.RoomLaunchFixtureBackend, '_egress')
        self.egress = self.egress_patch.start()
        self.addCleanup(self.egress_patch.stop)
        # Inert exact-class stand-ins: the mandatory observation methods are
        # mocked only in these pure tests. Hosted integration uses real objects.
        self.endpoint = object.__new__(room.RoomEndpoint)
        self.endpoint.room, self.endpoint.kind = 'alpha', 'git'
        self.endpoint.parent = room.ENDPOINT_ROOT / 'alpha/git'
        self.endpoint.leases = (Mock(expected=(1, 2, 3, 4)),)
        self.backend = room.RoomLaunchFixtureBackend('a' * 32, 'alpha',
            limits=room.RoomFixtureLimits(memory_bytes=128 * 1024**2, pids=64,
                nano_cpus=750_000_000, disk_bytes=16 * 1024**2, log_bytes=2 * 1024**2),
            endpoints=(self.endpoint,))
        self.state = {'room_id': 'alpha', 'instance_id': 'b' * 32,
                      'spec': self.backend.fixture_spec('sha256:' + 'c' * 64).document()}

    def test_limits_are_bounded_typed_immutable_and_part_of_profile(self):
        from dataclasses import FrozenInstanceError
        with self.assertRaises(FrozenInstanceError): self.backend.limits.pids = 128
        for values in ({'pids': True}, {'pids': 0}, {'memory_bytes': 0}, {'nano_cpus': 0},
                       {'disk_bytes': 8 * 1024**2 + 1}, {'log_bytes': 16 * 1024**2}, {'inodes': 0}):
            with self.subTest(values=values), self.assertRaises(LifecycleError):
                room.RoomFixtureLimits(**values)
        another = room.RoomLaunchFixtureBackend('a' * 32, 'alpha',
            limits=room.RoomFixtureLimits(), endpoints=(self.endpoint,))
        self.assertNotEqual(self.backend.profile_digest, another.profile_digest)
        self.assertEqual({'Memory':128*1024**2,'MemorySwap':128*1024**2,
            'NanoCpus':750_000_000,'PidsLimit':64},self.backend._resource_limits(self.state))
        self.assertEqual((16384,128),self.backend._quota_limits())
        self.assertEqual('2097152',self.backend._log_config(self.state)['Config']['max-size'])

    def test_profile_and_endpoint_changes_cannot_reuse_old_room_admission(self):
        for key in ('config_digest','profile_digest'):
            state=copy.deepcopy(self.state);state['spec'][key]='sha256:'+'f'*64
            with self.subTest(key=key), self.assertRaisesRegex(LifecycleError,'PROFILE_DRIFT'), \
                    patch.object(room,'guard') as guard:
                self.backend.admit(state)
            guard.assert_not_called()
        with patch.object(room,'guard'),patch.object(room,'probe'), \
                patch.object(room.RoomEndpoint,'require',side_effect=RuntimeError('endpoint replaced')), \
                patch.object(room.GuestBoundaryBackend,'admit') as admit:
            with self.assertRaisesRegex(RuntimeError,'endpoint replaced'):self.backend.admit(self.state)
            admit.assert_not_called()

    def test_guest_kernel_endpoint_and_existing_backend_are_ordered_before_start(self):
        events=[]
        self.egress.side_effect=lambda:events.append('egress')
        with patch.object(room,'guard',side_effect=lambda *_:events.append('guest')), \
                patch.object(room,'probe',side_effect=lambda:events.append('kernel')), \
                patch.object(room.RoomEndpoint,'require',side_effect=lambda:events.append('endpoint')), \
                patch.object(room.GuestBoundaryBackend,'admit',side_effect=lambda *_:events.append('existing')):
            self.backend.admit(self.state)
        self.assertEqual(['guest','egress','kernel','endpoint','existing'],events)
        with patch.object(room,'guard'),patch.object(room,'probe',side_effect=RuntimeError('unsupported kernel')), \
                patch.object(room.RoomEndpoint,'require') as endpoint,patch.object(room.GuestBoundaryBackend,'create') as create:
            with self.assertRaisesRegex(RuntimeError,'unsupported kernel'):self.backend.create(self.state,'container')
            endpoint.assert_not_called();create.assert_not_called()

    def test_only_nonempty_same_room_unique_owned_endpoint_set_is_accepted(self):
        for endpoints in ((),(self.endpoint,self.endpoint),(object(),)):
            with self.subTest(endpoints=endpoints),self.assertRaises(LifecycleError):
                room.RoomLaunchFixtureBackend('a'*32,'alpha',limits=room.RoomFixtureLimits(),endpoints=endpoints)
        self.endpoint.room='beta'
        with self.assertRaises(LifecycleError):
            room.RoomLaunchFixtureBackend('a'*32,'alpha',limits=room.RoomFixtureLimits(),endpoints=(self.endpoint,))

    def test_fixed_endpoint_readonly_mount_and_limits_reach_actual_create_argv(self):
        with patch.object(room.RoomEndpoint,'require'),patch.object(self.backend,'inspect',return_value=None), \
                patch.object(self.backend,'_project_paths'),patch.object(self.backend,'_run') as run:
            DockerFixtureBackend.create(self.backend,self.state,'container')
        args=run.call_args.args[0]
        self.assertIn('type=bind,source=/run/uas-room-endpoints/alpha/git,target=/uas/git,readonly',args)
        self.assertEqual('134217728',args[args.index('--memory')+1])
        self.assertEqual('0.750000000',args[args.index('--cpus')+1])
        self.assertEqual('64',args[args.index('--pids-limit')+1])
        self.assertIn('max-size=2097152',args)
        self.assertNotIn('--privileged',args)
        self.assertNotIn('host',args)
        self.assertNotIn('label=disable',args)

    def test_endpoint_mount_drift_is_rejected_by_existing_inspect_gate(self):
        from test_docker_fixture import DockerFixtureContractTests
        helper=DockerFixtureContractTests();helper.setUp()
        self.addCleanup(helper.doCleanups)
        base=helper.backend
        selected=(('/uas/git','/trusted/narrow'),)
        original=helper.admitted_object()
        original['Mounts'].append({'Type':'bind','Source':'/trusted/narrow','Destination':'/uas/git',
                                  'RW':False,'Propagation':'rprivate'})
        with patch.object(base,'_endpoint_mounts',return_value=selected), \
                patch.object(base,'_run',side_effect=helper.observed_run(original)):
            self.assertEqual(original,base.admit(helper.state))
        for change in ({'RW':True},{'Source':'/run/docker.sock'},{'Propagation':'rshared'},
                       {'Type':'volume'},{'Destination':'/other'}):
            value=copy.deepcopy(original);value['Mounts'][-1].update(change)
            with self.subTest(change=change),patch.object(base,'_endpoint_mounts',return_value=selected), \
                    patch.object(base,'_run',side_effect=helper.observed_run(value)) as run:
                with self.assertRaises(LifecycleError):base.start(helper.state)
                self.assertTrue(all(call.args[0][0] in ('info','inspect') for call in run.call_args_list))

    def test_endpoint_lease_labels_parents_contents_and_listeners_fail_closed(self):
        from types import SimpleNamespace
        from contextlib import ExitStack
        import socket
        import stat
        endpoint=object.__new__(room.RoomEndpoint)
        endpoint.room,endpoint.kind='alpha','git'
        endpoint.parent=room.ENDPOINT_ROOT/'alpha/git'
        lease=object.__new__(room.EndpointLease)
        lease.path=endpoint.parent/'request.sock';lease.owner=room.SUPERVISOR_UID
        lease.group=room.WORKSTATION_HOST_UID;lease.expected=(1,2,3,4)
        listener=Mock(family=socket.AF_UNIX)
        listener.fileno.return_value=123
        listener.getsockname.return_value=str(lease.path)
        listener.getsockopt.side_effect=lambda level,kind: socket.SOCK_SEQPACKET if kind==socket.SO_TYPE else 1
        endpoint.listeners=(listener,);endpoint.leases=(lease,)
        def check(*,label=None,socket_label=b'system_u:system_r:container_t:s0:c101,c102',extra=False,mode=None,owner=0):
            def node(path):
                selected=0o755 if path==room.ENDPOINT_ROOT else 0o711
                return SimpleNamespace(st_mode=stat.S_IFDIR|(selected if mode is None else mode),st_uid=owner,st_gid=0)
            with ExitStack() as stack:
                stack.enter_context(patch.object(Path,'lstat',node))
                stack.enter_context(patch.object(Path,'iterdir',return_value=[lease.path]+([endpoint.parent/'host-secret'] if extra else [])))
                stack.enter_context(patch.object(room.EndpointLease,'require'))
                def xattr(target, attribute, **options):
                    self.assertEqual('security.selinux',attribute)
                    if type(target) is int:
                        self.assertEqual(123,target);self.assertEqual({},options)
                        if isinstance(socket_label,Exception):raise socket_label
                        return socket_label
                    self.assertIn(target,(endpoint.parent,lease.path))
                    self.assertEqual({'follow_symlinks':False},options)
                    return label if label is not None else b'system_u:object_r:container_file_t:s0:c101,c102'
                stack.enter_context(patch.object(room.os,'getxattr',side_effect=xattr))
                enable=stack.enter_context(patch.object(room,'enable'))
                endpoint.require()
                self.assertEqual([unittest.mock.call(listener)],enable.call_args_list)
        check()
        check(socket_label=b'system_u:system_r:container_t:s0:c101,c102\0')
        for values in ({'label':b'system_u:object_r:container_file_t:s0:c103,c104'},
                       {'label':b'system_u:object_r:container_file_t:s0:c101.c104'},
                       {'extra':True},{'mode':0o777},{'owner':65532},
                       {'socket_label':b''},
                       {'socket_label':b'system_u:system_r:container_t:s0:c103,c104'},
                       {'socket_label':b'system_u:object_r:container_file_t:s0:c101,c102'},
                       {'socket_label':b'unconfined_u:system_r:container_t:s0:c101,c102'},
                       {'socket_label':b'system_u:system_r:container_t:s0:c101.c104'},
                       {'socket_label':b'system_u:system_r:container_t:s0:c101,c102\0\0'}):
            with self.subTest(values=values),self.assertRaises(LifecycleError):check(**values)
        with self.assertRaises(OSError):check(socket_label=OSError('unsupported held descriptor label'))
        lease.owner=0
        with self.assertRaisesRegex(LifecycleError,'ENDPOINT_SCOPE'):check()
        lease.owner=room.SUPERVISOR_UID
        listener.getsockname.return_value='/unapproved/request.sock'
        with self.assertRaisesRegex(LifecycleError,'LISTENER_DRIFT'):check()

    def test_real_observer_failure_becomes_lifecycle_failure_without_effect(self):
        with patch.object(room,'guard'),patch.object(room,'probe',side_effect=room.OriginUnavailable('missing')), \
                patch.object(room.GuestBoundaryBackend,'create') as create:
            with self.assertRaisesRegex(LifecycleError,'ENDPOINT_UNAVAILABLE'):
                self.backend.create(self.state,'volume')
            create.assert_not_called()
        with patch.object(room,'guard'),patch.object(room,'probe'), \
                patch.object(room.RoomEndpoint,'require',side_effect=OSError('listener label unavailable')), \
                patch.object(room.GuestBoundaryBackend,'create') as create:
            with self.assertRaisesRegex(LifecycleError,'ENDPOINT_UNAVAILABLE'):
                self.backend.create(self.state,'volume')
            create.assert_not_called()

    def test_fixed_egress_is_observed_not_a_readiness_receipt(self):
        from types import SimpleNamespace
        import stat
        marker = {'version':1,'nonce':'a'*32,**room.EGRESS_PROFILE}
        links = [{'ifname':'uas-egress','address':'52:54:00:62:00:01'}]
        # Actual IPv4-filtered address output does not contain a link-layer MAC.
        addresses = [{'ifname':'uas-egress',
                      'addr_info':[{'family':'inet','local':'10.0.2.15','prefixlen':24}]}]
        routes = [{'dev':'uas-egress','gateway':'10.0.2.2'}]
        def check(*,document=None,mac='52:54:00:62:00:01',link=None,address=None,route=None,ipv6=None,mode=0o600):
            def read(path):
                return json.dumps(marker if document is None else document) if path.name=='uas-room-network-profile' else mac
            observations = {
                ('ip','-j','link','show','dev','uas-egress'): links if link is None else link,
                ('ip','-j','-4','address','show','dev','uas-egress'): addresses if address is None else address,
                ('ip','-j','-4','route','show','default'): routes if route is None else route,
                ('ip','-j','-6','route','show','default'): [] if ipv6 is None else ipv6,
            }
            with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|mode,
                      st_uid=0,st_nlink=1,st_size=300)),patch.object(Path,'read_text',read), \
                    patch.object(room,'command',side_effect=lambda *args: json.dumps(observations[args])) as command:
                EGRESS(self.backend)
                self.assertEqual([
                    ('ip','-j','link','show','dev','uas-egress'),
                    ('ip','-j','-4','address','show','dev','uas-egress'),
                    ('ip','-j','-4','route','show','default'),
                    ('ip','-j','-6','route','show','default'),
                ], [call.args for call in command.call_args_list])
        check()
        for values in ({'document':{**marker,'nonce':'b'*32}},{'mac':'52:54:00:00:00:02'},
                       {'mode':0o644},{'link':[]},{'link':[{}]},{'link':[None]},
                       {'link':[{'ifname':'wrong','address':'52:54:00:62:00:01'}]},
                       {'link':[{'ifname':'uas-egress','address':'52:54:00:62:00:02'}]},
                       {'link':[{'ifname':'uas-egress'}]},{'link':links*2},
                       {'address':[]},{'address':[None]},{'address':[{'ifname':'wrong'}]},
                       {'address':[{'ifname':'uas-egress','addr_info':[]}]},
                       {'address':[{'ifname':'uas-egress','addr_info':[{'family':'inet','local':'10.0.2.16','prefixlen':24}]}]},{'route':[]},{'route':[{'dev':'other','gateway':'10.0.2.2'}]},
                       {'ipv6':[{'dev':'uas-egress','gateway':'fe80::1'}]}):
            with self.subTest(values=values),self.assertRaises(LifecycleError):check(**values)
