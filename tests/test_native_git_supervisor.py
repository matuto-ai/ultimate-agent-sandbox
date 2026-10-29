"""Actual GitSupervisor constructor with inert socket/launch boundaries."""
from pathlib import Path
from types import SimpleNamespace as N
from contextlib import nullcontext
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from uas.forge import ForgeBinding
from uas.git_process import GitSeat
from uas.git_supervisor import GitSupervisor
from uas.kernel_origin import HeldOrigin, OriginDenied
from uas.ledger import Origin
from uas.native_git_resources import NativeGitResources
from uas.workstation_exec import ExecSeat, EndpointLease


class InertSocket:
    family=socket.AF_UNIX
    type=socket.SOCK_SEQPACKET
    def __init__(self,path):self.path=path
    def getsockname(self):return self.path


class NativeGitSupervisorTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.resources=object.__new__(NativeGitResources)
        self.resources.container_id='c'*64;self.resources.worker_host_uid=165530;self.resources.worker_host_gid=165532
        self.resources.require=Mock(return_value=True)
        self.resources.backend_fd=77;self.resources.backend_sha256='a'*64
        for name in ('request','worker'):
            path=self.root/(name+'.sock');endpoint=object.__new__(EndpointLease)
            endpoint.path=path;endpoint.require=Mock()
            setattr(self.resources,name+'_endpoint',endpoint)
            setattr(self.resources,name+'_listener',InertSocket(str(path)))
        self.origin=Origin('actor','participant','incarnation','authority',('git-read','git-push'))
        held=object.__new__(HeldOrigin)
        self.seat=GitSeat(self.origin,held,lambda:True,((1,2),(3,4)),2)
        self.worker=ExecSeat('room','instance','participant','actor','seat-a','c'*64,165530,165532)
        self.children=Mock();self.coordinator=Mock()
        for p in (patch('uas.git_supervisor.socket.socket',InertSocket),patch('uas.git_supervisor.enable'),
                patch('uas.git_supervisor.GitChildAuthority',return_value=self.children),
                patch('uas.git_supervisor.GitCoordinator',return_value=self.coordinator)):
            p.start();self.addCleanup(p.stop)

    def create(self,**overrides):
        r=self.resources
        args=dict(request_listener=r.request_listener,worker_listener=r.worker_listener,
            request_endpoint=r.request_endpoint,worker_endpoint=r.worker_endpoint,
            journal_dir=self.root,backend_fd=r.backend_fd,backend_sha256=r.backend_sha256,
            lifecycle_lock=nullcontext,run_scope=lambda *_:None,native_resources=r)
        args.update(overrides)
        return GitSupervisor(ForgeBinding('room','project','owner/repo'),'instance',{},(),object(),object(),
            object(),(self.seat,),(self.worker,),**args)

    def test_actual_mapped_constructor_rechecks_resources_before_worker(self):
        owner=self.create();self.resources.require.assert_called_once_with('room','instance','c'*64)
        launch=Mock()
        with patch('uas.git_supervisor.GitExecLaunch',return_value=launch):owner._worker(self.origin)
        self.assertEqual(self.resources.require.call_count,2)
        launch.launch.assert_called_once_with(self.resources.worker_listener)
        launch.attach_worker.assert_called_once()

    def test_wrong_mapped_worker_and_detached_resource_deny(self):
        for uid,gid in ((65530,65532),(165532,165532),(165530,65532)):
            self.worker=ExecSeat('room','instance','participant','actor','seat-a','c'*64,uid,gid)
            with self.assertRaisesRegex(OriginDenied,'worker seat'):self.create()
        with self.assertRaisesRegex(OriginDenied,'resource ownership'):self.create(backend_fd=88)

    def test_default_identity_mapping_unchanged_without_native_profile(self):
        self.worker=ExecSeat('room','instance','participant','actor','seat-a','c'*64,65530,65532)
        owner=self.create(native_resources=None)
        self.assertIsNone(owner.native_resources);self.resources.require.assert_not_called()

    def test_expired_resource_prevents_owned_launch(self):
        owner=self.create();self.resources.require.side_effect=OriginDenied('expired')
        with patch('uas.git_supervisor.GitExecLaunch') as launch:
            with self.assertRaisesRegex(OriginDenied,'expired'):owner._worker(self.origin)
        launch.assert_not_called()
