"""Fixed concrete owner assembly with controlled filesystem/native boundaries."""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
from contextlib import contextmanager
from uas import native_gate_operations as operations
from uas.native_gate_resources import NativeGateResources
from uas.native_gate_control import NativeGateControl
from uas.native_gate_workflow import NativeGateWorkflow
from uas.artifact_helper import GateEndpointLease,GateHelperLaunch
from uas.artifact_protocol import ArtifactError
from uas.docker_exec_api import DockerExecAPI
import test_native_gate_control as fixture


class NativeGateOperationsTests(unittest.TestCase):
    def setUp(self):
        self.control=fixture.facade();self.host=self.control.host
        self.resources=object.__new__(NativeGateResources)
        r=self.resources;r.review_host=self.host;r.supervisor=self.host.identity.supervisor
        r.engine=object.__new__(DockerExecAPI);r.room_id=fixture.fixture.SCOPE['room_id'];r.instance=fixture.fixture.SCOPE['room_instance']
        r.workstation=fixture.fixture.workstation();r.require=Mock(return_value=True)
        r.scratch_root=Path('/owned/scratch');r.journal_root=Path('/owned/targets');r.launch_journal_root=Path('/owned/launches')
        r.listener=Mock();r.endpoint=object.__new__(GateEndpointLease);r.reserve_capacity=Mock()
        self.targets=Mock();self.targets.resolver=self.host.identity.resolver
        self.targets.host_profile=r.workstation.host_profile
        self.lease=Mock();self.lease.document.return_value=fixture.fixture.TARGET
        self.targets.lease.return_value=self.lease
        self.constructor=patch.object(operations,'ArtifactTargets',return_value=self.targets).start()
        self.addCleanup(patch.stopall)

    def test_assembly_binds_real_service_fixed_launch_and_canonical_target_resolver(self):
        owner=operations.NativeGateOperations(self.host,self.resources)
        self.constructor.assert_called_once_with(self.resources.scratch_root,self.resources.journal_root,
            self.host.identity.resolver,reserve_capacity=self.resources.reserve_capacity,host_profile=None)
        self.assertIs(owner.service.resolver,self.host.sources)
        self.assertIs(owner.service.targets,self.targets);self.assertIs(owner.service.listener,self.resources.listener)
        self.assertIs(type(owner.control),NativeGateControl)
        launch=owner._launch(fixture.fixture.SCOPE,fixture.fixture.TARGET,self.lease)
        self.assertIs(type(launch),GateHelperLaunch);self.assertIs(launch.admission,self.resources)
        self.assertIs(launch.engine,self.resources.engine);self.assertIs(launch.target_lease,self.lease)
        expected=hashlib.sha256(fixture.fixture.SCOPE['evaluation_id'].encode()).hexdigest()+'.json'
        self.assertEqual(launch.journal_path,self.resources.launch_journal_root/expected)

    def test_other_owner_and_denied_admission_fail_before_targets(self):
        self.resources.review_host=object()
        with self.assertRaises(ArtifactError):operations.NativeGateOperations(self.host,self.resources)
        self.constructor.assert_not_called()
        self.resources.review_host=self.host;self.resources.require.return_value=False
        with self.assertRaises(ArtifactError):operations.NativeGateOperations(self.host,self.resources)
        self.constructor.assert_not_called()

    def test_fixed_launch_rejects_replaced_source_and_lease(self):
        owner=operations.NativeGateOperations(self.host,self.resources)
        with self.assertRaises(ArtifactError):owner._launch(fixture.fixture.SCOPE,fixture.fixture.TARGET,Mock())
        self.targets.resolver=Mock()
        with self.assertRaises(ArtifactError):owner._launch(fixture.fixture.SCOPE,fixture.fixture.TARGET,self.lease)

    def test_attached_idle_workflow_denies_effect_active_uses_full_pin_fence(self):
        workflow=object.__new__(NativeGateWorkflow);workflow.host=self.host;workflow.active=None
        self.host.gate_workflow=workflow
        with self.assertRaises(ArtifactError):self.control.prepare(fixture.fixture.SCOPE,{})
        self.control.service.targets.prepare.assert_not_called()
        workflow.active=object();seen=[]
        @contextmanager
        def fence(gates):
            self.assertIs(gates,self.host.gates);seen.append('enter')
            yield
            seen.append('exit')
        workflow.commit=fence;self.host.gates=object()
        def prepare(*args):
            self.assertEqual(seen,['enter','exit']);return fixture.fixture.TARGET
        self.control.service.targets.prepare.side_effect=prepare
        self.control.prepare(fixture.fixture.SCOPE,{})

    def test_close_attempts_all_owned_descriptors_and_never_claims_cleanup(self):
        owner=operations.NativeGateOperations(self.host,self.resources)
        offer,launch=Mock(),Mock();offer.close.side_effect=OSError('close')
        owner.control._offers={'one':offer};owner.service._launches={'one':launch}
        with self.assertRaises(OSError):owner.close()
        offer.close.assert_called_once();launch.close.assert_called_once()
        self.targets.reconcile.assert_not_called();self.targets.cleanup.assert_not_called()
        owner.close();offer.close.assert_called_once()
        with self.assertRaises(ArtifactError):owner.control.reconcile('one')
