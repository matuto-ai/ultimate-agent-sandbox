"""Fixed artifacts Gate assembly from concrete native resource custody."""
import hashlib

from .artifact_helper import GateHelperLaunch, GateSupervisorService, PROFILE_ID
from .artifact_target import ArtifactTargets
from .artifact_protocol import ArtifactError
from .docker_exec_api import DockerExecAPI
from .native_gate_resources import NativeGateResources
from .native_gate_control import NativeGateControl
from .native_review_host import NativeReviewHost


class NativeGateOperations:
    def __init__(self, host, resources):
        if (type(host) is not NativeReviewHost or type(resources) is not NativeGateResources
                or resources.review_host is not host
                or resources.supervisor is not host.identity.supervisor
                or type(resources.engine) is not DockerExecAPI
                or resources.room_id != host.identity.binding.room_id
                or resources.instance != host.identity.binding.room_instance
                or resources.workstation.profile != PROFILE_ID):
            raise ArtifactError('EXACT_NATIVE_GATE_RESOURCES_REQUIRED')
        if resources.require(resources.workstation) is not True:
            raise ArtifactError('GATE_BOUNDARY_NOT_ADMITTED')
        self.host, self.resources = host, resources
        self.closed = False
        self.targets = ArtifactTargets(resources.scratch_root, resources.journal_root,
            host.identity.resolver, reserve_capacity=resources.reserve_capacity,
            host_profile=resources.workstation.host_profile)
        self.service = GateSupervisorService(host.sources, self.targets,
            launch_factory=self._launch, listener=resources.listener, profile=PROFILE_ID)
        self.control = NativeGateControl(host, self.service, profile=PROFILE_ID)

    def _launch(self, scope, target, lease):
        resources = self.resources
        if (self.closed or resources.review_host is not self.host
                or resources.supervisor is not self.host.identity.supervisor
                or scope['room_id'] != resources.room_id
                or scope['room_instance'] != resources.instance
                or self.targets.host_profile is not resources.workstation.host_profile
                or self.targets.resolver is not self.host.identity.resolver
                or self.targets.lease(target) is not lease):
            raise ArtifactError('EXACT_NATIVE_GATE_RESOURCES_REQUIRED')
        journal = resources.launch_journal_root / (hashlib.sha256(scope['evaluation_id'].encode()).hexdigest()+'.json')
        return GateHelperLaunch(resources.engine, resources.workstation,
            resources.endpoint, journal, admission=resources, target_lease=lease, scope=scope)

    def close(self):
        """Release owned descriptors only; never infer helper exit/cleanup.

        Target journals/quarantine remain with canonical resource ownership.
        Every owned close is attempted even if another descriptor close fails.
        """
        if self.closed:
            return
        self.closed = True
        self.control._closed = True
        error = None
        for value in (*self.control._offers.values(), *self.service._launches.values()):
            if value is not None:
                try:
                    value.close()
                except BaseException as failure:
                    error = error or failure
        if error is not None:
            raise error
