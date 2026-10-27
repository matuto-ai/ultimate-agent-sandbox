"""Conservative checkout writer fencing at the trusted Docker Supervisor seam.

Slots are not security boundaries. A stopped exact owned Workstation, not an
exited exec parent, revoked badge, cached receipt or prior incarnation, proves
its complete writer set quiescent. The host/Docker daemon remain trusted. This
does not claim production outer-confinement or native Runtime qualification.
"""
from .checkout_scope import valid_timestamp, valid_writer_scope
from .docker_fixture import DockerFixtureBackend
from .lifecycle import BackendUnknown, LifecycleError, OwnershipConflict, _path


class DockerCheckoutBackend(DockerFixtureBackend):
    """Fixed writable repository/slot-root variant of the admitted fixture.

    Only the two trusted configured roots are writable; all other policy,
    immutable-image and exact same-path mount admission remains unchanged.
    """
    def __init__(self, repo, checkouts, **kwargs):
        super().__init__(**kwargs)
        self.writable = frozenset((str(_path(repo)), str(_path(checkouts))))
        if len(self.writable) != 2:
            raise LifecycleError('PROJECT_BINDING_CONFLICT')

    def _project_writable(self, state, path):
        if not self.writable <= set(state['spec']['project_paths']):
            raise LifecycleError('PROJECT_BINDING_CONFLICT')
        return path in self.writable

    def checkout_writer_guard(self, supervisor):
        return DockerCheckoutWriters(supervisor)


class DockerCheckoutWriters:
    """Used only by CheckoutAllocator under its Supervisor lifecycle lock."""
    def __init__(self, supervisor):
        if not isinstance(supervisor.backend, DockerCheckoutBackend):
            raise LifecycleError('INVALID_WRITER_GUARD')
        self.supervisor = supervisor

    valid_scope = staticmethod(valid_writer_scope)
    _timestamp = staticmethod(valid_timestamp)

    @staticmethod
    def _state(resource):
        state = resource['State']
        if (type(state) is not dict or type(state.get('Running')) is not bool
                or type(state.get('Pid')) is not int or state['Pid'] < 0
                or state.get('Paused') is not False or state.get('Restarting') is not False
                or state.get('Dead') is not False
                or not DockerCheckoutWriters._timestamp(state.get('StartedAt'))):
            raise BackendUnknown()
        if state['Running']:
            if state.get('Status') != 'running' or state['Pid'] <= 0:
                raise BackendUnknown()
        elif (state.get('Status') != 'exited' or state['Pid'] != 0
                or not DockerCheckoutWriters._timestamp(state.get('FinishedAt'))):
            raise BackendUnknown()
        return state

    def capture(self, lifecycle):
        try:
            resource = self.supervisor.backend.admit(lifecycle)
            observed = self._state(resource)
            if (lifecycle['phase'] == 'running') is not observed['Running']:
                raise BackendUnknown()
            scope = {'kind': 'docker-workstation', 'instance': lifecycle['instance_id'],
                     'container': resource['Id'], 'started_at': observed['StartedAt']}
            if not self.valid_scope(scope, lifecycle['instance_id']):
                raise BackendUnknown()
            return scope
        except (BackendUnknown, OwnershipConflict, KeyError, TypeError) as error:
            raise LifecycleError('WRITER_OBSERVATION_UNKNOWN') from error

    def quiescent(self, lifecycle, scope):
        if not self.valid_scope(scope, lifecycle['instance_id']):
            return False  # Legacy or unknown scope is never silently adopted.
        try:
            resource = self.supervisor.backend._inspect_object(lifecycle, 'container')
            if resource is None or resource['Id'] != scope['container']:
                return False  # Absence/name reuse is not proof about old tasks.
            observed = self._state(resource)
            # Even a later StartedAt cannot excuse current writers in shared
            # paths. Stopped observation is fresh at release AND every reuse /
            # removal. Paused/restarting/unknown states always retain work.
            return observed['Running'] is False
        except (BackendUnknown, OwnershipConflict, LifecycleError, KeyError, TypeError, OSError):
            return False
