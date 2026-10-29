"""Local-only primary checkout reuse through the canonical root lifecycle.

No new privileged command surface: the held child asks about an exact canonical
PREPARING admission. Stop/Start still use the installation's actual revocation
owner. The child must cooperatively service P/R while waiting for this reply.
"""
from copy import deepcopy
import select
import time

from .native_checkout_handoff import (NativeCheckoutClient, request_value,
    reservation, remaining, ready_slot, require, MAX_REPLY)


def local_request(value):
    if type(value) is dict and value.get('kind') == 'REUSE_PRIMARY':
        request_value({**value, 'kind': 'ALLOCATE'})
        return value
    return request_value(value)


class LocalNativeCheckoutClient(NativeCheckoutClient):
    def __init__(self, channel, *, deadline, current, after_reuse=None):
        require(callable(current) and (after_reuse is None or callable(after_reuse)), 'LOCAL_CHECKOUT_CURRENT_REQUIRED')
        super().__init__(channel, deadline=deadline)
        self.current = current
        self.after_reuse = after_reuse

    _request = staticmethod(local_request)

    def _receive(self):
        while True:
            self.current()
            ready, _, failed = select.select([self.channel], [], [self.channel],
                                              min(.05, remaining(self.deadline)))
            require(not failed, 'CHECKOUT_TRANSFER_UNKNOWN')
            if ready:
                return self.channel.recvmsg(MAX_REPLY, 0)

    def reuse_primary(self, run, operation_id):
        slot = self._call('REUSE_PRIMARY', run, operation_id)
        ready_slot(slot, run, slot.get('participant'))
        if self.after_reuse is not None:
            try: self.after_reuse()
            except BaseException:
                self.close()
                raise
        return slot


def authorize_local(handoff, request, *, initial):
    handoff._held()
    handoff.plan.require_unchanged()
    lifecycle = handoff.owner._read()
    phase = getattr(handoff, '_reuse_phase', 'running')
    require(lifecycle is not None and lifecycle['phase'] == phase
            and lifecycle['instance_id'] == handoff.resources.data['instance']
            and lifecycle['spec']['config_digest'] == 'sha256:' + handoff.plan.config_digest,
            'CHECKOUT_ROOM_CHANGED')
    participant, pinned = reservation(handoff._snapshot(), request, handoff.plan.room,
                                     handoff.actors, initial=initial, local_reuse=True)
    pin = (request['run_id'], participant, pinned)
    previous = handoff.pins.setdefault(request['run_id'], pin)
    require(previous == pin and len(handoff.pins) == 1, 'CHECKOUT_RESERVATION_CHANGED')
    handoff.pin = pin
    return True


def reuse_primary(handoff, request):
    from .local_services import LocalServices
    services = handoff.local_resources.services
    require(type(services) is LocalServices, 'LOCAL_CHECKOUT_SERVICE_OWNER_REQUIRED')
    # Serialize operator Stop/Start with this complete transition. The lifecycle
    # file lock remains short-lived so the child can prove retirement.
    with services.operation_lock:
        return _reuse_primary(handoff, request)


def _reuse_primary(handoff, request):
    """One attempted root transition; uncertain effects are never retransmitted."""
    from .local_services import LocalServices
    local_request(request)
    require(request['kind'] == 'REUSE_PRIMARY', 'CHECKOUT_REQUEST_INVALID')
    services = handoff.local_resources.services
    require(type(services) is LocalServices, 'LOCAL_CHECKOUT_SERVICE_OWNER_REQUIRED')
    require(request['run_id'] not in handoff.attempted, 'CHECKOUT_ALLOCATION_RECONCILE_ONLY')
    with handoff.owner._locked(deadline=handoff.deadline):
        authorize_local(handoff, request, initial=True)
        run, participant, pinned = handoff.pin
        predecessor = pinned.get('preceding_run')
        require(type(predecessor) is dict, 'CHECKOUT_PREDECESSOR_REQUIRED')
        before = deepcopy(handoff.owner._read())
        resource = handoff.owner.backend.admit(before)
        container = resource['Id']
        # In-process custody must still name the exact child and resource owner.
        row = services._rooms.get(handoff.plan.room['id'])
        require(row is not None and row.get('runtime_owner') is handoff.local_resources
                and row.get('process') is handoff.child and row.get('instance') == before['instance_id']
                and row.get('runtime_phase') == 'active', 'LOCAL_CHECKOUT_SERVICE_OWNER_CHANGED')
    handoff.attempted.add(run)
    # This invokes the actual retained service owner, including P/receipt. It
    # never infers revocation from a journal or calls backend.stop around it.
    handoff.owner.stop()
    handoff._reuse_phase = 'stopped'
    with handoff.owner._locked(deadline=handoff.deadline):
        authorize_local(handoff, request, initial=True)
        stopped = handoff.owner._read()
        observed = handoff.owner.backend.admit(stopped)
        require(observed['Id'] == container and observed['State']['Running'] is False,
                'CHECKOUT_STOP_UNCONFIRMED')
    with handoff.allocator._locked('status') as slots:
        authorize_local(handoff, request, initial=True)
        primary = slots['slots'].get('primary')
        require(type(primary) is dict and primary.get('run') == predecessor['run_id']
                and primary.get('participant') == participant and primary.get('active') is True
                and primary.get('phase') == 'ready', 'CHECKOUT_PREDECESSOR_CHANGED')
        require(handoff.allocator._quiescent(primary), 'WRITER_NOT_QUIESCENT')
        require(handoff.allocator._observe(slots, 'primary')['disposition'] == 'clean',
                'PRIMARY_NOT_RECONCILED')
    released = handoff.allocator.release(predecessor['run_id'], participant,
        authorize=lambda: authorize_local(handoff, request, initial=True))
    require(released['disposition'] == 'clean' and released['active'] is False,
            'PRIMARY_NOT_RECONCILED')
    slot = handoff.allocator.reserve(run, participant,
        authorize=lambda: authorize_local(handoff, request, initial=True))
    require(slot['path'] == str(handoff.allocator.repo), 'CHECKOUT_PRIMARY_REQUIRED')
    ready_slot(slot, run, participant)
    # Exact selected spec, same Room instance and owned container. No re-create.
    handoff.owner.start(handoff.local_resources.backend.profile.spec())
    handoff._reuse_phase = 'running'
    with handoff.owner._locked(deadline=handoff.deadline):
        authorize_local(handoff, request, initial=True)
        resumed = handoff.owner._read()
        observed = handoff.owner.backend.admit(resumed)
        require(observed['Id'] == container and observed['State']['Running'] is True,
                'CHECKOUT_START_UNCONFIRMED')
    services.ensure(handoff.plan.room['id'], handoff.owner, handoff.local_resources.backend, resumed)
    require(row.get('runtime_phase') == 'active', 'LOCAL_CHECKOUT_RESUME_UNCONFIRMED')
    handoff.local_resources.state = deepcopy(resumed)
    handoff.reused_primary = run
    remaining(handoff.deadline)
    return ready_slot(slot, run, participant)
