"""Single-owner outside-Hub event loop over already trusted/admitted descriptors.

No endpoint creation, Engine, RPC, launch object, provider or Broker is available.
Namespace/SELinux/profile qualification is external and remains mandatory.
"""
from types import MappingProxyType
import selectors
import select
import threading

from .kernel_origin import OriginDenied, alive
from .workstation_admission import HubAdmission
from .workstation_peer import AdmittedPeerDispatcher


class AdmittedHubLoop:
    def __init__(self, admissions, dispatcher, control, *, context_generations, canonical_context_generations=False):
        if (type(admissions) is not HubAdmission or type(dispatcher) is not AdmittedPeerDispatcher
                or dispatcher.admissions is not admissions
                or type(canonical_context_generations) is not bool
                or type(context_generations) is not dict
                or set(context_generations) != set(admissions.seats)
                or any(type(value) is not int or not 0 < value < 2**53
                       for value in context_generations.values())):
            raise OriginDenied('trusted Hub control/context configuration required')
        self.admissions, self.dispatcher, self.control = admissions, dispatcher, control
        admissions.bind_control(control)
        self.context_generations = MappingProxyType(dict(context_generations))
        self.canonical_context_generations=canonical_context_generations
        self._owner = threading.get_ident()
        self._selector = selectors.DefaultSelector()
        self._registered = {}
        self._closed = False
        try:
            control.setblocking(False)
            self._selector.register(control, selectors.EVENT_READ, ('control', None))
            self._selector.register(admissions.supervisor.pidfd, selectors.EVENT_READ, ('supervisor', None))
            self._sync()
        except BaseException:
            self.close()
            raise

    def _require_owner(self):
        if self._closed or threading.get_ident() != self._owner:
            raise OriginDenied('Hub ledger event loop requires its owning thread')

    def _attach(self, operation):
        binding = self.admissions.binding(operation)
        self.dispatcher.attach_current(operation,
            context_generation=(None if self.canonical_context_generations else
                                self.context_generations[binding.seat.participant_id]))

    def _sync(self):
        # Descriptor integers are selector readiness handles only; attribution
        # always rechecks the held kernel object and immutable binding.
        with self.admissions._lock:
            wanted = {}
            for operation, (offer, binding) in self.admissions._active.items():
                if binding.native_payload_digest is None:
                    offer.channel.setblocking(False)
                    wanted[('peer', operation)] = offer.channel
                wanted[('task', operation)] = offer.origin.pidfd
                if offer.host_origin is not None:
                    wanted[('host-task', operation)] = offer.host_origin.pidfd
            for operation, offer in self.admissions._helpers.items():
                offer.channel.setblocking(False)
                wanted[('helper', operation)] = offer.channel
                wanted[('helper-task', operation)] = offer.origin.pidfd
        for key, (resource, number) in tuple(self._registered.items()):
            if key not in wanted or wanted[key] != resource:
                self._selector.unregister(number)
                del self._registered[key]
        for key, resource in wanted.items():
            if key not in self._registered:
                selected = self._selector.register(resource, selectors.EVENT_READ, key)
                self._registered[key] = (resource, selected.fd)

    def step(self, timeout=.1):
        """One bounded poll. Control loss/revocation wins over ready peer data."""
        self._require_owner()
        if type(timeout) not in (int, float) or not 0 <= timeout <= 1:
            raise OriginDenied('bounded Hub poll required')
        try:
            with self.admissions._lock:
                if self.admissions._closed or self.admissions._fenced:
                    raise OriginDenied('Hub admission controller fenced')
            self.admissions.endpoint.require()
            if not alive(self.admissions.supervisor.pidfd):
                raise OriginDenied('Supervisor task exited')
            self._sync()
            events = self._selector.select(timeout)
            # Drain a bounded control batch first. If more remains queued,
            # defer peers rather than letting queued REVOKE lose to peer data.
            control_pending = False
            for key, _ in events:
                kind, operation = key.data
                if kind == 'supervisor':
                    raise OriginDenied('Supervisor task exited')
                if kind == 'control':
                    for _ in range(32):
                        if not select.select([self.control], [], [], 0)[0]:
                            break
                        self.admissions.serve_once(self.control, on_admitted=self._attach,
                                                   on_delivery=self.dispatcher.delivery,
                                                   on_forge_reserve=self.dispatcher.reserve_host_forge)
                    control_pending = bool(select.select([self.control], [], [], 0)[0])
                elif kind == 'helper-task':
                    self.admissions.revoke_helper(operation)
                elif kind in ('task','host-task'):
                    self.admissions.revoke(operation)
            self._sync()
            if control_pending:
                return []
            results = []
            for key, _ in events:
                kind, operation = key.data
                if kind == 'peer' and ('peer', operation) in self._registered:
                    results.append(self.dispatcher.receive(operation))
                elif kind == 'helper' and ('helper', operation) in self._registered:
                    results.append(self.dispatcher.receive_helper(operation))
            self._sync()
            return results
        except BaseException:
            try:
                self.admissions.control_lost()
            finally:
                self.close()
            raise

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self.admissions.control_lost()
            finally:
                try:
                    self.control.close()
                finally:
                    self._selector.close()
