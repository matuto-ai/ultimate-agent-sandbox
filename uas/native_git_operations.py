"""Consumed native Git owner; original Participant lineage supplies authorship.

Only the first canonical primary checkout has a prepared projection. A retained
successor is rejected, never redirected to the old primary worktree. Gates are
not supplied by this owner.
"""
from contextlib import contextmanager
from pathlib import Path

from .git_controller import GitCheckout
from .git_process import GitSeat, ProcView, _Task
from .git_provenance import actor_git_identity
from .git_service import GitBrokerClient
from .git_supervisor import GitSupervisor
from .kernel_origin import OriginDenied
from .ledger import LedgerError
from .native_run_admission import NativeRunAdmission
from .native_reviewer_recruitment import NativeReviewerRecruitment
from .native_git_resources import NativeGitResources
from .workstation_exec import ExecSeat


class NativeGitOperations:
    def __init__(self, owner, reviewer, resources, broker):
        if (type(owner) is not NativeRunAdmission
                or type(reviewer) is not NativeReviewerRecruitment or reviewer.owner is not owner
                or reviewer.root is None or reviewer.root.review_host is None
                or type(resources) is not NativeGitResources or type(broker) is not GitBrokerClient):
            raise LedgerError('NATIVE_GIT_OWNER_REQUIRED')
        owner._require_owner()
        self.owner, self.reviewer, self.resources, self.broker = owner, reviewer, resources, broker
        self.supervisor = owner.supervisor
        self.identity = reviewer.root.review_host.identity
        self._capability = None
        self.closed = False
        self.service = None
        self.pi, self.claude = reviewer.pi, reviewer.root
        self.ingresses = (self.pi.forge_service, self.claude.forge_service)
        self.processes = (self.pi.launch.origin, self.claude.origin)
        self.scope = dict(self.pi.launch.native_recipe.scope)
        binding = owner.broker.binding
        if (resources.supervisor is not self.supervisor or resources.plan is not owner.launcher.plan
                or self.identity.supervisor is not self.supervisor or self.identity.ledger is not owner.ledger
                or self.identity.provenance is not reviewer.provenance
                or self.identity.resolver is not reviewer.resolver
                or self.identity.ingresses != self.ingresses
                or broker.binding != binding or broker.closed
                or broker.scope != {**binding.__dict__, 'room_instance': resources.profile.instance_id}):
            raise LedgerError('NATIVE_GIT_OWNER_MISMATCH')
        if (any('git-read' not in i.origin.capabilities for i in self.ingresses)
                or 'git-push' not in self.ingresses[0].origin.capabilities):
            raise LedgerError('NATIVE_GIT_CAPABILITY_UNAVAILABLE')
        identities = {i.origin.actor_id: actor_git_identity(owner.actors[i.origin.actor_id])
                      for i in self.ingresses}
        seats, workers = [], []
        with self._fence():
            self._current()
            view = ProcView()
            try:
                for ingress, process, seat in zip(self.ingresses, self.processes,
                                                   (self.pi.launch.seat, self.claude.seat)):
                    # Numeric /proc is only corroboration of the existing held
                    # pidfd, never an authority source or fallback after loss.
                    task = _Task(view, process.credentials[0], expected=process.identity)
                    try:
                        seats.append(GitSeat(ingress.origin, process,
                            lambda i=ingress: self._seat_current(i), task.namespace,
                            len(task.status['NSpid'])))
                    finally:
                        task.close()
                    workers.append(ExecSeat(seat.room_id,seat.room_instance,seat.participant_id,
                        seat.actor_id,seat.slot,seat.container_id,
                        resources.worker_host_uid,resources.worker_host_gid))
            finally:
                view.close()
        profile = resources.profile
        checkout = GitCheckout('primary', profile.repo, '/opt/uas/git-views/primary/gitdir',
            '/opt/uas/git-views/primary/common', '/opt/uas/git-views/primary/common/config',
            '/opt/uas/bin', 65532)
        self.service = GitSupervisor(binding, profile.instance_id, identities, (checkout,),
            reviewer.provenance, broker, owner.launcher.engine, tuple(seats), tuple(workers),
            request_listener=resources.request_listener, worker_listener=resources.worker_listener,
            request_endpoint=resources.request_endpoint, worker_endpoint=resources.worker_endpoint,
            journal_dir=Path(owner.launcher.resources['supervisor_directory'])/'git-launches',
            backend_fd=resources.backend_fd, backend_sha256=resources.backend_sha256,
            lifecycle_lock=self._fence, run_scope=self._run_scope, native_resources=resources)
        try:
            with self._fence():
                self._current()
                resources.request_listener.listen(8)
        except BaseException:
            try:self.service.close()
            finally:resources.request_listener.close()
            raise

    @contextmanager
    def _fence(self):
        self.owner._require_owner()
        if self._capability is not None:
            raise LedgerError('NATIVE_GIT_NESTED_FENCE')
        with self.supervisor._locked() as capability:
            self._capability = capability
            try:
                yield capability
            finally:
                self._capability = None

    def _current(self):
        if self.closed or self._capability is None:
            raise LedgerError('NATIVE_GIT_FENCE_REQUIRED')
        self._capability.require(self.supervisor)
        profile = self.resources.profile
        self.resources.require(profile.room_id,profile.instance_id,profile.container_id)
        if (self.reviewer.root is not self.claude or self.reviewer.pi is not self.pi
                or self.owner.launcher.started.get(self.pi.seat.participant_id) is not self.pi
                or self.pi.forge_service is not self.ingresses[0]
                or self.claude.forge_service is not self.ingresses[1]
                or self.pi.launch.origin is not self.processes[0]
                or self.claude.origin is not self.processes[1]):
            raise OriginDenied('native Git retained owners replaced')
        if (self.pi.launch.native_recipe.scope != self.scope
                or getattr(self.pi.launch.native_recipe, 'git_profile', None) is not self.resources.profile
                or getattr(self.claude.recipe, 'git_profile', None) is not self.resources.profile):
            raise OriginDenied('native Git recipe projection changed')
        state = self.owner.ledger.snapshot()['state']
        run = state.get('runs',{}).get(self.scope['run_id'])
        if (not run or run.get('status') != 'ACTIVE' or run.get('generation') != self.scope['generation']
                or run.get('participant_id') != self.pi.seat.participant_id):
            raise LedgerError('NATIVE_GIT_RUN_UNAVAILABLE')
        source = self.reviewer.resolver.resolve_locked(self._capability,self.scope['run_id'],
            self.pi.seat.participant_id,profile.instance_id)
        profile.require_checkout(source['slot_id'],run['checkout']['path'])
        for ingress in self.ingresses:
            self.identity.seat_current(ingress,state,self.scope['run_id'],self.scope['generation'])
        return state

    def _seat_current(self, ingress):
        self._current()
        if ingress not in self.ingresses:
            raise OriginDenied('native Git origin changed')
        return True

    def _run_scope(self, origin, checkout):
        self._current()
        if checkout != 'primary' or not any(i.origin == origin for i in self.ingresses):
            raise LedgerError('NATIVE_GIT_CHECKOUT_UNAVAILABLE')
        return {k:self.scope[k] for k in ('run_id','generation')}

    @property
    def request_listener(self):
        return self.resources.request_listener

    def serve_next(self, *, timeout=1):
        self.owner._require_owner()
        if self.closed or self.service is None:
            raise LedgerError('NATIVE_GIT_CLOSED')
        return self.service.serve_next(timeout=timeout)

    def require_successor(self):
        # Driver calls before retirement/allocation: existing completed evidence
        # and held owners remain intact while the projection is unavailable.
        self.owner._require_owner()
        raise LedgerError('NATIVE_SUCCESSOR_GIT_VIEW_UNAVAILABLE')

    def require_pi_restore(self, old):
        """Structural cut only: the old Pi is dead, so live _current cannot apply."""
        from .git_process import GitChildAuthority
        if (self.closed or self._capability is not None or self.pi is not old
                or self.reviewer.pi is not old or self.reviewer.root is not self.claude
                or self.identity is not self.reviewer.root.review_host.identity
                or self.identity.ingresses != self.ingresses
                or self.ingresses != (old.forge_service, self.claude.forge_service)
                or self.processes != (old.launch.origin, self.claude.origin)
                or type(self.service) is not GitSupervisor or self.service.closed
                or type(self.service.children) is not GitChildAuthority
                or self.service.native_resources is not self.resources):
            raise LedgerError('NATIVE_RESTORE_GIT_GRAPH_CHANGED')
        pair = self.service.seats.get(old.seat.participant_id)
        if (not pair or pair[0].origin != old.forge_service.origin
                or pair[0].process is not old.launch.origin
                or self.service.children.seats.get(old.launch.origin.identity) is not pair[0]):
            raise LedgerError('NATIVE_RESTORE_GIT_SEAT_CHANGED')
        return pair

    def prepare_pi_restore(self, old, new):
        pair = self.require_pi_restore(old)
        process = new.launch.origin
        if (new.launch.native_recipe.scope != self.scope
                or new.launch.native_recipe.git_profile is not self.resources.profile
                or process.identity in self.service.children.seats
                or process.credentials[1:] != old.launch.origin.credentials[1:]):
            raise LedgerError('NATIVE_RESTORE_GIT_NEW_SEAT')
        # Corroborate only the already-held new process; no PID authority adoption.
        task = _Task(self.service.children.view, process.credentials[0], expected=process.identity)
        try:
            if task.namespace != pair[0].namespace or len(task.status['NSpid']) != pair[0].pid_depth:
                raise OriginDenied('resumed Pi changed admitted Git namespace')
            return GitSeat(new.forge_service.origin, process,
                lambda: self._seat_current(new.forge_service), task.namespace, len(task.status['NSpid']))
        finally:
            task.close()

    def publish_pi_restore(self, new, seat):
        """Private assignment phase called only after NativePiRebind validation.

        No new service, coordinator, child authority, listener or effect registry.
        Existing unknown workers/transactions retain their original attribution.
        """
        old = self.pi
        worker = self.service.seats[old.seat.participant_id][1]
        del self.service.children.seats[old.launch.origin.identity]
        self.service.children.seats[new.launch.origin.identity] = seat
        self.service.seats[new.seat.participant_id] = (seat, worker)
        self.pi = new
        self.ingresses = (new.forge_service, self.ingresses[1])
        self.processes = (new.launch.origin, self.processes[1])

    def close(self):
        if not self.closed:
            self.closed = True
            if self.service is not None:self.service.close()
