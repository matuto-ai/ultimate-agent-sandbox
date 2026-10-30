"""Native review acceptance at the trusted host, on the ONE canonical Room DB.

FD4 supplies original kernel records, never a Hub-authored Actor assertion.
Provider preparation is outside locks. Final local order is lifecycle -> Git ->
Room ledger. No distributed history lease or second workflow store exists.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib

from .artifact_target import ArtifactSourceResolver
from .context import FixtureContextHub
from .forge_read_service import ReviewBrokerClient, GateForgeBrokerClient
from .gate_evaluation import GateRoomBinding
from .gate_hub import GateHub
from .gate_identity import ContributionOwner
from .git_provenance import GitProvenance
from .ledger import LedgerError, RoomLedger, _json
from .native_host_forge import NativeHostForge, NativePiHostForge
from .run_review import RunReview


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


class NativeReviewIdentity:
    """Concrete retained native authorities + canonical contexts + Git history."""
    def __init__(self, ingresses, ledger, provenance, resolver, binding):
        if (type(ledger) is not RoomLedger or type(provenance) is not GitProvenance
                or type(resolver) is not ArtifactSourceResolver or type(binding) is not GateRoomBinding
                or type(ingresses) is not tuple or not ingresses
                or any(type(i) not in (NativeHostForge, NativePiHostForge) for i in ingresses)
                or provenance.room_id != ledger.room_id or binding.room_id != ledger.room_id
                or provenance.project_id != binding.project_id):
            raise LedgerError('INVALID_NATIVE_REVIEW_OWNER')
        self.supervisor = resolver.supervisor
        if any(i.client.supervisor is not self.supervisor or i.client.binding.room_id != ledger.room_id
               or i.client.binding.project_id != binding.project_id or i.client.room_instance != binding.room_instance
               for i in ingresses):
            raise LedgerError('INVALID_NATIVE_REVIEW_OWNER')
        if len({i.origin.participant_id for i in ingresses}) != len(ingresses):
            raise LedgerError('AMBIGUOUS_NATIVE_REVIEW_SEAT')
        self.ingresses, self.ledger, self.provenance, self.resolver = ingresses, ledger, provenance, resolver
        self.binding = binding
        self.contributions = ContributionOwner(ledger, binding)
        self.contexts = FixtureContextHub(self)
        self.dispatcher = self  # RunReview selects exact seats through this canonical interface.
        self.active = None

    def _state(self):
        return self.active.state if self.active is not None and self.active.state is not None else self.ledger.snapshot()['state']

    def seat_current(self, ingress, state, run_id=None, generation=None):
        ingress._current()  # Exact retained native root/helper/SDK host, controller and Room.
        origin = ingress.origin
        row = state.get('peer_traffic', {}).get('connections', {}).get(origin.participant_id)
        definition = state.get('peer_traffic', {}).get('definition', {}).get('participants', {}).get(origin.participant_id)
        if (not definition or definition.get('actor_id') != origin.actor_id or not row
                or row.get('attachment_id') != 'admit-' + ingress.binding.operation_id
                or row.get('incarnation_id') != origin.incarnation_id or row.get('readiness') == 'lost'
                or not self.contexts.current(origin.participant_id, row.get('context_generation'), state)):
            raise LedgerError('STALE_CONNECTION')
        if run_id is not None:
            run = state.get('runs', {}).get(run_id)
            admission = state.get('run_admissions', {}).get(run_id)
            if (not run or run['generation'] != generation or run['status'] not in ('ACTIVE','PAUSED')
                    or admission is not None and admission['status'] != 'ACTIVE'
                    or not self.contexts.permits(origin.participant_id, row['context_generation'], run_id, generation, state)):
                raise LedgerError('REVIEW_RUN_STALE')
        return origin

    def actor_authority(self, actor, version=None):
        state = self._state(); matches = []
        for ingress in self.ingresses:
            if ingress.origin.actor_id != actor or version is not None and ingress.origin.authority_version != version:
                continue
            try: matches.append(self.seat_current(ingress, state))
            except (LedgerError, RuntimeError): continue
        if len(matches) > 1: raise LedgerError('GATE_IDENTITY_AMBIGUOUS')
        if not matches:
            return {'actor_id':actor,'kind':'participant','active':False,'authority_epoch':version or 'inactive','capabilities':[]}
        origin = matches[0]
        return {'actor_id':actor,'kind':'participant','active':True,'authority_epoch':origin.authority_version,
                'capabilities':sorted(origin.capabilities)}

    def reviewer_authority(self, participant_id, run_id, generation):
        matches = [i for i in self.ingresses if i.origin.participant_id == participant_id]
        if len(matches) != 1: raise LedgerError('REVIEW_PARTICIPANT_UNAVAILABLE')
        return self.seat_current(matches[0], self._state(), run_id, generation)

    def require_operation_fence(self):
        if self.active is None or self.active.capability is None:
            raise LedgerError('GATE_IDENTITY_FENCE_REQUIRED')
        self.active.capability.require(self.supervisor)
        if not getattr(self.provenance, '_history_fenced', False):
            raise LedgerError('GATE_IDENTITY_FENCE_REQUIRED')

    def __call__(self, run, actor, head):
        return self.read_identity(run, actor, head, None)

    def read_identity(self, run, actor, head, version):
        if self.active is not None and self.active.capability is not None:
            self.require_operation_fence()
            return self._read_identity(run, actor, head, version)
        with self.supervisor._locked():
            with self.provenance.history_fence():
                return self._read_identity(run, actor, head, version)

    def _read_identity(self, run, actor, head, version):
        authority = self.actor_authority(actor, version)
        positive = self.contributions.known(run, state=self._state())
        git = self.provenance.known_contribution_snapshot(
            {'run_id':run['run_id'],'generation':run['generation']}, run['repository'], head)
        contributors = sorted(set(positive['contributors']) | set(git['contributors']))
        if len(contributors) > 128: raise LedgerError('CONTRIBUTION_CAPACITY')
        return {**authority,'contributors':contributors,'history_status':'read',
                'contribution_version':_digest({'positive':positive['version'],'git':git['version']})}


class NativeReviewSources:
    """Read-only actual source resolver; no evaluator launch or generic RPC."""
    def __init__(self, identity):
        self.identity = identity
        self.repo = identity.resolver.repo

    def resolve(self, run_id, participant_id, room_instance):
        owner = self.identity; scope = owner.active
        if scope is not None and scope.capability is not None:
            result = owner.resolver.resolve_locked(scope.capability, run_id, participant_id, room_instance)
        else:
            result = owner.resolver.resolve(run_id, participant_id, room_instance)
        if scope is not None: scope.capture_source(result)
        return result

    def current(self, source):
        result = self.resolve(source['run_id'], source['participant_id'], source['room_instance'])
        if result != source: raise LedgerError('GATE_SOURCE_CHANGED')
        return result


class NativeReviewAcceptance:
    """Single invocation; neither this object nor its observations are wire data."""
    def __init__(self, host, ingress, record, envelope, *, human_fence=None, host_poll=False):
        from .manager_actions import OwnerFence
        if (type(host) is not NativeReviewHost or type(host_poll) is not bool or human_fence is None and not host_poll and ingress not in host.identity.ingresses
                or host_poll and (ingress is not None or record is not None or human_fence is not None)
                or human_fence is not None and (type(human_fence) is not OwnerFence
                    or human_fence.ledger is not host.identity.ledger
                    or human_fence.supervisor is not host.identity.supervisor
                    or human_fence.value != envelope or ingress is not None or record is not None)):
            raise LedgerError('INVALID_NATIVE_REVIEW_SCOPE')
        self.host, self.identity, self.gates = host, host.identity, host.gates
        self.ingress, self.record = ingress, record
        from .review_broker import review_origin
        self.human_fence, self.host_poll = human_fence, host_poll
        self.origin = (review_origin(host.identity.binding.room_instance) if host_poll else
                       ingress.origin if ingress is not None else human_fence.session.human)
        self.admission_operation = (ingress.binding.operation_id if ingress is not None else
                                    'native-review-poll' if host_poll else 'native-review-human')
        self.envelope = deepcopy(envelope); self.digest = _digest(envelope)
        self.phase = 'new'; self.capability = self.state = None
        self.eligibility = None
        self.sources, self.refreshes, self.finished, self.views = {}, {}, set(), []

    def require_observing(self):
        if self.phase != 'observing' or self.identity.active is not self:
            raise LedgerError('INVALID_NATIVE_REVIEW_SCOPE')

    def authorize(self):
        if self.phase not in ('observing','consuming') or self.identity.active is not self:
            return False
        if self.host_poll:
            room = self.identity.supervisor._read()
            if (not room or room['phase'] != 'running' or room['instance_id'] != self.identity.binding.room_instance):
                return False
            # Service observation is not a new Participant action. Existing
            # native authorities/controller must still be held and current.
            for ingress in self.identity.ingresses:
                self.identity.seat_current(ingress,self.identity._state())
        elif self.human_fence is not None:
            if not self.human_fence.authorize(): return False
        else:
            self.ingress._current(self.record)
            self.identity.seat_current(self.ingress, self.identity._state(), self.envelope['run_id'], self.envelope['generation'])
        return _digest(self.envelope) == self.digest

    @contextmanager
    def operation(self, admission_operation):
        self.gates._require_owner()
        if self.phase != 'new' or self.identity.active is not None or admission_operation != self.admission_operation:
            raise LedgerError('INVALID_NATIVE_REVIEW_SCOPE')
        self.identity.active = self; self.phase = 'observing'
        try:
            if not self.authorize(): raise LedgerError('FORBIDDEN')
            state = self.identity._state(); run = state.get('runs', {}).get(self.envelope['run_id'])
            if not run: raise LedgerError('REVIEW_RUN_STALE')
            self.host.sources.resolve(run['run_id'], run['participant_id'], self.identity.binding.room_instance)
            yield
        finally:
            self.phase = 'closed'; self.identity.active = None
            self.capability = self.state = None
            self.sources.clear(); self.refreshes.clear(); self.finished.clear(); self.views.clear()

    def capture_source(self, source):
        key = (source['run_id'],source['participant_id'],source['room_instance'])
        if self.phase == 'consuming' and key not in self.sources:
            raise LedgerError('GATE_SOURCE_NOT_PREPARED')
        if key in self.sources and self.sources[key] != source:
            raise LedgerError('GATE_SOURCE_CHANGED')
        if self.phase not in ('observing','consuming'):
            raise LedgerError('INVALID_NATIVE_REVIEW_SCOPE')
        self.sources[key] = deepcopy(source)

    def capture_refresh(self, row, operation):
        self.require_observing()
        refresh = row.get('refresh', {})
        if refresh.get('operation_id') != operation or refresh.get('phase') != 'TERMINAL':
            raise LedgerError('INVALID_NATIVE_REVIEW_SCOPE')
        self.refreshes[(row['evaluation_id'],operation)] = deepcopy(row)

    def finish_refresh(self, evaluation, operation):
        if (evaluation,operation) not in self.refreshes:
            raise LedgerError('INVALID_NATIVE_REVIEW_SCOPE')
        self.finished.add((evaluation,operation))

    def refreshed_rows(self, rows):
        result = deepcopy(rows)
        for key in self.finished:
            if key[0] in result: result[key[0]] = deepcopy(self.refreshes[key])
        return result

    def capture_gates(self, view, rows, origin):
        self.require_observing()
        self.views.append((deepcopy(view),deepcopy(rows),origin))

    @contextmanager
    def commit(self):
        self.require_observing()
        if self.eligibility is not None: raise LedgerError('NATIVE_REVIEW_READ_ONLY')
        with self.identity.supervisor._locked() as cap:
            with self.identity.provenance.history_fence():
                self.capability = cap; self.phase = 'consuming'
                try:
                    if not self.authorize(): raise LedgerError('FORBIDDEN')
                    for key, source in tuple(self.sources.items()):
                        if self.identity.resolver.resolve_locked(cap, *key) != source:
                            raise LedgerError('GATE_SOURCE_CHANGED')
                    yield
                finally:
                    self.capability = self.state = None; self.phase = 'observing'

    def check_state(self, state):
        self.state = state
        if not self.authorize(): raise LedgerError('FORBIDDEN')
        for view, rows, origin in self.views:
            self.gates.validate_native_operation(state, view, rows, origin=origin)


class NativeReviewHost:
    """Concrete native owner, not a callback accepting claims from isolated Hub."""
    def __init__(self, ingresses, ledger, provenance, resolver, binding, *, reviewers, human_mergers):
        self.identity = NativeReviewIdentity(tuple(ingresses), ledger, provenance, resolver, binding)
        self.sources = NativeReviewSources(self.identity)
        self.gate_workflow = None
        client = self.identity.ingresses[0].client
        self.broker = ReviewBrokerClient(client)
        from .diff_target import DiffSourceResolver
        self.diff_sources = DiffSourceResolver(self.sources)
        self.gates = GateHub(ledger,binding,self.sources,authorize=self.authorize,identity=self.identity,
                             forge=GateForgeBrokerClient(client), repository=self.sources, diff=self.diff_sources)
        self.reviews = RunReview(ledger,self.gates,self.identity,self.broker,reviewers=reviewers,
            target_fence=self.unavailable_target,authorize_human=self.authorize_human,
            human_mergers=human_mergers,native_host=self)
        if any(getattr(ingress,'review_host',None) is not None for ingress in self.identity.ingresses):
            raise LedgerError('NATIVE_REVIEW_ALREADY_ATTACHED')
        for ingress in self.identity.ingresses: ingress.review_host = self

    @contextmanager
    def unavailable_target(self):
        raise LedgerError('NATIVE_REVIEW_SCOPE_REQUIRED')
        yield

    def authorize_human(self, origin):
        scope = self.identity.active
        if scope is not None and scope.eligibility is not None:
            session, action = scope.eligibility
            return origin == session.human and session.allowed(action)
        return (scope is not None and scope.human_fence is not None
                and origin == scope.human_fence.session.human and scope.human_fence.authorize())

    def authorize(self, origin, command):
        scope = self.identity.active
        return scope is not None and origin.canonical() == scope.origin.canonical() and scope.authorize()

    def submit(self, ingress, record, envelope):
        self.gates._require_owner()
        if envelope.get('kind') not in ('submit-for-review','review-result'):
            raise LedgerError('INVALID_REVIEW_COMMAND')
        scope = NativeReviewAcceptance(self,ingress,record,envelope)
        return self.reviews.submit(envelope,origin=ingress.origin,authorize=scope.authorize,
                                   admission_operation=ingress.binding.operation_id,_native_scope=scope)

    def prepare_submission(self, command, origin):
        if self.gate_workflow is not None:
            from .native_gate_workflow import NativeGateWorkflow
            if type(self.gate_workflow) is not NativeGateWorkflow or self.gate_workflow.host is not self:
                raise LedgerError('EXACT_NATIVE_GATE_WORKFLOW_REQUIRED')
            self.gate_workflow.prepare_submission(command, origin)

    def prepare_completion(self,command,origin):
        if self.gate_workflow is not None:
            from .native_gate_workflow import NativeGateWorkflow
            if type(self.gate_workflow) is not NativeGateWorkflow or self.gate_workflow.host is not self:
                raise LedgerError('EXACT_NATIVE_GATE_WORKFLOW_REQUIRED')
            self.gate_workflow.prepare_completion(command,origin)

    def human_action(self, value, *, session, audit):
        """Existing authenticated Manager vocabulary; never a native tool route."""
        self.gates._require_owner()
        from .manager_actions import HumanSession, OwnerFence, REVIEW_ACTIONS
        from .forge_audit import ForgeAudit
        from .native_broker_audit import NativeBrokerAudit
        if (type(session) is not HumanSession or type(audit) not in (ForgeAudit, NativeBrokerAudit)
                or session.room_id != self.identity.binding.room_id
                or session.instance_id != self.identity.binding.room_instance
                or audit.deployment_id != session.deployment_id
                or type(audit) is NativeBrokerAudit and (audit.session is not session
                    or audit.client is not self.identity.ingresses[0].client)):
            raise LedgerError('MANAGER_AUTHENTICATION_REQUIRED')
        fence = OwnerFence(self.identity.ledger,session,value,REVIEW_ACTIONS,audit=audit,
                           repository=self.identity.binding.repository,supervisor=self.identity.supervisor)
        scope = NativeReviewAcceptance(self,None,None,fence.value,human_fence=fence)
        with scope.operation(scope.admission_operation):
            return self.reviews.manager_action(value,session=session,admission_operation=scope.admission_operation,
                audit=audit,repository=self.identity.binding.repository,supervisor=self.identity.supervisor)

    def human_eligibility(self, action, run_id, *, session):
        """Read-only existing Manager eligibility with an actual HumanSession."""
        self.gates._require_owner()
        from .manager_actions import HumanSession, REVIEW_ACTIONS
        if (type(session) is not HumanSession or action not in REVIEW_ACTIONS
                or session.room_id != self.identity.binding.room_id
                or session.instance_id != self.identity.binding.room_instance
                or not session.allowed(action)):
            raise LedgerError('MANAGER_AUTHENTICATION_REQUIRED')
        run = self.identity.ledger.snapshot()['state'].get('runs', {}).get(run_id)
        if not run: raise LedgerError('UNKNOWN_RUN')
        scope = NativeReviewAcceptance(self,None,None,{'run_id':run_id,'generation':run['generation']},host_poll=True)
        scope.eligibility = (session,action)
        with scope.operation(scope.admission_operation):
            return self.reviews.manager_eligibility(action,run_id,session=session,
                admission_operation=scope.admission_operation,supervisor=self.identity.supervisor)

    def observe_completion(self, operation_id, run_id, generation, submission_id, *, observation_id=None):
        """Trusted host poll only; observes human merge, never performs a merge."""
        self.gates._require_owner()
        from .ledger import _token
        if type(generation) is not int or not 1 <= generation < 2**53:
            raise LedgerError('INVALID_REVIEW_COMMAND')
        envelope = {'id':_token(operation_id),'run_id':_token(run_id),'generation':generation,
                    'submission_id':_token(submission_id),'observation_id':observation_id}
        scope = NativeReviewAcceptance(self,None,None,envelope,host_poll=True)
        with scope.operation(scope.admission_operation):
            return self.reviews.complete(operation_id,run_id,generation,submission_id,origin=scope.origin,
                authorize=scope.authorize,admission_operation=scope.admission_operation,observation_id=observation_id)


class NativeReviewStartup:
    """Explicit trusted startup input consumed by NativeClaudeRoot.initialize_helper.

    The ledger is the host connection to the already selected Hub Room database,
    not a new database path or copied state. No defaults invent credentials,
    reviewer GitHub identities, human merger policy or missing Git history.
    """
    def __init__(self, pi_ingress, ledger, provenance, resolver, binding, *, reviewers, human_mergers):
        if type(pi_ingress) is not NativePiHostForge:
            raise LedgerError('NATIVE_PI_REVIEW_BINDING_REQUIRED')
        self.pi_ingress, self.ledger, self.provenance = pi_ingress, ledger, provenance
        self.resolver, self.binding = resolver, binding
        self.reviewers, self.human_mergers = deepcopy(reviewers), tuple(human_mergers)
        self._used = False

    def attach(self, claude_ingress):
        if self._used or type(claude_ingress) is not NativeHostForge:
            raise LedgerError('NATIVE_REVIEW_STARTUP_ALREADY_USED')
        self._used = True
        return NativeReviewHost((self.pi_ingress,claude_ingress),self.ledger,self.provenance,self.resolver,
            self.binding,reviewers=self.reviewers,human_mergers=self.human_mergers)
