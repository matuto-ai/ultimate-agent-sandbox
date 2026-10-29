"""Co-located trusted Gate transport over the existing operational service.

No evaluator/profile admission is supplied by this facade. Its service must be
assembled by the native qualification owner with real target/resource leases.
Verdicts and scratch reservations remain the canonical GateHub's responsibility.
"""
import uuid

from .artifact_helper import (GateSupervisorService, GateHelperLaunch, GateOffer,
    BOOTSTRAPS, DIFF_PROFILE, PROFILE_ID, MAX_EVALUATIONS, _profile_target,
    _profile_request)
from .artifact_protocol import ArtifactError, canonical, validate_scope, profile_scope_digest
from .native_review_host import NativeReviewHost, NativeReviewSources, NativeReviewAcceptance
from .diff_target import DiffSourceResolver


class NativeGateControl:
    def __init__(self, host, service, *, profile=PROFILE_ID):
        if (type(host) is not NativeReviewHost or type(service) is not GateSupervisorService
                or profile not in BOOTSTRAPS or service.profile != profile):
            raise ArtifactError('TRUSTED_NATIVE_GATE_SERVICE_REQUIRED')
        sources = host.diff_sources if profile == DIFF_PROFILE else host.sources
        if (type(host.sources) is not NativeReviewSources
                or host.sources.identity is not host.identity
                or profile == DIFF_PROFILE and (type(sources) is not DiffSourceResolver or sources.resolver is not host.sources)
                or service.resolver is not sources):
            raise ArtifactError('NATIVE_GATE_SOURCE_OWNER_MISMATCH')
        self.host, self.service, self.sources, self.profile = host, service, sources, profile
        self.controller = uuid.uuid4().hex  # local correlation only, not authority
        self._offers = {}
        self._closed = False

    def _call(self, command, payload):
        if self._closed:
            raise ArtifactError('NATIVE_GATE_CONTROL_CLOSED')
        expected = self.host.diff_sources if self.profile == DIFF_PROFILE else self.host.sources
        if (self.service.resolver is not self.sources or expected is not self.sources
                or self.service.profile != self.profile
                or self.profile == DIFF_PROFILE and self.sources.resolver is not self.host.sources
                or self.host.sources.identity is not self.host.identity):
            raise ArtifactError('NATIVE_GATE_SOURCE_OWNER_MISMATCH')
        return self.service.handle(command, payload)

    def _effect(self, scope):
        active = self.host.identity.active
        if (type(active) is not NativeReviewAcceptance or active.host is not self.host
                or active.identity is not self.host.identity or active.phase != 'observing'
                or active.capability is not None
                or scope['room_id'] != self.host.identity.binding.room_id
                or scope['room_instance'] != self.host.identity.binding.room_instance
                or scope['run_id'] != active.envelope['run_id']
                or scope['generation'] != active.envelope['generation']):
            raise ArtifactError('NATIVE_GATE_ACTIVE_SCOPE_REQUIRED')
        # Currentness cut only: release lifecycle/Git locks before materializing
        # targets or calling Engine. Canonical success consumption rechecks them.
        workflow = getattr(self.host, 'gate_workflow', None)
        if workflow is not None:
            from .native_gate_workflow import NativeGateWorkflow
            if type(workflow) is not NativeGateWorkflow or workflow.host is not self.host or workflow.active is None:
                raise ArtifactError('NATIVE_GATE_ACTIVE_SCOPE_REQUIRED')
            fence = workflow.commit(self.host.gates)
        else:
            fence = active.commit()
        with fence:
            pass

    def resolve(self, run_id, participant_id, room_instance, subject=None):
        payload = {'run_id': run_id, 'participant_id': participant_id, 'room_instance': room_instance}
        if self.profile == DIFF_PROFILE:
            payload['subject'] = subject
        elif subject is not None:
            raise ArtifactError('UNSUPPORTED_GATE_SUBJECT')
        return self._call('resolve', payload)

    def current(self, source):
        return self._call('current', {'source': source})

    def prepare(self, scope, source):
        validate_scope(scope)
        self._effect(scope)
        return _profile_target(self.profile, self._call('prepare', {'scope': scope, 'source': source}))

    def start(self, scope, target, paths):
        validate_scope(scope); _profile_target(self.profile, target); _profile_request(self.profile, paths)
        evaluation = scope['evaluation_id']
        if evaluation in self._offers or len(self._offers) >= MAX_EVALUATIONS:
            raise ArtifactError('GATE_START_ALREADY_ATTEMPTED')
        self._effect(scope)
        self._offers[evaluation] = None
        launch = self._call('start', {'scope': scope, 'target': target})
        if (type(launch) is not GateHelperLaunch or launch.workstation.profile != self.profile
                or canonical(launch.scope) != canonical(scope)
                or canonical(launch.target) != canonical(target)):
            raise ArtifactError('TRUSTED_GATE_LAUNCH_REQUIRED')
        offer = launch.local_offer(paths, exchange_id=uuid.uuid4().hex, controller=self.controller)
        self._offers[evaluation] = offer
        return offer

    def finish(self, target, offer):
        if (type(offer) is not GateOffer or offer.state != 'exited'
                or canonical(target) != canonical(offer.target)
                or self._offers.get(offer.scope['evaluation_id']) is not offer):
            raise ArtifactError('GATE_EXITED_OFFER_REQUIRED')
        return self._call('finish', {'evaluation_id': offer.scope['evaluation_id'],
            'target': target, 'final_digest': profile_scope_digest(self.profile, offer.scope, target)})

    def abort(self, evaluation_id, target=None, offer=None):
        if offer is not None and (type(offer) is not GateOffer
                or self._offers.get(evaluation_id) is not offer):
            raise ArtifactError('GATE_OFFER_BINDING_MISMATCH')
        return self._call('abort', {'evaluation_id': evaluation_id, 'target': target})

    def reconcile(self, evaluation_id):
        return self._call('reconcile', {'evaluation_id': evaluation_id})
