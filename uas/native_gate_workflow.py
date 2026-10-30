"""Trusted native review preparation, not a Participant Gate endpoint.

The existing original submission chooses a proposal only. Canonical target
verification/evaluators retain their own durable intents and verdict reducers.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib

from .artifact_helper import PROFILE_ID, COMMAND_PROFILE, DIFF_PROFILE
from .gate_evaluation import _digest
from .gate_forge import validate_forge_target
from .ledger import Command, Event, LedgerError, Transition
from .native_review_host import NativeReviewHost, NativeReviewAcceptance
from .native_gate_control import NativeGateControl


def _id(prefix, value):
    return prefix + hashlib.sha256(value.encode()).hexdigest()


def _run_pin(run):
    return {key: deepcopy(run.get(key)) for key in (
        'run_id','generation','status','actor_id','participant_id','project_id',
        'repository','policy','checkout','control_pending','control_revision')}


class _Preparation:
    def __init__(self, owner, command, origin):
        scope=owner.host.identity.active
        if (type(scope) is not NativeReviewAcceptance or scope.host is not owner.host
                or scope.ingress is None or origin != scope.ingress.origin
                or command.canonical() != Command(scope.envelope['id'],
                    'review.'+scope.envelope['kind'],scope.envelope['run_id'],
                    scope.envelope['generation'],deepcopy(scope.envelope['payload'])).canonical()
                or command.kind!='review.submit-for-review'):
            raise LedgerError('NATIVE_GATE_PREPARATION_SCOPE_REQUIRED')
        scope.require_observing()
        self.owner,self.scope,self.command,self.origin=owner,scope,command,origin
        self.operation=_id('native-gate-prepare-',command.id)
        self.binding_id=_id('native-gate-bind-',command.id)
        self.target=validate_forge_target(command.payload['target'])
        self.pin=None

    def require(self,state):
        if self.owner.active is not self or self.owner.host.identity.active is not self.scope:
            raise LedgerError('NATIVE_GATE_PREPARATION_SCOPE_REQUIRED')
        run=state.get('runs',{}).get(self.command.target)
        if (run is None or run['status']!='ACTIVE' or run['generation']!=self.command.generation
                or run.get('control_pending') or run['actor_id']!=self.origin.actor_id
                or run['participant_id']!=self.origin.participant_id
                or 'implement' not in self.origin.capabilities):
            raise LedgerError('REVIEW_IMPLEMENTER_REQUIRED')
        if self.pin is not None:
            if _run_pin(run)!=self.pin['run']:
                raise LedgerError('NATIVE_GATE_PREPARATION_STALE')
            key=(run['run_id'],run['participant_id'],self.owner.host.identity.binding.room_instance)
            if self.scope.sources.get(key)!=self.pin['source']:
                raise LedgerError('GATE_SOURCE_CHANGED')
            prior=(run.get('gate_target'),run.get('gate_target_binding')) == (
                self.pin['prior_target'],self.pin['prior_binding'])
            row=state.get('gate_target_bindings',{}).get(self.binding_id)
            own=(type(row) is dict and row.get('phase')=='TERMINAL'
                and row.get('result',{}).get('status')=='BOUND' and row.get('target')==self.target
                and row.get('source')==self.pin['source'] and row.get('origin')==self.origin.canonical()
                and run.get('gate_target')==self.target
                and run.get('gate_target_binding',{}).get('operation_id')==self.binding_id)
            if not prior and not own:raise LedgerError('GATE_TARGET_BINDING_CONFLICT')
        return run

    def reserve(self):
        ledger=self.owner.host.identity.ledger
        expected=self.command.canonical()
        def authorized(*_):
            self.scope.check_state(ledger.snapshot()['state']);self.require(ledger.snapshot()['state'])
            return self.scope.authorize() is True
        def matches(command):
            return (command.kind=='native.review-prepare' and command.target==self.command.target
                and command.generation==self.command.generation and command.payload=={'command':expected})
        with self.scope.commit():
            receipt=ledger.matched_receipt(self.operation,self.origin,authorize=authorized,matches=matches)
            if receipt is not None:
                self.pin=deepcopy(receipt['result']);self.require(ledger.snapshot()['state']);return
            intent=Command(self.operation,'native.review-prepare',self.command.target,
                           self.command.generation,{'command':expected})
            def decide(state,_):
                run=self.require(state);self.scope.check_state(state)
                key=(run['run_id'],run['participant_id'],self.owner.host.identity.binding.room_instance)
                source=self.scope.sources.get(key)
                if source is None:raise LedgerError('GATE_SOURCE_NOT_PREPARED')
                pin=self.capture_pin(state,run,source)
                return Transition(state,(Event('native.review-preparation-reserved',
                    {'operation_id':self.operation,'submission_id':self.command.id}),),pin)
            receipt=ledger.apply(intent,self.origin,authorize=authorized,decide=decide)
            self.pin=deepcopy(receipt['result'])


    def capture_pin(self,state,run,source):
        return {'run':_run_pin(run),'source':deepcopy(source),
                'prior_target':deepcopy(run.get('gate_target')),
                'prior_binding':deepcopy(run.get('gate_target_binding'))}


class _CompletionPreparation(_Preparation):
    """Service-owned completion preparation, never Participant bind authority."""
    def __init__(self,owner,command,origin):
        from .review_broker import review_origin
        scope=owner.host.identity.active
        expected=(Command(scope.envelope['id'],'review.observe-completion',
            scope.envelope['run_id'],scope.envelope['generation'],
            {'submission_id':scope.envelope['submission_id']})
            if type(scope) is NativeReviewAcceptance and scope.host_poll else None)
        if (expected is None or scope.host is not owner.host or scope.ingress is not None
                or origin != review_origin(owner.host.identity.binding.room_instance)
                or command.canonical()!=expected.canonical()):
            raise LedgerError('NATIVE_GATE_COMPLETION_SCOPE_REQUIRED')
        scope.require_observing()
        self.owner,self.scope,self.command,self.origin=owner,scope,command,origin
        self.operation=_id('native-gate-complete-prepare-',command.id)
        self.binding_id=None
        self.pin=None

    def require(self,state):
        if self.owner.active is not self or self.owner.host.identity.active is not self.scope:
            raise LedgerError('NATIVE_GATE_COMPLETION_SCOPE_REQUIRED')
        run=self.owner.host.reviews._run(state,self.command.target,self.command.generation)
        row=state.get('run_reviews',{}).get(self.command.target,{}).get('current')
        if (not row or row['submission_id']!=self.command.payload['submission_id']
                or row['generation']!=self.command.generation
                or row['stage'] not in {'READY_FOR_HUMAN','ATTENTION'}
                or not (row['result']=='pass' or row.get('override_id'))):
            raise LedgerError('REVIEW_PASS_REQUIRED')
        self.owner.host.reviews._target(run,row['target'])
        if not row.get('override_id'):
            self.owner.host.reviews._fact(run,row['reviewer']['actor_id'],row['reviewer']['authority_epoch'])
        if self.pin is not None:
            key=(run['run_id'],run['participant_id'],self.owner.host.identity.binding.room_instance)
            if (_run_pin(run)!=self.pin['run'] or row!=self.pin['review']
                    or run.get('gate_target')!=self.pin['prior_target']
                    or run.get('gate_target_binding')!=self.pin['prior_binding']):
                raise LedgerError('REVIEW_COMPLETION_STALE')
            if self.scope.sources.get(key)!=self.pin['source']:
                raise LedgerError('GATE_SOURCE_CHANGED')
        return run

    def capture_pin(self,state,run,source):
        return {**super().capture_pin(state,run,source),
                'review':deepcopy(state['run_reviews'][run['run_id']]['current'])}


class NativeGateWorkflow:
    """One exact co-located workflow owner; absent profiles never become passes."""
    def __init__(self, host, artifact_control, *, command_control=None, diff_control=None):
        if type(host) is not NativeReviewHost or getattr(host,'gate_workflow',None) is not None:
            raise LedgerError('EXACT_NATIVE_GATE_WORKFLOW_REQUIRED')
        controls=((artifact_control,PROFILE_ID),(command_control,COMMAND_PROFILE),(diff_control,DIFF_PROFILE))
        for control,profile in controls:
            if control is None and profile!=PROFILE_ID:continue
            if type(control) is not NativeGateControl or control.host is not host or control.profile!=profile:
                raise LedgerError('EXACT_NATIVE_GATE_CONTROL_REQUIRED')
        host.gates._require_owner()
        self.host,self.active=host,None
        self.controls={profile:control for control,profile in controls}
        # All validation precedes attachment; default-deny target authority is
        # never replaced by a partially constructed resource composition.
        host.gates.control=artifact_control
        if command_control is not None:host.gates.repository_hub.control=command_control
        if diff_control is not None:host.gates.diff_hub.control=diff_control
        for gates in (host.gates,host.gates.repository_hub,host.gates.diff_hub):
            if gates is not None:gates._native_workflow=self
        host.gates.authorize_target=self.authorize_target
        host.gate_workflow=self

    @contextmanager
    def commit(self, gates):
        if gates not in (self.host.gates,self.host.gates.repository_hub,self.host.gates.diff_hub) or self.active is None:
            raise LedgerError('NATIVE_GATE_PREPARATION_SCOPE_REQUIRED')
        with self.active.scope.commit():
            self.active.require(self.host.identity.ledger.snapshot()['state'])
            yield

    def check_state(self,state):
        if self.active is None:raise LedgerError('NATIVE_GATE_PREPARATION_SCOPE_REQUIRED')
        self.active.scope.check_state(state);self.active.require(state)

    def authorize_target(self,origin,command):
        prep=self.active
        if (type(prep) is not _Preparation or origin!=prep.origin or command.kind!='gate.bind-target'
                or command.id!=prep.binding_id or command.target!=prep.command.target
                or command.generation!=prep.command.generation
                or command.payload!={'target':prep.target,'expected_binding':
                    None if prep.pin['prior_target'] is None else _digest(prep.pin['prior_target'])}):
            return False
        try:
            if prep.scope.phase=='consuming':
                self.check_state(self.host.identity.ledger.snapshot()['state'])
                return prep.scope.authorize() is True
            with self.commit(self.host.gates):return prep.scope.authorize() is True
        except Exception:return False

    def prepare_submission(self,command,origin):
        self.host.gates._require_owner()
        if self.active is not None:raise LedgerError('NATIVE_GATE_PREPARATION_IN_FLIGHT')
        prep=_Preparation(self,command,origin);self.active=prep
        try:
            prep.reserve()
            result=self.host.gates.bind_target(prep.binding_id,command.target,command.generation,
                prep.target,origin=origin,expected_binding=None if prep.pin['prior_target'] is None else _digest(prep.pin['prior_target']))
            if result.get('status')!='BOUND':raise LedgerError('NATIVE_GATE_TARGET_UNAVAILABLE')
            with self.commit(self.host.gates):
                run=deepcopy(prep.require(self.host.identity.ledger.snapshot()['state']))
            for gate in run['policy']['gates']:
                if gate['kind']!='mechanical' or 'submit-for-review' not in gate['guarded_operations']:continue
                profile={'artifacts':PROFILE_ID,'command':COMMAND_PROFILE,'diff-claims':DIFF_PROFILE}.get(gate['evaluator'])
                if profile is not None and self.controls.get(profile) is None:
                    raise LedgerError('NATIVE_GATE_PROFILE_UNAVAILABLE')
                operation=_id('native-gate-evaluate-',command.id+':'+gate['id'])
                evaluation=self.host.gates.evaluate(operation,command.target,command.generation,gate['id'],origin=origin)
                if evaluation.get('phase')!='TERMINAL' or evaluation.get('result',{}).get('verdict')=='error':
                    raise LedgerError('NATIVE_GATE_EVALUATION_UNAVAILABLE')
            with self.commit(self.host.gates):prep.require(self.host.identity.ledger.snapshot()['state'])
        finally:self.active=None


    def prepare_completion(self,command,origin):
        self.host.gates._require_owner()
        if self.active is not None:raise LedgerError('NATIVE_GATE_PREPARATION_IN_FLIGHT')
        prep=_CompletionPreparation(self,command,origin);self.active=prep
        try:
            prep.reserve()
            with self.commit(self.host.gates):
                run=deepcopy(prep.require(self.host.identity.ledger.snapshot()['state']))
            for gate in run['policy']['gates']:
                if (gate['kind']!='mechanical' or 'complete' not in gate['guarded_operations']
                        or 'submit-for-review' in gate['guarded_operations']):continue
                profile={'artifacts':PROFILE_ID,'command':COMMAND_PROFILE,'diff-claims':DIFF_PROFILE}.get(gate['evaluator'])
                if profile is not None and self.controls.get(profile) is None:
                    raise LedgerError('NATIVE_GATE_PROFILE_UNAVAILABLE')
                # Merge polls are not evaluator retries. Every poll for this exact
                # submission/candidate shares the original immutable attempt.
                key={'room':self.host.identity.binding.room_id,
                     'instance':self.host.identity.binding.room_instance,
                     'run':command.target,'generation':command.generation,
                     'submission':command.payload['submission_id'],
                     'target':prep.pin['prior_target'],'gate':gate['id']}
                operation='native-gate-complete-'+_digest(key)
                evaluation=self.host.gates.evaluate(operation,command.target,command.generation,gate['id'],origin=origin)
                if evaluation.get('phase')!='TERMINAL' or evaluation.get('result',{}).get('verdict')=='error':
                    raise LedgerError('NATIVE_GATE_EVALUATION_UNAVAILABLE')
            with self.commit(self.host.gates):prep.require(self.host.identity.ledger.snapshot()['state'])
        finally:self.active=None
