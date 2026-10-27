"""Canonical, revision-bound review workflow over the Room ledger.

Typed Participant statements are proposals. The admitted origin, known Actor
history, protected-operation Gates and audited Broker observations establish
facts. Native prose never chooses a verdict. No process or provider is launched
by this module; the trusted host supplies the existing fenced owners.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib

from .ledger import Command, Event, LedgerError, Origin, Transition, _json, _token
from .gate_hub import identity_fact, require_operation_gates
from .gate_forge import validate_forge_target
from .forge_projections import enqueue_run_projection, _capacity
from .peer import _now, TERMINAL


MAX_ATTEMPTS = 128
VERDICTS = {'pass': 'APPROVED', 'changes-requested': 'CHANGES_REQUESTED',
            'human-needed': 'COMMENTED'}


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _id(prefix, operation):
    return prefix + _digest(operation)


def _evidence(value):
    if (type(value) is not list or not 1 <= len(value) <= 64
            or any(type(item) is not str for item in value) or len(set(value)) != len(value)):
        raise LedgerError('INVALID_REVIEW_EVIDENCE')
    for item in value:
        _token(item)
    return deepcopy(value)


class RunReview:
    """A trusted host-owned reducer, sharing the exact Gate/Participant ledger.

    ``target_fence`` holds the existing source/worktree authority across reads
    and the consuming transaction. ``identity.operation_fence`` holds admitted
    Actor and controlled Git history authority. Neither can be supplied in a
    Participant packet. Reviewer configuration is fixed at host construction.
    Broker methods must be durable/idempotent, including uncertain outcomes.
    """
    def __init__(self, ledger, gates, identity, broker, *, reviewers, target_fence,
                 authorize_human, human_mergers):
        if (gates.ledger is not ledger or gates.identity is not identity
                or not callable(getattr(identity, 'operation_fence', None))
                or not callable(target_fence) or not callable(authorize_human)):
            raise LedgerError('INVALID_REVIEW_OWNER')
        if type(reviewers) is not list or len(reviewers) > 64:
            raise LedgerError('INVALID_REVIEWER_CONFIGURATION')
        seen = set()
        for seat in reviewers:
            if (type(seat) is not dict or set(seat) != {'actor_id', 'participant_id', 'github_user_id'}
                    or type(seat['github_user_id']) is not int or seat['github_user_id'] <= 0
                    or seat['participant_id'] in seen):
                raise LedgerError('INVALID_REVIEWER_CONFIGURATION')
            _token(seat['actor_id']); _token(seat['participant_id']); seen.add(seat['participant_id'])
        if (type(human_mergers) not in (list, tuple) or not human_mergers
                or any(type(x) is not int or x <= 0 for x in human_mergers)):
            raise LedgerError('INVALID_HUMAN_MERGER_POLICY')
        self.ledger, self.gates, self.identity, self.broker = ledger, gates, identity, broker
        self.reviewers, self.target_fence = deepcopy(reviewers), target_fence
        self.authorize_human, self.human_mergers = authorize_human, frozenset(human_mergers)

    @contextmanager
    def _fence(self, admission_operation):
        with self.identity.operation_fence(admission_operation):
            with self.target_fence():
                yield

    @staticmethod
    def _run(state, run_id, generation, *, paused=False):
        run = state.get('runs', {}).get(run_id)
        if (run is None or run.get('generation') != generation
                or run.get('status') not in ({'ACTIVE', 'PAUSED'} if paused else {'ACTIVE'})
                or run.get('control_pending')):
            raise LedgerError('REVIEW_RUN_STALE')
        return run

    @staticmethod
    def _target(run, target):
        target = validate_forge_target(target)
        if (target != run.get('gate_target') or target['repository'] != run['repository']
                or not run.get('gate_target_binding')):
            raise LedgerError('REVIEW_TARGET_NOT_BOUND')
        return target

    @staticmethod
    def _scope(run):
        return _digest({k: run.get(k) for k in ('run_id', 'generation', 'status', 'actor_id',
            'participant_id', 'policy', 'checkout', 'gate_target', 'gate_target_binding', 'control_pending', 'control_revision')})

    def _apply(self, command, origin, authorize, decide):
        return self.ledger.apply(command, origin, authorize=lambda *_: authorize() is True,
                                 decide=decide)['result']

    def _receipt(self, command, origin, authorize):
        receipt = self.ledger.exact_receipt(command, origin, authorize=lambda *_: authorize() is True)
        return None if receipt is None else receipt['result']

    def _finish(self, state, run, kind, result, events=()):
        review = state.get('run_reviews', {}).get(run['run_id'])
        if review and review['current']:
            review['current']['updated_at'] = _now()
            for index, attempt in enumerate(review['attempts']):
                if attempt['submission_id'] == review['current']['submission_id']:
                    review['attempts'][index] = deepcopy(review['current'])
                    break
        projection = enqueue_run_projection(state, self.ledger.room_id, run['run_id']) if 'issue_id' in run else None
        events = tuple(events) + (Event(kind, deepcopy(result)),)
        if projection is not None: events += (projection,)
        _capacity(state)
        return Transition(state, events, deepcopy(result))

    def _request(self, state, run, operation, recipient, text, actor):
        """Same canonical peer outbox and immutable delivery receipts as #68/#69."""
        domain = state.get('peer_traffic')
        if domain is None or recipient not in domain['definition']['participants']:
            raise LedgerError('REVIEW_PARTICIPANT_UNAVAILABLE')
        request_id = _id('review-request-', operation)
        if request_id in domain['traffic']:
            raise LedgerError('ID_CONFLICT')
        domain['traffic'][request_id] = {'id': request_id, 'kind': 'peer.work-request',
            'sender': 'run-hub', 'actor_id': actor, 'run_id': run['run_id'],
            'generation': run['generation'], 'recipients': [recipient], 'text': text,
            'parent_id': None, 'correlation_id': request_id, 'submitted_at': _now(),
            'submitted_seq': self.ledger.snapshot()['room_seq'] + 1, 'deliveries': {},
            'status': 'QUEUED', 'response_started_at': None, 'reason': None, 'attention': None}
        return request_id, Event('peer.submitted', {'traffic_id': request_id, 'recipients': [recipient]})

    def _fact(self, run, actor, epoch=None):
        fact = identity_fact(self.identity.read_identity(run, actor, run['gate_target']['head_sha'], epoch), actor)
        if (not fact['active'] or fact['kind'] != 'participant' or 'review' not in fact['capabilities']
                or actor == run['actor_id'] or actor in fact['contributors']
                or epoch is not None and fact['authority_epoch'] != epoch):
            raise LedgerError('REVIEWER_INELIGIBLE')
        return fact

    def _select(self, state, run):
        participants = state.get('peer_traffic', {}).get('definition', {}).get('participants', {})
        for seat in self.reviewers:
            peer = participants.get(seat['participant_id'])
            if not peer or peer['actor_id'] != seat['actor_id']: continue
            try:
                admitted = self.identity.dispatcher.reviewer_authority(seat['participant_id'], run['run_id'], run['generation'])
                if admitted.actor_id != seat['actor_id']: continue
                fact = self._fact(run, seat['actor_id'], admitted.authority_version)
            except (LedgerError, RuntimeError):
                continue
            return {**seat, 'authority_epoch': fact['authority_epoch']}
        return None

    def _observe(self, command, origin, authorize, target, *, attempt=None):
        """Intent before I/O; an interrupted exact read never invents a new key."""
        op = _id('review-observe-', [command.canonical(), None if attempt is None else _token(attempt)])
        intent = Command(op, 'review.observe-intent', command.target, command.generation, {'target': target})
        def start(state, _):
            rows = state.setdefault('review_observations', {})
            if len(rows) >= 1024: raise LedgerError('REVIEW_OBSERVATION_CAPACITY')
            rows[op] = {'target': deepcopy(target), 'response': None}
            return Transition(state, (Event('review.observation-started', {'operation_id': op}),), {'operation_id': op})
        self._apply(intent, origin, authorize, start)
        row = self.ledger.snapshot()['state']['review_observations'][op]
        if row['response'] is not None:
            raise LedgerError('REVIEW_OBSERVATION_REQUIRES_FRESH_ATTEMPT')
        # Broker owns exactly-once attempt/reconciliation, not this Room intent.
        response = self.broker.observe(target, op, authorize=authorize)
        if (type(response) is not dict or set(response) != {'audit_reference', 'observation'}
                or type(response['observation']) is not dict):
            raise LedgerError('INVALID_REVIEW_OBSERVATION')
        _token(response['audit_reference'])
        done = Command(_id('review-observed-', [command.canonical(), attempt]), 'review.observed',
                       command.target, command.generation, response)
        def finish(state, _):
            state['review_observations'][op]['response'] = deepcopy(response)
            return Transition(state, (Event('review.observed', {'operation_id': op,
                'audit_reference': response['audit_reference']}),), deepcopy(response))
        return self._apply(done, origin, authorize, finish)

    @staticmethod
    def _observed(response, target, *, merged=False):
        observation = response['observation']
        if (observation.get('status') != 'OK' or observation.get('completeness') != 'complete'
                or observation.get('target') != target):
            raise LedgerError('REVIEW_OBSERVATION_UNAVAILABLE')
        pull = observation.get('pull')
        if (type(pull) is not dict or pull.get('id') != target['pull_id']
                or pull.get('number') != target['pull_number']
                or pull.get('head', {}).get('sha') != target['head_sha']
                or pull.get('base', {}).get('sha') not in ({target['base_sha'], pull.get('merge_commit_sha')} if merged else {target['base_sha']})
                or pull.get('base', {}).get('ref') != target['base_ref']
                or pull.get('base', {}).get('repo', {}).get('full_name') != target['repository']
                or pull.get('draft') is not False or pull.get('merged') is not merged
                or pull.get('state') != ('closed' if merged else 'open')):
            raise LedgerError('REVIEW_CANDIDATE_CHANGED')
        return observation

    def submit(self, envelope, *, origin, authorize, admission_operation, observation_id=None):
        if (type(envelope) is not dict or set(envelope) not in (
                {'id', 'kind', 'run_id', 'generation', 'payload'},
                {'id', 'kind', 'run_id', 'generation', 'payload', 'observation_id'})
                or type(envelope['kind']) is not str or envelope['kind'] not in {'submit-for-review', 'review-result'}
                or type(origin) is not Origin or 'peer-traffic' not in origin.capabilities):
            raise LedgerError('INVALID_REVIEW_COMMAND')
        requested_attempt = envelope.get('observation_id')
        if requested_attempt is not None:
            _token(requested_attempt)
            if observation_id is not None and observation_id != requested_attempt:
                raise LedgerError('INVALID_REVIEW_OBSERVATION_ATTEMPT')
            observation_id = requested_attempt
        command = Command(envelope['id'], 'review.' + envelope['kind'], envelope['run_id'],
                          envelope['generation'], deepcopy(envelope['payload']))
        command.canonical()
        with self._fence(admission_operation):
            cached = self._receipt(command, origin, authorize)
            if cached is not None: return cached
            if envelope['kind'] == 'submit-for-review':
                return self._submit_review(command, origin, authorize, observation_id)
            return self._result(command, origin, authorize, observation_id)

    def _submit_review(self, command, origin, authorize, observation_id=None):
        payload = command.payload
        if type(payload) is not dict or set(payload) != {'target', 'evidence'}:
            raise LedgerError('INVALID_REVIEW_COMMAND')
        evidence = _evidence(payload['evidence'])
        state = self.ledger.snapshot()['state']; run = self._run(state, command.target, command.generation)
        if ('implement' not in origin.capabilities or origin.actor_id != run['actor_id']
                or origin.participant_id != run['participant_id']):
            raise LedgerError('REVIEW_IMPLEMENTER_REQUIRED')
        target = self._target(run, payload['target']); scope = self._scope(run)
        gate_view = self.gates.operation_gates(command.target, command.generation, 'submit-for-review', origin=origin)
        require_operation_gates(state, gate_view)
        self._observed(self._observe(command, origin, authorize, target, attempt=observation_id), target)
        selected = self._select(state, run)
        def decide(state, _):
            current = self._run(state, command.target, command.generation)
            if self._scope(current) != scope: raise LedgerError('REVIEW_RUN_STALE')
            require_operation_gates(state, gate_view)
            review = state.setdefault('run_reviews', {}).setdefault(command.target,
                {'returns': 0, 'cap': current['policy'].get('review_return_cap', 5), 'attempts': [], 'overrides': [], 'current': None})
            if len(review['attempts']) >= MAX_ATTEMPTS: raise LedgerError('REVIEW_CAPACITY')
            if review['cap'] is not None and review['returns'] >= review['cap']:
                raise LedgerError('REVIEW_RETURN_CAP')
            superseded_events = ()
            old = review['current']
            implementation_id = (old.get('implementation_request') if old and old['generation'] == command.generation
                                 else None) or current.get('implementation_request')
            if implementation_id:
                responsibility = state['peer_traffic']['traffic'].get(implementation_id)
                if (not responsibility or responsibility['run_id'] != command.target
                        or responsibility['generation'] != command.generation
                        or responsibility['recipients'] != [origin.participant_id]
                        or responsibility['status'] not in {'ACCEPTED', 'COMPLETED'}):
                    raise LedgerError('REVIEW_IMPLEMENTATION_NOT_ACCEPTED')
                if responsibility['status'] == 'ACCEPTED':
                    responsibility.update(status='COMPLETED', reason=None, attention=None)
                    superseded_events += (Event('peer.request.changed', {'request_id': implementation_id, 'status': 'COMPLETED'}),)
            if old is not None and old['stage'] in {'REVIEWING', 'READY_FOR_HUMAN'}:
                if old['target'] == target and old['generation'] == command.generation:
                    raise LedgerError('REVIEW_ALREADY_ACTIVE')
                # A newly verified Gate subject supersedes, never inherits, the
                # prior approval/responsibility. This consumes no review return.
                old.update(stage='SUPERSEDED', reason='CANDIDATE_CHANGED')
                for index, attempt in enumerate(review['attempts']):
                    if attempt['submission_id'] == old['submission_id']:
                        review['attempts'][index] = deepcopy(old)
                stale_request = state['peer_traffic']['traffic'].get(old.get('request_id'))
                if stale_request and stale_request['status'] not in TERMINAL:
                    stale_request.update(status='CANCELLED', reason='Review candidate superseded', attention=None)
                    superseded_events += (Event('peer.request.changed', {'request_id': stale_request['id'], 'status': 'CANCELLED'}),)
            if selected is not None: self._fact(current, selected['actor_id'], selected['authority_epoch'])
            row = {'submission_id': command.id, 'generation': command.generation, 'target': deepcopy(target),
                'evidence': evidence, 'reviewer': selected, 'round': review['returns'] + 1,
                'stage': 'REVIEWING' if selected else 'ATTENTION', 'reason': None if selected else 'NO_ELIGIBLE_REVIEWER',
                'result': None, 'request_id': None, 'review_reference': None}
            events = superseded_events
            if selected:
                row['request_id'], event = self._request(state, current, command.id, selected['participant_id'],
                    'Independent review: Standards, Specification, Runtime. ' + _json({'target': target, 'evidence': evidence}),
                    origin.actor_id)
                events += (event,)
            review['current'] = row; review['attempts'].append(row)
            current['review_stage'] = row['stage']
            return self._finish(state, current, 'review.submitted', row, events)
        return self._apply(command, origin, authorize, decide)

    @staticmethod
    def _native_review(observed, target, selected, reference, verdict):
        matches = [item for item in observed.get('reviews', []) if item.get('html_url') == reference]
        if len(matches) != 1: raise LedgerError('REVIEW_REFERENCE_UNVERIFIABLE')
        native = matches[0]
        # A later submitted review from this author supersedes the earlier one,
        # including an explicit withdrawal/comment; prose never selects verdict.
        author_reviews = [item for item in observed['reviews'] if item.get('user', {}).get('id') == selected['github_user_id']
                          and item.get('submitted_at') is not None and item.get('state') != 'PENDING']
        if (native.get('user', {}).get('id') != selected['github_user_id'] or native.get('commit_id') != target['head_sha']
                or native.get('state') != VERDICTS[verdict] or not native.get('submitted_at')
                or not author_reviews or max(author_reviews, key=lambda item: (item['submitted_at'], item['id'])) != native
                or native.get('pull_request_url') != f"https://api.github.com/repos/{target['repository']}/pulls/{target['pull_number']}"):
            raise LedgerError('REVIEW_REFERENCE_UNVERIFIABLE')
        return native

    def _result(self, command, origin, authorize, observation_id=None):
        payload = command.payload
        if (type(payload) is not dict or set(payload) != {'submission_id', 'verdict', 'review_reference', 'lenses'}
                or type(payload['verdict']) is not str or payload['verdict'] not in VERDICTS
                or payload['lenses'] != ['Standards', 'Specification', 'Runtime']
                or type(payload['review_reference']) is not str):
            raise LedgerError('INVALID_REVIEW_RESULT')
        state = self.ledger.snapshot()['state']; run = self._run(state, command.target, command.generation)
        review = state.get('run_reviews', {}).get(command.target); row = review and review['current']
        if not row or row['submission_id'] != payload['submission_id'] or row['stage'] != 'REVIEWING':
            raise LedgerError('REVIEW_SUBMISSION_STALE')
        selected = row['reviewer']
        if (origin.actor_id != selected['actor_id'] or origin.participant_id != selected['participant_id']
                or origin.authority_version != selected['authority_epoch']):
            raise LedgerError('REVIEWER_REQUIRED')
        request = state['peer_traffic']['traffic'].get(row['request_id'], {})
        delivery = request.get('deliveries', {}).get(origin.participant_id, {})
        if (request.get('status') not in {'ACCEPTED', 'COMPLETED'}
                or delivery.get('incarnation_id') != origin.incarnation_id):
            raise LedgerError('REVIEW_DELIVERY_REQUIRED')
        self._fact(run, origin.actor_id, origin.authority_version)
        target = self._target(run, row['target']); scope = self._scope(run)
        response = self._observe(command, origin, authorize, target, attempt=observation_id)
        observed = self._observed(response, target)
        self._native_review(observed, target, selected, payload['review_reference'], payload['verdict'])
        def decide(state, _):
            current = self._run(state, command.target, command.generation)
            if self._scope(current) != scope: raise LedgerError('REVIEW_RUN_STALE')
            reviews = state['run_reviews'][command.target]; active = reviews['current']
            if active != row: raise LedgerError('REVIEW_SUBMISSION_STALE')
            self._fact(current, origin.actor_id, origin.authority_version)
            if any(old.get('review_reference') == payload['review_reference'] for old in reviews['attempts']):
                raise LedgerError('REVIEW_REFERENCE_REUSED')
            active.update(result=payload['verdict'], review_reference=payload['review_reference'],
                          audit_reference=response['audit_reference'])
            state['peer_traffic']['traffic'][active['request_id']].update(status='COMPLETED', reason=None, attention=None)
            events = (Event('peer.request.changed', {'request_id': active['request_id'], 'status': 'COMPLETED'}),)
            if payload['verdict'] == 'pass': active['stage'] = 'READY_FOR_HUMAN'
            elif payload['verdict'] == 'human-needed':
                active.update(stage='ATTENTION', reason='REVIEW_HUMAN_NEEDED'); current['status'] = 'PAUSED'
            else:
                reviews['returns'] += 1
                if reviews['cap'] is not None and reviews['returns'] >= reviews['cap']:
                    active.update(stage='ATTENTION', reason='REVIEW_RETURN_CAP'); current['status'] = 'PAUSED'
                else:
                    active['stage'] = 'IMPLEMENTING'
                    request, event = self._request(state, current, command.id, current['participant_id'],
                        'Implement changes from ' + payload['review_reference'], origin.actor_id)
                    active['implementation_request'] = request; events += (event,)
            current['review_stage'] = active['stage']
            return self._finish(state, current, 'review.result', active, events)
        return self._apply(command, origin, authorize, decide)

    def _human(self, origin, authorize):
        return (type(origin) is Origin and 'human-control-run' in origin.capabilities
                and authorize() is True and self.authorize_human(origin) is True)

    def control(self, operation_id, run_id, generation, payload, *, human, authorize, admission_operation):
        """Explicit bounded policy changes, with exact subject and durable audit.

        An override is never recorded as independent review or fabricated Gate
        evidence. It cannot change identity, external authority or merge facts.
        """
        if (type(payload) is not dict or set(payload) != {'submission_id', 'target', 'action', 'reason', 'rounds'}
                or type(payload['action']) is not str or payload['action'] not in {'add-rounds', 'waive-cap', 'retry-review', 'override-review'}
                or type(payload['reason']) is not str or not 1 <= len(payload['reason']) <= 2048
                or (payload['action'] == 'add-rounds' and
                    (type(payload['rounds']) is not int or not 1 <= payload['rounds'] <= 20))
                or (payload['action'] != 'add-rounds' and payload['rounds'] is not None)):
            raise LedgerError('INVALID_REVIEW_CONTROL')
        command = Command(operation_id, 'review.human-control', run_id, generation, deepcopy(payload))
        auth = lambda: self._human(human, authorize)
        with self._fence(admission_operation):
            def decide(state, _):
                run = self._run(state, run_id, generation, paused=True)
                self._target(run, payload['target'])
                review = state.get('run_reviews', {}).get(run_id); row = review and review['current']
                if (not row or row['submission_id'] != payload['submission_id'] or row['target'] != payload['target']
                        or row['generation'] != generation or row['stage'] not in {'ATTENTION', 'READY_FOR_HUMAN'}):
                    raise LedgerError('REVIEW_CONTROL_STALE')
                if len(review['overrides']) >= MAX_ATTEMPTS: raise LedgerError('REVIEW_CAPACITY')
                if run.get('native_stop') and not run['native_stop'].get('restored', False):
                    raise LedgerError('NATIVE_RESTORE_REQUIRED')
                action = payload['action']
                if action == 'add-rounds':
                    if review['cap'] is None: raise LedgerError('REVIEW_CAP_ALREADY_WAIVED')
                    review['cap'] += payload['rounds']
                elif action == 'waive-cap': review['cap'] = None
                elif action == 'override-review':
                    row.update(stage='READY_FOR_HUMAN', reason='HUMAN_REVIEW_OVERRIDE', override_id=operation_id)
                if action != 'override-review':
                    if review['cap'] is not None and review['returns'] >= review['cap']:
                        raise LedgerError('REVIEW_RETURN_CAP')
                    row.update(stage='IMPLEMENTING', reason=None)
                run['status'] = 'ACTIVE'; run['review_stage'] = row['stage']
                run['control_revision'] = run.get('control_revision', 0) + 1
                audit = {**deepcopy(payload), 'operation_id': operation_id, 'generation': generation,
                         'human_origin': human.canonical()}
                review['overrides'].append(audit)
                events = ()
                if row['stage'] == 'IMPLEMENTING':
                    request, event = self._request(state, run, operation_id, run['participant_id'],
                        'Resume implementation for exact review subject: ' + _json(payload['target']), human.actor_id)
                    row['implementation_request'] = request; events = (event,)
                return self._finish(state, run, 'review.human-control', {'audit': audit, 'review': row}, events)
            return self._apply(command, human, auth, decide)

    def complete(self, operation_id, run_id, generation, submission_id, *, origin, authorize, admission_operation, observation_id=None):
        """Observe an already performed human GitHub merge; never merge here."""
        command = Command(operation_id, 'review.observe-completion', run_id, generation,
                          {'submission_id': _token(submission_id)})
        with self._fence(admission_operation):
            cached = self._receipt(command, origin, authorize)
            if cached is not None: return cached
            state = self.ledger.snapshot()['state']; run = self._run(state, run_id, generation)
            review = state.get('run_reviews', {}).get(run_id); row = review and review['current']
            if (not row or row['submission_id'] != submission_id or row['stage'] not in {'READY_FOR_HUMAN', 'ATTENTION'}
                    or row['generation'] != generation or not (row['result'] == 'pass' or row.get('override_id'))):
                raise LedgerError('REVIEW_PASS_REQUIRED')
            target = self._target(run, row['target']); scope = self._scope(run)
            if not row.get('override_id'):
                self._fact(run, row['reviewer']['actor_id'], row['reviewer']['authority_epoch'])
            gates = self.gates.operation_gates(run_id, generation, 'complete', origin=origin)
            require_operation_gates(state, gates)
            response = self._observe(command, origin, authorize, target, attempt=observation_id)
            observed = response['observation']
            if observed.get('status') == 'OK' and observed.get('pull', {}).get('merged') is False:
                try: self._observed(response, target)
                except LedgerError:
                    return self._completion_attention(command, origin, authorize, scope, 'MERGE_CANDIDATE_CHANGED')
                return self._completion_attention(command, origin, authorize, scope, 'AWAITING_HUMAN_MERGE')
            try: observation = self._observed(response, target, merged=True)
            except LedgerError as error:
                return self._completion_attention(command, origin, authorize, scope, 'MERGE_' + error.code)
            if not row.get('override_id'):
                try: self._native_review(observation, target, row['reviewer'], row['review_reference'], 'pass')
                except LedgerError:
                    return self._completion_attention(command, origin, authorize, scope, 'MERGE_REVIEW_STALE')
            merger = observation.get('merge')
            if (type(merger) is not dict or merger.get('merger_type') != 'User'
                    or type(merger.get('merger_id')) is not int or merger['merger_id'] not in self.human_mergers
                    or merger.get('method') not in {'merge', 'squash', 'rebase'}
                    or type(merger.get('integration_sha')) is not str or len(merger['integration_sha']) != 40
                    or any(c not in '0123456789abcdef' for c in merger['integration_sha'])
                    or merger['integration_sha'] != observation['pull'].get('merge_commit_sha')):
                return self._completion_attention(command, origin, authorize, scope, 'MERGE_IDENTITY_UNVERIFIABLE')
            def decide(state, _):
                current = self._run(state, run_id, generation)
                if self._scope(current) != scope or state['run_reviews'][run_id]['current'] != row:
                    raise LedgerError('REVIEW_COMPLETION_STALE')
                require_operation_gates(state, gates)
                if not row.get('override_id'):
                    self._fact(current, row['reviewer']['actor_id'], row['reviewer']['authority_epoch'])
                active = state['run_reviews'][run_id]['current']
                active.update(stage='COMPLETED', completion={'candidate_sha': target['head_sha'],
                    **deepcopy(merger), 'audit_reference': response['audit_reference']})
                current.update(status='CLOSED', outcome='completed', review_stage='COMPLETED',
                               completion=deepcopy(active['completion']), coordinator=None)
                current['control_revision'] = current.get('control_revision', 0) + 1
                if 'fixture_context' in state:
                    context_run = state['fixture_context']['runs'].get(run_id)
                    if not context_run or context_run['generation'] != generation:
                        raise LedgerError('RUN_CONTEXT_OWNERSHIP_UNKNOWN')
                    context_run.update(status='CLOSED', terminal_fact='COMPLETED')
                if run_id in state.get('run_admissions', {}):
                    state['run_admissions'][run_id]['status'] = 'CLOSED'
                events = []
                for request in state.get('peer_traffic', {}).get('traffic', {}).values():
                    if (request['run_id'] == run_id and request['generation'] == generation
                            and request['kind'] == 'peer.work-request' and request['status'] not in TERMINAL):
                        request.update(status='CANCELLED', reason='Exact candidate merged by authorized human', attention=None)
                        events.append(Event('peer.request.changed', {'request_id': request['id'], 'status': 'CANCELLED'}))
                return self._finish(state, current, 'review.completed', active, events)
            return self._apply(command, origin, authorize, decide)

    def _completion_attention(self, command, origin, authorize, scope, reason):
        def decide(state, _):
            run = self._run(state, command.target, command.generation)
            if self._scope(run) != scope: raise LedgerError('REVIEW_COMPLETION_STALE')
            row = state['run_reviews'][command.target]['current']
            if row['submission_id'] != command.payload['submission_id']:
                raise LedgerError('REVIEW_COMPLETION_STALE')
            row.update(stage='READY_FOR_HUMAN' if reason == 'AWAITING_HUMAN_MERGE' else 'ATTENTION', reason=reason)
            run['review_stage'] = row['stage']
            return self._finish(state, run, 'review.merge-observed', row)
        return self._apply(command, origin, authorize, decide)

    def request_changes(self, operation_id, run_id, generation, payload, *, human, authorize, admission_operation, observation_id=None):
        """One ordinary comment, then implementation; unknown writes need reconcile."""
        if (type(payload) is not dict or set(payload) != {'submission_id', 'target', 'body'}
                or type(payload['body']) is not str or not 1 <= len(payload['body']) <= 8192):
            raise LedgerError('INVALID_HUMAN_CHANGES')
        command = Command(operation_id, 'review.human-changes', run_id, generation, deepcopy(payload))
        auth = lambda: self._human(human, authorize)
        with self._fence(admission_operation):
            cached = self._receipt(command, human, auth)
            if cached is not None:
                return deepcopy(self.ledger.snapshot()['state']['review_comments'][operation_id])
            state = self.ledger.snapshot()['state']; run = self._run(state, run_id, generation)
            row = state.get('run_reviews', {}).get(run_id, {}).get('current')
            if not row or row['submission_id'] != payload['submission_id'] or row['stage'] != 'READY_FOR_HUMAN':
                raise LedgerError('HUMAN_CHANGES_STALE')
            target = self._target(run, payload['target']); scope = self._scope(run)
            observation = self._observe(command, human, auth, target, attempt=observation_id)
            self._observed(observation, target)
            def prepare(state, _):
                current = self._run(state, run_id, generation)
                if self._scope(current) != scope or state['run_reviews'][run_id]['current'] != row:
                    raise LedgerError('HUMAN_CHANGES_STALE')
                comments = state.setdefault('review_comments', {})
                if len(comments) >= MAX_ATTEMPTS: raise LedgerError('REVIEW_COMMENT_CAPACITY')
                item = {'operation_id': operation_id, 'run_id': run_id, 'generation': generation,
                    **deepcopy(payload), 'scope': scope, 'human_origin': human.canonical(),
                    'status': 'pending', 'receipt': None, 'observation_audit': observation['audit_reference']}
                comments[operation_id] = item
                return self._finish(state, current, 'review.comment-requested', item)
            self._apply(command, human, auth, prepare)
            receipt = self.broker.comment(target, payload['body'], operation_id, authorize=auth)
            return self._settle_comment(operation_id, receipt, human, auth)

    def reconcile_changes(self, operation_id, *, human, authorize, admission_operation, reconciliation_id=None):
        auth = lambda: self._human(human, authorize)
        with self._fence(admission_operation):
            if not auth(): raise LedgerError('FORBIDDEN')
            row = self.ledger.snapshot()['state'].get('review_comments', {}).get(operation_id)
            if not row: raise LedgerError('UNKNOWN_REVIEW_COMMENT')
            if row['status'] not in {'pending', 'unknown', 'confirmed-awaiting-target'}: return deepcopy(row)
            attempt = reconciliation_id or _id('review-reconcile-', operation_id)
            if self._reserve_comment_attempt(operation_id, attempt, 'reconcile', human, auth):
                return deepcopy(self.ledger.snapshot()['state']['review_comments'][operation_id])
            receipt = (row['receipt'] if row['status'] == 'confirmed-awaiting-target' else
                       self.broker.reconcile_comment(row['target'], row['body'], operation_id, authorize=auth, reconciliation_id=attempt))
            return self._settle_comment(operation_id, receipt, human, auth, attempt=attempt)

    def _reserve_comment_attempt(self, operation_id, attempt, kind, human, authorize):
        _token(attempt)
        row = self.ledger.snapshot()['state']['review_comments'][operation_id]
        command = Command(attempt, 'review.comment-attempt', row['run_id'], row['generation'],
                          {'operation_id': operation_id, 'kind': kind})
        def decide(state, _):
            attempts = state['review_comments'][operation_id].setdefault('attempts', {})
            if len(attempts) >= MAX_ATTEMPTS: raise LedgerError('REVIEW_COMMENT_CAPACITY')
            attempts[attempt] = {'kind': kind, 'receipt': None}
            return Transition(state, (Event('review.comment-attempt', command.payload),), {'attempt': attempt})
        self._apply(command, human, authorize, decide)
        return self.ledger.snapshot()['state']['review_comments'][operation_id]['attempts'][attempt]['receipt'] is not None

    def retry_changes_preflight(self, operation_id, preflight_id, *, human, authorize, admission_operation):
        """Explicit new bounded read after proven pre-write rejection; same POST key."""
        auth = lambda: self._human(human, authorize)
        with self._fence(admission_operation):
            if not auth(): raise LedgerError('FORBIDDEN')
            row = self.ledger.snapshot()['state'].get('review_comments', {}).get(operation_id)
            if not row or row['status'] != 'error': raise LedgerError('REVIEW_PREFLIGHT_RETRY_FORBIDDEN')
            current = self._run(self.ledger.snapshot()['state'], row['run_id'], row['generation'])
            if self._scope(current) != row['scope']: raise LedgerError('HUMAN_CHANGES_STALE')
            if self._reserve_comment_attempt(operation_id, preflight_id, 'preflight', human, auth):
                return deepcopy(self.ledger.snapshot()['state']['review_comments'][operation_id])
            receipt = self.broker.comment(row['target'], row['body'], operation_id,
                                          authorize=auth, preflight_id=preflight_id)
            return self._settle_comment(operation_id, receipt, human, auth, attempt=preflight_id)

    def _settle_comment(self, operation_id, receipt, human, authorize, *, attempt=None):
        if (type(receipt) is not dict or set(receipt) != {'status', 'audit_reference', 'comment_reference'}
                or receipt['status'] not in {'confirmed', 'unknown', 'error'}):
            raise LedgerError('INVALID_REVIEW_COMMENT_RECEIPT')
        _token(receipt['audit_reference'])
        original = self.ledger.snapshot()['state']['review_comments'][operation_id]
        reference = receipt['comment_reference']
        if receipt['status'] == 'confirmed':
            expected_url = (f"https://github.com/{original['target']['repository']}/pull/{original['target']['pull_number']}"
                            f"#issuecomment-{reference.get('id') if type(reference) is dict else ''}")
            if (type(reference) is not dict or set(reference) != {'kind', 'id', 'url'}
                    or reference['kind'] != 'comment' or type(reference['id']) is not int
                    or reference['id'] <= 0 or reference['url'] != expected_url):
                raise LedgerError('INVALID_REVIEW_COMMENT_RECEIPT')
        target_current = True
        if receipt['status'] == 'confirmed':
            check = Command(_id('review-comment-target-', [operation_id, attempt]), 'review.comment-target',
                            original['run_id'], original['generation'], {'target': original['target']})
            response = self._observe(check, human, authorize, original['target'])
            try: self._observed(response, original['target'])
            except LedgerError as error:
                target_current = False if error.code == 'REVIEW_CANDIDATE_CHANGED' else None
        command = Command(_id('review-comment-settle-', {'operation_id': operation_id, 'receipt': receipt, 'attempt': attempt}),
            'review.comment-settled', original['run_id'], original['generation'], deepcopy(receipt))
        def decide(state, _):
            item = state['review_comments'][operation_id]
            if item['status'] not in {'pending', 'unknown', 'error', 'confirmed-awaiting-target'}:
                return Transition(state, (), deepcopy(item))
            if attempt is not None: item['attempts'][attempt]['receipt'] = deepcopy(receipt)
            item.update(status=receipt['status'], receipt=deepcopy(receipt))
            run = state['runs'][item['run_id']]
            row = state['run_reviews'][item['run_id']]['current']
            events = ()
            if receipt['status'] == 'confirmed':
                if target_current is None:
                    item['status'] = 'confirmed-awaiting-target'
                elif (not target_current or self._scope(run) != item['scope'] or row['submission_id'] != item['submission_id']
                        or row['stage'] != 'READY_FOR_HUMAN'):
                    item['status'] = 'stale'
                else:
                    row.update(stage='IMPLEMENTING', reason='HUMAN_CHANGES_REQUESTED')
                    run['review_stage'] = row['stage']
                    request, event = self._request(state, run, operation_id, run['participant_id'],
                        'Human changes requested: ' + receipt['comment_reference']['url'], human.actor_id)
                    row['implementation_request'] = request; item['implementation_request'] = request; events = (event,)
            return self._finish(state, run, 'review.comment-settled', item, events)
        return self._apply(command, human, authorize, decide)


    def snapshot_run(self, run_id, *, snapshot=None):
        """Passive Manager projection; no provider contact, authorization or mutation.

        room_seq/updated_at describe stored observations, not current provider
        freshness. Manager separately reads Gate and Broker owner projections.
        """
        return snapshot_review_run(self.ledger.snapshot() if snapshot is None else snapshot,
                                   self.ledger.room_id, run_id)

    def refresh_request(self, operation_id, run_id, generation, *, origin, authorize, admission_operation):
        """Bounded host observation of failed responsibility; never a review return."""
        command = Command(operation_id, 'review.refresh-request', run_id, generation, {})
        with self._fence(admission_operation):
            cached = self._receipt(command, origin, authorize)
            if cached is not None: return cached
            state = self.ledger.snapshot()['state']; run = self._run(state, run_id, generation)
            row = state.get('run_reviews', {}).get(run_id, {}).get('current')
            if not row or row['stage'] != 'REVIEWING': raise LedgerError('REVIEW_SUBMISSION_STALE')
            request = state['peer_traffic']['traffic'][row['request_id']]
            scope = self._scope(run)
            reason = None
            if request['status'] in {'BLOCKED', 'DECLINED', 'CANCELLED', 'DEFERRED'}:
                reason = 'REVIEW_REQUEST_' + request['status']
            try:
                active = self.identity.dispatcher.reviewer_authority(row['reviewer']['participant_id'], run_id, generation)
                self._fact(run, row['reviewer']['actor_id'], row['reviewer']['authority_epoch'])
                if active.authority_version != row['reviewer']['authority_epoch']: reason = 'REVIEWER_RESTARTED'
            except (LedgerError, RuntimeError): reason = 'REVIEWER_UNAVAILABLE'
            queued = request['status'] == 'QUEUED'
            timeout = run['policy'].get('queue_timeout_seconds' if queued else 'response_timeout_seconds')
            timestamp = request['submitted_at'] if queued else request.get('response_started_at')
            if reason is None and type(timeout) is int and timeout > 0 and timestamp:
                elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds()
                if elapsed >= timeout: reason = 'REVIEW_QUEUE_TIMEOUT' if queued else 'REVIEW_RESPONSE_TIMEOUT'
            def decide(state, _):
                current = self._run(state, run_id, generation)
                active = state['run_reviews'][run_id]['current']
                if self._scope(current) != scope or active != row or state['peer_traffic']['traffic'][row['request_id']] != request:
                    raise LedgerError('REVIEW_SUBMISSION_STALE')
                if reason is not None:
                    active.update(stage='ATTENTION', reason=reason)
                    current.update(status='PAUSED', review_stage='ATTENTION',
                                   control_revision=current.get('control_revision', 0) + 1)
                    pending = state['peer_traffic']['traffic'][row['request_id']]
                    if pending['status'] not in TERMINAL:
                        pending.update(status='CANCELLED', reason=reason, attention=None)
                return self._finish(state, current, 'review.request-observed', active)
            return self._apply(command, origin, authorize, decide)


def snapshot_review_run(snapshot, room_id, run_id):
    """Owner-defined passive export from one supplied read-only Room cut."""
    if type(snapshot) is not dict or snapshot.get('room_id') != room_id:
        raise LedgerError('REVIEW_SNAPSHOT_ROOM_MISMATCH')
    state = snapshot['state']
    run = state.get('runs', {}).get(run_id)
    if run is None: raise LedgerError('UNKNOWN_RUN')
    review = state.get('run_reviews', {}).get(run_id)
    requests = [deepcopy(item) for item in state.get('peer_traffic', {}).get('traffic', {}).values()
                if item['run_id'] == run_id and item['generation'] == run['generation']
                and item['kind'] == 'peer.work-request']
    return {'room_id': room_id, 'room_seq': snapshot['room_seq'],
            'run_id': run_id, 'generation': run['generation'], 'status': run['status'],
            'review': deepcopy(review), 'work_requests': requests}

