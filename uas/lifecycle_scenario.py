"""Bounded trusted-host composition for #78; not a launcher or acceptance gate.

Native proposals enter only through the admitted dispatcher. Human operations
use RunReview's existing authorization, idempotency and reconciliation. There
is no second workflow journal, automatic retry, merge, or supplied Actor claim.
The current implementation qualifies controlled composition only.
"""
from copy import deepcopy

from .ledger import LedgerError, _token
from .run_review import RunReview
from .workstation_peer import AdmittedPeerDispatcher
from .workstation_control import SupervisorAdmission


MISSING_LIVE_SEAMS = (
    'production-native-launch-and-admission',
    'selected-runtime-provider-and-github-account-qualification',
    'real-return-crash-reset-and-uncertain-write-evidence',
    'authorized-human-merge-evidence',
)


def preflight():
    """No credential booleans or fixture successes can enable live mode."""
    return {'status': 'blocked', 'classification': 'controlled-composition',
            'real_lifecycle_qualified': False, 'missing': list(MISSING_LIVE_SEAMS)}


class LifecycleScenario:
    """One bounded invocation over already constructed trusted host owners.

    The caller owns launch, admission, readiness, event selection and shutdown.
    This driver does not turn user JSON into owners or provide an authority
    factory. Human controls and reports bind one Run generation; transport
    pumps remain Room/seat-scoped and use the canonical per-envelope authority.
    A fresh instance never authorizes retries of uncertain writes.
    """
    def __init__(self, review, dispatcher, run_id, generation, *, max_steps=32):
        if (type(review) is not RunReview or type(dispatcher) is not AdmittedPeerDispatcher
                or dispatcher.reviews is not review or review.identity.dispatcher is not dispatcher
                or dispatcher.hub.ledger is not review.ledger or review.gates.ledger is not review.ledger
                or review.gates.identity is not review.identity):
            raise LedgerError('SCENARIO_OWNER_MISMATCH')
        if (type(generation) is not int or generation < 1 or type(max_steps) is not int
                or not 1 <= max_steps <= 128):
            raise LedgerError('SCENARIO_INVALID_BOUND')
        self.review, self.dispatcher = review, dispatcher
        self.run_id, self.generation = _token(run_id), generation
        self.remaining = max_steps
        self._snapshot()

    def _snapshot(self):
        snapshot = self.review.ledger.snapshot()
        run = snapshot['state'].get('runs', {}).get(self.run_id)
        binding = self.review.gates.binding
        if (snapshot['room_id'] != binding.room_id or run is None
                or run['generation'] != self.generation
                or run['project_id'] != binding.project_id or run['repository'] != binding.repository):
            raise LedgerError('SCENARIO_SCOPE_CHANGED')
        return snapshot

    def _step(self, *, run_scoped=True):
        # Count failures too. No hidden waits, retries or budget reset on error.
        if self.remaining == 0:
            raise LedgerError('SCENARIO_STEP_LIMIT')
        self.remaining -= 1
        if run_scoped:
            self._snapshot()

    def receive_room_once(self, admission_operation):
        """Pump one Room channel packet, not a selected-Run operation.

        The authenticated packet can address another permitted Run. Only the
        canonical dispatcher decides its per-packet scope. This is not evidence
        that this scenario's selected Run advanced. The host must select an
        already readable channel with a bounded timeout; do not change it here.
        """
        self._step(run_scoped=False)
        channel = self.dispatcher.admissions.peer_channel(_token(admission_operation))
        timeout = channel.gettimeout()
        if timeout is None or not 0 < timeout <= 5:
            raise LedgerError('SCENARIO_UNBOUNDED_CHANNEL')
        return self.dispatcher.receive(admission_operation)

    def receive_helper_once(self, helper_operation):
        """Pump the exact admitted fixed MCP helper; Root scopes remain canonical."""
        self._step(run_scoped=False)
        channel = self.dispatcher.admissions.helper_channel(_token(helper_operation))
        timeout = channel.gettimeout()
        if timeout is None or not 0 < timeout <= 5:
            raise LedgerError('SCENARIO_UNBOUNDED_CHANNEL')
        return self.dispatcher.receive_helper(helper_operation)

    def deliver_seat_once(self, controller):
        """Pump one seat's queue, which can include other permitted Runs.

        Delegate SAFE observation and envelope selection to the Supervisor.
        Never mark a receipt as belonging to the scenario's selected Run.
        """
        self._step(run_scoped=False)
        allowed = type(controller) is SupervisorAdmission
        if not allowed:
            from .claude_native_admission import NativeClaudeSupervisorAdmission
            allowed = type(controller) is NativeClaudeSupervisorAdmission
        if (not allowed
                or controller.seat.room_id != self.review.ledger.room_id
                or self.dispatcher.admissions.seats.get(controller.seat.participant_id) != controller.seat
                or controller.controller != self.dispatcher.admissions.controller):
            raise LedgerError('SCENARIO_DELIVERY_OWNER_MISMATCH')
        admission = controller.launch.admission
        if type(admission) is not dict or admission.get('state') != 'admitted':
            raise LedgerError('SCENARIO_DELIVERY_OWNER_MISMATCH')
        binding = self.dispatcher.admissions.binding(admission['operation_id'])
        if binding.seat != controller.seat or binding.incarnation != controller.launch.incarnation:
            raise LedgerError('SCENARIO_DELIVERY_OWNER_MISMATCH')
        return controller.deliver_one()

    def request_changes(self, operation_id, payload, *, human, authorize, admission_operation):
        self._step()
        return self.review.request_changes(operation_id, self.run_id, self.generation,
            payload, human=human, authorize=authorize, admission_operation=admission_operation)

    def reconcile_changes(self, operation_id, reconciliation_id, *, human, authorize, admission_operation):
        self._step()
        # Existing owner checks the stored operation's Run/generation. Check
        # this scope as well before allowing this scenario to reconcile it.
        state = self._snapshot()['state']
        row = state.get('review_comments', {}).get(operation_id)
        if row is None or row.get('run_id') != self.run_id or row.get('generation') != self.generation:
            raise LedgerError('SCENARIO_OPERATION_SCOPE_MISMATCH')
        return self.review.reconcile_changes(operation_id, human=human, authorize=authorize,
            admission_operation=admission_operation, reconciliation_id=_token(reconciliation_id))

    def observe_completion(self, operation_id, submission_id, *, human, authorize,
                           admission_operation, observation_id=None):
        self._step()
        return self.review.complete(operation_id, self.run_id, self.generation, submission_id,
            origin=human, authorize=authorize, admission_operation=admission_operation,
            observation_id=observation_id)

    def report(self):
        """Allowlisted metadata from one ledger cut; no prompts or raw receipts.

        Stored completion is not live evidence or current provider freshness.
        Caller-supplied classifications cannot upgrade controlled composition.
        """
        snapshot = self._snapshot()
        projection = self.review.snapshot_run(self.run_id, snapshot=snapshot)
        review = projection.get('review') or {}
        current = review.get('current') or {}
        def pick(value, keys):
            return {key: deepcopy(value[key]) for key in keys if key in value}
        result = preflight()
        result.update(room_id=snapshot['room_id'], room_seq=snapshot['room_seq'],
            run_id=self.run_id, generation=self.generation, run_status=projection['status'],
            remaining_steps=self.remaining, returns=review.get('returns', 0),
            review=pick(current, ('submission_id', 'stage', 'round', 'result', 'review_reference')),
            target=pick(current.get('target') or {}, ('repository', 'pull_number', 'pull_id',
                'head_sha', 'base_sha', 'base_ref')),
            reviewer=pick(current.get('reviewer') or {}, ('actor_id', 'participant_id', 'authority_epoch', 'github_user_id')),
            completion=pick(current.get('completion') or {}, ('candidate_sha', 'integration_sha', 'merger_id', 'method')),
            work_requests=[pick(row, ('id', 'generation', 'status', 'recipients'))
                           for row in projection['work_requests']])
        return result
