"""Bounded, trusted fixture Run/context facts on the Room ledger.

Not product Run admission, Forge evidence, or a generic workflow engine. Native
handles/proofs stay with the Supervisor; no Participant payload enters here.
"""
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import hashlib
import uuid

from uas.ledger import LedgerError, _token

MAX_CONTEXT_GENERATION = 2**53 - 1
MAX_CONTEXTS = 32
MAX_RUNS = 64
_TERMINAL_REQUESTS = {"COMPLETED", "DECLINED", "CANCELLED"}


@dataclass(frozen=True)
class FixtureRun:
    run_id: str
    generation: int = 1

    def document(self):
        if type(self.generation) is not int or not 1 <= self.generation <= MAX_CONTEXT_GENERATION:
            raise LedgerError("INVALID_SCOPE")
        return {"run_id": _token(self.run_id), "generation": self.generation}


class FixtureRunTerminal(Enum):
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


def initial_contexts(participants, default_run, initial_runs=None):
    if type(default_run) is not FixtureRun:
        raise LedgerError("INVALID_SCOPE")
    if initial_runs is not None and (type(initial_runs) is not dict or set(initial_runs) - set(participants)):
        raise LedgerError("INVALID_SCOPE")
    runs, rows = {}, {}
    for participant in participants:
        run = (initial_runs or {}).get(participant, default_run)
        if type(run) is not FixtureRun:
            raise LedgerError("INVALID_SCOPE")
        scope = run.document()
        previous = runs.get(run.run_id)
        if previous and previous["generation"] != run.generation:
            raise LedgerError("INVALID_SCOPE")
        runs[run.run_id] = {"generation": run.generation, "status": "OPEN", "terminal_fact": None}
        rows[participant] = {"context_generation": 1, "status": "READY", "bound_run": None,
                             "reserved_run": scope, "reset": None}
    return {"participants": rows, "runs": runs}


def reserve_context_capacity(state):
    """Replace the projection with its maximal allowed *future* footprint.

    This runs even before legacy enablement, so peer admission cannot consume
    bytes a future context transition needs. It does not change real state.
    """
    wide = "x" * 256
    scope = {"run_id": wide, "generation": MAX_CONTEXT_GENERATION}
    reset = {"id": wide, "participant_id": wide, "status": "SUCCEEDED",
             "expected_context_generation": MAX_CONTEXT_GENERATION,
             "next_context_generation": MAX_CONTEXT_GENERATION,
             "preceding_run": scope, "target_run": scope, "reason_code": wide}
    state["fixture_context"] = {
        "participants": {f"{i:03d}" + "x" * 253: {
            "context_generation": MAX_CONTEXT_GENERATION, "status": "UNAVAILABLE",
            "bound_run": scope, "reserved_run": scope, "reset": reset} for i in range(MAX_CONTEXTS)},
        "runs": {f"{i:03d}" + "x" * 253: {"generation": MAX_CONTEXT_GENERATION,
                 "status": "CLOSED", "terminal_fact": "COMPLETED"} for i in range(MAX_RUNS)}}


class FixtureContextHub:
    """Only trusted harness/controller actions; callbacks are pure fresh proof."""
    def __init__(self, hub):
        self.hub = hub
        self.ledger = hub.ledger

    def _domain(self, state=None):
        if state is None:
            state = self.ledger.snapshot()["state"]
        domain = state.get("fixture_context")
        if domain is None:
            raise LedgerError("CONTEXT_NOT_ENABLED")
        return domain

    def _row(self, participant_id, state=None):
        row = self._domain(state)["participants"].get(participant_id)
        if row is None:
            raise LedgerError("UNKNOWN_PARTICIPANT")
        return row

    @staticmethod
    def _assigned(row):
        return row["bound_run"] or row["reserved_run"]

    def _scope(self, participant_id, row, run=None, generation=None):
        run = run or self._assigned(row)
        return {"room_id": self.ledger.room_id, "participant_id": participant_id,
                **run, "context_generation": row["context_generation"] if generation is None else generation}

    def scope(self, participant_id):
        row = self._row(participant_id)
        if row["status"] != "READY":
            raise LedgerError("CONTEXT_UNAVAILABLE")
        return self._scope(participant_id, row)

    def _events(self):
        cursor, through = 0, self.ledger.snapshot()["room_seq"]
        while cursor < through:
            events = self.ledger.replay(cursor, through_seq=through, limit=1000)
            if not events:
                break
            yield from events
            cursor = events[-1]["room_seq"]

    def reset_status(self, reset_id):
        _token(reset_id)
        for row in self._domain()["participants"].values():
            if row["reset"] and row["reset"]["id"] == reset_id:
                return deepcopy(row["reset"])
        latest = None
        for event in self._events():
            if event["kind"].startswith("context.reset.") and event["payload"].get("id") == reset_id:
                latest = event["payload"]
        if latest is None:
            raise LedgerError("UNKNOWN_RESET")
        return deepcopy(latest)

    def pending_scope(self, reset_id):
        reset = self.reset_status(reset_id)
        row = self._row(reset["participant_id"])
        if (not row["reset"] or row["reset"]["id"] != reset_id
                or reset["status"] not in {"REQUESTED", "FAILED"}
                or row["context_generation"] != reset["expected_context_generation"]):
            raise LedgerError("STALE_RESET")
        target = self._domain()["runs"].get(reset["target_run"]["run_id"])
        if not target or target["status"] != "OPEN" or target["generation"] != reset["target_run"]["generation"]:
            raise LedgerError("TARGET_RUN_UNAVAILABLE")
        return self._scope(reset["participant_id"], row, reset["target_run"], reset["next_context_generation"])

    def _finish(self, state, kind, payload, result=None):
        self._prune(state)
        # Preserve already-admitted peer lifecycles, not just current JSON size.
        self.hub._reserve_capacity(state)
        return self.hub._transition(state, kind, payload, result if result is not None else payload)

    def _control(self, operation_id, kind, payload, decide, authorize=None):
        return self.hub._control(operation_id, "context." + kind, payload, decide, authorize)

    def enable(self, operation_id):
        """Explicit atomic upgrade of a legacy fixture; may reject for headroom."""
        definition = self.hub._state()["definition"]
        payload = {"run_id": definition["run_id"], "generation": definition["generation"]}
        def decide(state, _):
            if "fixture_context" in state:
                raise LedgerError("ALREADY_CONFIGURED")
            state["fixture_context"] = initial_contexts(definition["participants"], FixtureRun(**payload))
            # Preserve prior confirmed legacy binding, rather than pretending
            # that an already-used context has never received anything.
            for participant, row in state["fixture_context"]["participants"].items():
                if any(item["deliveries"].get(participant)
                       for item in state["peer_traffic"]["traffic"].values()):
                    row["bound_run"], row["reserved_run"] = row["reserved_run"], None
            return self._finish(state, "context.enabled", payload)
        return self._control(operation_id, "enable", payload, decide)

    def open_run(self, operation_id, run):
        if type(run) is not FixtureRun:
            raise LedgerError("INVALID_SCOPE")
        payload = run.document()
        def decide(state, _):
            domain = self._domain(state)
            if run.run_id in domain["runs"]:
                raise LedgerError("RUN_ALREADY_EXISTS")
            if any(event["kind"] == "context.run.closed" and event["payload"]["run_id"] == run.run_id
                   for event in self._events()):
                raise LedgerError("RUN_CLOSED")
            self._prune(state)
            if len(domain["runs"]) >= MAX_RUNS:
                raise LedgerError("RUN_CAPACITY_EXHAUSTED")
            domain["runs"][run.run_id] = {"generation": run.generation, "status": "OPEN", "terminal_fact": None}
            return self._finish(state, "context.run.opened", payload)
        return self._control(operation_id, "open", payload, decide)

    def close_run(self, operation_id, run_id, fact):
        _token(run_id)
        if type(fact) is not FixtureRunTerminal:
            raise LedgerError("INVALID_TERMINAL_FACT")
        payload = {"run_id": run_id, "terminal_fact": fact.value}
        def decide(state, _):
            run = self._domain(state)["runs"].get(run_id)
            if run is None or run["status"] != "OPEN":
                raise LedgerError("RUN_CLOSED")
            if any(item["run_id"] == run_id and item["kind"] == "peer.work-request"
                   and item["status"] not in _TERMINAL_REQUESTS for item in state["peer_traffic"]["traffic"].values()):
                raise LedgerError("RUN_HAS_LIVE_REQUESTS")
            run.update(status="CLOSED", terminal_fact=fact.value)
            return self._finish(state, "context.run.closed", {**payload, "generation": run["generation"]})
        return self._control(operation_id, "close", payload, decide)

    @staticmethod
    def _prune(state):
        domain = state["fixture_context"]
        referenced = set()
        for row in domain["participants"].values():
            for scope in (row["bound_run"], row["reserved_run"]):
                if scope:
                    referenced.add(scope["run_id"])
            if row["reset"]:
                referenced.update(row["reset"][key]["run_id"] for key in ("preceding_run", "target_run"))
        domain["runs"] = {key: value for key, value in domain["runs"].items()
                          if value["status"] == "OPEN" or key in referenced}

    def request_reset(self, operation_id, participant_id, expected_context_generation, target_run):
        _token(operation_id)
        _token(participant_id)
        if type(target_run) is not FixtureRun:
            raise LedgerError("INVALID_SCOPE")
        if type(expected_context_generation) is not int or not 1 <= expected_context_generation <= MAX_CONTEXT_GENERATION:
            raise LedgerError("CONTEXT_MISMATCH")
        target = target_run.document()
        payload = {"participant_id": participant_id, "expected_context_generation": expected_context_generation,
                   "target_run": target}
        def decide(state, _):
            domain, row = self._domain(state), self._row(participant_id, state)
            if row["context_generation"] != expected_context_generation:
                raise LedgerError("CONTEXT_MISMATCH")
            if row["status"] != "READY":
                raise LedgerError("CONTEXT_UNAVAILABLE")
            if expected_context_generation == MAX_CONTEXT_GENERATION:
                raise LedgerError("CONTEXT_GENERATION_EXHAUSTED")
            preceding = self._assigned(row)
            old = domain["runs"].get(preceding["run_id"])
            new = domain["runs"].get(target_run.run_id)
            if not old or old["status"] != "CLOSED":
                raise LedgerError("PRECEDING_RUN_OPEN")
            if not new or new["status"] != "OPEN" or new["generation"] != target_run.generation:
                raise LedgerError("TARGET_RUN_UNAVAILABLE")
            reset = {"id": operation_id, **payload, "status": "REQUESTED",
                     "next_context_generation": expected_context_generation + 1,
                     "preceding_run": deepcopy(preceding), "reason_code": None}
            row.update(status="RESETTING", reset=reset)
            return self._finish(state, "context.reset.requested", deepcopy(reset))
        return self._control(operation_id, "reset.request", payload, decide)

    @staticmethod
    def _completion_id(reset_id, status):
        return "context-reset-" + hashlib.sha256(reset_id.encode()).hexdigest() + "-" + status.lower()

    def _complete(self, reset_id, expected_generation, status, reason_code, authorize, operation_id=None):
        reset = self.reset_status(reset_id)
        if type(expected_generation) is not int or expected_generation != reset["expected_context_generation"]:
            raise LedgerError("CONTEXT_MISMATCH")
        payload = {"id": reset_id, "expected_context_generation": expected_generation, "reason_code": reason_code}
        def current():
            row = self._row(reset["participant_id"])
            return (row["reset"] is not None and row["reset"]["id"] == reset_id
                    and (authorize is None or authorize() is True))
        def decide(state, _):
            domain, row = self._domain(state), self._row(reset["participant_id"], state)
            pending = row["reset"]
            if (pending["status"] not in {"REQUESTED", "FAILED"}
                    or row["context_generation"] != expected_generation):
                raise LedgerError("STALE_RESET")
            if status == "SUCCEEDED":
                target = domain["runs"].get(pending["target_run"]["run_id"])
                if not target or target["status"] != "OPEN" or target["generation"] != pending["target_run"]["generation"]:
                    raise LedgerError("TARGET_RUN_UNAVAILABLE")
                row.update(status="READY", context_generation=pending["next_context_generation"],
                           bound_run=None, reserved_run=deepcopy(pending["target_run"]))
            else:
                row["status"] = "UNAVAILABLE"
            pending.update(status=status, reason_code=reason_code)
            return self._finish(state, "context.reset." + status.lower(), deepcopy(pending))
        return self._control(operation_id or self._completion_id(reset_id, status),
                             "reset." + status.lower(), payload, decide, current)

    def succeed_reset(self, reset_id, expected_generation, *, authorize):
        if not callable(authorize):
            raise LedgerError("NATIVE_PROOF_REQUIRED")
        return self._complete(reset_id, expected_generation, "SUCCEEDED", None, authorize)

    def fail_reset(self, reset_id, expected_generation, reason_code, *, attempt_id=None):
        # Failures belong to individual native attempts; repeated attempts may
        # fail differently without conflicting with the single success key.
        attempt_id = _token(attempt_id) if attempt_id is not None else uuid.uuid4().hex
        operation_id = self._completion_id(reset_id + ":" + attempt_id, "failed")
        return self._complete(reset_id, expected_generation, "FAILED", _token(reason_code), None, operation_id)

    def current(self, participant_id, generation, state=None):
        row = self._row(participant_id, state)
        return row["status"] == "READY" and row["context_generation"] == generation

    def permits(self, participant_id, generation, run_id, run_generation, state=None):
        if state is None:
            state = self.ledger.snapshot()["state"]
        if not self.current(participant_id, generation, state):
            return False
        row = self._row(participant_id, state)
        run = self._domain(state)["runs"].get(run_id)
        return (run is not None and run["status"] == "OPEN"
                and run["generation"] == run_generation
                and self._assigned(row) == {"run_id": run_id, "generation": run_generation})

    def reserve_delivery(self, state, participant_id, generation, run_id, run_generation):
        if not self.permits(participant_id, generation, run_id, run_generation, state):
            raise LedgerError("DELIVERY_FENCED")
        row = self._row(participant_id, state)
        # Existing reservation is deliberately retained across unknown effects.
        if row["bound_run"] is None:
            row["reserved_run"] = {"run_id": run_id, "generation": run_generation}

    def confirm_delivery(self, state, participant_id, generation, run_id, run_generation):
        self.reserve_delivery(state, participant_id, generation, run_id, run_generation)
        row = self._row(participant_id, state)
        row["bound_run"] = {"run_id": run_id, "generation": run_generation}
        row["reserved_run"] = None
