"""Typed peer-traffic domain on the Room application ledger.

FixturePeerHub is a trusted, in-process fixture entry point, NOT an authenticated
endpoint. #63 must supply process-bound authority before a production transport
can expose this domain. The Hub is the sole owner of traffic state and receipts.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import uuid

from uas.context import (FixtureContextHub, FixtureRun, MAX_CONTEXT_GENERATION,
                         initial_contexts, reserve_context_capacity)
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition, MAX_SEQUENCE, _json, _token


class Readiness(Enum):
    SAFE = "safe"
    BUSY = "busy"
    AMBIGUOUS = "ambiguous"
    COMPACTING = "compacting"
    LOST = "lost"


@dataclass(frozen=True)
class FixtureParticipant:
    participant_id: str
    actor_id: str
    work_slots: int = 1


@dataclass(frozen=True)
class Message:
    id: str
    run_id: str
    generation: int
    recipient: str | None
    text: str
    parent_id: str | None = None


@dataclass(frozen=True)
class WorkRequest:
    id: str
    run_id: str
    generation: int
    recipient: str
    text: str


@dataclass(frozen=True)
class RequestCommand:
    id: str
    run_id: str
    generation: int
    request_id: str
    action: str
    reason: str | None = None


@dataclass(frozen=True, eq=False)
class FixtureConnection:
    """Harness-owned object identity; not a process badge or security boundary."""
    participant_id: str
    incarnation_id: str
    context_generation: int
    attachment_id: str
    receiver: object


MAX_TEXT_BYTES = 16_384

TERMINAL = {"COMPLETED", "DECLINED", "CANCELLED"}
TRANSITIONS = {
    "accept": ({"DELIVERED", "DEFERRED", "BLOCKED"}, "ACCEPTED"),
    "complete": ({"ACCEPTED"}, "COMPLETED"),
    "decline": ({"DELIVERED", "DEFERRED", "BLOCKED"}, "DECLINED"),
    "defer": ({"DELIVERED", "ACCEPTED"}, "DEFERRED"),
    "block": ({"DELIVERED", "ACCEPTED"}, "BLOCKED"),
}
_CONTROL = Origin("fixture-harness", "fixture-harness", "fixture-control", "fixture-v1", ("fixture-control",))


def _now():
    return datetime.now(timezone.utc).isoformat()


def _text(value):
    if type(value) is not str or not value or len(_json(value).encode("utf-8")) - 2 > MAX_TEXT_BYTES:
        raise LedgerError("INVALID_PAYLOAD")
    return value


def digest(envelope):
    return hashlib.sha256(_json(envelope).encode()).hexdigest()


class FixturePeerHub:
    """One fixture Room owner using #60's transactions, sequences and replay.

    configure/connect/observe/cancel are trusted harness actions. Client input
    enters only submit(); its identity comes from an attached connection object.
    A new Hub has no usable connections or safe-point observations. No socket,
    product Run admission, runtime launch, stop, or Forge authority is added.
    contexts exposes only bounded trusted fixture facts/reset decisions; native
    reset and process authority remain the Supervisor's separate responsibility.
    """
    def __init__(self, ledger: RoomLedger):
        self.ledger = ledger
        self._connections = {}
        self.contexts = FixtureContextHub(self)

    def _state(self):
        state = self.ledger.snapshot()["state"].get("peer_traffic")
        if not state:
            raise LedgerError("NOT_CONFIGURED")
        return state

    def _control(self, operation_id, kind, payload, decide, authorize=None):
        return self.ledger.apply(
            Command(operation_id, "peer.fixture." + kind, self.ledger.room_id, None, payload), _CONTROL,
            authorize=lambda *_: True if authorize is None else authorize(), decide=decide)

    @staticmethod
    def _transition(state, kind, payload, result):
        return Transition(state, (Event(kind, payload),), result)

    def configure(self, operation_id, participants, run_id, generation=1, *, initial_runs=None):
        """Bind a synthetic scope, not a Forge work item or a product Run."""
        _token(run_id)
        if type(generation) is not int or not 1 <= generation <= MAX_CONTEXT_GENERATION:
            raise LedgerError("INVALID_SCOPE")
        if type(participants) is not tuple or not 2 <= len(participants) <= 32:
            raise LedgerError("INVALID_PARTICIPANTS")
        peers = {}
        for participant in participants:
            if type(participant) is not FixtureParticipant:
                raise LedgerError("INVALID_PARTICIPANTS")
            name = _token(participant.participant_id)
            if name in peers or name == _CONTROL.participant_id:
                raise LedgerError("INVALID_PARTICIPANTS")
            if type(participant.work_slots) is not int or not 1 <= participant.work_slots <= 16:
                raise LedgerError("INVALID_CAPACITY")
            peers[name] = {"actor_id": _token(participant.actor_id), "work_slots": participant.work_slots}
        contexts = initial_contexts(peers, FixtureRun(run_id, generation), initial_runs)
        definition = {"participants": peers, "run_id": run_id, "generation": generation}
        if initial_runs is not None:
            definition["initial_runs"] = {key: value.document() for key, value in initial_runs.items()}
        def decide(state, _):
            if "peer_traffic" in state:
                raise LedgerError("ALREADY_CONFIGURED")
            state["peer_traffic"] = {"definition": definition, "traffic": {}, "offers": {},
                                     "connections": {}, "cursors": {name: 0 for name in peers}}
            state["fixture_context"] = deepcopy(contexts)
            self._reserve_capacity(state)
            return self._transition(state, "peer.configured", definition, {"configured": True})
        return self._control(operation_id, "configure", definition, decide)

    def connect(self, operation_id, participant_id, incarnation_id, receiver, *, context_generation=1):
        """Attach only the Hub's current context, never caller-invented scope."""
        _token(incarnation_id)
        if participant_id not in self._state()["definition"]["participants"]:
            raise LedgerError("UNKNOWN_PARTICIPANT")
        if type(context_generation) is not int or not self._context_current(participant_id, context_generation):
            raise LedgerError("CONTEXT_MISMATCH")
        connection = FixtureConnection(participant_id, incarnation_id, context_generation, operation_id, receiver)
        binding = {"participant_id": participant_id, "incarnation_id": incarnation_id,
                   "context_generation": context_generation, "attachment_id": operation_id}
        def decide(state, _):
            if not self._context_current(participant_id, context_generation, state):
                raise LedgerError("CONTEXT_MISMATCH")
            current = state["peer_traffic"]["connections"].get(participant_id)
            if (current and current["incarnation_id"] == incarnation_id
                    and current["context_generation"] != context_generation):
                raise LedgerError("INCARNATION_RETIRED")
            if current and current["incarnation_id"] != incarnation_id:
                # Incarnations are never recycled. Use immutable attachment
                # history rather than an unbounded list in materialized state.
                cursor, through = 0, self.ledger.snapshot()["room_seq"]
                while cursor < through:
                    events = self.ledger.replay(cursor, through_seq=through, limit=1000)
                    if any(event["kind"] == "peer.attached"
                           and event["payload"]["participant_id"] == participant_id
                           and event["payload"]["incarnation_id"] == incarnation_id
                           for event in events):
                        raise LedgerError("INCARNATION_RETIRED")
                    cursor = events[-1]["room_seq"]
            state["peer_traffic"]["connections"][participant_id] = {
                **binding, "readiness": Readiness.AMBIGUOUS.value, "observation_id": None}
            return self._transition(state, "peer.attached", binding, binding)
        self._control(operation_id, "attach", binding, decide,
                      authorize=lambda: self._context_current(participant_id, context_generation))
        # Even an exact attach retry cannot revive a superseded attachment.
        if self._state()["connections"][participant_id]["attachment_id"] != operation_id:
            raise LedgerError("STALE_CONNECTION")
        self._connections[participant_id] = connection
        # Readiness never survives Hub reconstruction, even if the attach ID did.
        self.observe(connection, Readiness.AMBIGUOUS)
        return connection

    def _context_current(self, participant_id, generation, state=None):
        state = self.ledger.snapshot()["state"] if state is None else state
        if "fixture_context" not in state:
            return generation == 1  # Explicit legacy enablement is separately bounded.
        return self.contexts.current(participant_id, generation, state)

    def _scope_permits(self, participant_id, context_generation, run_id, generation, state=None):
        state = self.ledger.snapshot()["state"] if state is None else state
        admission = state.get('run_admissions', {}).get(run_id)
        if admission is not None and admission['status'] != 'ACTIVE':
            return False
        canonical = state.get('runs', {}).get(run_id)
        if canonical is not None and (canonical['status'] != 'ACTIVE' or canonical['generation'] != generation):
            return False
        if "fixture_context" not in state:
            scope = state["peer_traffic"]["definition"]
            return run_id == scope["run_id"] and generation == scope["generation"] and context_generation == 1
        return self.contexts.permits(participant_id, context_generation, run_id, generation, state)

    def _current(self, connection, *, safe=False, observation_id=None):
        if type(connection) is not FixtureConnection or self._connections.get(connection.participant_id) is not connection:
            return False
        current = self._state()["connections"].get(connection.participant_id, {})
        matches = (current.get("attachment_id") == connection.attachment_id
                   and current.get("incarnation_id") == connection.incarnation_id
                   and current.get("context_generation") == connection.context_generation)
        if safe:
            matches = matches and current.get("readiness") == Readiness.SAFE.value
        if observation_id is not None:
            matches = matches and current.get("observation_id") == observation_id
        return (matches and current.get("readiness") != Readiness.LOST.value
                and self._context_current(connection.participant_id, connection.context_generation))

    def observe(self, connection, readiness):
        if type(readiness) is not Readiness:
            raise LedgerError("INVALID_OBSERVATION")
        if not self._current(connection):
            raise LedgerError("STALE_CONNECTION")
        observation_id = "observation-" + uuid.uuid4().hex
        def decide(state, _):
            current = state["peer_traffic"]["connections"][connection.participant_id]
            current.update(readiness=readiness.value, observation_id=observation_id)
            return self._transition(state, "peer.observed", {
                "participant_id": connection.participant_id, "incarnation_id": connection.incarnation_id,
                "readiness": readiness.value}, {"observation_id": observation_id})
        return self._control(observation_id, "observe", {"participant_id": connection.participant_id,
                             "readiness": readiness.value}, decide,
                             authorize=lambda: self._current(connection))

    @staticmethod
    def parse(data):
        """Strict transport-neutral client schema; authority fields never parse."""
        if type(data) is not dict or set(data) != {"id", "run_id", "generation", "kind", "payload"}:
            raise LedgerError("INVALID_ENVELOPE")
        payload = data["payload"]
        if type(payload) is not dict:
            raise LedgerError("INVALID_PAYLOAD")
        common = {key: data[key] for key in ("id", "run_id", "generation")}
        if data["kind"] == "message" and set(payload) == {"recipient", "text", "parent_id"}:
            return Message(**common, **payload)
        if data["kind"] == "work-request" and set(payload) == {"recipient", "text"}:
            return WorkRequest(**common, **payload)
        if data["kind"] == "command" and set(payload) == {"request_id", "action", "reason"}:
            return RequestCommand(**common, **payload)
        raise LedgerError("INVALID_PAYLOAD")

    def submit(self, connection, traffic, *, origin=None, authorize=None):
        """Trusted fixture seam; optional Origin is NEVER client input.

        The process fixture supplies a supervisor-derived Origin and a fresh
        authority check under the ledger transaction. Existing in-process
        callers retain synthetic fixture authority, not process authentication.
        """
        if type(traffic) is dict:
            traffic = self.parse(traffic)
        if type(traffic) not in (Message, WorkRequest, RequestCommand):
            raise LedgerError("INVALID_ENVELOPE")
        if not self._current(connection):
            raise LedgerError("STALE_CONNECTION")
        peer = self._state()["definition"]["participants"][connection.participant_id]
        if origin is None:
            origin = Origin(peer["actor_id"], connection.participant_id, connection.incarnation_id,
                            "fixture-v1", ("peer-traffic",))
        elif (type(origin) is not Origin or origin.actor_id != peer["actor_id"]
              or origin.participant_id != connection.participant_id
              or origin.incarnation_id != connection.incarnation_id
              or "peer-traffic" not in origin.capabilities or authorize is None):
            raise LedgerError("FORBIDDEN")
        if type(traffic) is RequestCommand:
            payload = {"request_id": traffic.request_id, "action": traffic.action, "reason": traffic.reason}
            kind = "peer.command"
        else:
            payload = {"recipient": traffic.recipient, "text": traffic.text}
            kind = "peer.message" if type(traffic) is Message else "peer.work-request"
            if type(traffic) is Message:
                payload["parent_id"] = traffic.parent_id
        operation = Command(traffic.id, kind, traffic.run_id, traffic.generation, payload)
        def decide(state, command):
            domain = state["peer_traffic"]
            if not self._scope_permits(connection.participant_id, connection.context_generation,
                                       command.target, command.generation, state):
                raise LedgerError("STALE_GENERATION")
            if command.kind == "peer.command":
                return self._request_command(state, connection, command)
            return self._admit(state, connection, origin, command)
        return self.ledger.apply(operation, origin,
                                 authorize=lambda *_: self._current(connection)
                                 and (authorize is None or authorize() is True), decide=decide)

    def _admit(self, state, connection, origin, command):
        domain, payload = state["peer_traffic"], command.payload
        _text(payload["text"])
        peers = domain["definition"]["participants"]
        parent_id = payload.get("parent_id")
        correlation_id = command.id
        recipient = payload["recipient"]
        if parent_id is not None:
            parent = domain["traffic"].get(_token(parent_id))
            if (not parent or connection.participant_id not in parent["recipients"]
                    or parent["run_id"] != command.target or parent["generation"] != command.generation):
                raise LedgerError("FORBIDDEN_PARENT")
            if not parent["deliveries"].get(connection.participant_id):
                raise LedgerError("PARENT_NOT_DELIVERED")
            if recipient is not None:
                raise LedgerError("REPLY_TARGET_DERIVED")
            recipient = parent["sender"]
            correlation_id = parent["correlation_id"]
        if recipient == "*" and command.kind == "peer.message" and parent_id is None:
            recipients = sorted(set(peers) - {connection.participant_id})
        elif type(recipient) is str and recipient in peers and recipient != connection.participant_id:
            recipients = [recipient]
        else:
            raise LedgerError("INVALID_RECIPIENT")
        record = {"id": command.id, "kind": command.kind, "sender": connection.participant_id,
                  "actor_id": origin.actor_id, "run_id": command.target, "generation": command.generation,
                  "recipients": recipients, "text": payload["text"], "parent_id": parent_id,
                  "correlation_id": correlation_id, "submitted_at": _now(),
                  "submitted_seq": self.ledger.snapshot()["room_seq"] + 1, "deliveries": {}}
        if command.kind == "peer.work-request":
            record.update(status="QUEUED", response_started_at=None, reason=None, attention=None)
        domain["traffic"][command.id] = record
        self._reserve_capacity(state)
        return self._transition(state, "peer.submitted", {"traffic_id": command.id, "recipients": recipients},
                                {"traffic_id": command.id, "admission": "QUEUED"})

    @staticmethod
    def _reserve_capacity(state):
        """Admit only if every admitted item can reach its largest projection.

        Reserve all recipient offers/receipts, reasons, clocks and connection
        replacement metadata before returning QUEUED. Immutable event history
        grows on disk, not in this bounded projection. Other Room state present
        at admission is included; its trusted owner must preserve this budget.
        """
        reserved = deepcopy(state)
        # A canonical admission can temporarily transfer its own reserved bytes
        # to a bounded Broker read. Model the inevitable refund, not temporary
        # padding/slack that a new peer item could otherwise steal mid-read.
        from .forge import ReadOnlyForgeBroker
        for key, pending in list(reserved.get('forge_pending', {}).items()):
            funding = pending.get('admission_funding')
            if funding is not None and reserved.get('run_admissions', {}).get(
                    funding['run_id'], {}).get('status') == 'PREPARING':
                ReadOnlyForgeBroker._release_pending(reserved, key)
        for admission in reserved.get('run_admissions', {}).values():
            if admission['status'] == 'PREPARING':
                admission['attention'] = 'x' * 256
        for run in reserved.get('runs', {}).values():
            run.update(control_revision=MAX_CONTEXT_GENERATION, control_reason='x' * 256)
        reserve_context_capacity(reserved)
        domain = reserved["peer_traffic"]
        widest = "x" * 256  # Ledger token bound, including future incarnations.
        timestamp = "x" * 32  # UTC ISO timestamp emitted by _now().
        for participant in domain["definition"]["participants"]:
            domain["connections"][participant] = {
                "participant_id": participant, "incarnation_id": widest,
                "context_generation": MAX_CONTEXT_GENERATION, "attachment_id": widest,
                "readiness": "compacting", "observation_id": widest}
            domain["cursors"][participant] = MAX_SEQUENCE
        for item in domain["traffic"].values():
            domain["offers"][item["id"]] = {}
            for participant in item["recipients"]:
                receipt = {"delivery_id": "delivery-" + "x" * 64, "digest": "x" * 64,
                           "participant_id": participant, "incarnation_id": widest,
                           "context_generation": MAX_CONTEXT_GENERATION}
                item["deliveries"][participant] = {**receipt, "confirmed_at": timestamp}
                domain["offers"][item["id"]][participant] = {
                    "delivery_id": receipt["delivery_id"], "digest": receipt["digest"],
                    "incarnation_id": widest, "context_generation": MAX_CONTEXT_GENERATION,
                    "outcome": "UNCONFIRMED", "offer_seq": MAX_SEQUENCE,
                    "superseded_unconfirmed": {"count": MAX_SEQUENCE, "first_seq": MAX_SEQUENCE,
                                                "last_seq": MAX_SEQUENCE}}
            if item["kind"] == "peer.work-request":
                item.update(status="COMPLETED", response_started_at=timestamp,
                            reason="x" * MAX_TEXT_BYTES, attention="BLOCKED")
        try:
            _json(reserved)
        except LedgerError as error:
            if error.code != "INVALID_JSON":
                raise
            raise LedgerError("QUEUE_CAPACITY_EXHAUSTED") from error

    def _request_command(self, state, connection, command):
        domain, payload = state["peer_traffic"], command.payload
        request = domain["traffic"].get(_token(payload["request_id"]))
        if (not request or request["kind"] != "peer.work-request"
                or request["run_id"] != command.target or request["generation"] != command.generation):
            raise LedgerError("UNKNOWN_REQUEST")
        if request["recipients"] != [connection.participant_id]:
            raise LedgerError("FORBIDDEN_REQUEST")
        action = payload["action"]
        if type(action) is not str or action not in TRANSITIONS:
            raise LedgerError("UNKNOWN_COMMAND")
        if action in {"decline", "defer", "block"}:
            _text(payload["reason"])
        elif payload["reason"] is not None:
            raise LedgerError("INVALID_PAYLOAD")
        allowed, target = TRANSITIONS[action]
        if request["status"] not in allowed:
            raise LedgerError("INVALID_TRANSITION")
        delivery = request["deliveries"].get(connection.participant_id, {})
        if (delivery.get("incarnation_id") != connection.incarnation_id
                or delivery.get("context_generation") != connection.context_generation):
            raise LedgerError("DELIVERY_REQUIRED")
        if action == "accept":
            used = sum(item.get("status") == "ACCEPTED" and item["recipients"] == [connection.participant_id]
                       for item in domain["traffic"].values())
            if used >= domain["definition"]["participants"][connection.participant_id]["work_slots"]:
                raise LedgerError("CAPACITY_EXHAUSTED")
        request.update(status=target, reason=payload["reason"],
                       attention="BLOCKED" if target == "BLOCKED" else None)
        return self._transition(state, "peer.request.changed", {"request_id": request["id"], "status": target},
                                {"command_status": "APPLIED", "request_id": request["id"], "status": target})

    def cancel(self, operation_id, request_id, reason):
        """Trusted fixture-control cancellation; peers cannot issue force-stop."""
        _token(request_id)
        _text(reason)
        def decide(state, _):
            request = state["peer_traffic"]["traffic"].get(request_id)
            if not request or request["kind"] != "peer.work-request":
                raise LedgerError("UNKNOWN_REQUEST")
            if request["status"] in TERMINAL:
                raise LedgerError("INVALID_TRANSITION")
            request.update(status="CANCELLED", reason=reason, attention=None)
            return self._transition(state, "peer.request.changed", {"request_id": request_id, "status": "CANCELLED"},
                                    {"command_status": "APPLIED", "status": "CANCELLED"})
        return self._control(operation_id, "cancel", {"request_id": request_id, "reason": reason}, decide)

    def _pending(self, connection):
        """Replay admissions after durable cursor, plus retained responsibility."""
        snapshot = self.ledger.snapshot()
        domain = snapshot["state"]["peer_traffic"]
        participant = connection.participant_id
        cursor = domain["cursors"][participant]
        ids = set()
        while cursor < snapshot["room_seq"]:
            events = self.ledger.replay(cursor, through_seq=snapshot["room_seq"], limit=1000)
            if not events:
                break
            for event in events:
                if event["kind"] == "peer.submitted" and participant in event["payload"]["recipients"]:
                    ids.add(event["payload"]["traffic_id"])
            cursor = events[-1]["room_seq"]
        # A cursor does not discard pending confirmation or active responsibility.
        ids.update(item["id"] for item in domain["traffic"].values()
                   if participant in item["recipients"] and (
                       not item["deliveries"].get(participant)
                       or item.get("status") not in TERMINAL and item["kind"] == "peer.work-request"))
        pending = []
        for id in ids:
            item = domain["traffic"][id]
            previous = item["deliveries"].get(participant)
            if (item.get("status") in TERMINAL or not self._scope_permits(
                    participant, connection.context_generation, item["run_id"], item["generation"], snapshot["state"])):
                continue
            if previous and (item["kind"] == "peer.message" or previous["incarnation_id"] == connection.incarnation_id):
                continue
            pending.append(item)
        return sorted(pending, key=lambda item: item["submitted_seq"])

    def deliver(self, connection, *, limit=100):
        """At-least-once offer; commit intent, receive proof, then confirm.

        An absent/mismatched receipt or a changed observation leaves an unresolved
        durable offer. It is not evidence that the receiver had no effect.
        """
        if type(limit) is not int or not 1 <= limit <= 100:
            raise LedgerError("INVALID_LIMIT")
        if not self._current(connection, safe=True):
            return {"outcome": "HELD", "deliveries": []}
        delivered = []
        for item in self._pending(connection)[:limit]:
            current = self._state()["connections"][connection.participant_id]
            observation = current["observation_id"]
            if not self._current(connection, safe=True):
                break
            envelope = {key: value for key, value in item.items() if key in (
                "id", "kind", "sender", "actor_id", "run_id", "generation", "text", "parent_id", "correlation_id", "submitted_seq")}
            envelope.update(room_id=self.ledger.room_id, participant_id=connection.participant_id,
                            incarnation_id=connection.incarnation_id, context_generation=connection.context_generation)
            delivery_id = "delivery-" + digest(envelope)
            envelope["delivery_id"] = delivery_id
            envelope_digest = digest(envelope)
            def begin(state, _, envelope=envelope, envelope_digest=envelope_digest):
                request = state["peer_traffic"]["traffic"][envelope["id"]]
                if "fixture_context" in state:
                    self.contexts.reserve_delivery(state, connection.participant_id, connection.context_generation,
                                                   envelope["run_id"], envelope["generation"])
                if request.get("status") in TERMINAL:
                    raise LedgerError("DELIVERY_FENCED")
                offers = state["peer_traffic"]["offers"].setdefault(envelope["id"], {})
                previous = offers.get(connection.participant_id)
                history = deepcopy(previous["superseded_unconfirmed"]) if previous else {
                    "count": 0, "first_seq": 0, "last_seq": 0}
                superseded = None
                if previous and previous["outcome"] == "UNCONFIRMED":
                    history["count"] += 1
                    history["first_seq"] = history["first_seq"] or previous["offer_seq"]
                    history["last_seq"] = previous["offer_seq"]
                    superseded = previous["delivery_id"]
                offer = {"delivery_id": envelope["delivery_id"], "digest": envelope_digest,
                         "incarnation_id": connection.incarnation_id,
                         "context_generation": connection.context_generation,
                         "outcome": "UNCONFIRMED", "offer_seq": self.ledger.snapshot()["room_seq"] + 1,
                         "superseded_unconfirmed": history}
                offers[connection.participant_id] = offer
                return self._transition(state, "peer.delivery.offered", {
                    **offer, "traffic_id": envelope["id"], "participant_id": connection.participant_id,
                    "supersedes_unconfirmed": superseded}, {"delivery_id": envelope["delivery_id"]})
            authorize = lambda: self._current(connection, safe=True, observation_id=observation)
            def offer_allowed():
                current_item = self._state()["traffic"].get(item["id"], {})
                return (authorize() and current_item.get("status") not in TERMINAL
                        and self._scope_permits(connection.participant_id, connection.context_generation,
                                                item["run_id"], item["generation"]))
            self._control(delivery_id + ":offer", "offer", envelope, begin, offer_allowed)
            # Recheck even an exact offer retry before possible receiver contact.
            if not offer_allowed():
                raise LedgerError("DELIVERY_FENCED")
            # This is the only external effect. Nothing runs inside ledger.apply.
            receipt = connection.receiver.accept(envelope)
            expected = {"delivery_id": delivery_id, "digest": envelope_digest,
                        "participant_id": connection.participant_id, "incarnation_id": connection.incarnation_id,
                        "context_generation": connection.context_generation}
            if (type(receipt) is not dict or set(receipt) != set(expected)
                    or any(type(receipt[key]) is not type(value) or receipt[key] != value
                           for key, value in expected.items())):
                raise LedgerError("UNCONFIRMED_DELIVERY")
            def confirm(state, _, envelope=envelope, receipt=receipt):
                domain = state["peer_traffic"]
                offer = domain["offers"].get(envelope["id"], {}).get(connection.participant_id)
                request = domain["traffic"][envelope["id"]]
                if (not offer or offer["delivery_id"] != envelope["delivery_id"]
                        or offer["digest"] != receipt["digest"] or request.get("status") in TERMINAL):
                    raise LedgerError("DELIVERY_FENCED")
                if "fixture_context" in state:
                    self.contexts.confirm_delivery(state, connection.participant_id, connection.context_generation,
                                                   envelope["run_id"], envelope["generation"])
                offer["outcome"] = "CONFIRMED"
                now = _now()
                request["deliveries"][connection.participant_id] = {**receipt, "confirmed_at": now}
                if request.get("status") == "QUEUED":
                    request.update(status="DELIVERED", response_started_at=now)
                domain["cursors"][connection.participant_id] = max(
                    domain["cursors"][connection.participant_id], request["submitted_seq"])
                return self._transition(state, "peer.delivery.confirmed", receipt, receipt)
            confirm_allowed = lambda: authorize() and self._scope_permits(
                connection.participant_id, connection.context_generation, item["run_id"], item["generation"])
            result = self._control(delivery_id + ":confirm", "confirm", receipt, confirm, confirm_allowed)
            delivered.append(result)
        return {"outcome": "CONFIRMED" if delivered else "HELD", "deliveries": delivered}

    def snapshot(self):
        """Trusted harness view. A production transport must scope disclosure."""
        return self.ledger.snapshot()
