"""Test-only deterministic domain; it does not implement a product Run."""
from uas.ledger import Command, Event, LedgerError, Origin, Transition

ORIGIN = Origin("alice", "builder", "process-1", "policy-v1", ("counter-write",))


def authorized(origin, command):
    return origin.actor_id == "alice" and "counter-write" in origin.capabilities


def command(id="op-1", amount=1, generation=0):
    return Command(id, "counter.add", "counter", generation, {"amount": amount})


def increment(state, operation):
    if operation.kind != "counter.add" or operation.target != "counter":
        raise LedgerError("UNKNOWN_COMMAND")
    if set(operation.payload) != {"amount"} or type(operation.payload["amount"]) is not int:
        raise LedgerError("INVALID_PAYLOAD")
    if operation.generation != state.get("generation", 0):
        raise LedgerError("STALE_GENERATION")
    value = state.get("value", 0) + operation.payload["amount"]
    generation = state.get("generation", 0) + 1
    return Transition({"value": value, "generation": generation},
                      (Event("counter.changed", {"value": value}),), {"value": value})
