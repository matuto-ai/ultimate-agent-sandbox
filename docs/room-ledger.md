# Room application ledger

The first persistence slice implements [#60](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/60) behind `uas.ledger.RoomLedger`. It follows the [Room protocol](architecture/room-protocol.md#ledger-and-recovery): one Room, one SQLite database, an atomic command boundary, and ordered replay. This is application/domain persistence, **not** a durable agent execution engine. It does not select or replace Pi Durable, implement Runs, launch CLIs, or mutate Forge.

## Interface and ownership

```python
from uas.ledger import Command, Event, Origin, RoomLedger, Transition

# Illustrative trusted Hub identity, not data accepted from a Participant.
origin = Origin("alice", "builder", "process-1", "policy-v1", ("note-write",))
command = Command("note-1", "note.record", "room-notes", None, {"text": "hello"})

# Domain-specific validation and authorization belong to trusted application code.
def authorize(origin, command):
    return origin.actor_id == "alice" and "note-write" in origin.capabilities

def decide(state, command):
    if command.kind != "note.record" or command.target != "room-notes":
        raise ValueError("unsupported command")
    if set(command.payload) != {"text"} or type(command.payload["text"]) is not str:
        raise ValueError("invalid typed payload")
    return Transition(
        {"last_note": command.payload["text"]},
        (Event("note.recorded", command.payload),),
        {"recorded": True},
    )

# The parent directory must already exist outside Workstation-accessible mounts.
with RoomLedger("room.sqlite3", "alpha") as ledger:
    receipt = ledger.apply(command, origin, authorize=authorize, decide=decide)
    snapshot = ledger.snapshot()
    later_events = ledger.replay(snapshot["room_seq"], limit=100)
```

A Room Hub constructs `Origin` from authenticated, process-bound authority, not client fields. This slice supplies the seam; it does not yet authenticate a socket or prove the Workstation/control-plane separation. The caller chooses the database under the validated Room `state_root`, never a project mount. The store binds its Room ID and rejects a different Room or unsupported schema; there is no cross-Room routing or implicit migration.

The authenticated context includes Actor, Participant, process incarnation, authority version, and capabilities. Never put bearer tokens, provider secrets, or transcript contents in it. A different security context cannot reuse an ID to recover another context's result; retry identity must be reconciled by the future authenticated Hub rather than silently replaced. Every call, including a duplicate, requires fresh `authorize(...) is True` **after acquiring the SQLite write transaction**, before duplicate lookup. Authorization must be trusted, pure, and local; a callback that needs Room-owned policy can call `snapshot()` on this same connection for a transaction-consistent read. It must not perform nested writes or external effects. This ordering prevents a permission decision made before waiting for a writer from surviving a policy revocation committed by that writer. Authentication/authorization of snapshot and replay consumers also belongs to the future Hub transport: these are trusted in-process methods, not public network endpoints.

`decide(state, command)` is a pure, trusted domain handler, called inside the write transaction only for a new operation ID. It must validate the command-kind-specific typed payload, applicable generation, and domain rules before returning a `Transition`. There is no arbitrary client-supplied handler or generic network state-write API. It must not perform external effects, perform nested ledger writes, or retain/mutate inputs after returning. Later slices add typed domain commands using this boundary; a callback is not permission to bypass domain policy.

A transition contains the next materialized state, 1–256 events, and its result. State, event payloads, and result are JSON objects. The ledger assigns event sequence, timestamp, operation association, target, generation, and authenticated origin. The test counter and note example above are illustrations, not product commands or a Run model.

## Atomic acknowledgement and retry

SQLite `BEGIN IMMEDIATE` serializes writers. One transaction appends the events and original result and advances materialized state plus Room sequence. Only a successful `COMMIT` permits acknowledgement. WAL with `synchronous=FULL` requests SQLite's durable local-filesystem behavior. This assumes a filesystem/storage stack honoring SQLite locking and sync; it is not a demonstrated host-power-loss, network-filesystem, or malicious-storage guarantee.

Canonical equality binds Room, operation ID, kind, target, applicable generation, typed JSON payload, and authenticated context. Object-key/capability order is immaterial; JSON boolean, integer, floating-point, and string types are distinct. An authorized exact retry returns the original receipt before re-running generation/domain checks, including after reopening the disk database. A differing canonical envelope returns `ID_CONFLICT` without returning the stored result or changing state.

Authorization, malformed-input, and domain exceptions reject admission with no committed operation. They are not persisted command outcomes. A domain outcome that must remain stable under retry should be returned as a transition/result with its corresponding event. Storage errors return `STORAGE_ERROR`, **not proof that a command failed to commit**: after restoring storage availability, reopen and retry the same identity/envelope. Never manufacture a new operation ID to resolve an uncertain acknowledgement.

Each connection belongs to one thread; separate connections/processes serialize with SQLite (five-second lock timeout). Lock contention may surface as `STORAGE_ERROR` and follows the same retry contract. Connections support `with` and explicit `close()`. No connection pool, retention/compaction, migration framework, or distributed coordination is added here.

## Snapshot and cursor replay

`snapshot()` returns `{room_id, room_seq, state}` from one read statement, so state and sequence share a read cut. A new client starts with that snapshot and asks `replay(after_seq=snapshot["room_seq"])` for later events. Each replay call returns a bounded ascending range, default 100 and maximum 1,000 events. Continue from the last returned `room_seq`; an optional `through_seq` bounds a finite catch-up range. Repeating a range repeats its events. Exactly-once membership in a cursor range is **not** exactly-once network delivery or external execution. No stream, wake-up, subscriber transport, or outbox is implemented yet.

The store is append-only through its interface. This is not a tamper-evident audit log against a privileged host/database editor. JSON values have a one-MiB encoded bound, nesting depth 32, bounded collection size, finite numbers, and signed 64-bit integer limits. Sequences are positive signed 64-bit integers and never reused after a committed event; rolled-back sequences remain available. These are implementation bounds, not measured Room capacity recommendations.

## Evidence and remaining boundaries

Run `./validate.sh` for the aggregate configuration, CLI, and application-ledger suite. The same entry point runs in GitHub CI. Ledger evidence includes:

- append, exact retry, typed-envelope/security-context conflicts, and fresh retry authorization;
- multi-event atomic state/result/sequence, rejected handlers, and rollback after a valid first event;
- disk reopen and new-process retry/conflict through the public interface;
- actual process `SIGKILL` after an event but before result/state, immediately before commit, and after commit but before acknowledgement;
- actual SQLite `SQLITE_FULL` using a disposable database page quota, followed by reopen/recovery (not filling the host disk);
- independent-process duplicate/conflict races, revocation while waiting for the write lock (both new-command and duplicate-result paths), consistent snapshots during writes, and paged ordered replay;
- wrong-Room, unsupported-version, invalid-cursor, malformed-input, and closed-handle failures.

This proves the application storage seam in the tested local/CI environments. It does not prove production authentication, secure mounts, actual Runtime delivery, paid-provider access, Forge reconciliation, host power loss, or a complete product. Those remain separate implementation and integration obligations.
