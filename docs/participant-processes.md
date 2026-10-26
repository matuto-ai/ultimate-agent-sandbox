# Process-bound Participant fixture (partial #63)

This slice connects the existing fixture `Supervisor`, #60 `RoomLedger`, and #65
peer domain to **actual disposable Linux processes**. It is not a production
launcher, native Pi/Claude adapter, Broker, or qualification of #62's Workstation
boundary. **#63 stays open** until that integration is demonstrated.

## Narrow API and authority

`supervisor.participants(hub, FixtureCredentials(...))` creates one trusted
`FixtureParticipantController`. Explicit `launch(FixtureSeat(...), receiver)`
starts only the bundled, fixed Python fixture Runtime. There is no shell, arbitrary
executable selection, provider call, secret loading, or production configuration
activation. The worker runs with an isolated Python environment, no inherited
account environment, and an empty disposable runtime directory—not the control
store as its working directory. Root/effective-capability-bearing fixture launch
is rejected. The supervisor's existing authorization callback gates control actions.

The immutable seat selects Actor, Participant, profile, declared capabilities,
fixture Runtime arguments, and required synthetic credential kinds. Once recorded,
a Participant cannot switch Actor, profile, or arguments, including after restart;
this fixture has no profile/configuration migration operation. Another Actor needs
another Participant. The supervisor's immutable badge additionally binds Room,
Room instance, controller ownership, random process incarnation, and epoch.

The badge is **not a bearer token** and is never parsed from child input. Each seat
has a fresh `AF_UNIX/SOCK_SEQPACKET` socketpair, inherited only by its launched
process. `SO_PASSCRED` is enabled before spawn. Every received record must contain
exactly one valid kernel `SCM_CREDENTIALS` tuple matching that child PID/UID/GID,
and the original held pidfd must still denote a live process. Connection-time
`SO_PEERCRED` or UID equality alone would not survive socket descriptor passing.
Forked children and unrelated same-UID processes receiving the socket through
`SCM_RIGHTS` are denied. Native child/auxiliary calls cannot become independent
Actors through inherited descriptors: they must be mediated by the original
Participant, retaining its attribution, or explicitly supervisor-launched as a
separate seat. This is an authority rule, not child confidentiality/isolation.

Packets are at most 64 KiB. Truncated payload/control data, missing/duplicate or
malformed credentials, unexpected ancillary data, duplicate JSON keys, invalid
UTF-8/nonfinite JSON, excessive nesting, and identity/capability/model fields in
client traffic fail closed. Received rights are closed even on rejected records;
ancillary truncation is never interpreted as absent optional credentials.

`receive(handle)` derives `Origin` from the stored badge and calls the existing
peer parser and ledger. The ledger's security-context digest includes the entire
badge. Exact retries by the same authorized incarnation return the prior receipt;
a different incarnation cannot recover that receipt merely by repeating its ID.
The existing trusted in-process `FixturePeerHub.submit` API remains a fixture
seam, not an externally authenticated production endpoint.

## Lifecycle, storage failure, and recovery

- A private, fsynced `participants.json` under the Room instance holds at most
  32 immutable seat definitions. It is outside the application ledger's bounded
  materialized state and does not consume #65's reserved peer lifecycle budget.
- Launch intent fences older authority before spawning. Successful binding is
  persisted before a handle is returned. Failure kills/waits the new process and
  closes descriptors even when the compensating manifest write also fails.
- Authorization and the complete peer/ledger transaction share the Supervisor's
  lifecycle lock with revocation, credential observation, Stop, and Destroy.
  Transaction-time revalidation is pure: an exit/credential race rolls back first,
  then updates authority and peer liveness outside the ledger transaction.
- Exit is checked through the held pidfd, not a reusable PID. Revocation/close
  changes the epoch/status before termination. Stop/Destroy must verify nonempty
  process revocation before touching the fixture backend. A reconstructed
  Supervisor cannot replace that check with the old vacuous boolean callback.
- Store uncertainty fences in-memory authority and latches that controller
  unavailable. Reconstruction rotates controller ownership and revokes every old
  binding; persisted PIDs/UIDs are never adopted as current authority. Epoch
  exhaustion rejects new launch before effects; revocation remains valid at the
  maximum epoch and never wraps or writes an unreadable store.
- A reconstructed controller does not own the old pidfds. It only observes whether
  recorded retired PIDs are absent/exited, never kills an arbitrary persisted PID.
  A live retired process blocks verified Stop/Destroy. PID reuse may conservatively
  block cleanup; it cannot restore authority or authorize killing the new process.
  The original live controller may dispose of its own children. The fixed fixture
  exits when a killed supervisor's stdio closes; that behavior is tested, not
  assumed for future native Runtimes.

There is no autonomous seat restart. An exact synthetic
`(Actor, forge.fixture.invalid, credential kind)` binding resolves a
`fixture-*` reference, with no sibling/generic/provider-host fallback.
`set_credential_available` serializes fixture observations and stops only active
seats that require the missing reference. Repair permits explicit affected-seat
launch without Room restart. These references contain no real credential bytes
and their availability does not claim real account/provider qualification.

Receiver acceptance is still #65's existing disk-backed fixture or a trusted test
receiver supplied at launch. This slice proves authenticated outbound process
submission, not native Runtime inbox delivery, safe points, context reset, or
contribution-policy evaluation. Existing Actor-keyed ledger history is retained;
process/model/seat replacement supplies no operation to erase or reattribute it.

## Evidence and remaining boundary

```sh
UAS_REQUIRE_PARTICIPANT_PROCESS_TESTS=1 \
  python3 -m unittest discover -s tests -p test_participant.py -v
./validate.sh
```

The focused suite runs real processes and real Unix socket records, not a
caller-supplied trusted-peer flag. It covers positive ledger/peer attribution,
same-UID fork and explicit FD handoff denial, malformed/truncated records and FD
leak checks, forged client fields, profile capabilities, exit/replacement/replay,
credential loss/repair and unaffected sibling seats, Stop/Destroy ordering,
controller replacement, actual supervisor `SIGKILL` recovery, bounded epoch
exhaustion, double launch-store failure, failed revocation persistence, and
credential/exit races after the ledger transaction starts. It does not force
system-wide PID wraparound or change any host security setting. Invalid ancillary
shapes that Linux itself rejects on send are tested at the parser seam; those
unit cases are distinct from the actual socket tests.

CI sets `UAS_REQUIRE_PARTICIPANT_PROCESS_TESTS=1`: missing Linux primitives fail
rather than silently skip. Actual Linux execution is mandatory evidence. Local
Docker skips do not qualify Docker/VM behavior, and a docs-exempt workflow is not
process evidence.

**The control plane and child processes deliberately share a namespace/UID in
this synthetic harness.** Although packets cannot acquire another process's
identity by socket theft or FD passing, this is **not** protection from arbitrary
host/same-UID filesystem modification, ptrace/code injection, or control-plane
compromise. The harness does not mount or expose a real authority store to a
Workstation and proves no separation of that store here. Private labelled shared
transport, SELinux confinement, cross-namespace PID translation/pidfd ownership,
real launch admission, actual Actor credentials, Pi/Claude child handling, native
readiness, and Broker integration remain unqualified #62/#63/#70/#71 work.
