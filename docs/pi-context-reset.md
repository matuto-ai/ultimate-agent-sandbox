# Durable Pi context reset — bounded fixture integration

This slice connects the Room ledger, peer domain, Supervisor process authority,
and actual official Pi 1.4.0. It follows the [accepted reset resolution](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/27#issuecomment-6397324839)
and [Room protocol](architecture/room-protocol.md#ledger-and-recovery). It does
**not** implement canonical GitHub Run admission, human merge/completion evidence,
production Workstation transport, paid providers, or deployment image qualification.
The same-UID Linux fixture limitations in [Pi runtime](pi-runtime.md) still apply.

## Recorded seams and bounded facts

`FixturePeerHub.contexts` owns typed fixture Run/context facts in the existing
Room SQLite ledger. There is no second workflow engine or new persistence limit.
`configure(..., initial_runs={participant: FixtureRun(...)})` optionally assigns
initial fixture scopes atomically before any process attachment; defaults retain
the original one-Run setup. It cannot reassign a previously configured Participant.

Trusted fixture control alone calls `open_run` or `close_run`. Closing requires a
`FixtureRunTerminal` enum, never a Participant-provided boolean. Every Work Request
in that Run must already be terminal; cancellation uses the existing explicit
trusted cancellation action. These are **synthetic terminal facts**, not claims
that GitHub human merge or real product Run completion has been verified.

Each Participant has its own context row. Initial assignment reserves one Run;
only a matching confirmed native delivery records `bound_run`. The reservation
exists before native handoff and survives uncertainty. Multiple work slots remain
within that Run. A reset of Pi does not move a sibling to a different Run or
replace its process. Closing a shared Run naturally prevents new traffic for that
Run, but does not silently change any Participant's binding.

Explicit fixture limits are 32 current context rows, 64 open/referenced Run rows,
and context/Run generations no greater than `2^53-1` (exact across Python/JS).
Rows retain only current binding/reservation and latest reset status. Complete
reset/terminal history remains append-only ledger events. Unreferenced closed
Run projection rows may be removed; their history and old traffic are not.
Opening a previously closed Run ID checks terminal history and fails closed.
These are finite **fixture limits**, not measured production capacity defaults.

## Shared one-mebibyte state reservation

Peer admission reserves worst-case future connection/offer/receipt/clock/reason
sizes as before, plus **101,999 bytes** for all maximum-width context and Run
rows and future generation digits. Context/Run transitions use that same combined
reservation against the existing 1 MiB state bound and all other actual Room
state. Reset does not consume a hidden, unbudgeted state allowance.

The saturation regression admits traffic until the bound rejects admission,
then fills all remaining Run slots with maximum-width IDs and maximum generation,
cancels/closes, resets, reopens the ledger, restores delivery, and completes the
already admitted responsibility. No admitted traffic, unknown outcome, receipt,
or immutable event is evicted to make a control transition fit.

Older ledger projections without context rows require explicit trusted
`contexts.enable(operation_id)`. This preserves prior confirmed binding and
checks the full future reserve. An older already-full ledger may reject enabling
atomically; it is never silently rewritten, compacted, or stripped of admitted
responsibility. Fresh configurations include the reservation from first admission.

## Reset sequence and process ownership

The trusted controller calls:

```python
controller.reset_pi(reset_operation_id, immutable_seat, fixed_target_recipe,
                    expected_context_generation=old_generation,
                    target_run=FixtureRun("next-run"))
```

1. Hub control verifies the preceding Run is terminal, target Run is open,
   generation matches, and no other reset owns this context. The ledger atomically
   records `context.reset.requested`, fences old connections, and blocks delivery
   into either Run for this Participant. No native effect precedes that commit.
2. Supervisor revokes the old badge, terminates/reaps its exact owned process and
   verifies stop. Retired foreign-owner PIDs are only checked for absence/liveness;
   they are never adopted or killed. Unverified old-process absence blocks reset.
3. A fixed recipe directly starts a fresh official Pi CLI, with a new PID/pidfd,
   badge and extension runtime UUID. There is no `--session`, parent-session
   tracking, compaction fallback, proxy, or terminal scraping. Authority stays
   pending. Native RPC waits occur outside the lifecycle lock.
4. Supported `get_state`, `get_entries`, and extension observations prove a fresh
   session ID, idle/no pending messages, zero conversation messages, and only the
   fresh model/thinking metadata entries. The new context's intent journal must
   be empty. No prompt is injected to prime/flush it; no native JSONL is written.
5. A bounded, fsynced **private Supervisor checkpoint** records native handles and
   the scoped recipe directory. Native session IDs, paths and transcript data do
   not enter Hub state. Under the lifecycle lock, fresh pending-handle, epoch,
   credentials, controller ownership and pidfd checks authorize the ledger's
   `context.reset.succeeded` transaction. Only that transaction advances the
   monotonic context generation, exactly once.
6. Only after success is durable may Hub attachment and active manifest publication
   complete. The target Run is reserved, not yet falsely reported as delivered;
   its first confirmed native delivery establishes the new binding.

The fixed recipe uses separate native HOME/session/journal directories for each
context generation, but preserves the same fixture workspace. Project bytes,
Actor identity/contribution history, Participant/profile/capabilities, old native
artifacts, and Hub/Forge history are not erased or reattributed. Old session
artifacts remain inactive and never become automatic reset inputs. Reset is not
checkout release/adoption or permission to reuse dirty Project checkouts; those
production admission/checkout gates remain separate.

## Failures, exact retry and restoration

- Requested/failed reset leaves the Participant unavailable and the preceding Run
  closed. Explicit retry of the same reset ID can create a new pending native
  attempt; each failure has its own audited operation identity. Success has one
  deterministic completion key. Invalid/stale completion cannot advance twice.
- Stop/revoke/replacement winning while native proof runs defeats the late
  completion. Cleanup kills only the pending process it owns, not a replacement.
- A lost success acknowledgement is reconciled from ledger truth before any retry
  or failure transition. Succeeded reset is never downgraded or repeated merely
  because active manifest publication failed. Exact retry returns only a current,
  freshly authorized matching handle or reports restoration required.
- `restore_pi` uses the private checkpoint for the **current ledger-approved
  context only**. An older generation/session or mismatched recipe fails before
  process effects. A persisted current session resumes with a new process badge.
- Pi may not create a brand-new session file until its first conversation flush.
  If reset succeeded before that point, fresh restart **within the same generation**
  is permitted only while the context remains unbound and the retained scoped
  journal proves zero native handoffs. It uses fresh native proof and does not
  advance generation or inject a priming prompt. A missing/corrupt journal or any
  handoff intent blocks this exception. Unknown first-flush delivery still needs
  explicit recovery; it cannot be disguised as an empty context.
- Old-Run unknown offers and native intents remain literal historical unknowns.
  An explicit terminal/cancellation fact permits reset, not retroactive delivery
  confirmation or redelivery into the new session.

All ledger/journal operations and active lifecycle coordination run on their
owning thread. Background native readers only collect events. General cross-thread
Stop after active attachment is not promised without owner-thread marshaling.

## Evidence

```sh
python3 -m unittest discover -s tests -p test_context.py -v
sh tests/pi/run-tests.sh
UAS_PI_INSTALL="$PWD/tests/pi" ./validate.sh
```

The domain suite covers typed terminal authority, first-confirm binding, stale
native confirmation, exact retry, generation limits, pruned closed-ID rejection,
legacy enablement, and the shared-reserve saturation lifecycle. Its native proof
callbacks are explicit synthetic fixtures, not real Pi evidence.

Actual Pi tests cross A → verified stop → fresh B → native delivery/peer tools,
preserving a live sibling, Actor attribution, dirty fixture workspace bytes,
Project bytes, and old traffic/session history. Negatives include compaction,
failed fresh proof, private checkpoint failure, Stop/replacement races, lost
success acknowledgement, active plus compensating manifest failure, stale
success authority, unknown old handoff retention, and the zero-journal restore
guard. The mandatory CI gate acquires the locked official package and runs in a
child network namespace. Per-case evidence contains generation/status/events,
not conversation contents. #70 and full-product acceptance remain open.
