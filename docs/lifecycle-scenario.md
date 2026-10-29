# Pi–Claude–GitHub lifecycle harness (#78, preparation)

`uas.lifecycle_scenario.LifecycleScenario` is a bounded **trusted-host composition
driver**, not a production launcher or a replacement workflow reducer. It uses
an existing `RunReview`, its attached `AdmittedPeerDispatcher`, the same Room
ledger/Gate identity. Human controls and reports bind a fixed Run generation;
transport pumping is Room/seat-scoped. No second journal is created.
`./validate.sh` discovers its pure contract tests and real-ledger controlled-owner
tests through the existing unit inventory. No new workflow or heavy auto-test
is introduced.

## What the driver actually invokes

- `receive_room_once(operation)` receives one native frame through the admitted
  dispatcher. The host must choose a readable channel with a positive timeout
  of at most five seconds. The driver neither manufactures Origin nor calls the
  dispatcher's private submission method with a guessed Actor. The authenticated
  packet may address another permitted Run: the dispatcher, not the harness,
  decides its scope. Its receipt is returned unchanged, not attributed to the
  selected scenario Run.
- `deliver_seat_once(controller)` invokes the canonical `SupervisorAdmission` owner.
  That owner observes native SAFE and performs the existing offer/receipt
  protocol for the next permitted seat message, potentially for another Run.
  The harness does not set SAFE or manufacture a native acknowledgment.
- `request_changes` delegates a real human-control request to `RunReview`, with
  its original operation ID, body, target, authenticated human and authorization
  callback. `reconcile_changes` delegates the explicit bounded read attempt for
  that same operation; it never posts a replacement comment.
- `observe_completion` observes an already performed human merge using the
  existing review owner. It cannot merge. Candidate and integration SHA remain
  separate, including after terminal receipt replay.

The host supplies already constructed owners, not user-configured callbacks
that stand in for production identity. It remains responsible for launch,
readiness-driven event selection, channel deadlines, native session restoration
and shutdown. Room/seat pumps can remain useful after the selected Run changes
generation; that does not authorize human controls or reports for its old
generation, which are rejected. There are at most 128 explicit calls per driver invocation (32 by
default), with failures counted. Each call is one attempt; no hidden sleep,
model retry or provider retry is performed. This count is not a whole-run wall
clock deadline or permission to replay an uncertain write. The canonical owners
retain durable idempotency/reconciliation across driver restarts.

`report()` reads one ledger cut and exports allowlisted workflow metadata, not
prompts, comment bodies, raw Broker receipts or credentials. Its stored status
is not a fresh GitHub observation. A controlled Run reaching CLOSED is still
classified `controlled-composition`, with `real_lifecycle_qualified: false`.

## Current native route and legacy controlled preflight

This `LifecycleScenario` driver still deliberately returns its historical
`controlled-composition` preflight. That is not the current native CLI's
capability inventory. The consumed native route is now
[`qualify-native`](native-qualification-entrypoint.md), with optional
[`native_human_entry`](native-human-qualification.md): an existing protected
operator grant and accepted raw stream authenticate one retained HumanSession,
which reaches native admission, reviewer recruitment, human changes and the
finite `NativeSessionDriver`. Do not implement another host based on the older
missing-host wording.

Remaining #78 acceptance is concrete:

1. Prepare the selected Workstation **and Hub** images and actual installation
   metadata for the existing disposable backend. Image packaging/readback does
   not observe its XFS/SELinux/network/runtime boundary. The combined image passed
   [one real stopped-container readback](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40842890210)
   at `475c1160509b1f9f2e5418d33d12f69fb010d1e0`; that run retained logs/hashes,
   not a published or installed image.
2. Select the actual Project/Room configuration and authorized GitHub target,
   existing provider/Git/Forge references, explicit merger IDs and human TLS
   grant/listener. These are operator choices/references, not new credentials or
   missing source functions. Gate requirements must come from that selected
   policy; do not weaken it or require optional Gate profiles unconditionally.
3. Execute the original real Pi implementation/Claude review return, stale-review
   denial, same-Run Pi crash/safe-point redelivery, context/reset observation,
   human changes, uncertain Forge response reconciliation and unchanged-candidate
   human merge. Existing canonical owners and retained native adapters provide
   the source route; controlled tests are not those observations.

The current qualification session is explicitly bounded to **180 seconds** and
stops starting operations with less than 45 seconds remaining. This source slice
does not enlarge that limit. Plan the real scenario and its human interaction
against this bound before execution; a timeout is not a pass or permission to
restart an uncertain effect. The one-Run crash route must not be confused with
the separate successor-Run route, which still lacks a successor Git projection.

See the [canonical review owner](architecture/run-review-owner.md),
[admitted Workstation transport](workstation-pi-transport.md), and
[accepted reconciliation](architecture/source-reconciliation.md). No additional
VM or target-host execution is launched by this harness.

The implemented [opt-in native Pi exact-exec recipe](native-pi-recipe.md)
is consumed by the existing Supervisor launch owner. It does not change this
controlled driver's classification; actual provider execution and full lifecycle
qualification remain distinct from source composition.

The opt-in Claude host/native/helper composition is described in
[the runtime boundary](claude-native-admission.md) and
[the shared admission contract](native-claude-admission.md). It remains preparation
for #78, not real-provider or isolated-Hub qualification.
