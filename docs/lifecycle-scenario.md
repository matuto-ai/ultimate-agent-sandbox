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

## Explicit blocked live preflight

`preflight()` reports the missing live seams; no environment flag, credential
presence boolean or supplied evidence label enables live acceptance. Today:

1. `uas.__main__` provides validation and read-only launch preflight, not a
   product launcher. `Supervisor` and current native recipes remain fixture
   qualified. The selected Pi/Claude native launch, production admission and
   provider/tool configuration need actual host composition, not a renamed
   fixture recipe.
2. The dispatcher/review/Git/Broker owners need to be assembled with actual
   immutable seat authority, controlled Project history/target fences and the
   selected authorized GitHub account. Existing controlled admission/provenance
   facts do not establish this.
3. Real Pi and Claude must execute the implementation/review return and retain
   runtime/image versions, Actor/context generations, Work Requests, exact
   candidate/base/integration revisions, native review identity and CI attempts.
4. Stale review, crash/safe-point recovery, context reset, human changes and
   ambiguous Forge write must be exercised through those seams. Finally an
   authorized human merges the unchanged candidate, and the owner observes it.

Those are existing [#78](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/78)
obligations, not new product gates. This preparation does not complete that
issue. The next implementation work is the concrete native/host composition
above, followed by authorized real execution—not another generic evidence store.
Account availability, credentials and human merge are external prerequisites,
not code that can be replaced by a successful controlled test.

See the [canonical review owner](architecture/run-review-owner.md),
[admitted Workstation transport](workstation-pi-transport.md), and
[accepted reconciliation](architecture/source-reconciliation.md). No additional
VM or target-host execution is launched by this harness.

The next source slice adds an [opt-in native Pi exact-exec recipe](native-pi-recipe.md)
consumed by the existing Supervisor launch owner. It does not change this
harness's live preflight classification; selected-image/provider execution,
Claude native-child/MCP composition and full lifecycle qualification remain.

The opt-in Claude host/native/helper composition is described in
[the runtime boundary](claude-native-admission.md) and
[the shared admission contract](native-claude-admission.md). It remains preparation
for #78, not real-provider or isolated-Hub qualification.
