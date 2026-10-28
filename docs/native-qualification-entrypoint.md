# Native pair qualification entrypoint (#78)

The supported entrypoint is `python -m uas qualify-native`, not an operator-written
Python composition script. This is an explicitly limited **paired native startup
and transport/owner attachment** milestone. Production `check-launch` remains
disabled. There is no implicit VM execution, image build, credential creation,
permission grant, provider fallback, or deployment.

## Check first

```sh
python -m uas qualify-native project.json \
  --installation /private/native-selection.json \
  --installation-sha256 SELECTED_SHA256
```

Default checking reads bounded configuration and digest-selected public
installation metadata. It never starts processes, reads token contents, contacts
providers, creates resources or changes permissions. Exit 3 means checking is
not a launch/qualification success. Missing input references are reported by
code; a parsed boundary declaration is not observed enforcement.

Selection version 1 has exactly:

- `profile: "disposable-native-v1"`, `room_id`, the disposable guest `nonce`;
- `timeout_seconds`, an integer from 1 through 180 for the native child session;
- `pi_manifest`, `claude_manifest`, `boundary_manifest`, `hub_manifest`,
  `broker_manifest`, each `{ "path": "absolute path", "sha256": "selected digest" }`;
- `human_mergers`, an explicit nonempty list of allowed GitHub User IDs.

The selected Room has exactly one Pi and one Claude seat, explicit provider auth
references and supported provider/model arguments. Claude's configured Actor
needs its exact `github_user_id`. Both native payload envelopes must identify
the same selected Workstation image, with exact supported artifact inventories
and versions. Manifest bytes must pass the existing nofollow, private regular
file, ownership, size and digest checks before parsing is trusted.

The [backend profile](native-qualification-backend.md) defines fixed disposable
storage, quota, userns, MCS, network, endpoint and immutable image requirements.
These are prerequisites with actual readback, not `qualified: true` claims.

Broker metadata version 1 contains `credential_path`, `gh_executable`,
`gh_sha256`, `gate_actor`, and `review_actor`. The actors must exist in the
configuration. Optional `mutation_actors` and `work_labels` must appear together;
Actor/User IDs must match configuration. The referenced token file already
belongs privately to the fixed Broker UID; neither setup nor checking creates,
copies or prints its contents. No mutation backend is silently enabled when
these optional fields are absent.

## Explicit disposable execution

Add `--execute-qualification` only in the prepared disposable guest, with
separate authorization to run it. The command is not a replacement for #62/#79
qualification or a production startup switch.

The root owner admits exact resources through canonical `Supervisor` lifecycle
ownership and starts fixed trusted children. It records expected process custody
before spawning and binds the returned concrete process handle immediately.
The non-root trusted Supervisor alone gets Engine access; neither Hub,
Workstation nor Manager receives its socket, group or private state.

The host follows the actual held-kernel Hub handshake; launches/adopts no PID
from a configuration string; creates native Pi and Claude recipes from the
validated configuration; performs both required admissions; and attaches the
direct original-record FD4 Forge/review ingress. It uses the same Room database
as Hub, not a copy, plus separate host-private Git history and journals.
The shared Room directory/file group is restricted to Hub and trusted host;
Supervisor-private stores are never mounted into Hub.

No model prompt or product Run is manufactured by this startup milestone.
The bootstrap `qualification-scope` is a **synthetic transport context**. A new
empty Git provenance owner is initialization, not proof of contribution history
or reviewer independence. Evidence explicitly reports those limits and
`RUN_ADMISSION_NATIVE_ADAPTER_UNAVAILABLE`. Native Run admission is the next
same-#78 adapter, using existing admission/request owners; this command does not
claim to implement the full accepted work-item/review/human-merge lifecycle.

Dispatch is finite and never retransmits a tool mutation. An uncertain Pi ADMIT
can only query its existing STATUS; uncertain Claude initialization queries
existing owners and fails rather than reinitializing. A lost Broker response
retains the canonical unknown-result/reconciliation behavior.

The root owner bounds child startup/session waits. Broker startup pipe writes
are nonblocking and share the deadline. Revocation precedes channel/store
closure. An exited trusted child is not claimed to have stopped all native
Workstation tasks: the root lifecycle owner separately stops the exact owned
container. All issued-session audit and journals are retained, including a
successful attachment, because a dispatched request may have contacted a
provider. The result reports `stopped-evidence-retained`, not destroyed/fully
cleaned. This fixed profile permits one qualification per disposable guest until
explicit reconciliation; it does not erase evidence to make another run fit.
A still-live or uncertain Broker prevents verified stop/cleanup and retains its
audit/resources; it is not killed and retried to force success.

## Security and evidence

The accepted [security boundary](architecture/security-boundary.md) deliberately
allows same-Room peers to share Runtime/provider state. This profile does not add
per-seat credential confidentiality. Cross-Room/host isolation remains required;
Forge tokens, Git private keys and Manager secrets remain outside Workstation.

Local validation for this source uses guarded pure tests with explicit process,
socket and provider doubles. They cover configuration, exact owner constructor
compatibility, bounded writes/dispatch, custody, uncertain results and cleanup
ordering. They are not evidence of an executed native image, authenticated model,
real provider action or successful guest boundary qualification.

## Initial native Run admission (trusted hosting API)

`native_session.run(..., human_request=NativeHumanRunRequest(...))` consumes an
**existing authenticated `HumanSession`** supplied by the hosting application.
Neither the CLI JSON nor the installation manifest constructs a session or grants
human-open authority. The ordinary command remains the paired attachment check;
its missing prerequisite is an authenticated native Run host, not an identity
string to paste into configuration.

The initial Pi path uses the existing `RunAdmission` reservation, fresh Forge
observation, eligibility and activation reducers on the same Room database.
Before any native launch, the root-owned checkout handoff verifies the exact
persisted PREPARING reservation and allocates through `CheckoutAllocator`.
The non-root host receives only the resulting owned slot. It never receives
permission to edit root lifecycle/checkout metadata. After provider observation,
the root re-observes that same slot before canonical activation.

The native recipe binds the reserved Run/context and owned checkout before
`ExecLaunch.attach_native` proves a fresh session. Original kernel admission and
canonical attachment must remain current through provider contact and the final
transaction. The canonical implementation Work Request is delivered only after
activation through `SupervisorAdmission.deliver_one`; uncertain delivery uses
its existing journal, not another prompt. Exact committed retries return the
existing terminal receipt without allocating, launching, reading Forge or
queueing a second Work Request.

The authenticated path then recruits the initially unopened configured Claude
reviewer for that exact active Run. It reserves the generation-1 context on the
same Room ledger before launch; a connected, previously delivered or used context
is rejected rather than relabeled. The canonical unused-context predicate is
shared with initial implementer admission. Human authorization, original Pi
attachment, active Run/control revision, configured reviewer identity and the
complete checkout source are rechecked at launch and admission cuts. Once Claude
is attached, its exact canonical attachment/incarnation must remain current too.
Stable retries return the held reviewer only; uncertain startup preserves its
journal and refuses a second launch.

The bounded dispatch loop now consumes both native Forge/review receivers after
recruitment, and implementation Work Request delivery still follows canonical
activation. This is not full implementation/review/completion qualification.
It does not invent self-assignment authority, authenticated login, native
reset/replacement/stop or participant Run Request routing. Reused reviewer
contexts fail with `NATIVE_REVIEWER_RESET_REQUIRED`: reset needs independent
proof of all old native/helper/SDK-host exits before advancing context generation.
The default CLI remains the paired attachment check and never manufactures the
authenticated HumanSession required by this initial-Run path.
