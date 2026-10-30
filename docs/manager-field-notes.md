# Live Field Notes — issue #76

## Pre-implementation contract and proof plan (2026-10-27)

Read: the installed Bruno development workflow; actual #76 and #58; domain
language; source reconciliation; Manager read-model, Room protocol and security
contracts; the merged Field Notes HTML and its existing `check.cjs` interaction
check. Source baseline is #75's frozen `manager75-review-final-v1`, tree
`b88a836198e352fcd468a132c6b91cc3866c76a8`. Implementation was subsequently
reconciled to merged #75 main `2cff3a4b211e510352d75204107a64187f0c213b`, including
its three fixed source-stage allowlists. The following plan preceded code.

No framework selection, second UI, approval/merge control, credentials, listener,
deployment, provider mutation, or extra browser suite is part of this change.

### Affected routes

Keep `?variant=C|D` (Field Notes light/dark) and `?page=projects|inbox|health|project|run`.
The selected Project remains the Room's operating context; Runs stay nested
beneath it. Add only a Room detail subview if the existing Project context needs
one, not another global hierarchy. Preserve query navigation and Back/Forward.
`?page=room&project=...` is the same selected Project's technical Room subview;
it is reached from Project details, not a new top-level navigation area.

### Live mapping

- `ManagerReadModel.view()` owns connection, catching-up and projection staleness.
- Its versioned `projection.sections` own all displayed facts. Preserve each
  envelope's owner, observation version/time, commit time, status, freshness and
  reason. A fresh document does not refresh an old source observation.
- `runs`, `candidate`, `review`, `attention` and `work_requests` supply Run/Inbox
  facts. No invented titles, rounds, percentages, successful requests or approval.
- `gate_truth` is separate from `gate_history`; recorded results never become
  current passes. `pending_ci` is an owner checkpoint, not proof remote CI runs.
- Seats, persisted process authority, adapter attachment, readiness, binding,
  provider validity, inference, quota and context remain independent observations.
- Health progressively discloses lifecycle, image/profile drift, projection
  drift, checkout paths/working state, capabilities and sanitized diagnostics.
- Project identity for idle Rooms and chronological Run-specific observations
  must come from their actual owners; absent fields stay explicitly unknown.

### Stale behavior and authority

Disconnected, catching-up/stale, unknown/unavailable, partial, failed and drift
retain literal labels; no substring matching may paint `disconnected` as green.
Last accepted snapshots may remain visible with their source cut and warning.
Controls are disabled previews until #77 supplies authenticated, currently
eligible commands. Open in GitHub is validated navigation only.

### End-to-end proof and execution boundaries

Extend the existing `spike/manager-ui/check.cjs`, not a second suite. Produce
fixtures through actual RoomLedger → RoomStream → ManagerReadModel → document
rendering, then exercise every route/theme, navigation, drawers, stale/reconnect,
Run/Gate separation, and disabled controls in that check. Review the exact harness
before running it bounded in hosted CI, as a parallel job within the existing
three-minute total budget. Local checks may only use explicitly audited pure
guards; no local browser, sockets, process/native, Docker or VM tests.

The existing check uses Node VM and a small DOM double. It is interaction/rendered
markup evidence, **not real-browser layout, screenshot, or accessibility proof**.
Actual browser proof remains separate and must be recorded honestly.

### Open source/hosting questions identified before implementation

#75 has Python read-model APIs and authenticated Room POST transport, but no
human-authenticated browser server. Do not reuse Room client certificates as
human authority or add an unauthenticated endpoint. An endpoint-free document
renderer can consume an already-authorized read-model view; production browser
hosting/login must remain explicit until its real owner is connected.

The current stream omits Run scope from replay event metadata and initial
bootstrap need not include historical events. A fabricated journey cannot fill
that gap. The source owner confirmed that Project metadata comes from validated
configuration and chronological history must use finite, named owner contracts.

## Implemented read-only integration

`uas.manager_ui.FieldNotesDocument` takes an existing `ManagerReadModel` and a
fixed tuple of `ProjectBinding` values. The already-authorized trusted host owns
the allowed identities and rechecks its human permission before each render.
`ProjectBinding.from_configuration(source, identity)` validates the existing
configuration and exports only Project ID and repository, never roots, runtime
arguments or credential references. Its binding digest identifies configuration
metadata, **not** a live source version.

`render()` embeds a fresh bounded, escaped JSON capture into the existing HTML.
The page has no built-in network client and is read-only without an explicit
authenticated action attachment (see [Manager actions](manager-actions.md)).
An authorized containing host may supply another capture through `installDocument()` or reload a freshly
rendered document; this closes old drawers/dialogs before showing new facts.
The page independently ages its accepted snapshot deadline and warns on clock
skew. No page refresh extends a source observation's lifetime. Rendering this
component is not standalone deployment or production login qualification.

### Projection v2 and history compatibility

The v2 producer adds one `hub`-owned `journey` envelope. It captures at most the
latest 200 original Room events through the **same** snapshot cut. Attribution
uses only the named Run/Review owner contracts in `manager_journey.py`; arbitrary
targets, peer events, raw bodies, human reasons and request content are omitted.
Each included event retains its original sequence/time and validated Run and
generation, plus finite review stage/verdict when present. This is an observed
chronological window, never invented intermediate state or a Gate decision.

The range records first sequence, cut and complete/partial **supported-window**
coverage. Even a complete range does not claim that omitted event kinds or older
unretained Runs were idle. Bootstrap now receives this bounded window without
reconstructing an unbounded archive. The separate passive `ManagerReadModel.events`
accessor paginates already-retained metadata through the installed cut and marks
missing pre-bootstrap history; pending replay cannot leak into the current view.

Upgrade the consumer before the producer. The new consumer accepts v1 snapshots
as history-unavailable; v2 is explicit and never silently stripped. A new
`RoomStream(..., schema_version=1)` remains available for an explicitly configured
old consumer. Old consumers reject a v2 `begin` using their existing exact-version
guard, preserving their last accepted snapshot. There is no automatic fallback
or negotiation that changes authority or erases known facts. A same-cut v1→v2
upgrade must preserve every existing Hub fact and source watermark. Once v2 is
installed, downgrade is rejected. Old replay event frames and exact-retry
equality are unchanged; storage schema remains version 1.

## Verification records

The focused Python tests and 48 existing read-model/host/workflow/source-closure/CI-budget
checks passed under explicit process/socket/thread/kernel-effect tripwires:
59 tests, zero skips and zero trips. An initial run used the wrong working
directory for three existing fixtures; rerunning from the repository root passed
without changing those tests. These are pure/filesystem/SQLite results, not
browser, TLS, native, provider-account or deployment evidence.

The existing `check.cjs --fixtures DIRECTORY` covers every light/dark route and
interaction using documents produced by the actual read-model seam, rather than
hard-coded frontend scenarios. Its `--browser` mode is explicitly hosted-only:
preinstalled Chrome, intact sandbox, unique disposable profile, Node built-ins,
file documents, blocked HTTP(S)/WS(S), no package/browser downloads or server.
The official [Ubuntu runner manifest](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md#browsers-and-drivers)
lists Chrome; each executed receipt records the actual version instead of
claiming a fixed image. A 35-second owned-child deadline and outer 40-second
bound run in a one-minute parallel CI sibling within the existing three-minute
critical path. It checks actual layout, accessible heading/navigation, dialog
focus/Escape, navigation/Back, disconnected/reconnected state and mobile overflow.
Five bounded screenshots and a JSON receipt are retained for independent pixel
inspection. Source/harness review must precede hosted execution. At this source
checkpoint the real-browser mode and pixel inspection have **not run**.


## Optional typed human controls

A trusted containing host can call `installActionHost(projectKey, binding)` for
one already-authorized Room. The binding exposes `view(runId)`, `lifecycle()`,
`replacement(participantId)`, `execute(packet)`, and `inspect(originalPacket)` through its existing
transport to `FieldNotesActionHost`. No browser JSON supplies a HumanSession,
login, credential, endpoint, owner or Room authority. Missing bindings retain
read-only controls. Opening Human controls obtains fresh owner eligibility;
projection status does not enable an action.

The panel preserves the owner's exact scope, version, object and generation.
One in-flight packet blocks duplicate clicks. An unknown response keeps the
original operation identity without offering a replacement mutation or automatic
retry; the user can refresh owner state and use a separately eligible explicit
reconciliation action. Receipt, selected-not-launched, denied, partial and unknown
outcomes remain literal. Snapshot replacement or disconnection closes controls.
Open in GitHub remains a source link, not a merge action.

The browser action fixture uses a controlled injected adapter to verify actual
clicks, modal focus, packet construction and uncertainty presentation. Separate
Python host integration tests exercise those envelopes against actual Hub owners
with controlled backend resources. Neither is a deployed login or account proof.

The unresolved-action panel also offers explicit read-only inspection of the
unchanged original packet. It clears uncertainty only when the owner confirms a
matching durable receipt. Failed navigation or inspection cannot overwrite that
original uncertain mutation, and neither operation repeats the mutation.

## Library operations — issue #180

The existing Project page now exposes the authenticated Room's `library`
observation. It is a metadata-only view, not a bundle/content browser. Explicit
field groups cover queue/drain state, publication/projection identities, bounded
measurement windows, literal provider observations and classified failures.
Source owner, version, observation/commit times, status, freshness and reason
remain visible through the existing provenance renderer. Nulls stay unknown;
missing feedback/effectiveness stays unmeasured. BLOCKED, disconnected, unknown,
and stale are not flattened into one health indicator. An empty queue, current
projection or successful publication never implies healthy inference or quality.

Library action and installation-wide settings attachment points are separate,
inert sections. This slice adds no mutation, lifecycle control or operator API.
All displayed values come from an explicit metadata field allowlist; there is no
arbitrary row enumeration, title/body/prompt display or browser-side fetch.

The existing Field Notes fixture/check covers validated Library-owned rows through
RoomStream, ManagerSession, ManagerReadModel and FieldNotesDocument: explicit
current, unknown, stale under a newer Hub cut, disconnected/catching-up, and
repeated reconnection (including an unchanged stale source). The second authorized
Room cannot inherit the first Room's Library metadata. The one existing guarded
Chrome proof additionally captures Project/Library desktop and mobile layouts and
exercises refresh interruption/repetition, without adding a suite or live account.
The fixture is a typed owner-contract sample; actual Library Owner/Hub production
and authenticated binding are covered by `tests/test_library_observations.py`.

### Library installation settings

`?page=library-settings` is a separate installation page, linked from the Library
metadata attachment. A Project action binding does not enable it. The trusted
containing host may call `installLibrarySettingsHost({deployment, handle})`;
`handle(packet)` returns a promise for the response from
`FieldNotesLibrarySettingsHost.handle(canonical(packet), trusted_context)` in
`uas.manager_library_settings`. Never obtain context, callbacks, URLs, identity or
grants from the JSON document. Detach with `installLibrarySettingsHost(null)`.
This adds no listener, login, provider provisioning, account change or deployment.

The host authenticates a current HumanSession, the installation Hub checks its
fixed deployment/Room/instance and `library-settings` eligibility, and the service
independently resolves LocalHuman installation authority (`project=None`). Both
connection and grants are checked again at owner fences. Settings-only authority
has no Project content capability. The existing Project private transport still
rejects settings requests.

The page explicitly refreshes current version and shared limits/filter modes;
there are no default values, per-Project overrides or editable provider references.
An update carries configuration version, settings digest and unique request ID.
The Hub reserves the typed request digest; the durable SettingsOwner atomically
commits shared config and its receipt. Exact repeats are receipt-only, changed
payloads conflict, and lost-before-owner cannot later become an accidental write.
Unknown results keep their original packet in memory and offer only read-only
reconciliation. Rejection/success requires refresh before another edit. A
confirmed receipt states the durable configuration version, not a restart or
inference claim. In-flight operations retain their pinned config; new operations
read the new version.

`tests/manager_settings_fixture.py` is test-only pipe wiring to the actual host,
Hub and SQLite SettingsOwner. Existing `check.cjs` exercises it in VM contracts
and hosted Chrome (not scripted outcome substitutes), including installation-only,
Project-only, revoked, stale, invalid and lost-before/after-owner cases. It uses
no sockets, network, provider or real user settings. Browser evidence records the
actual path and settings scenarios, with desktop/mobile screenshots for independent
pixel review. Production host attachment remains an embedding responsibility.
