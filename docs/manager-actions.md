# Typed Manager actions and attention

Manager is a command client, not a second workflow owner. Field Notes is read-only by default. A trusted host may attach its existing authenticated transport to one preselected `FieldNotesActionHost` per Room. The attachment opens no listener, installs no login, and creates no credential or permission. The host supplies its authenticated request context to a resolver that returns a fresh `HumanSession`; browser JSON cannot select that context or identity.

The five bounded envelopes are `run` (one Run ID), `lifecycle`, `replacement` (one failed Participant ID), `execute` (one typed request), and `inspect` (the unchanged original request). Unknown keys, duplicate keys, prose, non-finite JSON, and oversized messages fail closed. A view includes the fixed Deployment/Room/instance scope and owner-computed eligibility, object ID, generation, and observed version. UI enablement is only presentation: the final owning module rechecks current authority and state inside its consuming transaction.

## Actions

- Pause/resume use the existing Run Admission owner, preserve human attribution, and cannot restore native processes. Native restoration still required by the owner is not bypassed.
- Human changes requests, added rounds, cap waiver, and scoped review override use Run Review. Overrides cannot manufacture review evidence, independent identity, structural authority, a merge, or a closed Run.
- Replacement selection is offered only after the Participant owner records a failed restoration. The owner computes eligible existing candidates and fences the failed incarnation, controller, context, Run, and review identity. A successful response means `selected-not-launched`: it does not launch a process, rebind an Actor, reassign Work Requests, or appoint a reviewer.
- Start/Stop use the existing Supervisor for that persistent Room instance. Requests contain no specification, mount, image, path, engine arguments, Destroy, or runtime operation. Stop retains the control plane and Project data; Start still requires that exact control plane to be ready.
- Open in GitHub returns the canonical Project pull-request link. It never approves or merges.

Each request binds version 1, a stable operation ID, action, Deployment, Room, instance, Run/generation (null only for Start/Stop), object ID, observed version, and an action-specific payload. The authenticated human is supplied separately. Reusing an operation ID cannot invoke another owner action. Stale, foreign, revoked, disconnected, and ineligible requests are denied with a bounded current-state response where authorized.

Ordinary Forge audit, including interrupted/unknown and partial writes, participates in the owner version and continuation fence. Manager does not infer success from a missing response. Human changes expose their persisted receipt and audit reference; an unknown changes request must be reconciled through the explicit original operation and a new stable reconciliation-read ID, not resubmitted. Start/Stop reserve the shared Hub operation namespace before lifecycle effects and retain unknown intent for owner reconciliation. The UI preserves uncertainty and does not auto-retry writes.

## Gotify

Attention payloads contain only finite reason text, validated Deployment/Room/Run identifiers, generation/version, and a canonical Project source link. No body text, participant prose, logs, credentials, or arbitrary URLs are copied. The host explicitly invokes one bounded HTTPS POST using an existing fixed application endpoint and credential reference. There is no subscription, polling daemon, token creation, automatic retry, or live notification in the tests. Missing or malformed provider confirmation remains unknown, not delivered.

## Evidence and limits

Focused tests exercise the real Hub/Run Review/Forge Audit SQLite owners and the exact host-to-protocol dispatch. Supervisor and Participant tests use controlled backend resources; no Docker/VM/account claim follows from them. Inert HTTP channels test Gotify bounds, headers, responses, disconnection, and cleanup without sending a notification. Field Notes' existing browser check covers its injected host adapter, packet construction, disabled/no-host behavior, and literal outcomes. Deployment login, real account credentials, notification delivery, and target-host lifecycle qualification remain deployment/integration concerns, not implicit effects of attaching this module.


Explicit read-only inspection of an unknown operation submits the unchanged
original packet. The owner matches its digest and exact authenticated Origin to
the durable receipt under current policy. Only a confirmed matching receipt
clears the UI's unresolved action; absent, partial, unknown, legacy unbound or
unavailable receipts do not authorize a retry. Lifecycle inspection reads its
existing receipt store without invoking Start/Stop again. Revoked observation
permission suppresses receipt and state disclosure, including after a write.
