# Native Run admission: external read bridge

`NativeAdmissionBroker` retains `ReadOnlyForgeBroker`'s canonical Room intent,
funded reservation, immutable terminal receipt and dependency projection. It
changes only how the observation reaches the fixed external credential owner.
The trusted Run owner supplies an original admitted-native authority callback;
this module creates neither human grants nor native identities.

The owner prepares under the existing lifecycle lock. The adapter binds the
exact operation, issue, immutable Origin and PREPARING reservation/context.
Provider contact occurs outside lifecycle/Room transactions. `ReadBrokerClient`
checks the same callback immediately before dispatch, on the external owner's
live authorization challenges, and before disclosure. Canonical completion
checks it again before committing. No authority callback is serialized.

The private Supervisor-to-Broker envelope is exactly `id`, `kind` equal to
`admission-read`, and bounded integer `issue_number`. It has no Actor, URL,
credential, repository override or arbitrary argv. The authenticated channel
carries the host-selected Origin. Native participant ingress still accepts only
its existing Forge read/write/reconcile kinds, never admission-read. External
read audit/cache identity uses the original operation ID, not transport UUIDs;
a lost/interrupted observation does not trigger another provider action.

The external provider calls canonical `GitHubReadProvider.read_issue` with
`admission=True`, obtaining assignment, dependencies and delivery classification.
Generic display output is not substituted for these eligibility facts. Actor
credentials remain exclusively in the external Broker.

This bridge supports already-assigned issues. It exposes no assignment adapter:
an unassigned issue is refused by canonical eligibility until an explicit
assignment bridge exists. It does not silently self-assign or fabricate audit.

Tests exercise real SQLite reservations, terminals and external audit/cache,
with controlled provider/IPC boundaries, including the actual client challenge
loop. They are not live account, native process or isolated-runtime proof.
