# Opt-in Claude native admission (#78)

This source composes the existing launch, admission, Hub, RunReview, delivery and
external Forge owners. It does not change fixture defaults or grant credentials.
It is not evidence that a selected image, account or real lifecycle has passed.

## Three different held tasks

1. `NativeClaudeHostLaunch` binds the exact Engine exec task. Its fixed bootstrap
   releases into the SDK host; that task remains the cleanup owner, not a Participant.
2. `NativeClaudeRoot` binds the actual Claude bootstrap child using the kernel
   record, held task identity and Supervisor-pinned immediate-child lineage. Its
   separate one-shot challenge is never authorization after release. The bootstrap
   execs pinned Claude in the same task, preserving stdio and a lifetime channel.
   Native readiness must come from the concrete receiver, not an image label.
3. `NativeDescendantLease` binds the fixed, directly spawned MCP helper. The
   Supervisor proves immediate-child ancestry at admission. The Hub receives the
   exact helper channel and held helper pidfd, tied to the already admitted native
   root operation, incarnation, epoch, controller and installation manifest digest.

The native root is **not** the Engine PID. The helper is **not** allowed to claim
its root's kernel identity. Existing direct `HeldOrigin.require` checks remain
unchanged. No arbitrary descendant, shell intermediary, PID reconstruction,
second workflow store, or persisted receipt creates authority.

## Initialization without an authority cycle

The helper's first release permits only local MCP initialization and tool listing.
Native SDK initialization may therefore finish before native admission. The Hub
sends the fixed activation record only after the exact root has passed readiness
and its helper lease is installed. Before that marker, tool calls fail closed.
The marker itself is not a credential: every actual record still requires the
exact held helper and current root admission. Pre-transfer queued data or EOF is
rejected, and caller-provided Actor/seat/capability claims are not accepted.

Hub checks are local under the existing admission lock, including transaction-time
rechecks. They check held helper/root and SDK-host liveness and the root's exact admission epoch.
Native-only ADMIT transfers the held SDK-host pidfd as a third descriptor, bound
to its exact identity; ordinary ADMIT remains two descriptors. Host exit revokes
the root and its helpers even if the native child survives.
They do **not** claim fresh procfs ancestry on every call: immediate-child lineage
was proved in the Supervisor namespace at admission. No Supervisor RPC or host
procfs handle enters a RoomLedger transaction. Exit, revoke, reset or control loss
invalidates the lease; a replacement needs new admission, never a restored PID.

The bounded helper history is ephemeral and prevents reuse within the live
controller. On uncertain transfer, reconcile the same operation using status;
do not resend with a new ID. Controller loss removes authority even if a durable
root receipt exists.

## Canonical application paths

The dispatcher derives the Origin from the admitted native root. Messages,
contributions and review results use their existing owners and namespace. Helper
transport is Room/seat scoped, not implicitly scoped to one selected Run. The
scenario harness retains its explicit selected-Run human controls.

An explicitly attached, exact `ReadBrokerClient` provides Forge operations through
existing reservation, preparation, external I/O and authority rechecks. It never
puts Forge credentials in the native HOME. Provider I/O is outside the admission
and ledger locks; lifecycle-before-admission ordering is retained. Without that
trusted service, Forge is unavailable, not simulated as successful.

This attachment is **trusted-host, same-process composition only**. The existing
client owns a Supervisor lifecycle object; it cannot be serialized into a separately
isolated Hub or justify mounting its control store there. A separate-Hub deployment
remains blocked until its owned boundary is wired. Exact Python type is not deployment
authority.

Requests are limited to one 64 KiB encoded frame before any effect; larger Forge
writes are unsupported on this route. Replies reuse the existing bounded chunked
Broker response format, not a new framing or recovery store.

## Remaining real acceptance

Trusted selected image installation and its exact admitted mounts are prerequisites.
Fresh native HOME creation cannot adopt a previous session; provider authentication
provisioning still needs its existing approved owner. No new token copy or ambient
credential fallback is introduced here. Unsupported immediate-child MCP topology,
missing fresh-session evidence, or unavailable native adapter fails closed.

Pure protocol/owner tests and hosted C syntax/pure-JS checks do not qualify native
SDK startup, provider authentication, Linux process/SELinux isolation, or the full
Pi–Claude–GitHub workflow through human merge. Those remain explicit #78 acceptance
requirements; this preparation is not grounds to close the issue.
