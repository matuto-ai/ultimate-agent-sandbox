# Request-scoped human mTLS prerequisite (#78)

`uas.human_mtls` is a **source prerequisite**, not a consumed native host or
completed authenticated scenario. It creates no listener, connection, thread,
TLS context, certificate, key, account or operator configuration. No credential
bytes are read. A real hosting owner must supply an already-established,
server-side `ssl.SSLSocket` with required client certificates and TLS 1.3.

## Explicit trusted grant

The operator supplies a frozen `HumanActionGrant` containing the exact
Deployment, Room, Room instance, Manager ID, unchanged `Origin`, and explicit
action tuple. The default empty tuple grants **nothing**, regardless of Origin
capabilities. Allowed scopes are only `observe`, `open-run`,
`authorize-run-request`, `request-changes`, and `reconcile-changes`.

`HumanActionBindings` maps exact client-certificate DER SHA-256 fingerprints to
those grants. A trusted CA chain alone is insufficient. Start certificates and
Room-stream bindings, dictionaries pretending to be grants, and subclasses are
not accepted as human action authority. Start, Stop, reset, replacement, merge,
credential changes and general Manager actions are outside this component.

Binding replacement increments a retained generation even for an equal grant or
the same grant object. Revocation removes the mapping; re-adding it gets a new
generation. An old connection/session requires both its original immutable grant
object and exact generation, so removal/re-addition cannot revive it. Revocation
remains available at generation exhaustion; new binding then fails closed.
Registry mutation/acceptance and connection processing/checks/close are confined
to their creating thread. No thread is started, no cross-thread registry locking
is claimed, and illegal cross-thread context exit still invalidates its session.

## One received frame, one processing scope

`bindings.accept(channel)` binds the exact TLS socket and grant, but exposes no
`HumanSession`. The host uses:

```python
with connection.receive() as (frame, session):
    # Future fixed host dispatch invokes existing owners here, with session.
    # No owner invocation is implemented by this prerequisite.
    ...
```

The existing bounded HTTP/JSON framing is reused at `/uas/human-action/v1`.
The exact envelope is `{"version":1,"action":"…","payload":{…}}`, at most
16 KiB after canonical JSON encoding. Principal, capabilities, grant/session
fields and authority identity claims are rejected, including in nested payload
objects. Existing Manager packets may retain `deployment_id`, `room_id`,
`instance_id`, and optional `manager_id` verbatim as **correlation data**, but each must equal the immutable
operator grant; mismatches are refused, never rewritten. Those fields cannot
select a scope or confer authority. The original Manager envelope remains intact
for its canonical owner. Action-specific validation and idempotency still belong
to that owner.

Before exposing a session, the requested action and every named dependency must
be individually granted:

| Received action | Only permitted session checks |
| --- | --- |
| `observe` | `observe` |
| `authorize-run-request` | `authorize-run-request` |
| `open-run` | `open-run`, `authorize-run-request` |
| `request-changes` | `request-changes`, `observe` |
| `reconcile-changes` | `reconcile-changes`, `observe` |

These pairs do not confer a missing grant. Other operator-granted actions cannot
bleed into the current frame. The original `Origin` and exact scope are retained;
copying a session does not make another authenticated session.

The session works only inside its received-frame context. Normal exit, processing
error, observed EOF/transport error, explicit authentication `close()`, changed
certificate/TLS state, local socket close or registry revocation invalidates it.
Nested processing fails closed. `close()` invalidates authentication only: the
hosting owner retains responsibility for its borrowed TLS socket.

Certificate getters **do not prove that a remote peer remains connected**.
Remote EOF is only known when transport I/O observes it. The narrow claim is
authenticated processing of the already-received frame, not indefinite network
liveness. Every canonical owner/provider check must stay inside that processing
scope and continue calling the supplied session's fresh checks.

## Still required

The native driver and inbox currently require a persistent same-object
`HumanSession`; this request-scoped session is **not yet that integration**.
The fixed hosting lifetime, Broker audit view, exact instance-owner binding,
dispatch, response/unknown reconciliation and consumed native entry still need
implementation and independent review. Certificate provisioning, an actual TLS
handshake and the original real Pi–Claude–GitHub scenario remain unexecuted.

`python3 tests/run_human_mtls_source.py` runs only the explicitly named controlled
source test class. Its pre-import guards prohibit process, socket, thread,
permission, TLS-context/certificate loading and ctypes effects, and any attempted effect fails the run even when
caught. These tests are not real TLS, native-runtime or deployment evidence.
