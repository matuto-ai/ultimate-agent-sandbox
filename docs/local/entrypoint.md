# Local installation and lifecycle

The local entrypoint retains installation choices and uses the existing Room
Supervisor, native backend, Hub ledger and Manager projections. It is not the
disposable `qualify-native` command and does not automatically run qualification.

## What is available without accounts

An offline installation can validate and persist a Project configuration and
show what is missing. With the native host profile prepared, it can start the
Workstation and an authenticated **idle** Hub, stop the Workstation without
removing the Room's data, and restart it. Participant/provider execution is not
claimed by idle infrastructure readiness. Selecting runtime bindings enables a
bounded authenticated native Run operation through the Manager Issue form. The optional local Manager displays
real Room projections through the existing mutually authenticated TLS grant;
without that grant it stays unavailable, not anonymously authenticated.

## Prepare once

Run the source with Python 3.11 or later. Select an existing validated Project
JSON and record its absolute canonical path and SHA-256. The installation
selection contains references only, never credential values:

```json
{
  "version": 1,
  "project": {"path": "/absolute/project.json", "sha256": "<sha256>"},
  "native": null,
  "manager": null
}
```

```sh
python -m uas local --root /absolute/private-install setup selection.json
python -m uas local --root /absolute/private-install inspect
```

The installation directory is private to its OS owner. Repeating the same setup
is safe; different selections are refused rather than silently replacing data.
Changing the selected files in place invalidates their digest. Do not put API
keys into this file or publish local configuration. Native operation requires a
root-owned installation; offline inspection does not grant native authority.

For exact producer inputs and validated descriptor generation, follow the
[prepared-host operator handoff](operator-handoff.md). Host provisioning remains
a separate operation; this entrypoint does not turn an unprepared machine into a native host.

## Native prerequisites

Native startup consumes the `local-native-v1` descriptor validated by
`uas.local_native.validate_document`. It records exact imported image IDs,
prepared per-Room storage identities, XFS project quotas, MCS categories,
endpoint root and private network selection. Its images must include the
persistent `uas.local_hub` entrypoint. The earlier #78 image archives predate
that entrypoint and must not be represented as containing this change.

The existing Linux native profile still requires Docker Engine 29.8.2, SELinux,
user namespace mapping `0:100000:65536`, fixed isolated host owners, and prepared
XFS quotas. This command does **not** reconfigure Docker, create accounts, alter
mounts/security policy, or provision personal credentials. A plain Docker
installation or non-Linux desktop is not an equivalent confinement profile.
Actual host preparation remains an explicit operator step, not a hidden side
effect of setup.

The optional `local-manager-v1` descriptor selects an existing protected human
grant, exact Room instance/configuration digest, loopback authority and existing
TLS file references. It does not generate credentials or trust arbitrary browser
clients. An installation without runtime bindings is observation-only. With runtime
bindings, the Manager dispatches into the existing native Run admission, Pi
implementation and Claude reviewer owners on the same authenticated thread. After first startup,
inspect the actual Room instance, stop the foreground host, and select the
existing Manager descriptor reference explicitly:

```sh
python -m uas local --root /absolute/private-install select-manager manager-reference.json
```

The reference file contains only `path` and `sha256`. This operation refuses a
running host and preserves Project/native selections and all Room data. It does
not create TLS keys, approve access, or reconfigure the Room. Restart the host
and Room afterward.

## Retained host and daily lifecycle

Keep the foreground host running under the installation's OS owner:

```sh
python -m uas local --root /absolute/private-install serve
```

From another terminal, use the same installation:

```sh
python -m uas local --root /absolute/private-install start --room ROOM
python -m uas local --root /absolute/private-install status --room ROOM
python -m uas local --root /absolute/private-install stop --room ROOM
```

The host owns the authenticated Hub process and private operator socket. Status
reports the Manager URL only after its selected listener/projections are ready.
Stopping a Room retains Hub/data; terminating the host fences its children and
stops owned infrastructure without deleting durable trees. A new host can recover
owned socket endpoints only while both containers are confirmed stopped and its
exclusive installation lock excludes any surviving helper. Running or uncertain
prior resources fail closed: do not repeatedly issue start to bypass that state.
No installation destroy/reset command is exposed.

## Validation boundary

The account-free real CLI/process/socket smoke passed in 1.846 seconds, including
setup, host ownership, shutdown and restart with native bindings absent. The
source tests additionally use controlled process/Engine/network doubles and real local
ledger projections. They do not establish that a user's host has the required
native policy. Real native startup, image rebuild/import, personal accounts and
provider/Git integration belong to the explicitly authorized final local test.


## Enable the native Run path

Before first starting a Room, select its `local-runtime-v1` descriptor using
`local --root … select-runtime --room ROOM runtime-reference.json`. The reference
again contains only `path` and `sha256`. The descriptor binds the existing Pi and
Claude manifests, Forge broker metadata and approved human mergers; Git and Gate
bindings use the existing paired manifests. Credential values are not copied.
Runtime selections change required mounts, so changing them after Room creation
is refused rather than silently reusing incompatible resources.

The first start may report `waiting-for-manager`: it establishes the actual Room
instance without starting brokers or models. Stop the host, select the existing
Manager grant for that instance, then restart. The Manager's Issue form uses one
operation ID and does not automatically retry an uncertain operation.

Each Issue click authenticates a new explicit command. Open returns an `ACTIVE`
admission receipt with the canonical Run ID and generation after native owners
have been established; it does not wait for the Run to finish. The request's
human session ends with that response. The retained owner services that one Run
using a narrow, revocable grant tied to the admitted operation and original
binding generation, not a saved HTTP session or permission to issue new commands.
Closing the browser does not revoke admitted work. Revoking/replacing the human
binding, losing ownership, changed canonical scope or uncertain native effects
fences further service. Status comes from the Room ledger; errors do not silently
restart an operation.

The at-most-180-second budget bounds admission; each subsequent effect has its
own bounded deadline. It is not a maximum Run lifetime. The qualification runner
remains finite and unchanged. The form no longer preselects a second issue.
Repeated Open with the same operation and exact identity returns the original
admission receipt; a different operation cannot interrupt an active Run. A later
Run additionally requires verified predecessor retirement and safe root-owned
checkout reuse; uncertain custody or dirty workspace remains blocked, never
silently discarded. A process restart does not reconstruct native authority
from a stored receipt.

Normal Stop sends a fixed pause to the retained child and requires its exact
participant-revocation receipt before stopping the Workstation. For a completed
Run, the child retains exact native exit observations without retaining human
authority. After Room Start, no old task is automatically resumed: the next
explicit authenticated Open adopts those observations into canonical retirement
and safely reuses the checkout. The Hub and data remain. An interrupted active
Run is reported separately as stopped service/attention, not as completed; its
explicit terminal recovery is a separate step, never an automatic new Run. Missing/uncertain receipts are reported as such, never retried blindly.
Actual accounts, native execution, browser TLS and provider integration remain
part of the final authorized local test, not claims established by source tests.

Absent protected Actor/Broker credential files leave the Hub available and
report `missing-credentials`; they do not start broker processes. Malformed,
changed or uncertain bindings still fail closed rather than masquerading as
ordinary absence. Existing Manager observation remains available.
