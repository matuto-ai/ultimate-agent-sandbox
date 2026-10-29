# Local installation and lifecycle

The local entrypoint retains installation choices and uses the existing Room
Supervisor, native backend, Hub ledger and Manager projections. It is not the
disposable `qualify-native` command and does not automatically run qualification.

## What is available without accounts

An offline installation can validate and persist a Project configuration and
show what is missing. With the native host profile prepared, it can start the
Workstation and an authenticated **idle** Hub, stop the Workstation without
removing the Room's data, and restart it. Participant/provider execution is not
claimed by idle infrastructure readiness. The optional local Manager displays
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
clients. Manager-only observation has no mutation action owner. After first startup,
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

The source tests use controlled process/Engine/network doubles and real local
ledger projections. They do not establish that a user's host has the required
native policy. Real native startup, image rebuild/import, personal accounts and
provider/Git integration belong to the explicitly authorized final local test.
