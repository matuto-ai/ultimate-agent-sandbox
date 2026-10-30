# Prepared-host handoff (local test installation)

New users should begin with [guided inspection/proposal](host-preparation.md#guided-first-installation),
which does not require image reports or a hand-written Project. The explicit
producer inputs below remain supported for existing integrations. Current
verified Workstation and persistent Hub images are required only at plan/bind;
Git checkout and credentials are separate later prerequisites. Runtime
selection must precede the first Room start.

This is the reproducible handoff **after** an operator has prepared the native
host. It does not install Fedora, configure Docker/userns, create users, change
SELinux/XFS quotas, issue TLS grants, or provision credentials. Those are separate
explicitly approved host/account operations; host-bootstrap automation is tracked
separately in [#202](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/202).
This handoff uses the existing v1 default-Engine profile, not an unimplemented
isolated-Engine adapter. No temporary provider account is
needed to generate these public installation records.

## 1. Obtain compatible image products once

Use an explicitly selected clean source revision containing `uas/local_hub.py`.
The older retained #78 archives do not contain this entrypoint. A **new authorized
image build** is needed; do not reinterpret earlier consumed approval as permission
to run it. After approval, the existing producer commands are:

```sh
python runtime/native/check-image.py \
  --selection runtime/native/image-check-selection.json \
  --output "$BUILD/workstation" --retain-image-archive
python runtime/native/check-hub-image.py \
  --selection runtime/native/hub-image-check-selection.json \
  --output "$BUILD/hub" --retain-image-archive
```

`BUILD` is an operator-selected absolute output directory; each child output
must not already exist. Alternatively, download both outputs from one successful
current `native-image-readback.yml` invocation. Keep each `report.json` alongside
its `artifacts/` directory. Require passed terminal reports, matching exact source
revision, verified payloads and confirmed readback-container cleanup. Failed or
partial uploads are not usable installation inputs.

Follow [archive verification/load](../native-image-package.md#explicit-reusable-image-archives-no-registry-publication)
for the selected target Engine: verify SHA256/size/readback association before
`docker image load --platform=linux/amd64 --input ARCHIVE`, inspect the exact loaded
image ID/platform, and repeat stopped payload readback. Loading needs operator
installation authority. It is not performed by the handoff helper. A local
`sha256:…` config ID is used as itself, never converted into a registry digest.

## 2. Select the already prepared host facts

Keep your validated Project JSON, agent/model choices and explicit credential
references. Each selected Room's deployment image reference must equal the
observed Workstation image ID from the current report; update that explicit
selection yourself if needed, without changing agent/model choices.

The legacy version-1 handoff uses a private `host-selections.json` with these fields.
For selected Engine and nondefault UID ranges, use the version-2 preparation
flow in [host preparation](host-preparation.md); do not change a version-1 offset.
The owned-XFS image path upgrades the generated handoff to version 3 after
verified preparation; do not invent its image inode or UUID fields yourself.

| Field | Value to supply |
|---|---|
| `version` | integer `1` |
| `installation_id` | one persistent 32-character lowercase hex installation identity |
| `storage_root`, `endpoints_root` | distinct canonical absolute prepared directories |
| `engine_version` | `29.8.2` |
| `mapping` | object with `offset: 100000`, `size: 65536` |
| `rooms` | object keyed by every selected Project Room ID |

Each `rooms` row has exactly `quota_project_id`, `mcs_level`, `subnet`, `gateway`.
Use the **existing** unique XFS project ID, selected unique `s0:cN,cM` category
pair, non-overlapping private `/24` subnet, and its first-host gateway. Do not
copy arbitrary values from a test fixture. The helper validates the declaration;
it does not certify that quotas, labels, ownership or network isolation are
actually enforced.

The Project already specifies the Room state root and its `repo`, `workspace`,
`reference`, `checkouts` roots. Those directories and the Room's `runtime`
directory must exist under the selected storage root. The helper reads their
actual device/inode identities; it never fabricates them or creates those trees.
Root-owned, non-writable-by-others ancestors and the fixed runtime ownership
policy remain prerequisites for native operation.

## 3. Generate and validate the handoff without native effects

For native installation, run this metadata preparation and setup as the already
authorized installation owner (root), with its root-owned selected input files.
The commands do not change ownership to repair foreign inputs. Use absolute
paths and the exact full source revision recorded in both reports:

```sh
python -m uas.local_prepare \
  --project "$PROJECT" --settings "$HOST_SELECTIONS" \
  --workstation-output "$BUILD/workstation" --hub-output "$BUILD/hub" \
  --source-revision "$SOURCE_REVISION" --output-directory "$HANDOFF"
python -m uas local --root "$INSTALL" setup "$HANDOFF/installation-selection.json"
python -m uas local --root "$INSTALL" inspect
```

`HANDOFF` must be a new private output directory; it is not a scratch directory
that should later be moved or deleted. Generated references pin canonical paths
and bytes. Existing output is refused rather than overwritten. `INSTALL` is the
persistent installation directory, root-owned for native operation. The helper
validates the native descriptor against the real `LocalNativeProfile` schema;
reports and metadata are not proof that the images are loaded or the host is
prepared. An error leaves no successful-installation claim.

Generated `native.json` captures observed directory identities and exact image
selections; `native-reference.json` pins it. `installation-selection.json` pins
the Project/native files with Manager initially unselected. Pi and Claude
installation records (`pi.json`, `claude.json`, and their `*-reference.json`
files) use the verified image payload inventories, not guessed hashes.
`handoff.json` records the normalized configuration SHA256, deployment/Room IDs
and selected source/image identities for the later explicit Manager binding. Keep all generated files private: although they contain no credential
values, their absolute paths and installation choices are not public project
configuration.

## 4. Attach runtime and Manager bindings when available

Create the pinned runtime descriptor from the generated handoff and **existing
public Broker metadata**, before creating any Room lifecycle:

```sh
python -m uas.local_setup runtime-descriptor --prepared "$HANDOFF" \
  --room "$ROOM" --broker-manifest /absolute/protected/broker.json \
  --human-merger "$APPROVED_GITHUB_USER_ID"
python -m uas local --root "$INSTALL" select-runtime --room "$ROOM" \
  "$HANDOFF/runtime-$ROOM/runtime-reference.json"
```

Repeat `--human-merger` for additional explicitly approved identities. With a
single Room, `--room` is optional on the descriptor producer. For Git/Gate-enabled
Runs include the already-prepared `--git-manifest`, `--git-broker-manifest` and
`--gate-manifest` paths; Git and Git Broker must be paired, and Gate requires them.
These are public metadata files, **not credential files**. The helper binds their
actual bytes, validates the existing Runtime/Git/Gate contracts and writes a new
private descriptor/reference directory. It never reads credential contents,
creates accounts/grants, clones Git, starts a Room or admits work. Missing
metadata must be supplied through its existing owner; do not substitute fake
paths. Existing output is not overwritten.


Before the first Room start, select the `local-runtime-v1` record described in
[the local entrypoint guide](entrypoint.md#enable-the-native-run-path). It contains
`version: 1`, `profile: local-runtime-v1`, the actual `room_id`, the same
`installation_id`, generated Pi/Claude manifest references, an existing protected
`broker_manifest` reference and explicitly approved `human_mergers` GitHub IDs.
`operation_timeout_seconds` may be selected from 1 through 180. Optional
`git_manifest` and `git_broker_manifest` must be selected together; Gate additionally
requires that pair. See [Broker metadata](../native-qualification-entrypoint.md#check-first)
and [prepared Git resources](../native-git-prepared-resources.md) for their existing
contracts. Do not run the disposable qualifier as the local host.

Every reference is the actual canonical filename plus SHA256 of its bytes. The
raw Project file SHA256 and the normalized configuration SHA256 are **different
identities**; use the normalized configuration scope when preparing a Manager
grant. Do not change mounted runtime selections after creating a Room.

With runtime selected, first start can report `waiting-for-manager`. Record the
actual Room instance from status, stop the foreground host, and obtain/select an
existing approved `local-manager-v1` grant bound to that instance, deployment,
Room and normalized configuration digest. The grant supplies the loopback
authority, existing TLS filenames, client certificate DER SHA256, human origin
and allowed actions. For native Issue opening it needs both `open-run` and
`authorize-run-request` plus `human-open-run`; observation alone does not grant
execution. This handoff does not create those rights or certificates.

Use `select-manager` with its digest reference, restart the host, then start the
Room. Status exposes the Manager URL only when its actual listener is ready.
Missing credentials are reported, not synthesized. Daily commands and the
persistent Run ownership and stop/restart semantics remain in the entrypoint guide.

## Evidence and remaining validation

The real account-free CLI/process/socket smoke passed in **1.846 seconds**: setup,
inspection, same-owner transport, host-lock collision, disconnected caller,
shutdown and restart. Native bindings and Manager were deliberately absent.
Controlled source/composition tests also cover the native owner path. Neither
establishes actual native Room/Run execution, browser TLS, personal provider/Git
integration or prepared-host enforcement. Those remain deferred to the final
explicitly authorized local test, not silently marked passed.
