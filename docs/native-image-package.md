# Native image packaging (#78)

`uas.native_image_package` generates a concrete **linux/amd64** Docker build
recipe and fixed payload inventory. It does not build, pull, publish, launch, or
read credentials. Fixture defaults and the disabled product launcher are unchanged.

## Inputs and build boundary

The installation selects `node:24.22.1-bookworm-slim@sha256:<digest>` and
`gcc:14-bookworm@sha256:<digest>` independently. Both exact official image names,
versions and digests are required by `dockerfile(...)`; there are no invented
sample digests or mutable-tag fallback. No selected base digest or built image
is claimed by this source. Pinning controls inputs, not reproducible-build proof.

Use a clean context from the reviewed source revision, including its checked-in
Pi/Claude/SDK package locks. Write the UTF-8 Dockerfile returned by `dockerfile`
and `canonical(build_inventory())` as `native-inventory.json` in that context.
Never build from a working tree containing account files or credentials. The
Dockerfile copies only named runtime and package-lock paths, never a whole HOME
or source tree, and accepts no secret build arguments or credential mounts.

The build compiles the four reviewed fixed C connectors statically with stack
protection and a nonexecutable stack. It installs Pi1.4.0, Claude2.1.310 and
SDK0.3.310 with the existing official-registry URL/SHA512 lock checks and disabled
package lifecycle scripts. The native Linux x64 Claude file additionally matches
the already reviewed SDK-policy SHA256. Node version is checked before install.
No model inference or native bootstrap execution is part of this recipe.

Both runtime trees and their auth entry modules are installed at fixed `/opt/uas`
paths. Build-stage `write-payload.mjs` hashes the exact recipe inventories and
writes read-only payload manifests. Actual immutable image identity also covers
unlisted dependencies and OS libraries; the artifact map is not a substitute for
that identity or the enforced root/mount contract. The image has no selected
native entrypoint; the canonical Supervisor still owns launch.

## Two identities, no self-reference

1. **Baked payload**: canonical compact sorted ASCII JSON with `version`,
   `runtime`, `runtime_version`, optional `sdk_version`, and exact `artifacts`.
   No final image reference/ID appears here. Location is fixed:
   `/opt/uas/pi-manifest.json` or `/opt/uas/claude-manifest.json`.
2. **External installation envelope**: after building and independently observing
   the image content ID and digest-pinned reference, call `envelope(payload,
   image_reference=..., image_id=...)`. It includes identical payload metadata,
   `payload_manifest_digest`, and both observed image identities. Keep this file
   outside the image in the trusted private installation store; select its own
   SHA256 independently for Supervisor admission. Do not bake it back into image.

The recipe validates the payload digest by reconstructing it from the envelope,
so runtime version/artifact maps cannot disagree. Container inspection must match
both image identities. Claude's host receives the baked payload digest and checks
the bounded nofollow regular manifest and fixed payload files. Admission and
launch journal retain the **external envelope digest**, not merely payload identity.
A label, runtime-provided path, or approved flag cannot replace these checks.

Changing payload alters payload and image identity. Changing base or image
metadata can alter image identity without changing fixed payload hashes, which
still changes the external envelope identity. There is no circular final-image
hash requirement.

Source/pure-test results do not prove a built image, C execution, native provider
access, isolated deployment or the real #78 lifecycle. A separately authorized
build and exact artifact readback remain required before installation selection.

## Opt-in combined controlled-Git image

For the existing `native-git-primary-v1` prerequisite, pass `git_packages` to
`dockerfile(...)`, with exactly `python_package`, `git_package` (explicit Debian
package versions), and `python_version` (the expected `3.11.<patch>` runtime).
These selections have no defaults; examples in tests are synthetic and must not
be used as installation choices. Existing Pi/Claude-only rendering is unchanged.
No Hub, optional Gate helper, account or installation configuration is added.

The combined recipe retains the selected Node Bookworm base and its reviewed
Pi/Claude payload. Its build installs the two explicitly selected package
versions, compiles the existing fixed Git connector, and checks the actual
Python patch. Debian dependency resolution remains a build input: this is not
a claim of reproducible builds or pinned transitive package versions. Repository
availability or incompatible package choices must fail the build, not fall back.

`runtime/native/prepare-git.py` is a build-stage-only script. It stages the exact
controlled public entries as regular copied files at all three existing prefix
locations, removes upstream `git-core`, supplies the worker/shim/hook and a
bounded AST-derived UAS source closure, and preserves the existing worker-only
hook directory and sealed-FD helper link contracts. No Project code is imported.
The source closure conservatively includes conditional imports; it is not a new
Runtime authority boundary. Root-owned files are not group/world writable.

Before replacing public Git, the build records the matching raw package backend
in a **separate `git-backend-export` target**, together with `git-payload.json`.
The default final `combined` target removes `/build`, so the raw backend is not
reachable in its filesystem. Build layers/exports are trusted installation
artifacts, not secrets. The exported backend is never mounted into the native
Workstation: existing setup must select it at the fixed trusted-host path, and
existing admission seals it in a memfd. No copy into that host path occurs here.

The payload records actual Python/Git fixed-file hashes, UAS source-tree hash,
backend hash, and loader/library hashes obtained from the package Python, Git
and Python standard-library extension dependencies. Missing dependencies, foreign
ABI paths, symlink escapes/depth and inventory overflow fail closed. A stdlib
extension's `ldd` “statically linked” result is accepted only after a bounded
ELF64 x86-64 shared-object inspection finds a terminated dynamic table with no
`DT_NEEDED` and no program interpreter; Python and Git get no such exception.
The [ELF dynamic-section contract](https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section)
defines the dependency entries and termination. This is
observed dependency metadata, not execution proof: real ABI compatibility,
stock MAC/kernel constraints and native Git behavior still need qualification.

After independently observing the **final combined image** ID and digest-pinned
reference, call `git_envelope(payload, image_reference=..., image_id=...,
nonce=...)`. It validates through the existing Git selection contract and adds
only the observed image identities and fixed installation backend path. Use
that same final image identity in both Pi/Claude envelopes; never select the
intermediate payload or export target as the Workstation. The exported backend
and payload must come from the same build, with its digest checked during
installation. Do not invent an image digest, package version or nonce.

The canonical `verify_engine_payload` still independently reads the actual
selected container. Build metadata, static layout tests and controlled archive
fixtures cannot replace that readback. No build, package download, compiler,
image/VM/native process, credentials or live lifecycle is exercised by
`python tests/run_native_combined_image_source.py`; its finite inventory installs
process/socket/thread/native-loader/privilege guards before repository imports.

## Deliberate credential-free build/readback

`runtime/native/check-image.py` builds from a clean tracked Git revision in a
separate `git archive` context. It uses an empty Docker client configuration,
never starts a container, never reads provider accounts, and never pushes an
image. Optional explicit archive retention is described below. Invoke from the reviewed clean checkout:

```
python3 runtime/native/check-image.py \
  --selection runtime/native/image-check-selection.json \
  --output /tmp/uas-native-image-readback
```

The output directory must not exist. The manual `native-image-readback` workflow
uses the same entry point, outside automatic CI. It requires a deliberate
`workflow_dispatch`, or the reviewer's `qualify-native-image` label on a same-repo
PR. It is not triggered by ordinary commits or PR updates. Its 25-minute cap is
not permission to run it; review and an applicable execution budget come first.

The selected input manifest records these official metadata observations:

- [Node 24.22.1 Bookworm slim, linux/amd64 manifest](https://hub.docker.com/layers/library/node/24.22.1-slim/images/sha256-2dd9a4f758e173b65fee15388f7706af6fb01ef50cf7a2c0538711d67a6981ae).
- [GCC 14 Bookworm, linux/amd64 manifest](https://hub.docker.com/layers/library/gcc/14-bookworm/images/sha256-a689e29bc3adf4663ef9a141d23081252764d1319c63f591a027bd6fd676f4c1).
- [Debian Bookworm Python](https://packages.debian.org/bookworm/python3.11),
  `3.11.2-6+deb12u9`, expected interpreter `3.11.2`.
- [Debian Bookworm Git](https://packages.debian.org/bookworm/git),
  `1:2.39.5-0+deb12u3`.

These are evidenced immutable image selections, not a claim that mutable tags
still resolve to the same manifests. Registry availability and package-level
compatibility must pass in the actual build; no mutable fallback is allowed.

Readback inspects the actual local image ID and linux/amd64 platform, creates an
owned **stopped** container, hashes every fixed Pi/Claude payload file, and invokes
the existing production Git Engine readback verifier. It compares the separately
exported Git payload and backend with that same final image. Separate target
builds share their build graph/cache but cannot silently diverge: differing
payload/backend hashes fail. Unknown create outcomes are reconciled by the
invocation's unique name, label, image and stopped state before removal. No
shared image/container pruning occurs.

`report.json` records the exact source revision, selections, observed local image
ID, hashes, stage, outcome and cleanup. The raw backend export is retained beside
it, not installed on the host. A local image config ID is **not** a registry
manifest reference: the tool does not fabricate an installation envelope or claim
the image is published, native-qualified or account-connected. Readback proves
packaging consistency, not the #78 real lifecycle or #62 Room boundary. Failures
remain failures even when cleanup succeeds; cleanup failure cannot report success.

A timed-out Docker client does not prove the daemon stopped its build. Such a
result records `build_execution: unknown-daemon-outcome` and fails without retry.
`container_cleanup` describes only the invocation's stopped readback container,
not build/cache cleanup. A disposable hosted runner is the intended execution
site; do not reinterpret a client timeout as permission to start another build.

## Fixed Hub packaging and retained build products

The native backend also requires its separate fixed Hub image. The pure
`uas.native_hub_image` recipe installs the existing
`tini → /usr/bin/python3 -m uas.workstation_service` contract, UID/GID65531,
`PYTHONPATH=/opt/uas`, no bytecode writes and all flat UAS modules from the exact
archived source revision. It is not another host implementation. The recipe
reuses the already verified immutable Bookworm Node base (Node is not the Hub
entrypoint), with the same Python package plus Debian Bookworm's exact amd64
[`tini 0.19.0-1+b3`](https://packages.debian.org/bookworm/tini). No default mutable
image, account, deployment or privilege is added.

`runtime/native/check-hub-image.py --selection
runtime/native/hub-image-check-selection.json --output /tmp/uas-hub-readback`
performs one deliberate build followed by a stopped-container readback. It
checks the image configuration, every committed UAS module against the archived
source hashes, the fixed Python/tini files and the baked payload metadata. It
reuses the Workstation checker's bounded archive parser and ownership cleanup.
The Hub service is never started; this is packaging evidence, not native Hub
handshake/isolation evidence. The build has not been executed by source tests.

The existing manual workflow now sequences Workstation and Hub checks under the
same 25-minute maximum. A future invocation still needs explicit execution
approval; the earlier one-run approval was consumed. Build timeouts preserve
unknown daemon outcome rather than automatically retrying.

Build reports and a fixed allowlist of public build products are retained with
pinned `actions/upload-artifact` for seven days: verified Pi/Claude/Git/Hub
payloads, verified raw Git backend, selected inputs and rendered recipes. Upload
runs after success or failure so partial evidence is not lost; each report's
status and stage govern which products were verified. No Docker configuration,
Git checkout, private state or credentials are uploaded, and no registry
publication occurs. Explicit image archives are included as described below. Repository/artifact readers can read these intentionally public
products. `contents: read` remains unchanged.

### Explicit reusable image archives (no registry publication)

`--retain-image-archive` opts each checker into export **only after** that exact
image passed its stopped-container readback. The manual workflow supplies this
flag so a successful authorized execution retains reusable images rather than
requiring another build for transfer. The default CLI remains metadata-only.

The helper requests the Engine's Docker-save stream by exact observed image ID,
never a mutable tag or a running container. Limits are **2 GiB for Workstation,
1 GiB for Hub**, at most120 seconds per export, and free disk of at least the
selected limit plus512 MiB before each export. Streaming stops at the limit or
deadline; it does not buffer an image in memory. Only invocation-owned exclusive
partial files are cleaned on failure; existing files are never overwritten.

`combined-image.tar`/`.json` and `hub-image.tar`/`.json` are the only added upload
paths. The metadata binds archive SHA256/size, exact image ID, source revision
and the prior readback payload hashes. Bounded archive inspection checks its
single-image manifest, configuration digest and linux/amd64 platform without
extracting or executing it. It is a Docker-save archive, not a registry manifest
or an independent requalification of every layer. GitHub's artifact digest is
additional transfer evidence, not a replacement for these recorded identities.
Uploads use zero compression and seven-day retention; the combined archive cap
is3 GiB. These intentionally public build products include base-image layers and
repository source, but no provider accounts, private runtime state or credentials.

To reuse after download, an authorized installation owner must:

1. Check the terminal report passed, the metadata matches its exact source/image
   and readback hashes, and the archive size and SHA256 match before loading.
2. Use Docker's [image load](https://docs.docker.com/reference/cli/docker/image/load/)
   with `--platform=linux/amd64` in the selected target Engine. Loading requires
   installation authority; this checker does not do it or infer it from a build.
3. Inspect the loaded exact image ID/platform and perform the existing stopped
   payload readback before native admission. Loading alone is not runtime proof.
4. Supply any required independently observed installation/registry reference
   through the existing contract. Do not turn a local config ID into a fabricated
   registry digest. Publication, tagging and installation remain separate actions.

Docker documents this [save/load format](https://docs.docker.com/reference/cli/docker/image/save/)
for image transfer. The exported images can be reused without rebuilding, but
these checks still do not create installation envelopes or prove the live #78
scenario. Archive failure fails the checker while retaining the original
readback result and owned-container cleanup evidence; no automatic export retry
or additional image build is performed.
