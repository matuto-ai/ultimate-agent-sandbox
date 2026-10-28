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
