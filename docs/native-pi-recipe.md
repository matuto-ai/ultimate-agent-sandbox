# Opt-in native Pi exact-exec recipe (#78)

This is a concrete source path into `ExecLaunch`, not a product launcher and not
real integration acceptance. Existing fixture launches and helper recipes stay
unchanged. No image is pulled, container created, mount added, credential loaded,
permission granted or native process launched by configuration construction.

## Composition and ownership

The trusted Supervisor resolves `NativePiRecipe.from_configuration(...)` from the
existing installation/Room configuration and its **already admitted** Workstation
seat, checkout, endpoint and mount contract. The constructor checks the selected
Pi Participant/Actor, exact configured image reference, same host/container
Project roots, read-only references and Room-owned runtime subtree. Runtime
HOME is `<room.state_root>/runtime/<seat slot>`; native sessions additionally
use `contexts/<context generation>/sessions`. Only that runtime subtree is
mounted, never the Room control store or its parent.

Pi `--provider` must be explicit in seat arguments. `--model` is explicit or
comes from the selected provider's configured model; conflicting choices fail.
A logical provider ID is not a native provider name. Other startup arguments and
custom endpoint mapping are currently rejected before launch rather than
silently rewritten. Native auth/settings are pre-provisioned in the selected
HOME by the installation owner; this code does not read, write, copy or invent
credentials or account configuration. Pi's ordinary coding tools remain enabled;
this does not expose Forge/Git credentials or change Broker/network policy.

The trusted host constructs `ExecLaunch(..., native_recipe=recipe)` and uses its
existing `launch`, `attach_native` and `SupervisorAdmission` paths. The recipe is
accepted only by canonical `ExecLaunch`, not fixed helper subclasses. There is
no generic callback launcher or alternate process identity. Failure/ambiguity
retains the existing one-shot launch journal and fences the owner.

Before Engine mutation, and again near create/attachment, bounded container
inspection must match exact container ID, selected image content ID and reference,
the immutable-root/no-privilege declarations and the entire admitted bind-mount
inventory. Mounted replacements of `/opt/uas`, OS binaries/libraries or `/etc`
loader configuration are rejected. These observed declarations do **not** replace
#62's actual namespace, endpoint, SELinux, kernel and network qualification.

The new fixed `/opt/uas/bin/pi-native-connector` keeps the existing challenge,
kernel-record and release protocol, then execs Pi **in the same task**, preserving
the inherited peer FD. It has fixed Node/Pi/extension paths, bounded non-secret
argv, a cleared explicit environment, no shell/fork, no offline/faux provider and
no arbitrary executable selector. It must be built statically, with stack
protection and non-executable stack, in the selected image. The existing fixture
connector is not changed. A compile-only unit test checks source syntax, never
executes the bootstrap.

## Installation artifact binding

The installation selects a private regular manifest file and its independent
SHA-256 digest. The loader walks directories without symlinks, rejects writable
shared ancestors, opens the file nonblocking/no-follow, checks regular-file
ownership/mode/link count, bounds it to16KiB, hashes the bytes and checks stable
metadata on the held FD. A FIFO cannot turn manifest inspection into a blocking
read. Recipes are immutable and return defensive scope/identity copies.

The exact manifest fields are `version:1`, `runtime:"pi"`,
`runtime_version:"1.4.0"`, `image_reference` (configured digest-pinned reference),
`image_id` (`sha256:` content ID), and `artifacts`. `artifacts` contains SHA-256
entries for the fixed connector, Node, Pi package metadata/CLI and the two Pi
extension files listed by `ARTIFACTS` in `uas/native_pi_recipe.py`. This is trusted
installation artifact provenance plus actual image-ID binding—not proof that
each binary has been executed or independently read back from the image. No
runtime-selected manifest/digest, image label or `approved:true` flag grants
launch authority. The source does not introduce an artifact registry.

The existing Supervisor journal records the recipe digest, selected image and
runtime identity, and context scope, but no settings, tokens or challenge.
`attach_native` requires that same manifest digest/scope and the recipe's exact
session prefix; a fresh native receipt cannot be relabelled with unrelated
payload provenance.

## Remaining integration work

The image containing this connector, actual approved installation manifest and
mounts, provider inference and account access are not qualified by pure tests.
The production Room composition/installation path must supply them. Existing
Workstation Forge routing also needs the actual canonical Broker/Git owners.

Claude remains a separate missing composition: its SDK owns a native child,
not the SDK host PID, and the current controlled SDK invocation rejects MCP
servers and has no outbound native tool channel. A supported MCP bridge and
actual native-child process binding are required; neither Pi's same-task
identity nor the SDK host can stand in for that child. The full pair and #78
remain open until real lifecycle/recovery/human-merge acceptance is exercised.
