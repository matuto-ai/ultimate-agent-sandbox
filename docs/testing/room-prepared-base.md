# Room VM: explicit preparation and fresh qualification (#62)

The default cold qualification is retained for deliberate cold-path validation.
Warm qualification is opt-in and **never** falls back to an expensive cold run.
Neither mode belongs in automatic per-commit CI. A preparation run is separately
authorized and is not one of the qualification results.

## Two stages

1. `tests/vm/prepare_room_base.py NEW_ABSOLUTE_OUTPUT_DIRECTORY` runs in the same
   unprivileged disposable hosted profile as the existing Room runner. It verifies
   the pinned Fedora image, resolves and release-signature-verifies a bounded RPM
   pool, provisions only guest OS/tooling/configuration, and stops before starting
   Docker or any Room. It records installed RPM/tool versions and kernel, masks
   SSH, clears cloud-init cached seed/logs/machine identity and generated SSH host
   keys, then powers off. Only a normal guest exit with the exact nonce-bound
   preparation report permits flattening into a standalone qcow2. No external
   backing file, runtime image, active endpoint, lease, quota disk or Room state is
   published. The artifact contains `base.qcow2`, `pool/`, and `receipt.json`.
2. `tests/vm/run_room.py` with `UAS_ROOM_EXECUTION=warm`, an absolute
   `UAS_ROOM_PREPARED_DIR`, and externally trusted `UAS_ROOM_PREPARED_SHA256`
   verifies the receipt, exact base/pool bytes, producer identity, age (at most
   seven days), and current foundation sources **before QEMU**. It skips network
   RPM resolution/download and guest package installation. It still checks RPM
   signatures, builds current source/fixture/runtime payload, and creates a fresh
   overlay, cloud-init instance/seed/nonce and quota disk. Guest kernel, installed
   inventory, Docker/remap configuration and SELinux are re-observed. All existing
   qualification gates run; no old acceptance boolean is consumed.

Both commands require `GITHUB_ACTIONS=true`, `RUNNER_OS=Linux`, a non-root user,
`UAS_ROOM_VM_PROFILE=room-launch-ipv4-v1`; preparation also binds exact
`GITHUB_RUN_ID` and explicit `UAS_ROOM_PRODUCER_COMMIT` (the exact checked-out
head, not a PR merge-ref `GITHUB_SHA`). Those variables are context, not authorization.

## Identity and invalidation

The deterministic foundation key binds the official image lock, complete signed
RPM candidate pool (NEVRA, hashes and key fingerprint), repository metadata,
architecture/profile, and exact provisioning/guard/configuration source hashes.
Installed RPM inventory includes the actual RPM/DNF/tool versions; the warm guest
must match that inventory and the prepared kernel. The artifact SHA also binds
all disk bytes. The producer run/commit and receipt SHA must be selected from a
reviewed trusted run, never inferred from a downloaded artifact's own assertions.
An attacker can rewrite a self-supplied receipt and its hashes; it is not trust.

Nonce, current Room/application source, runtime archive and fixture changes do
not invalidate the OS base: those layers are rebuilt from the current checkout.
Changing provisioning, policy package versions, official image or signed pool
requires deliberate re-preparation. Runtime rootfs/trust generation and Docker
import remain **fresh per test** in this first increment; there is no runtime
image cache or bypass of its fresh canonical destination guard.

Missing, expired, mismatched, symlinked, externally backed or incomplete artifacts
fail closed and ask for explicit preparation. No `latest`, prefix restoration,
unbounded retry or automatic rebuild is supported. Local artifacts must be owned
by the invoking user and not group/world writable. Only a new output directory is
used. An interrupted publication lacks a verified complete receipt and is not
eligible; human/preexisting output is never adopted or deleted.

## Delivery and validation status

Source/file/mock contracts cover selection, hash/expiry/invalidation, fresh
payload assembly, no fallback, producer failure/ownership cleanup and stage
separation. They do not establish the real cloud-init reset/shutdown behavior or
warm performance. A separately authorized preparation run followed by one fresh
warm qualification is still required to measure timings and validate those real
boundaries. Cold-path qualification remains a distinct manual action.

The current workflow permissions are not expanded by this source change.
Cross-run Actions transport still needs reviewed, explicit producer run/artifact
selection and an approved `actions:read` permission (no PAT/new credential).
Download must enforce the exact artifact identity plus independently trusted
receipt SHA, and reject archive traversal/symlinks/oversize before extraction.
Do not treat an Actions download warning or a receipt's own hash as verification.
