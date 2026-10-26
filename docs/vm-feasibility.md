# Disposable Fedora VM feasibility

This is the platform gate for the next integrated Room boundary, **not a new
launcher or production qualification**. It asks whether a normal hosted CI runner
can boot a suitable SELinux-enforcing Linux guest without KVM, credentials, user
hardware or a paid provider account, observe its prerequisites, and remove it.

The separate `vm-feasibility` workflow runs only when its harness changes. It
installs QEMU/cloud-image tools on the disposable Ubuntu runner, then invokes
`python3 tests/vm/run.py` as the unprivileged runner user. The normal aggregate also
checks offline harness contracts; those tests do not claim that a VM booted.

## Pinned provenance

`tests/vm/fedora-image.json` pins official Fedora Cloud Base Generic **44-1.7**,
its exact filename/size/SHA256, signed-checksum URL, and Fedora 44 primary-key
fingerprint. These values were read from Fedora's [download page](https://fedoraproject.org/cloud/download/)
and [security page](https://fedoraproject.org/security/). Each run verifies the
checksum signature against that exact fingerprint, the signed image digest
against the repository pin, and the downloaded bytes against both. Unknown
signers, changed checksums, missing downloads and corrupt images fail; there is
no latest-image or unsigned fallback. Fedora's downloaded keyring is not accepted
merely because it accompanied the image.

## Actual experiment

- Software emulation only: `-accel tcg,thread=multi`, 2 vCPUs, 2 GiB guest RAM.
- No NIC, network backend, port forward, SSH key/password, host directory share,
  runtime socket, host block device, KVM, or QEMU monitor listener.
- The verified image is read-only; all guest changes use one newly allocated
  disposable qcow2 overlay. A local read-only NoCloud seed contains only the probe
  and poweroff instruction. See [cloud-init NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html).
- The guest reports SELinux enforcing state, cgroup-v2/controller availability,
  relevant kernel build features, XFS/overlay/netfilter module availability and
  absence of external interfaces. Only module loading occurs inside the guest;
  no guest firewall rules, filesystem formatting, quota policy, endpoint policy,
  external calls or model requests are installed or attempted.
- A nonce-bound serial report must include all checks and pass each one, and
  QEMU must exit cleanly following guest poweroff. Missing/failed observations,
  oversized logs, abnormal exits or exceeding the 600-second boot/probe/shutdown
  budget fail the job. This budget is the measured CI-feasibility condition,
  not a readiness claim based on waiting alone.
- The runner reports download/verification and boot/probe/shutdown wall times.
  Success, errors, timeout and ordinary cancellation all unwind the owned QEMU
  process and temporary image directory. Force-killing the runner is ultimately
  handled by disposal of GitHub's ephemeral VM, not by a claimed cleanup callback.

This job does not change runner firewall/SELinux/mount policy. It does not probe
real cloud metadata or a homelab. Local execution is intentionally guarded;
`GITHUB_ACTIONS` is an accidental-use guard, not an authentication boundary.

## What a pass means—and does not mean

A pass establishes a measured disposable guest suitable for the next integration.
Kernel XFS-quota support is **not** an enforced quota; SELinux enforcing is **not**
proof of a correctly confined Broker socket; no-NIC is **not** public-egress
filtering. The next reviewed slice must join actual guest-only network, quota and
endpoint controls to the existing Supervisor and prove two-Room positive,
negative, failure, recovery and cleanup behavior. Production launch stays disabled
until its full boundary is qualified. Installing those controls on the user's
actual host remains a separately authorized action.

GitHub does not guarantee nested-VM stability/performance; see its [hosted runner
constraints](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners).
QEMU [TCG support](https://www.qemu.org/docs/master/system/qemu-manpage.html) avoids
depending on nested hardware acceleration but still requires this real CI result.
