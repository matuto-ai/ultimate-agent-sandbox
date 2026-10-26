# Read-only launch preflight

This is a bounded **partial #62** delivery, built on the existing versioned configuration loader. It provides useful host observations and a deterministic desired plan, not a production launcher or proof of the whole security boundary. #61's non-empty endpoint revocation and persistent control-plane integration remainder stays open; this work does not remove that dependency.

```sh
python3 -m uas check-launch tests/fixtures/two-rooms.json --room alpha
```

The command emits JSON and exits **3 (launch blocked)**, even when every implemented observation is positive. Invalid configuration/unreadable input exits 2 as before. `validate-config` retains its existing behavior. No container/process launch, host policy change, firewall modification, mount, chmod/chown, provider call, endpoint connection, or payload transmission occurs.

## What is observed

- Existing Project directories and the selected Room control-store directory are inspected using directory descriptors, no-follow component traversal and filesystem metadata. Missing paths, symlink components, traversal and wrong types fail; unreadable/unavailable observations remain unknown. The observer never creates paths or reads file contents.
- An ephemeral local Unix socketpair probes actual kernel `SO_PEERCRED` support. This is explicitly **not** a connection to the Broker or proof of Participant identity.
- An optional narrow Broker socket path can be inspected without connecting:

  ```sh
  python3 -m uas check-launch room.json --room alpha \
    --broker-socket /configured/room-state/endpoints/broker.sock \
    --broker-uid 1001 --broker-gid 1001
  ```

  Expected UID/GID are policy selections from the trusted supervisor/operator, not evidence supplied by a Participant. Observed owner/group must match and be non-root. The conservative initial metadata check accepts socket modes 0600/0660 and control-parent modes 0700/0750, rejects writable/public parents, and requires the endpoint to be beneath that Room's control store. It does not declare that this metadata policy alone is a qualified endpoint transport.

`observe_unix_peer(connected_socket)` is the separate trusted transport seam: it reads the kernel's peer PID/UID/GID from an actual connected Unix stream descriptor. It accepts no caller-provided identity dictionary. The tests exercise a different real process. A PID/UID/GID observation is **not** an Actor/Participant binding, capability epoch, lifetime check, or protection against PID reuse; those remain #63 integration work.

Every check carries an explicit source and observed/failed/unknown status. Metadata records only type, device/inode, ownership and mode. Observations are point-in-time per-object facts, not an atomic filesystem snapshot, a retained mount lease, or a guarantee against replacement before launch. The eventual production launcher must bind/revalidate the actual objects it uses.

## What is only declared or remains unknown

The desired plan derives the configured digest-pinned image, resource bounds, Room network requirements, default-off ambient capabilities and same-path repository/workspace/reference mounts. References are read-only. The checkout-slot root is inspected but is **not** mounted wholesale; allocation remains #64. This plan is explicitly `declaration-only-not-launchable`, not executable Docker arguments.

Actual Runtime-state mounts, running non-root identity, outer confinement, public egress with host/private/metadata/sibling denial, running disk/memory/CPU/PID/log enforcement, Broker process binding and SELinux transport remain unknown. Configuration booleans cannot promote them to observed facts. Extra caller `observed_controls`, `launch_allowed`, device/mount/privileged/namespace fields are rejected by the existing fail-closed schema; there is no qualification override flag.

`launch_allowed` is always false and `production_launcher` always disabled. The separate #61 fixture backend remains fixture-only. This slice does not configure host security or change its launch semantics.

## Evidence and next integration

`./validate.sh` includes positive filesystem/plan checks, missing/wrong-type/symlink/traversal cases, a path swapped after configuration load, rejected caller evidence/unsafe overrides, endpoint ownership/mode cases, unknown kernel support, real cross-process Unix peer observations, read-only/no-external-connect checks, and CLI exit/report behavior.

A cloud sandbox may allow socketpairs while denying new Unix listeners. In that case the local socketpair observation is real, but the four listener/descriptor-dependent cases are explicitly skipped locally; that is not cross-process or endpoint proof. CI sets `UAS_REQUIRE_UNIX_PEER_TESTS=1`, so unavailable real Unix sockets fail the suite rather than silently skipping it. The existing dedicated Docker lifecycle job remains required for its separate two real-container cases. Neither job qualifies production SELinux, public-egress policy or disk quotas.

The [fixture lifecycle admission](room-lifecycle.md#enforced-fixture-execution-admission)
now reuses the no-follow path observer and checks the actual Docker boundary before
fixture execution, with real-container denial and kernel-probe CI coverage. This
does not promote the desired production plan to launchable: its network-none,
read-only Project mounts and plain named volume do not qualify production egress,
writable Projects, SELinux endpoint transport or disk quotas.

Further #62 integration must prove those missing controls on a suitable disposable host, without weakening policy to fit the test runner. Then #63 can bind actual processes/epochs and #61 can verify non-empty endpoint revocation. For the event → triage → test flow, a later authenticated event intake must submit an idempotent application command and deliver it to a real agent adapter, with test/result evidence returned to the ledger; this preflight does not invent that execution engine or select Pi Durable.
