# Cheap artifacts-native evidence

`tests/linux/artifact_native_smoke.py --run` is an explicit GitHub-hosted,
root-provisioned disposable fixture, not a production Gate launcher. Its
40-second bound includes copied-Git materialization, static builds and real
native cases. Do not invoke it in a source-only/local review environment.

The fixture stages a bounded exact source closure under its private `/tmp`
root, without following symlinks or changing runner-checkout permissions.
Dropped-UID processes and C builds consume those copied bytes; source and
binary hashes are reported. It uses the existing mapped Supervisor/helper
identities, private user/mount namespaces, read-only target views, actual
`SCM_PIDFD` sender binding, the unchanged static artifacts helper, final ACK,
held-task exit, and independently remeasured target cleanup.

The actual helper supplies facts for positive presence/nonempty Checks, a
missing-artifact refutation, target-mutation error and cleanup-identity error.
The Hub's existing reducer derives each verdict; the helper never asserts it.
Allocator/lifecycle setup and aggregate quota admission remain explicit
synthetic fixture inputs.

Separate test bootstrap/probe hashes use `UAS_ARTIFACT_PROBE` and the existing
`tests/vm/artifact_confinement_probe.c`, which includes the exact artifacts
setup/filter source. Expected normalized terminal statuses are retained:

| Probe | Expected status |
|---|---:|
| Network, process, forbidden descriptor, exec, timer reset, mmap (`N/P/F/E/T/M`) | 159 |
| Path escape, outside-target Landlock read, target write (`R/L/W`) | 0, after the intended denial |
| CPU ceiling (`C`) | 137, before the wall timer |
| Fatal wall timer (`H`) | 142, within the bounded interval |
| Oversized output (`O`) | Receiver rejects 16,385 bytes; helper exits 126 |

Each actual result is emitted before its assertion, including the decisive
expected/actual exit status. A success summary follows only confirmed fixture
cleanup. Failure retains an explicit quarantine path, not a success-looking
summary. These are cheap Linux #73 seam observations—not Docker, SELinux,
Room/#79, live Forge or complete VM qualification. The historical failed VM
qualification remains part of the evidence history.
