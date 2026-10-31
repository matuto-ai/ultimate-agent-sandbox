# Bounded Room lifecycle/capacity collection (#80)

`uas.host_capacity` prepares the existing [target-host acceptance issue #80](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/80). It does not supply a production launcher, qualify puglab, recommend defaults, or make fixture measurements production evidence. There is no automatic CI/VM invocation or new benchmark framework.

## Consumed owner interface

A trusted host constructs `HostCapacityScenario(supervisor, spec, ledger, report_path, session=human_session, deadline=absolute_monotonic_time, candidate_sha=..., workload_id=...)` and invokes `run()` once. `supervisor`, `spec`, `ledger`, and `session` must be the existing concrete `Supervisor`, `FixtureSpec`, persistent `RoomLedger`, and authenticated `HumanSession` for the selected Room. The caller supplies already-constructed owners, not JSON claiming authority. This module does not create a login, deployment, credentials, Runtime, model workload or Room.

The Room must already be running at the exact selected instance/spec. Each of the **100** cycles uses `Supervisor.manager_view` and `Supervisor.manager_action` for fenced Stop/Start. The Manager view must exactly match the last validated lifecycle observation; a newer revision is not automatically adopted. Those canonical operations then recheck current human authorization, connection, instance and observation revision and record their own durable intents. A changed Room/version or disconnected/revoked session cannot redirect a cycle to another instance. There is no direct Docker lifecycle operation, Destroy, reset, retry with a fresh operation ID, broad cleanup, or automatic reconciliation.

The source baseline supports the existing `DockerFixtureBackend` and disposable-guest `GuestBoundaryBackend` only. This is deliberately not an admission extension: neither backend supplies the required production puglab/Pi/Claude proof. Actual execution requires separately authorized access to a prepared host and its authenticated owners. This change does not authorize running even fixture cycles on a valuable host.

## Measurements and preservation checks

The consumed collector obtains exact owned container/volume identities through the existing backend's ownership validation. It makes fixed, one-shot `docker stats --no-stream` reads for CPU percentage, memory use/limit, process count and block I/O, plus a fixed writable-layer-size projection. No shell or arbitrary Docker command/format/name is introduced. The reused ownership validator captures full Docker inspection metadata (which may contain environment fields); the collector never selects or emits environment/credential/log content or Project contents. The metrics projection itself requests only the fixed fields above. Before/after ownership observations bind the sample to the same running container ID. Docker CPU is an interval percentage, block I/O is cumulative, writable-layer bytes exclude mounted Project data; these are not interchangeable with quota, whole-host usage or leak evidence.

Per-cycle records include observed timestamps, Stop/Start elapsed seconds, same instance/container/volume/image/Project-directory/ledger inode checks, nondecreasing Room sequence, and passive source-tagged Manager lifecycle/drift observations. Ledger state legitimately changes during authenticated lifecycle operations; the collector does not compare all mutable bytes. Directory identity and monotonic sequence do not prove all Project/ledger contents survived, nor do named-resource checks prove absence of additional leaked resources.

Candidate SHA and workload ID are **operator annotations**, not a source build attestation or proof that a particular workload ran. Host/kernel observations describe the execution host, not independently verified puglab identity.

## Bounded reporting, failure and custody

A fresh report outside Project roots is created exclusively and without following symlinks, then retained by inode. Its held parent directory is fsynced after exclusive creation, before any lifecycle effect, so the report name as well as subsequent record contents has a durability boundary. It is append-only JSONL: maximum 16 KiB per record, 512 records and 4 MiB total. Each exact operation/request intent is written and `fsync`ed before calling the lifecycle owner; each confirmed observation is recorded before the next effect. Existing reports are never overwritten or reopened to resume effects.

All 100 cycles produce 503 records in the ordinary path. A malformed/missing observation, capacity-report failure, stale version, identity mismatch or uncertainty stops collection. An unconfirmed operation remains `pending`; the last durable intent is retained even if terminal reporting also fails. No exception handler restarts, stops, destroys, cleans up or retries the Room. An interruption may therefore leave it stopped or running; inspect and reconcile using the existing authorized owner before deciding any further action. Do not infer that an absent terminal record means no effect occurred.

The deadline stops scheduling new actions/reads and is checked around observations. A one-shot read is not started unless the existing backend timeout (at most 20 seconds) fits the remaining budget. **It is not a hard overall wall-clock deadline:** the baseline's canonical lifecycle lock and owner internals do not expose bounded acquisition. This collector neither changes those APIs nor abandons their custody in a background thread.

## Acceptance still required

`collection: complete` means 100 collection cycles finished, **not** `#80` passed. Every result retains `qualification: unqualified` and `defaults: null`. Missing target-host production admission, complete resource inventory, actual Pi/Claude workload/process and safe-point measurements, useful concurrency, disk/log enforcement, limit exhaustion with human attention, interrupted reconciliation, dirty checkouts, seat failures, Manager reconnect/replay, profile drift/provider outages, explained storage growth and measured conservative margins remain explicit blockers. No supplied boolean can turn them into successful proof.

Storage growth can be legitimate workload/log output; this module does not invent a numeric leak threshold or clean data to obtain a flat chart. The eventual target-host run must explain observed growth and validate all recovery/enforcement requirements, then tie the evidence to the exact host, image, Runtime versions, candidate and workload. It must not replace the original 100-cycle obligation with a smaller run.

## Source tests

`tests/test_host_capacity.py` consumes actual canonical Manager/Supervisor/SQLite reducers and report writes, controlling only Docker/resource/clock boundaries. It checks the full 100-cycle path, same-instance fences, session revocation, uncertain Stop without replay, durable exact intents, reporting failures/bounds and observation changes. These fast checks provide no native process, Docker, VM, performance or target-host evidence. Existing aggregate discovery includes them; no heavy automatic job is added.
