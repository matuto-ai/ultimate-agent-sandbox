# Pi Durable bounded fit experiment

**Experimental execution proof, not a production Runtime or architecture change.**
The real Pi Durable 1.4.0 Harness uses its official faux provider to execute actual
local fixture tools. Reasoning is scripted; no real model, subscription, native
Pi/Claude CLI, Psst service, Forge mutation, or deployment is involved.

## Reproduce

Requires Linux, Node 24.22.1, Python 3.11+, and this repository's existing
`uas/ledger.py`. The module is imported from the repository; it is not copied here.

```sh
sh spike/pi-durable-fit/install-dependencies.sh
sh spike/pi-durable-fit/run-tests.sh
```

Acquisition verifies registry-only lock URLs, uses `npm ci --ignore-scripts`, and
isolates npm configuration. It retains existing proxy/CA trust but no account/model
settings; TLS verification remains enabled. Tests then scrub the environment, use
an empty local HOME, and register only the faux provider. No model charges occur.
Generated evidence remains in ignored `artifacts/` directories, outside product state.

## Six tests

1. Authorized event → real failing regression → exact fixture patch → passing test.
   Wrong-project, unauthorized, stale-generation, conflicting-command, and conflicting
   event inputs are rejected. Exact retries and same-event/new-command redelivery
   share the same Pi submission. Two structural views converge; post-snapshot tool,
   message, and run-end events are asserted.
2. Direct Pi request-ID deduplication demonstrates that it does **not** compare content.
3. Real inbox steering, follow-ups, queued withdrawal, and busy rejection.
4. Authority fence → scoped stop → fresh authorized continuation in the same conversation.
   Historical RoomLedger receipts are rechecked before Pi execution; `resume()` does
   not resurrect an aborted run.
5. Graceful close/reopen recovers a pending safe tool without a duplicate patch.
6. Actual SIGKILL of an isolated worker recovers the same committed pending work.

`draft-pr.json` is a **local proposal only**, recording candidate content hash, actual
test results, and conversation/observer evidence. It is not a PR or product completion.

## Boundaries and limitations

- RoomLedger owns authority in a separate SQLite store. The small host reducer is a
  single-event test policy, not a production Hub or message queue; Psst is not replaced.
- Native runtimes, autonomous diagnosis, subscriptions, real delivery, independent
  review, and human-merge acceptance remain unqualified.
- Stop is exercised at an asynchronous inspection barrier, not during the bounded
  synchronous test subprocess. Native-process cancellation is not proved.
- Authority checks and file writes are separate operations. Fence-before-abort order
  is tested; atomic revocation safety across an effect is not.
- Recovery is injected before patching. Lost responses after external mutations,
  interrupted unsafe writes, power loss, and universal exactly-once effects are not
  proved. Faux remaining responses are reconstructed explicitly after reopen.
- One process owns each Pi store. Two observers attach to that owner; competing
  writers are not tested. Pi SQLite uses its default WAL / `synchronous=NORMAL`.
- Tools expose fixed paths/commands, not a generic shell. The Node network guard is
  instrumentation, not a security boundary. Local runs assert zero guarded attempts;
  CI additionally proposes a no-network child namespace and fails if unavailable.
- Human actions come from the trusted test driver; authentication and production
  approval UI are not implemented.

## CI

The dedicated workflow checks this directory, `uas/ledger.py`, and its own changes.
It pins Node/actions, installs the exact lock with scripts disabled, then runs the six
tests with a scrubbed environment inside a separate Linux network namespace, dropping
back to the runner user. It changes no host network configuration and has no networked
fallback. This workflow is additional experimental evidence, not product acceptance.

See [PROVENANCE.md](PROVENANCE.md) for upstream identities and qualification limits.
The next useful integration is one native participant behind the existing transport
with real delivery/acceptance/cancellation evidence, not a larger mock framework.
