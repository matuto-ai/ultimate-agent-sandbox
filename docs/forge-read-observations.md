> Superseded read-surface boundary: [external read Broker](forge-read-service.md) now supplies the complete declared reads, process separation, canonical Deployment read audit and completed-job logs. The text below records the earlier bounded slice, not the current public surface.

> [Exact PR and review observations](forge-pull-observations.md) now add the
> read-only `gh pr view NUMBER` prerequisite. These facts do not submit a Run,
> pass a Gate or infer an independent-review verdict.

> The optional [audited self-assignment extension](forge-assignment.md) adds one
> write route. The read provider and its external `GhTransport` remain read-only;
> this extension does not qualify the full Forge surface or production boundary.

# Connected GitHub read observations

This is the first bounded connected slice of [#66](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/66), not its completion. The existing official Pi 1.4.0 process can now call the `gh` tool with a native argument vector through its existing authenticated Participant channel. No new disconnected Runtime or simulated Pi is introduced. Forge requests use a bounded 45-second channel deadline; existing peer traffic retains its two-second default. The optional gh executor bounds each call to ten seconds and the provider stops starting pages after its 30-second budget.

## Path and ownership

`runtime/pi/extension.mjs` registers `gh({id, argv})`. Its existing SOCK_SEQPACKET transport reaches `FixtureParticipantController.receive`: Linux per-record SCM_CREDENTIALS, a held pidfd, immutable badge, capability epoch, Room lifecycle, and credential availability are checked before decoding/dispatch. `forge-read` capability is required. The trusted supervisor binds exactly one `ReadOnlyForgeBroker` to the controller's existing RoomLedger and immutable `ForgeBinding`; its Project must equal both the captured and current Supervisor Room spec, checked again on dispatch; the envelope cannot select Actor, Room, Project, provider host, credential, endpoint, or context.

The accepted initial native spellings are generated from the same route table used for enforcement:

- `gh --help`
- `gh issue view NUMBER [--repo OWNER/REPO]` (`-R` also accepted)

The optional leading `gh` is accepted in `argv`. NUMBER must be one exact positive decimal issue number; URL, selector, path, shell, `api`, auth, mutation, log, artifact, and extra-option routes fail before provider selection/contact. This initial slice permits only the pinned repository. Same-Forge cross-repository reads remain **unimplemented**, not a replacement policy for the larger accepted #66 surface. The Pi tool carries native argument spelling; this does **not** qualify a Workstation-wide controlled `gh` executable or arbitrary shell interception.

`GitHubReadProvider` resolves an issue using exact API repository/number/URL identity, rejects PRs, and reads native `dependencies/blocked_by` pages. It retains only immutable IDs, numbers, states, assignee IDs/logins, page count, and bounded completeness/status. Body/title/error text, response headers, tokens, paths and raw transcripts never enter observations. Dependency IDs/numbers must be unique, not self, and in the pinned repository. No body-text dependency inference or assignment mutation occurs.

A terminal short page without a next link establishes traversal completion; full pages continue to an additional page. Failed pages, contradictory continuation, page caps (maximum ten), one-MiB aggregate raw input cap, 48,000-byte sanitized result cap, malformed data, permissions and timeouts are incomplete/unknown, never successful admission. Provider-issued links are not followed: only locally constructed numeric page paths are requested. GitHub HTTP 404 remains `NOT_FOUND / unknown / not-found-or-inaccessible`, not evidence of eligibility or absence. This is an observation over a bounded interval, not an atomic GitHub snapshot or permission to reuse it for later admission.

The optional Broker-side `GhTransport` uses a supervisor-selected SHA-256-pinned executable, no shell, fixed GET API paths, fixed github.com, clean temporary HOME/config/cwd, disabled prompts/update notification, bounded output/time, and discarded stderr. Its exact Actor/host credential callback is external and has no fallback. The account-free tests use a controlled executable stand-in; **live official gh, credential handling in a deployed boundary, redirect behavior and native account permission semantics are not qualified here**. Nothing automatically discovers credentials or activates that adapter. Trusted injected transports must honor their bounded-call contract; production executor isolation remains separate.

## Durability and uncertainty

Before any provider selection/contact, RoomLedger commits `forge-read-started` with authenticated origin, Project/host/repository, and canonical request digest, not raw argv. After a sanitized observation it commits `forge-read-observed` and the result. Both use the existing FULL-synchronous WAL transaction seam. Admission and final fresh-authority publication hold the lifecycle lock; provider I/O holds neither lifecycle nor ledger locks, so Stop/revoke can win before a result is published. Generic process denials use a service audit origin and a fixed code, never attacker-claimed identity or packet contents.

Exact retries require fresh authority, match the original origin/request digest, and return the original terminal observation without contacting GitHub. Conflicting operation reuse fails. A committed pending start after interruption becomes durable `INTERRUPTED_OBSERVATION / unknown`, not a blind retry. Pre-contact audit failure makes no provider call. Terminal audit failure fences the Broker and returns `AUDIT_UNAVAILABLE`; a trusted replacement/restart can recover the same operation from the ledger. A committed terminal with a lost acknowledgement recovers its original result. Pending intents retain bounded sanitized original command/Origin metadata and reserve 64 KiB each (at most eight), including the existing peer/context future-lifecycle budget, before contact. Terminal results remain in immutable operation receipts/events, not duplicated into the bounded Room projection. Exact retries first prove canonical request equality and fresh exact-origin authority before reading the server-derived terminal receipt. Verified late authority loss permits only controller-owned unknown abandonment of that exact original intent: reconcile any immutable terminal first, atomically record original attribution plus a fixed controller reason, then release only its own reservation. It neither returns the result to the revoked process nor downgrades a previously committed success. After real controller replacement, endpoint binding reconciles pending records whose original incarnation is proven fenced by the authoritative seat manifest. It reconstructs the exact original command/Origin, commits unknown abandonment without provider contact, and releases its reservation; an active matching incarnation is not abandoned. New Pi incarnations cannot read or replay an old Origin's receipt. A new operation ID requests a genuinely new observation; there is no automatic intake, polling or retry scheduler.

This uses the current **RoomLedger integration seam**, not the still-required canonical Deployment-level Forge audit service. The same-UID fixture controller serializes admission and terminal publication with revocation under its lifecycle lock, but never holds that lock during provider I/O. It is not production hostile-Hub isolation, Workstation credential confinement, or a canonical Run controller. Every result explicitly says `admission: not-evaluated`; fixture run context is not human authorization, assignment approval, policy/slot binding, or human merge truth.

## Reproduction and remaining evidence

```sh
./validate.sh
UAS_PI_INSTALL=/path/to/locked/pi-install sh tests/pi/run-tests.sh
```

`test_forge.py` covers durable exact retry/reopen, conflict, authority/Room checks, route denials, sanitization, before/after-commit storage uncertainty and provider failures. `test_forge_capacity.py` covers joint peer/context reservation, saturated request completion/reset, bounded pending reads and stable projection across repeated observations. `test_github_read.py` covers provider identity/pagination/bounds, route parsing, output validation, external Actor selection and no-shell timeout/output handling. `test_pi_forge.py` executes the real official Pi tool, authenticated process channel, read provider and durable ledger using controlled account-free GitHub responses. The existing mandatory `pi-native` CI gate discovers this test file automatically; no weaker docs-only gate is introduced.

Keep #66 open for the remaining read routes, native same-Forge access, completed-job logs/redirects, executable boundary and production authority/audit qualification. Keep #69 and #72 open: this implements neither mutation reconciliation/outbox nor Run admission/control. #58/#78/#79/#81 acceptance still needs live integrated lifecycle, production credentials and image/process confinement, disposable-VM isolation, independent exact-candidate review and the other frozen evidence obligations. No live GitHub product credential, production launch, human-merge observation, or full Run is claimed.

### Primary provider contract checked 2026-10-26

GitHub's [supported REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions#supported-api-versions) lists `2026-03-10`. Its [blocked-by dependency endpoint](https://docs.github.com/en/rest/issues/issue-dependencies#list-dependencies-an-issue-is-blocked-by) documents the exact GET route, numeric `page`, `per_page` maximum 100, issue identity fields and read permission. [Pagination guidance](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api) specifies the next relation and omission of Link when everything fits one page. Our short-page requirement is deliberately more conservative: a full final page incurs another read and may hit the cap as incomplete, rather than asserting absence. Provider response validation is not a substitute for future live-provider qualification.
