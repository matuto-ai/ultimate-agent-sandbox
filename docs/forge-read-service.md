# Process-bound external GitHub read Broker

This is the complete read-surface implementation for [#66](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/66), including the external execution and canonical read-audit seams absent from the earlier issue/PR observation slices. Acceptance requires the exact candidate's independent review and hosted tests below. It does not complete native Git (#67), Manager (#75/#77), general Workstation launch (#62), or live-account/end-to-end qualification (#78/#79).

## Fixed provider and public vocabulary

`github_routes.py` fixes GitHub before parsing. Its validated table generates discovery and enforces the following bounded routes (optional leading `gh` and `--repo OWNER/REPO` / `-R`):

| Read family | Public arguments |
| --- | --- |
| Repository and code | `repo view`; `repo read-file PATH [--ref REF]` |
| Labels | `label list [--limit N]` |
| Issues | `issue list [--state open|closed|all] [--limit N]`; `issue view NUMBER [--comments]`; `issue status`; `issue dependencies NUMBER`; `issue blocks NUMBER` |
| Pull requests | `pr list [--state open|closed|merged|all] [--limit N]`; `pr view NUMBER [--comments]`; `pr status`; `pr diff NUMBER`; `pr checks NUMBER`; typed `pr reviews NUMBER` and `pr review-comments NUMBER` |
| CI metadata | `workflow list`; `workflow view ID`; `run list`; `run view [RUN_ID] [--job JOB_ID] [--attempt N]` |
| Completed job logs | `run view [RUN_ID] --job JOB_ID --log [--attempt N]` |

The dependency, file-read and explicit review-read verbs are the declared typed extensions, not permission to use arbitrary REST. IDs are exact positive numbers, not URL aliases or arbitrary CLI expressions. Unsupported flags reject rather than passing through to an executable. Code reads resolve a revision to a commit and verify returned blob identity. GitHub-native Actor permission, using that Actor's credential, governs declared same-Forge reads; there is **no invented repository allowlist**. Completed logs remain pinned to the Room Project. Writes continue on the existing separate, narrowly audited assignment route; this change does not expand mutation authority.

No `api`, GraphQL, authentication/configuration, selected provider/host, shell, workflow dispatch/rerun/cancel, artifacts, whole-run logs, live logs or binary attachment route is exposed. Caller identity/capabilities never come from argv. `--log` without `--job` is refused, including for completed runs.

## Real request and credential boundaries

The existing `FixtureParticipantController` receives each Participant record using kernel credentials and its held process object, immutable badge, incarnation and current epoch. `bind_read_service` accepts only its own Supervisor-bound `ReadBrokerClient`. The client snapshots the canonical request, rechecks the same process/epoch under the Room lifecycle lock immediately before dispatch, consumes each prepared packet once and rechecks before result disclosure. Stop/revoke can defeat an already accepted read's disclosure; no claim is made that a remote read already in flight can be undone.

A private inherited `SOCK_SEQPACKET` pair connects only that Supervisor to the external Broker. Both endpoints must have the existing `kernel_origin.enable` options installed **before launch/first send**. The Broker pins the actual Supervisor process object at bootstrap and checks it on every record; descriptor inheritance, a numeric PID, same UID, or a forged Origin field from another process does not authenticate it. The Supervisor is the trusted badge issuer, not the Hub or Participant. Wrong-task, invalid-scope and forged-origin refusals receive fixed, unauthenticated-service denial attribution, never attacker-claimed Actor attribution.

The authenticated nonce handshake binds the exact Room instance and full immutable Forge binding (Project, repository and host). Even a worker with the expected UID and Room name cannot silently answer against a different home Project. Declared `-R` reads remain separate native Actor authorization after this home binding is established.

`python -m uas.forge_read_service FD` is a fixed external entrypoint. Its bounded trusted stdin configuration supplies Room/instance/Project, Deployment audit/result paths, exact Actor credential-file reference, executable path/digest and expected Supervisor UID/GID. It rejects root and same-UID Supervisor operation. It does not provision accounts, discover tokens, change trust/security policy, or accept client-selected configuration.

`ActorCredentialFile` reads only a current-owner, private regular file at the trusted canonical path. Lookup is exactly `(Actor, github.com)` with no ambient `GH_TOKEN`, sibling or generic fallback. Its private result is used only in the Broker process. `GhSurfaceTransport` holds the executable inode, verifies its SHA-256 and owner/mode, executes through that held descriptor without shell, and supplies a clean temporary HOME/config/cwd and fixed GET path/Accept/header vocabulary. Paths cannot select auth, host, arbitrary APIs or a log download. Response/time bounds and process-group cleanup apply. Replacing a pathname cannot replace the held executable. This is a launch contract for an operator-selected pinned official `gh`; account-free tests use a fixed executable fixture, not a claim of live account permission.

The dedicated single-threaded Broker resets inherited `SIGCHLD` disposition and is the exclusive reaper of its `gh` children. Cleanup observes the still-owned child with `waitid(WNOWAIT)` before signaling its session, then crosses one wait/reap boundary only. `ECHILD` or an uncertain wait fences the transport; it never retries signaling a released numeric process group. The include-envelope parser follows [official gh v2.87.3 output formatting](https://github.com/cli/cli/blob/v2.87.3/pkg/cmd/api/api.go#L420-L424): LF after status, CRLF after headers and the blank line. Tests use this source-faithful format, not an assumed raw HTTP-wire status line.

## Literal reads and completed logs

`github_surface.py` returns bounded actual issue/comment/review/code/diff text to the requesting Participant. Pagination uses locally constructed numeric pages; only an exhausted traversal is complete. Bounds, failed pages, malformed object identities or contradictory continuation remain incomplete/unknown. A GitHub 404 stays `NOT_FOUND` with not-found-or-inaccessible semantics, never proof of absence. PR closing reads detect head/base/identity drift. Review state is literal and never a Hub review verdict.

CI output keeps check runs (`filter=all`), commit statuses, Actions runs/jobs/attempts, exact tested SHA, producer and conclusions separate. Test-merge CI is distinct from head CI and records verified parent association or unknown; neither grants coverage or Gate pass. A job response is **not assumed to contain `run_attempt`**. The exact attempt's fully paginated jobs list establishes membership, including bounded historical-attempt lookup for job-only commands.

For logs, the Broker independently validates Project, run, attempt, job membership, completed states/conclusions and exact head association before requesting the fixed job-log API. It rechecks run/job identity after transfer. Informational `gh` reads derive the selected run's head externally; they do not claim that a current Hub candidate or Gate was qualified. The lower-level log provider additionally supports trusted PR head/base/test-merge association when a caller supplies that authoritative context.

Only the authenticated GitHub API may supply the short-lived location. The second HTTPS request permits only GitHub's documented Actions results-storage host family, uses a separate TLS connection, and sends **no Actor authorization, cookies or caller headers**. No proxy environment, automatic redirects or signed URL disclosure exists. The stream must complete its actual HTTP framing; truncation, compression, archives, conflicting lengths and transfer/time bounds fail without exact-count claims. A successful result returns at most 750,000 raw tail bytes encoded in base64, with exact total/dropped counts and SHA-256. The 64 MiB transfer ceiling and 30-second bound constrain counting work; exceeding them is an error, not fabricated truncation evidence. Broker responses reserve envelope space within the 1 MiB transport ceiling. Pi reconstructs bounded correlated chunks with sequence/count/digest validation; ordinary peer messages do not acquire a streaming route.

## One audit owner; output is not audit

The existing `ForgeAudit` Deployment SQLite store migrates atomically from v1 to v2, preserving assignment/reconciliation tables and adding read start/terminal records. Exact schema/Deployment checks precede migration. A committed read start binds Room/instance/Project, full Origin digest, Actor/Participant/incarnation/epoch, fixed host, requested/effective repository, typed route and request digest **before provider selection/contact**. A terminal contains only outcome, completeness/contact status, byte counts and result digest. No body, code, diff, log, raw argv, token, signed URL or provider exception enters canonical audit or Hub events.

Responses are retained separately in a private Broker-owned cache, with at most 64 records and a bounded per-result size. Atomic no-overwrite publication and the audit digest bind exact retries. A retry first reauthenticates and matches the canonical request/Origin; it never recontacts the provider. Missing/corrupt cached output is `RESULT_UNAVAILABLE`, not a replay grant. Cache capacity refuses new work before contact and records the refusal. Cache eviction/reprovisioning is an explicit owner action, not automatic Project deletion.

Pre-contact audit failure makes no provider call. Terminal uncertainty fences the owner and remains pending/unknown. A trusted replacement first fences the old private owner, then terminalizes interrupted reads without recontact. Old Origin/epoch requests cannot acquire another Actor's cached output. Operation keys include Room instance, so identical client operation IDs in separate Rooms do not collide.

The fixed process entrypoint acquires an exclusive private audit/Room/instance owner lock before recovery; a concurrent owner refuses rather than terminalizing a live request. The existing RoomLedger retains only a metadata-only operation-ID reservation, preserving cross-read/write/peer `ID_CONFLICT` semantics without making it a second read-audit or content store.

## Verification and limits

Pure suites: `test_github_routes`, `test_github_surface`, `test_github_logs`, `test_github_executor`, `test_forge_read`, `test_forge_read_provider`, and `test_forge_read_audit`, plus existing read/audit regressions. These exercise real parsing/providers/SQLite and mocked external I/O; they are not process or credential-isolation evidence.

The existing short `validate` job additionally requires:

- `test_forge_read_process.py`: actual Participant → Supervisor → external Broker, held kernel origins, forged/inherited-descriptor denial, revocation before contact, late-disclosure fencing, process exit/disconnect and multi-record output;
- `test_github_executor_process.py`: exited-leader descendants with retained or closed stdout, held-pidfd exit, signal-before-reap ownership and selector-registration cleanup;
- `UAS_FORGE_HTTP_TEST=1`: actual disposable loopback TLS, authenticated API redirect, credential-free storage request, untrusted-server refusal and truncated-body failure;
- `tests/linux/forge_read_smoke.py`: disposable numeric UID-separated Broker/Supervisor, actual pinned fixture executable, unreadable Broker credential/audit files, same-Forge read, different-Actor provider denial, missing-credential and cross-Actor replay refusal, raw-API denial and exact retry;
- `UAS_FORGE_CHANNEL_TEST=1`: the existing actual Node Pi-channel tests, including bounded chunk reconstruction, wrong sequence/digest/non-read rejection and existing packet/deadline regressions, without installing/running a native agent or model.

The UID smoke separately records the runner's real `gh --version` and held-executable SHA-256 under the unprivileged Broker UID, with empty HOME/config and no credentials or provider request. Actual API execution remains the source-faithful account-free fixture; offline version evidence is not live GitHub access evidence.

The new checks do not add VM or paid-provider runs. Existing 1-minute validation and parallel 2-minute Docker job bounds remain unchanged. Local restricted development runs only pure/source checks; real process/TLS/UID checks must pass on the reviewed hosted candidate. Fixture tokens/certificates are transient test data; there are no production credential/account changes. Same-UID process tests alone do not prove filesystem/ptrace isolation; the separate-UID smoke supplies the narrower external-credential check. General Workstation confinement and live GitHub permission qualification remain their explicitly separate responsibilities.
