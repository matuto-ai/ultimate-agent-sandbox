# October 2026 source reconciliation

**Current direction:** retain the deterministic successor architecture, implement GitHub as the first product Forge, and use one independent review owner covering Standards, Specification, and Runtime. Pi and Claude remain the first Runtimes. This is a contract and extraction baseline, not implementation or release evidence.

The human selected GitHub-first and confirmed the review-owner amendment during reconciliation on 2026-10-25; the [decision record](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58#issuecomment-6399490386) amends [specification #58](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58). The [approved August specification](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58#issuecomment-6399490154) is preserved separately. Historical closed decisions retain their original wording.

## Contents

- [Evidence identity](#evidence-identity)
- [Accepted boundaries](#accepted-boundaries)
- [GitHub provider contract](#github-provider-contract)
- [Independent review and proof](#independent-review-and-proof)
- [Source responsibility disposition](#source-responsibility-disposition)
- [Runtime and skill inventory](#runtime-and-skill-inventory)
- [Implementation slices](#implementation-slices)
- [Sibling scopes](#sibling-scopes)
- [Development workflow and remaining evidence](#development-workflow-and-remaining-evidence)

## Evidence identity

| Input | Identity and limit |
| --- | --- |
| August source investigation | Report cites `e732a1525ba4af25dcb89fd2a0305c30ef1fe7a9`; the earlier checkout was not available for an exact old/new diff. |
| Approved successor contract | August 29 specification and approval, preserved in the historical comment above. |
| October source | Supplied `ai-agents-sandbox-src-2026-10-25` tree; 471 paths verified against `snapshot-files.sha256`. Manifest SHA-256: `67b7c775c1eea6fe4c66120ffb4f6468919c7dbf1a4449965da62d9af0ee3d7c`. |
| Snapshot qualification | No established upstream Git revision. Content hashes follow two hook symlinks; they do not attest ownership, permissions, link topology, builds, or deployed images. |
| Receiving GitHub repository | Inspected `277985d30b622b38a57bf787e9f8a0e66526c73a`, including migration repairs and Pi Durable research. All 23 slice dependency sets matched their 64 native blocker edges. |

The handoff archive's seven members matched the unpacked five Markdown documents, static browser copy, and checksum manifest. Raw research and the source tree remain outside this repository; this document promotes the stable contract and dispositions rather than publishing private working notes. Future extraction must identify the supplied file and manifest, or deliberately establish a newer immutable source baseline. “Final source” is not a moving compatibility promise.

## Accepted boundaries

A Deployment contains several independently controlled Rooms. Each Room owns one Project binding, writable repository, persistent Workstation, Hub, Broker, ledger, endpoints, network, and outbound Manager connection. The supervisor owns lifecycle, seat authority, checkouts, resource controls, and reconciliation. Profiles supply judgment guidance; typed software owns state and permissions.

Keep direct seat Runtime/arguments/Actor/Profile selection, contribution-based reviewer eligibility, aggregate review, the five-valid-return cap, and verified human merge of the unchanged candidate. Remove live registered-Finding machinery, separate Run approval, pre-merge completion, Work Role, and Runtime Launch Profile concepts. A missing Actor credential disables affected seats, not the Room.

GitHub development hosting and GitHub product support were separate decisions; both now select GitHub. This does not authorize Gitea/GitLab parity, GitHub Projects-board automation, arbitrary GraphQL, or a provider-plugin framework. Preserve one typed Hub contract and one initial provider. The product still has no other-installation migration, coexistence, cutover, or retirement feature.

## GitHub provider contract

The reviewed capability baseline below replaces the unqualified “complete final Gitea route table.” Source anchors are `agents/forge-broker`, `agents/pi/gh`, `docs/FORGE_CLI_PROXY.md`, `docs/FORGE_AUTH.md`, and `docs/GIT_IDENTITY.md` within the manifest-identified snapshot. The source host CLI baseline is `gh 2.87.3`; the successor must deliberately pin and qualify its actual CLI/API versions rather than infer them from this document.

| Capability | Initial GitHub mapping and boundary |
| --- | --- |
| Discovery and provider execution | Controlled native `gh` plus Git; one validated typed route table generates help and enforces policy. A pinned external `gh` executes approved operations; exact bounded provider calls fill demonstrated CLI gaps. No caller-selected endpoint, credential, host config, or unrestricted API surface. |
| Work and repository reads | Bounded issue/PR/code/diff/comment/review, assignment, label, dependency, and CI metadata reads. Enumerate pages with continuation and incomplete-result state; a cap or failed page cannot prove absence. Only declared same-Forge read routes may cross repositories under native Actor permissions. |
| Mutations | Project-pinned issue/PR creation and bounded edits, comments/replies, assignment, labels, native dependency changes, and submitted review. Authenticate the fact's owner: Hub lifecycle projections and Participant work-type edits are different authority. Human merge, repository administration, workflow control, and branch-rule mutation are not agent capabilities. |
| Dependencies | Native GitHub issue dependencies, not body-text inference. Resolve issue numbers to immutable IDs after validating both issues in the pinned repository; reject PRs and self-dependencies. Parent hierarchy is not a blocker. |
| Reviews | Bind repository/PR identity, review ID/URL, author, submitted state, and `commit_id` to the exact candidate. Map authenticated aggregate `pass` to a qualifying approval, `changes-requested` to a submitted changes request, and `human-needed` to an explicit typed escalation with a submitted comment review. Native state or comment wording alone never advances the Hub. Pending, dismissed, stale, superseded, or unverifiable evidence cannot pass. REST review comments do not prove GraphQL thread-resolution state; the Hub needs no per-thread lifecycle. |
| CI | Normalize check runs and commit statuses separately from Actions runs/jobs/attempts. Record exact candidate, tested revision, relevant base, producer/context, applicability, and completion. A PR test-merge SHA is not its head SHA; it qualifies only with explicit verified head/base association and the policy's coverage rule. Missing configured CI or unreadable branch rules remains unknown. |
| Completed-job logs | Validate pinned repository, completed run/job, candidate relationship, attempt, and conclusions before retrieval. Use the job-log route, not live streaming or whole-run archive/artifact access. Fetch provider-issued short-lived redirects only through validated Broker-side HTTPS host policy; never forward Forge authorization to storage, expose signed URLs, or follow caller-selected destinations. Return at most 1 MiB with exact dropped bytes; incomplete transfer is an error, not a complete log. |
| Merge observation | Freshly read the exact PR's repository, base target, head SHA, merged state, merger identity, and integration SHA. An authorized human must have merged the unchanged reviewed candidate. `merge_commit_sha` can identify a test merge, merge commit, squash commit, or rebased result; it is not a substitute for head identity. Qualify supported merge methods in integration; unproven bot/queue attribution or changed candidates raise attention rather than complete. |
| Receipts and recovery | Operation ID, committed pre-contact audit, confirmed-field receipts, structured partial/unknown outcomes, and committed terminal audit. Lost response after possible contact requires authoritative reconciliation, for ordinary Participant writes as well as Hub outbox projections. Audit failure after contact stops the Broker with unknown outcome, never durable success. |
| Binary attachments | The source's issue/comment upload and download routes are Gitea-specific, not a verified GitHub capability. They are excluded from the initial GitHub surface rather than emulated with private browser endpoints, releases, or CI artifacts. The historical 4 MiB upload ceiling grants no route; the proposed 32 MiB download channel is deferred. Ordinary Markdown links remain text. |

Body input remains 512 KiB; ordinary output and completed logs remain 1 MiB. Preserve bounded argv/stdin/timeouts, exact identity selection, metadata-only audit, and no silent fallback. Route discovery is a maximum vocabulary, not an authorization grant. Source `gh pr merge` availability does not override human-only completion.

Primary GitHub references inspected for this mapping: [issue dependencies](https://docs.github.com/en/rest/issues/issue-dependencies), [pull-request identity and merge semantics](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request), [review identity and submitted events](https://docs.github.com/en/rest/pulls/reviews), [job metadata and log redirects](https://docs.github.com/en/rest/actions/workflow-jobs), [check runs](https://docs.github.com/en/rest/checks/runs), and [commit statuses](https://docs.github.com/en/rest/commits/statuses). Documentation establishes the mapping, not live credential, scope, rate-limit, redirect, or recovery proof. The read/mutation/integration slices must establish those facts with the selected account and pinned implementation.

## Independent review and proof

One independent owner reviews the exact candidate through Standards, Specification, and Runtime. The owner did not contribute code, conflict resolution, or an adopted exact patch. Separate seats, models, profiles, or native children do not establish independence. Add a specialist or another independent pass for a named unresolved question, not as three mandatory repetitions of the same review.

Retain every consequential positive, negative, failure, recovery, integration, security, manual, runtime, and target-host requirement. Distinguish complete-suite CI, branch-required checks, focused proof, and specialized evidence. Reuse exact-head evidence while its dependencies remain current; meaningful changes invalidate affected proof, not every observation. Recheck target ancestry and freshness after waits and expose the residual merge-time race.

One owner continues a bounded CI wait from a durable checkpoint. Pending CI, reviewer outage, stale candidates, and incomplete reviews consume no product return. The fifth valid changes-requested return pauses before another implementation request; human-needed pauses immediately. Source review-tool round counts are not this product counter.

## Source responsibility disposition

| Responsibility | Successor owner and disposition | Required outcome |
| --- | --- | --- |
| Images, pins, installed tools | Supervisor: adapt reviewed pins and provenance, not the source launcher or its entire tool catalogue. | Acceptance identifies actual image digest and Runtime versions. Mutable OS/npm inputs prevent a byte-identical-build claim from pins alone. |
| Provider/model routing | Runtime adapters/configuration: separate process, adapter, configuration validity, inference health, and quota observations. | Offline provider does not imply absent process or authorize fallback. Local network access remains deferred pending a narrow permitted route. |
| Identity and Git | Supervisor/Broker: preserve immutable exact lookup and host-qualification intent; replace mounted private keys with external transport. | Real fetch/Project push, cross-target denial, revocation, anchored cherry-pick attribution, and child/seat contribution tracking. |
| Forge | Broker: adapt native GitHub operations, correction/receipt semantics, and pagination; replace optional peer checks and ephemeral outcomes. | Mandatory kernel/process binding, confined private endpoint, durable start/terminal audit, explicit uncertainty, no duplicate writes. |
| Workflow skills | Participant Profiles for judgment; Hub for admission, policy, review, Gates, and recovery. | Prose, local paired-review tools, model changes, and subagent transports cannot confer authority or complete a Run. |
| Managed instructions/state | Supervisor: ownership-aware composition, quarantine/preservation of unowned data, bounded current model provenance, explicit updates. | Stage loaded-code/profile changes for restart or replacement; preserve custom settings and active policy snapshots. |
| Workstation and checkout lifecycle | Supervisor: retain dirty/untracked/unmerged/unverifiable data; use persistent Workstation and on-demand host-visible slots. | Concurrent allocation and interrupted cleanup remain safe; ignored human data is not automatically disposable. |
| Browser, preview, nested containers | Supervisor/Workstation: keep default-off despite source browser defaults. Reject source confinement exceptions. | No host/LAN bypass or disabled outer labels; preview leases are not Manager HTTP proxies. |
| Manager and diagnostics | Manager projects authoritative typed facts, sanitized source/time/quota/drift/partial/unknown observations. | No inference from a percentage, connection, or pretty UI grants readiness or authority. |
| Knowledge and Graphify | Library sibling map: preserve authored per-Project knowledge and native reads; retire obsolete managed Graphify integration from its frontier. | Existing graph output remains user data; no replacement graph/memory engine is implied. |

## Runtime and skill inventory

The snapshot declares Pi 1.4.0, Claude Code 2.1.310, Codex 0.164.0, native OpenCode 1.19.4, and Antigravity 1.4.7. Only Pi and Claude enter initial acceptance. Pi OpenCode Go is a Pi provider configuration, not native OpenCode; Antigravity's `gemini` launch alias is not Gemini CLI.

Pi Local now permits startup with valid offline configuration while an inference endpoint is unavailable and retains strictly inherited local subagent routing. It excludes intercom/model-profile packages and has no cloud fallback. Its host-loopback transport is not the successor network policy. Model authentication and quota credentials can refer to different accounts; Manager must report quota source, association when safe, consumed-versus-remaining semantics, timestamp, and unavailable reason. Antigravity auth/telemetry/account gaps and heterogeneous provider tool-call qualification remain reasons to defer support.

Pi's package manifest includes pinned web access, document parsing, subagents, intercom, paired review, model presets, local presentation, decision forms, and Ponytail. They remain Runtime tools or guidance, not mandatory Hub services. Interactive TUI forms have no durable remote Manager authority.

All 39 shipped source skill bundles have a disposition below; package-provided skills are additional. No bundle is imported merely because it exists.

| Bundles | Disposition |
| --- | --- |
| `code-review`, `codebase-design`, `docker`, `domain-modeling` | Keep bounded engineering/review judgment in Participant guidance. |
| `prototype`, `research`, `systematic-debugging`, `test-audit`, `wait-what`, `wizard` | Keep evidence-building and human-only setup methods without new workflow services. |
| `impeccable`, `taste`, `taste-brandkit`, `taste-brutalist`, `taste-full-output`, `taste-gpt`, `taste-image-to-code`, `taste-imagegen-mobile`, `taste-imagegen-web`, `taste-minimalist`, `taste-redesign`, `taste-soft`, `taste-stitch` | Optional design tools; no first-release dependency, frontend choice, or implied image-generation capability. |
| `work-issue`, `issue-management`, `init-project` | Contributor workflow remains separate from deterministic product control. |
| `wayfinder`, `to-spec`, `to-tickets`, `grilling`, `grill-with-docs` | Planning judgment; no implicit Run admission or implementation authority. |
| `execution-view`, `project-library`, `handoff`, `find-skills`, `one-shot`, `teach`, `writing-for-agents` | Read-model, knowledge, continuity, and optional education/discovery guidance. |
| `agent-browser` | Optional ambient tool; trusted-target guidance does not create per-Participant isolation. |

## Implementation slices

These remain existing open delivery scopes, not work completed by reconciliation. Their native dependency graph is retained.

| Slice | Reconciled obligation |
| --- | --- |
| [#59 Configuration](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/59) | Direct seats, two-Room ownership, provider-validity/health distinction, capability enforcement classes, and real aggregate checks wired into GitHub CI. |
| [#60 Hub storage](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/60) | Atomic result/event/state transaction, authenticated canonical equality, consistent snapshot/replay, disk restart and commit-failure proof; no Forge or Runtime expansion. |
| [#61 Room lifecycle](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/61) | Desired/observed ownership, image/config drift, staged updates, persistent resource identity, targeted Destroy retry. |
| [#62 Launch boundary](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/62) | Private endpoints, compulsory peer support, enabled outer confinement, default-off browser/nested variants, no inherited host-loopback exception. |
| [#63 Seats](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/63) | Immutable process/epoch authority, seat-scoped credential loss, child attribution and model non-authority. |
| [#64 Checkout slots](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/64) | On-demand same-path host slots, concurrent allocation, retained dirty/untracked/unmerged/ignored human work. |
| [#65 Messaging](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/65) | Distinct queue, Runtime delivery, Participant acceptance, completion; recovery redelivery and dedupe without exactly-once external-effect claims. |
| [#66 GitHub reads](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/66) | Reviewed route table, paginated native dependencies/reviews/CI, completed-job-only bounded logs, mandatory process authority. |
| [#67 Git](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/67) | External host-qualified transport, no Workstation keys or reusable auth socket, Project push pinning and anchored cherry-picks. |
| [#68 Mutations/audit](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/68) | GitHub number-to-ID validation, executed-field receipts, partial/unknown contact, durable audit; no invented GitHub attachment path. |
| [#69 Reconciliation](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/69) | GitHub authoritative reads and outbox recovery; ordinary writes also avoid duplicate create/comment/review. |
| [#70 Pi](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/70) | Re-prove actual selected version, queue acceptance, compaction, native reset, crash/restore, optional provider boundaries. |
| [#71 Claude](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/71) | Re-prove actual selected version; ambiguity, needs-input, reconnect, and resume hold until fresh safe evidence. |
| [#72 Run admission](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/72) | Exact human authorization, fresh native GitHub dependencies/assignment, policy/slot/context snapshot, no automatic intake. |
| [#73 Gates](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/73) | Separate coverage, required checks, focused/specialized proof, head/base and producer dependencies, unknown-versus-absent distinction. |
| [#74 Review/merge](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/74) | One independent owner, exact submitted GitHub review, five valid returns, verified human merge with separate candidate/integration identities. |
| [#75 Manager stream](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/75) | Literal provider/quota/drift/CI ownership and structured partial/unknown states; per-Room replay. |
| [#76 Manager UI](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/76) | Existing Field Notes design/check, live facts, no synthetic authority, approval button, or tool-imposed frontend choice. |
| [#77 Manager actions](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/77) | Exact observed-state fencing, authenticated human, bounded Gotify, Open in GitHub; no preview proxy. |
| [#78 Real integration](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/78) | Real Pi–Claude–GitHub lifecycle with exact image/runtime/Actor/head/base/review/merge evidence and uncertain-write recovery. |
| [#79 VM isolation](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/79) | Two Rooms, absent keys, strict peers, enabled confinement, hostile Hub, GitHub/Git pinning and sibling survival. |
| [#80 Host capacity](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/80) | 100 cycles, enforced limits, drift/provider-outage observations, retained work, measured defaults. |
| [#81 Acceptance](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/81) | Frozen responsibility dispositions, current implementation/image identities, exact-head proof, live docs, explicit residual risks. |

## Sibling scopes

The [Library map #30](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/30) remains separate. Remove obsolete managed Graphify/vault integration from its active questions; preserve existing graph output and authored/derived separation. External Cortex/provider ownership replaces source-owned model-server assumptions, while Library quality qualification and Project egress remain distinct from interactive coding. Operator controls [#43](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/43) and maintenance [#44](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/44) remain open. Native-read proof [#34](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/34) and research recovery [#47](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/47) remain complete.

The historical Library store decision selected private Gitea hosting. GitHub-first for the main product does not silently rewrite that sibling storage contract; resolve its hosting when the Library specification is resumed, preserving the sole-writer, private-store, and fast-forward/recovery guarantees.

[Artifact review #82](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/82) stays deferred and hands-on-human-gated. Pi forms and browser tools are prior art, not adoption evidence. [Pi Durable](../research/pi-durable-continuous-agents.md) remains a possible simplification to investigate, not an accepted replacement for the Hub, native Participants, or authorization/recovery boundaries.

## Development workflow and remaining evidence

At the inspected GitHub head, `.github/workflows/` and the GitHub agent support contract already exist, the obsolete `.gitea` workflows have been removed, and repository automation owns closed-issue lifecycle cleanup. Preserve those repairs. Migrated evidence links select immutable history even where assets were later removed from the current tree.

Validation is still a placeholder in both `validate.sh` and `.github/workflows/validate.yml`. Configuration slice #59 must replace it with owned executable checks and wire the same aggregate into CI, then later slices extend coverage. A workflow named validate, a docs-only exemption, or a green placeholder does not prove a release criterion.

The branch-protection read returned HTTP 404; a broader branch-metadata read was denied by the broker. Effective required checks/rulesets are therefore unverified, not known absent. Record that access gap until an authorized operator or supported read establishes the effective rules. Do not weaken the Broker or infer protection from a successful CI run.

Reconciliation leaves live Runtime lifecycle, account permissions, actual image contents, redirect safety, external Git/process binding, crash-durable audit, disposable-VM isolation, and host measurements to their explicit slices. Source tests, pinned versions, and prototype success cannot substitute for those outcomes.
