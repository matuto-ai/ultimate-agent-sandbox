# `pi-hermes-memory` 0.9.1 retirement inventory

## Decision

Do not treat `pi-hermes-memory` as the librarian. The active extension combines several concerns that need different owners:

- The per-Project librarian should replace **Project-scoped authored memory, Project retrieval, and the Project write/maintenance loop**.
- Global memory, user profile, failure lessons, procedural skills, session-history search, and security controls are outside a per-Project knowledge bundle. Each needs a separate owner or an explicit retirement decision.
- Context cost alone does not justify removing the package. The active configuration injects no stored memory and can disable even its fixed policy prompt.

Use a staged cutover. Keep the old state for rollback, introduce the librarian under distinct tools/storage, migrate and verify Project data, decide the unrelated capabilities, then remove both managed-package declarations. An atomic replacement is unnecessary.

## Evidence baseline

The inspected npm artifact is `pi-hermes-memory@0.9.1`, published from upstream commit [`71bc3eb8`](https://github.com/chandra447/pi-hermes-memory/tree/71bc3eb8b02517b9eb93e85fea04fc302e8b2949). Its registry tarball is [`pi-hermes-memory-0.9.1.tgz`](https://registry.npmjs.org/pi-hermes-memory/-/pi-hermes-memory-0.9.1.tgz), with npm integrity:

```text
sha512-ZFRKt1KyjfYhXExNCogH8S8BUWgc2NgjhQkoIeJR1u9X/NEjSNCXiHpu9hfmDFYZf4TxKnulJWcf1JN0pzomtQ==
```

Current-environment observations below were taken on 2026-08-04 without reading stored memory or session content. The deployment source snapshot was `puglab/ai-agents-sandbox` commit [`6443a7b6`](https://git.puglab.im/puglab/ai-agents-sandbox/src/commit/6443a7b609073280ca2c825aac1bfbe5ef3a8f87).

## Enablement and actual use

- The live Pi settings load `npm:pi-hermes-memory@0.9.1`. The deployment declares it in both the [managed package manifest](https://git.puglab.im/puglab/ai-agents-sandbox/src/commit/6443a7b609073280ca2c825aac1bfbe5ef3a8f87/agents/pi/packages.txt#L15) and [local-only manifest](https://git.puglab.im/puglab/ai-agents-sandbox/src/commit/6443a7b609073280ca2c825aac1bfbe5ef3a8f87/agents/pi/local-packages.txt#L10).
- The resolved active config path, `$PI_CODING_AGENT_DIR/hermes-memory-config.json`, does not exist. The path derives from [`AGENT_ROOT`](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/paths.ts#L6-L9), and absence selects [`DEFAULT_CONFIG`](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/config.ts#L41-L76).
- A content-free query of the live SQLite state found **148 sessions, 647 messages, and 47 memories**: 20 failure, 11 global-memory, and 16 user entries; 11 memory rows carry a Project. The Hermes-managed Project skill roots contain one `SKILL.md`. This proves that memory storage, Project memory, session indexing, and procedural-skill storage contain real data, but not how often each tool is called.
- The extension registers memory and skill tools, background review/flush/consolidation/correction handlers, management commands, live session indexing, `session_search`, and `memory_search` ([registration sequence](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/index.ts#L203-L252)).

## Context cost

The active defaults are `memoryMode: "policy-only"` and `memoryPolicyStyle: "full"` ([config](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/config.ts#L41-L65)). In this mode, `buildPromptContext()` returns only the policy literal and never loads stored memory into the system prompt ([prompt path](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/prompt-context.ts#L25-L42)).

Measured from the exact 0.9.1 source:

- policy literal: **3,683 JavaScript characters / 3,683 UTF-8 bytes**;
- incremental system-prompt text after the hook's two separating newlines: **3,685 characters**;
- automatically injected memory, user, Project, failure, or session content: **0 characters**.

No token estimate is stated because it depends on the selected model tokenizer. The literal is visible in [`constants.ts`](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/constants.ts#L34-L84), and the hook appends it in [`index.ts`](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/index.ts#L194-L201).

`memoryPolicyStyle` supports `full`, `compact`, `custom`, and `none`; `none` reduces this extension's prompt contribution to zero while retaining its tools and stores ([config parsing](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/config.ts#L87-L94), [policy resolution](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/prompt-context.ts#L7-L22)). Therefore the claimed context problem is configurable without retirement.

`legacy-inject` is materially different: it can add fenced global memory, user profile, recent failures, and Project memory. Its configured limits are JavaScript string lengths, not tokens, and formatting/failure blocks add overhead ([rendering](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/store/memory-store.ts#L375-L405)). It is installed but not active.

## Capability and ownership after removal

| Capability | Current behavior and evidence | Required disposition |
| --- | --- | --- |
| Project memory and retrieval | Project Markdown is mirrored into SQLite; `memory` and `memory_search` expose Project scope. Eleven live rows are Project-scoped. | **Librarian replaces.** Migrate Project-authored facts into OKF and preserve bounded deterministic retrieval. |
| Global memory, user profile, failure lessons | Separate durable targets share the memory tool and searchable SQLite store. They are populated in the live state. | **Separate decision.** A per-Project librarian must not silently absorb cross-Project/user/runtime state. Re-home or explicitly retire each target. |
| Automatic learning and durability | Review nudges, correction detection, compact/shutdown flush, and auto-consolidation are enabled by default ([defaults](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/config.ts#L47-L64)). | **Split by scope.** The librarian spec must define its Project enqueue/drain/maintenance triggers; unrelated targets need another owner or retirement. |
| Procedural skills | `skill_manage`, global/Project skill stores, discovery, and migration are part of the extension; one Project skill exists. | **Preserve separately or retire explicitly.** Skills are executable procedure metadata, not OKF knowledge. |
| Session-history search | Session JSONL is backfilled/live-indexed into FTS5 and exposed through `session_search`; `legacy` is active and `anchors` is an available inactive variant ([variants](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/config.ts#L20-L34), [registration](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/index.ts#L242-L252)). | **Separate owner or approved loss.** Session history is not authored Project knowledge. Its SQLite index is derived and rebuildable from retained Pi JSONL. |
| Memory search | `memory_search` returns bounded FTS5 matches across target, Project, and category filters ([tool](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/tools/memory-search-tool.ts#L15-L77)). | **Split by scope.** The librarian replaces Project lookup; other targets need another search surface or retirement. |
| Content scanning | Injection, exfiltration, secret, and invisible-character patterns are implemented in [`content-scanner.ts`](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/store/content-scanner.ts#L7-L85). Scanning covers extension-mediated memory creates/updates and skill creates/updates, but not direct Markdown edits or Markdown-to-SQLite sync. | **Re-home at each new write boundary.** This is a security requirement for replacement writes, not evidence that all current ingestion is protected. |
| Context fencing | `<memory-context>` fencing wraps only blocks rendered by `legacy-inject` ([fence](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/store/memory-store.ts#L523-L539)). It is inactive under `policy-only` and does not wrap `memory_search` output. | **Design requirement, not parity claim.** Librarian pull results must remain clearly untrusted reference data. |
| Management/diagnostics | Manual consolidate, insights, skills, interview, Project switch, learn, Markdown sync, preview-context, and index commands are registered ([commands](https://github.com/chandra447/pi-hermes-memory/blob/71bc3eb8b02517b9eb93e85fea04fc302e8b2949/src/index.ts#L228-L252)). | Decide command-by-command; do not recreate unused convenience surfaces by default. |
| SQLite lifecycle | WAL, locking, migration, recovery, and derived indexes support the extension's stores. | Keep old state for rollback. Uninstalling removes access/hooks but does **not** itself delete `$PI_CODING_AGENT_DIR/pi-hermes-memory`; deletion is a separate operation. |

## Cutover constraints

Coexistence is feasible only as a designed transition, not a current read-only mode. Configuration can disable automated review, correction detection, and compact/shutdown flush, but the old write tools remain registered. The transition therefore needs distinct librarian tool names plus either policy that prevents old writes or a small explicit read-only control. Tool-name compatibility must be verified before dual registration.

Before removing the package:

1. Migrate and verify Project-scoped authored memory into the OKF bundle; compare content-free counts and representative retrieval results.
2. Decide the fate of global memory, user profile, failure lessons, procedural skills, and session search.
3. Put scanning on every librarian write path and treat retrieved content as untrusted data.
4. Back up the Hermes state directory and retain Pi session JSONL according to policy. SQLite session indexes can be rebuilt; verify which memory rows are reconstructible from Markdown before deleting any state.
5. Remove `pi-hermes-memory` from both `agents/pi/packages.txt` and `agents/pi/local-packages.txt`. The bootstrap reads the selected [manifest](https://git.puglab.im/puglab/ai-agents-sandbox/src/commit/6443a7b609073280ca2c825aac1bfbe5ef3a8f87/agents/pi/pi-bootstrap-packages#L21-L24) and reconciles settings/install state through its generic [install/remove path](https://git.puglab.im/puglab/ai-agents-sandbox/src/commit/6443a7b609073280ca2c825aac1bfbe5ef3a8f87/agents/pi/pi-bootstrap-packages#L331-L377); there is no package-specific bootstrap entry.
6. Validate a fresh managed profile and local-only profile, then keep the old state until rollback expires.

## Result for the map

Retiring `pi-hermes-memory` remains viable, but it is not a prerequisite for reducing prompt context: `memoryPolicyStyle: "none"` already removes the extension's fixed prompt text. The librarian specification should own only Project knowledge. Removal is blocked on explicit disposition decisions for populated cross-Project/user/failure memory, one stored Project skill, session search, and the replacement write-security boundary.
