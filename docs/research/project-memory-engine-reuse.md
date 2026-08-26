# Evaluate established memory engines for Project knowledge

## Decision summary

Use the native per-Project OKF bundle and deterministic file lookup for the first Librarian specification. Do not adopt Hindsight, Mnemosyne, or OpenViking, and do not build a generic backend interface or a bespoke general-purpose memory engine.

The frozen two-Project comparison in [Evaluate memory-engine reuse before specifying Librarian internals](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/44) found:

- native OKF lookup passed every frozen correctness, isolation, provenance, deletion, export, and rebuild assertion at about `0.07 ms` p50;
- Mnemosyne 3.15.1 preserved deleted source content in recall and export and did not provide the required event-time correction behavior;
- OpenViking 0.4.13 exposed resource ingestion and session-derived memory, but no compliant explicit memory-retain path; session capture is prohibited here; and
- Hindsight 0.9.0 initialized locally, but its pinned CPU-only local model could not complete one explicit retain within a 900-second request bound and produced no stored operation.

No candidate materially outperformed native Project lookup while satisfying the hard gates. Reconsider an engine only after observed Project use demonstrates a specific missing capability and a candidate passes the same contract on the intended deployment profile.

## Status and evidence limits

Resolved 2026-08-08 from primary-source review plus the frozen local comparison. The candidate descriptions below remain documentation summaries; only the outcomes listed above and in the resolution ticket were directly observed. Vendor benchmarks and unexercised candidate claims are not comparative evidence.

The Mnemosyne evaluated was the project at <https://mnemosyne.site/en/> and its linked [mnemosyne-oss/mnemosyne](https://github.com/mnemosyne-oss/mnemosyne) source, not another project with the same name.

## Why the Librarian boundary must be reopened

The [current Librarian map](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/28) establishes:

- OKF Markdown in protected Git as the canonical store;
- explicit capture followed by model-assisted write-time synthesis;
- cross-reference and contradiction handling during asynchronous drains;
- deterministic native-file reads;
- no embedding or vector search.

The Project-specific requirements are legitimate, but they do not imply a bespoke memory engine. The following concerns belong to this Project and should remain locally owned:

- derive Project identity from authenticated Room and Hub authority;
- accept only explicit captures;
- enforce model-egress and secret policy;
- treat recalled content as reference data, never instruction authority;
- retain source identity, trust state, freshness, and human verification;
- expose audit and adjudication workflows.

The following are general memory-engine mechanics that could be delegated only when a candidate satisfies the contract and an observed Project need justifies them:

- parsing and chunking;
- fact extraction and embeddings;
- consolidation and deduplication;
- contradiction and temporal evolution;
- semantic and lexical ranking;
- deletion propagation and index rebuilding;
- retrieval traces and operational metrics.

The desired seam is therefore:

```text
Room / Participant
        |
        | explicit capture or recall
        v
Project Librarian governance module
  - authenticated Project binding
  - capture and egress policy
  - provenance/trust validation
  - reference-data fencing
        |
        v
per-Project OKF bundle
  - source-pinned Markdown
  - deterministic lookup
  - explicit drafts and corrections
```

Do not create a generic backend framework. If later evidence selects an engine, add one narrow adapter for that engine only.

## Candidate comparison

| Concern | OpenViking | Hindsight | Mnemosyne |
| --- | --- | --- | --- |
| Core interface | Resources and sessions; `find()`/`search()`; session commit extracts memory | Explicit `retain`, `recall`, and `reflect` | Explicit `remember`, `recall`, and `sleep` consolidation |
| Storage model | `viking://` virtual filesystem with L0/L1/L2 content and a derived vector index | PostgreSQL/pg0 memory banks containing documents, facts, entities, relationships, and observations | Local SQLite with working memory, episodic memory, scratchpad, and temporal triples |
| Consolidation | Session commit extracts and merges memories with model assistance | Observations consolidate facts and evolve from supporting or contradictory evidence | Sleep cycles move/summarize working memories into episodic memory |
| Provenance | Session archives, memory diffs, source URIs, and retrieval trajectories | Observations cite supporting facts and exact quotes; history and proof count are documented | Source fields, temporal triples, local database, and JSON export are documented; citation-grade derivation is less clear |
| Isolation | Account/user hierarchy; must be tested against Project authority | Memory banks are documented as isolated containers | Banks exist, but server-grade authorization and tenant isolation are not established by the reviewed sources |
| Portability | Resource deletion is documented; complete portable rebuild semantics are less explicit | Bank/document transfer omits embeddings and can rebuild them against a target model without repeating fact extraction | Local SQLite ownership and JSON export/import; complete derived-state rebuild and erasure semantics need testing |
| Local operation | Local deployment plus local model providers; separate VLM/LLM and embedding roles | Standalone, embedded, Docker, or external PostgreSQL; local/self-hosted model providers are supported | In-process SQLite; optional local embedding and LLM extras |
| Hermes requirement | None | None; Hermes provider is optional | None; `mnemosyne-hermes` is separately installed for Hermes users |
| License | AGPL-3.0 for the main project | MIT | MIT |
| Main concern | Broad scope, multiple model roles, duplicate content store, AGPL obligations | PostgreSQL and model/reranker operational weight; directives must not become instruction authority | Weaker documented provenance and multi-tenant enforcement; maintainer benchmark claims need reproduction |

### Hindsight

Hindsight currently appears closest to the proposed Librarian intelligence:

- `retain`, `recall`, and `reflect` are explicit operations;
- memory banks are documented as completely isolated;
- observations retain exact supporting quotes and evolve as evidence reinforces, extends, or contradicts them;
- automatic consolidation can be disabled and invoked explicitly;
- deleting source memories invalidates derived observations;
- whole-bank export/import can carry source documents, facts, and optionally observations while regenerating embeddings and indexes;
- standalone packages, embedded operation, Docker, and external PostgreSQL deployments are documented.

Hindsight does **not** require Hermes Agent. Its first-party installation documentation supports `hindsight-api`, `hindsight-all`, Docker, and Helm deployments. Hermes is an optional provider/integration.

Risks requiring direct testing:

- production deployment requires PostgreSQL 14+ and a supported vector extension;
- retain/consolidate behavior depends on the selected LLM, embedder, and reranker;
- a memory bank also supports directives described as hard rules. The Librarian must not expose or execute engine directives because Project knowledge is reference data only;
- documented bank isolation must be verified through the actual authorization topology, not accepted as a database naming convention;
- export/import and deletion must be checked for logs, backups, observations, operations, and other residual copies.

### Mnemosyne

Mnemosyne is the smallest operational candidate:

- direct Python `remember` and `recall` operations;
- SQLite ownership and offline operation;
- FTS5 plus optional sqlite-vec hybrid retrieval;
- BEAM working/episodic/scratchpad tiers;
- `sleep()` consolidation;
- validity-bearing temporal triples;
- JSON export/import and optional sync;
- MIT license.

Mnemosyne does **not** require Hermes Agent. The core package metadata lists PyYAML as its required dependency and offers separate extras for embeddings, local LLMs, MCP, and sync. The `mnemosyne-hermes` package is an optional integration profile.

Risks requiring direct testing:

- the reviewed material does not establish citation-grade evidence and transformation history comparable to Hindsight observations;
- one local file is a good single-user ownership model but not proof of Project authorization or cross-tenant isolation;
- automatic injection and integration hooks must be disabled; only explicit operations are acceptable;
- export/import, correction, contradiction, source deletion, embedding migration, and concurrent access need verification;
- published latency and benchmark numbers are maintainer claims under different models and corpora.

Mnemosyne is valuable even if it is not selected: it is a simple local baseline showing how little infrastructure a memory engine may require.

### OpenViking

OpenViking provides the broadest context-engine implementation:

- resources, memories, skills, and session archives under a `viking://` filesystem abstraction;
- L0 abstracts, L1 overviews, and L2 detail;
- hierarchical semantic retrieval and retrieval trajectories;
- session commit with asynchronous memory extraction;
- local embedded storage and standalone deployment;
- local/OpenAI-compatible model configuration.

Risks requiring direct testing:

- dense embeddings and the VLM/LLM are separate model roles; query planning and reranking may add more providers;
- its filesystem is its own content source, so use beside another canonical store creates duplicate persisted content;
- automatic session capture and its Pi extension conflict with explicit capture and reference-only presentation;
- account/user isolation must be mapped to authenticated Projects and tested for leakage;
- the main project is AGPL-3.0, requiring approval for the exact process, modification, distribution, and network-deployment shape;
- its broader ingestion and session features may be unnecessary for Project knowledge.

## Hard acceptance rules

A candidate is disqualified if it:

- requires Hermes Agent at runtime;
- cannot operate through explicitly approved local model and embedding providers;
- silently falls back to a hosted provider or downloads models at runtime;
- cannot derive isolation from authenticated Project authority;
- returns material from another Project;
- requires automatic transcript capture or hidden prompt injection;
- treats stored directives, skills, or recalled text as instructions;
- cannot preserve source identity and derivation evidence;
- cannot propagate correction and deletion through derived memories;
- cannot export or rebuild enough state for recovery and model migration;
- cannot fit predeclared resource, licensing, and operational budgets.

An optional Hermes adapter does not disqualify an otherwise independent engine.

## Common comparative evaluation

Use the same frozen two-Project corpus and expected-answer set for every candidate and for native file lookup. Do not first build a production-normalized interface; use small candidate-specific harness code and normalize only the recorded results.

### Corpus

Each Project should contain:

- exact identifiers and error codes;
- semantically equivalent paraphrases;
- accepted facts and decisions with rationale;
- facts that change over time;
- explicit corrections and contradictory sources;
- stale and superseded facts;
- duplicate and near-duplicate captures;
- deleted and moved sources;
- adversarial text that attempts to become instruction authority;
- deliberately similar names and facts across Projects.

### Operations

Exercise the native equivalent of:

1. retain an explicit capture with Project, source ID, event time, observation time, and provenance;
2. recall exact, semantic, temporal, and contradictory knowledge;
3. consolidate only when explicitly requested;
4. correct or supersede a fact;
5. forget one source and inspect every derived artifact;
6. export one Project;
7. rebuild/import it with a different embedding model;
8. inspect retrieval and consolidation traces;
9. restart or interrupt the engine during work and recover.

### Evidence

Record:

- Recall@k and mean reciprocal rank;
- exact-identifier accuracy;
- temporal `as_of` accuracy;
- answer-supportedness against source evidence;
- contradiction handling;
- cross-Project leakage;
- provenance completeness;
- deletion residue;
- export/import equivalence;
- cold start and p50/p95 retain, recall, and consolidation latency;
- CPU, RAM, VRAM, disk amplification, rebuild time, and concurrency;
- every network destination and model invocation;
- crash, cancellation, and retry behavior.

### Decision gate

Select the smallest engine that satisfies isolation, provenance, temporal correction, deletion, local deployment, and recovery while materially outperforming native Project lookup. If no candidate does, retain native files and add only the narrow capability demonstrated to be missing.

A successful engine evaluation does not authorize user/global memory, procedural skills, automatic session capture, or automatic prompt injection.

## Consequences for the existing Librarian map

The first specification keeps the map's native shape:

- OKF Markdown in protected Git remains canonical;
- capture remains explicit and synthesis remains a bounded asynchronous write concern;
- reads remain deterministic native-file lookup with no model or derived vector index;
- Project identity, model egress, provenance, trust, freshness, verification, and pending status remain visible and fail closed; and
- recalled knowledge remains reference data, never instruction authority.

This result does not justify a bespoke fact store, vector index, consolidation framework, or general contradiction engine. Add only a narrow capability after observed Project queries demonstrate that native files cannot supply it, then rerun the common contract before changing the storage or retrieval premise.

## Primary sources

### Project decisions

- [Librarian map](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/28)
- [Agent-facing interface decision](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/29#issuecomment-5460)
- [Canonical bundle decision](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/31#issuecomment-4874)
- [Explicit capture decision](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/33#issuecomment-5383)
- [Model-egress decision](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/35#issuecomment-5485)
- [Trust-boundary decision](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/37#issuecomment-5520)

### OpenViking

- [Repository and license](https://github.com/volcengine/OpenViking)
- [Architecture](https://docs.openviking.ai/en/concepts/01-architecture)
- [Retrieval](https://docs.openviking.ai/en/concepts/07-retrieval)
- [Session management](https://docs.openviking.ai/en/concepts/08-session)
- [Deployment](https://docs.openviking.ai/en/guides/03-deployment)

### Hindsight

- [Repository](https://github.com/vectorize-io/hindsight)
- [Installation and deployment](https://hindsight.vectorize.io/developer/installation)
- [Retrieval](https://hindsight.vectorize.io/developer/retrieval)
- [Observations and consolidation](https://hindsight.vectorize.io/developer/observations)
- [Memory banks and export/import](https://hindsight.vectorize.io/developer/api/memory-banks)
- [Optional Hermes integration](https://hindsight.vectorize.io/sdks/integrations/hermes)

### Mnemosyne

- [Official site](https://mnemosyne.site/en/)
- [Official source](https://github.com/mnemosyne-oss/mnemosyne)
- [Documentation](https://docs.mnemosyne.site/)
- [Package metadata](https://github.com/mnemosyne-oss/mnemosyne/blob/main/pyproject.toml)
