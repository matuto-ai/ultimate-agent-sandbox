# Human-confirmed source import (T15)

`uas.library_import.Importer` is the public service owner for explicit source
preview and confirmation. It composes the existing human-action contract,
source Resolver, canonical Git publisher, complete-tree gate and metadata-only
records. It does not supply a Manager UI, authenticate a new identity, fetch a
source repository, invoke a model or import anything automatically.

The trusted owner supplies a publisher, a Resolver bound to a service-owned bare
Git source clone and `current_scope(kind)`, which rechecks the authenticated
human's exact `library-import-preview` or `library-import-confirm` authority.
Resolver callbacks independently recheck Project/source grants around reads and
publication. Neither a remembered preview nor cached content grants authority.

## Preview and confirm

1. Admit a human `import-preview` action with `source_commit` (full immutable
   commit) and an explicit nonempty `paths` list. Optional `types` is an aligned
   list of `context`, `decision` or `research`; omitted means `context` for each.
2. Call `preview(operation, settings)`. The result shows the exact repository,
   commit, selected paths/types, available title/author/modification time,
   immutable source identities, byte sizes and whole-file range/hash. Source
   titles use the first H1, otherwise the filename. Git history supplies author
   and modification time; missing/invalid metadata refuses instead of guessing.
   No content commit occurs. The metadata ACK proves preparation, not display
   or human confirmation. Full source bodies are not returned in the preview.
3. Have an authorized human confirm the exact displayed manifest. Admit a
   distinct `import-confirm` action containing the same commit/paths/types,
   `preview_id` and `observed_version` from the preview. This authenticated action,
   not the preview receipt, is the confirmation boundary.
4. `confirm(operation, settings)` rereads pinned sources, current authority and
   current deterministic policy. It refuses changed identities or missing
   preview preparation. It writes all drafts, pending-index entries and one log
   entry in one validated Git publication. No partial batch is published.

Source bytes remain untrusted reference data. They are copied into generated
pending concepts with `status: draft`, intended type, exact source pins and
range/hash. Source author/date are deterministic escaped body metadata, avoiding
new unsupported OKF source keys. Import never supplies `verified`, accepts a
concept or refreshes evidence. Invalid source Markdown/content or secret policy
rejects the complete result, rather than silently rewriting it.

## Identity, bounds and failure

The full manifest identity binds the Project identity, repository, pinned commit,
exact files/types/metadata and content digests. Reordering equivalent selected
pairs does not create a new manifest. Changing a file, commit or intended type
creates a distinct manifest. Source branch advancement does not change an old
commit. Duplicate path selections are refused.

Public Command/request identities retain their exact admitted payload. Separate
metadata-only manifest records deduplicate publication across fresh authorized
commands/previews. The Git owner reconciles `import-publication` by its
content-addressed request identity before any repeated write, including after a
lost push response or receipt. This is historical durability, not proof of
current projection visibility or continued presence of the imported drafts.

Every admitted attempt records metadata-only intent and safe terminal evidence.
No source paths, titles, bodies, prompts or matched values enter the journal.
Unknown publication/storage outcomes remain retryable/unresolved rather than
claiming absence. An immutable refused/uncertain Command receipt is retried with
a fresh Command ID; successful publication is reconciled without duplicate.
Authority and source access are still required when recovering an old result.

Existing finite `batch_drafts`, `batch_bytes`, `body_bytes`, `document_bytes`,
`payload_bytes`, `title_chars`, full-bundle bounds and the T14 200-line excerpt
limit apply. There is no directory scan, truncation, archive extraction or
alternate queue. Git reads use bounded output/time and source metadata is bounded.
The source clone and authenticated callback bindings are trusted infrastructure,
not caller-controlled inputs. A source unavailable at confirmation fails safely;
it is not inferred to be absent or automatically replaced with a newer revision.

## Evidence

`tests/test_library_import.py` exercises disposable real source/canonical Git:
explicit preview, pinned commit advancement, human/source revocation, exact
confirmation fences, intended types and unverified metadata, atomic multiple
drafts, distinct/repeated manifests, raw Command identity, mutable-input fencing,
policy changes, source/batch bounds, and lost publication/receipt recovery.
No live private source, provider call, credential, deployment, UI or host-mount
qualification is implied by these service-level tests.
