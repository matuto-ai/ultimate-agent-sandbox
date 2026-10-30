# Deterministic synthesis compiler

`uas.library_compiler.compile_proposal` is the pure T18 service seam. It takes
an authenticated Project scope, admitted settings, complete canonical `Tree`,
selected queue identities, input commit, drain identity, attempt and service time.
It returns only a complete T05-validated proposed tree, per-draft outcomes,
operation-to-path mapping and proposal digest. It performs no I/O, inference,
verification or publication. T19 owns fresh authorization, input-change fencing,
records and the atomic drain commit. Passing this compiler does not prove truth.

## Model manifest

Call `catalog` on the same inputs to obtain opaque existing-concept references.
The proposal is exactly:

- `version: 1`, matching `drain_id` and `attempt`;
- `operations`, at most 64 objects, with unique lowercase `id` and selected
  `drafts` (queue identities) explicitly attributing each content operation;
- `outcomes`, exactly one entry per selected draft.

Operations:

- `create`: `id`, `op`, `drafts`, supported `type`, `title`, `description`, `body`.
- `update`: `id`, `op`, `drafts`, opaque `target`, `title`, `description`, `body`.
- `deprecate`: `id`, `op`, `drafts`, opaque `target`, bounded reason token `reason`.

Outcomes are `queue_id`, `kind`, and either `targets` (operation IDs) for
`integrated`/`merged`, or a bounded `reason` token for `parked`. Merged outcomes
must target existing concepts. Every operation's attribution must exactly agree
with its drafts' outcome targets. Parked drafts cannot contribute to operations.
Missing, duplicate, conflicting or unknown attribution rejects the entire result.
Zero content operations is valid only when all selected drafts are parked.

No model paths, diffs, source records, metadata, verification, freshness or
arbitrary mutation fields are accepted. This strict compiler manifest supersedes
the older path-oriented `library.admit_proposal` transport admission for synthesis;
that existing admission helper remains compatible for its current consumers,
but cannot produce a compiler result. T17/T19 callers must use this seam and
its catalog, not treat old transport admission as publication approval.

## Deterministic generation and provenance

Types choose `context`, `decisions` or `research`; create titles choose lowercase
ASCII slugs. Collisions append a full stable digest of the sorted attributed
queue identities. A remaining collision refuses rather than overwriting data.
Updates and deprecations retain the same path and supported type. No accepted
concept is deleted or renamed. Model array order does not change output bytes.

Source entries are copied only from supplied canonical selected drafts and the
existing target, with exact duplicate elimination. The model cannot invent,
replace or remove provenance. Sources are not automatically verified or fetched.
A generated concept records the service time, drain, exact input commit and
source-draft byte digests; that commit retains original Actor/Run/time evidence
in Git history after a pending file is integrated. The log records every outcome.

The service stamps stable/deprecated lifecycle, generated=true and verified=false
on meaningful changes. Exact unchanged title/body/description/sources/status
preserves original bytes and verification, while recording the merge in the log.
Existing `stale_after` is retained, never inferred or renewed. There is no new
verification grant in this seam. Catalog bodies include their existing service
notice/provenance; unchanged updates must return that exact body. Unknown existing
frontmatter blocks and unrelated reader files remain unchanged.

Concepts and generated indexes contain the fixed reference-data notice. Index
entries include title, relative link, type, lifecycle and description. Parked
pending entries retain DRAFT and PARKED reason state, and draft bytes remain
unchanged. Unselected pending files are untouched. Recognizable affected index
entries are rebuilt; ambiguous authored entries refuse compilation instead of
silently deleting prose. Other index text and log history are preserved.

## Bounds and failure behavior

The service validates selected batch count/bytes, proposal size, all fields,
identifiers/references and content limits, then runs the complete Project result
through T05. Invalid structure, source declarations, unsafe body links, HTML,
images, credentials, unsupported writer data or out-of-scope inputs yield no
result and no partial writes. A refusal is a stable `LibraryError`, not permission
to integrate the valid subset. Attributable parked outcomes plus unrelated valid
work are an explicit single atomic proposal, not best-effort mutation.

These are deterministic structural and content-policy checks, not semantic
contradiction detection or prompt-injection proof. Actual model qualification,
source assembly and the publication/retry lifecycle belong to their slices.

## Verification

`PYTHONPATH=.:tests python3 -m unittest discover -s tests -p test_library_compiler.py`
exercises the public compiler with real complete trees and T05, including
collisions, updates/deprecation, exact verification preservation, unknown reader
keys, source provenance, multi-draft integration/parking, all-or-nothing failures,
limits and untrusted output rejection. Normal aggregate discovery includes it;
no provider, VM, target repository or user credentials are used.

The escaped-title prerequisite corrects the structural reader's comparison of
backslash-escaped Markdown labels without relaxing title equality. Real enqueue
coverage includes underscores, brackets, backslashes, emphasis and code labels.
The measured enqueue module moves to the existing additional CI partition after
the remainder exceeded its one-minute budget; no tests or timeouts are removed.
