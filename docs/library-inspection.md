# Bounded confidential local inspection (T23)

The existing `Controls` / private `library-operator.sock` interface now supports
an explicit `inspect`. Kernel peer ownership still precedes the trusted host's
human resolver; an installation-level settings grant is not a Project grant.
Every observation and open needs a connected `LocalHuman` with a fresh
`library-inspect` grant for the immutable Project. No Participant route is added.

First send version 1, action `observe`, `for_action: inspect`, the Project ID and
one queue ID. The result contains only versions: canonical commit, target hash,
complete Project content hash, settings ID, and an opaque observed version bound
to the human authority, Project identity/coordinates and queue. No body is read
back to the human in this observation. Then send version 1, action `inspect`,
Project ID, queue ID, request ID, settings ID and observed version. Unexpected
fields, paths, identity/grant claims, collections of items and recursive options
are rejected. Changed content, target, configuration or human authority requires
a fresh observation. The result is the exact pending file from that committed
snapshot, including its original submission/source provenance, never an
operational-record reconstruction or working-copy edit.

Context is selected by the service, not by request paths: direct concept sources
and parsed Markdown links from that item may select existing `context/`,
`decisions/` or `research/` documents in the same Project. No other pending item,
index, log or sibling Project is context. References in selected context are not
expanded recursively. Missing, unsupported, remote or second-hop material and
size omissions set `insufficient_context` with safe finite reason codes. This
bounded direct-reference selection is not a claim that all context necessary for
human adjudication has been discovered. Broader review must use a separately
authorized local inspection. There is no source resolver, network fetch, model,
rendering, image loading, hyperlink navigation or HTML execution in this path.
The typed response declares `text/plain`, inert resources and no recursion.
Consumers must preserve those boundaries; browser/Hub transport is T31/T32.

Required operational limits (no hidden default on missing configuration):

- `inspection_bytes`: published initial 16,384, hard maximum 262,144; bounds the
  complete encoded JSON response, including metadata and escaping. The existing
  local transport has an additional fixed 16,384-byte ceiling.
- `inspection_context_bytes`: published initial 32,768, hard maximum 1,048,576;
  bounds the aggregate UTF-8 bytes of the pending document and all selected
  context. If the item alone exceeds either bound, opening is refused. Context
  that does not fit is omitted with an explicit insufficient-context result;
  documents are never silently truncated.

These are deployment-supplied finite ceilings, not a live deployment
qualification. Settings owners must include the new context limit explicitly.
The complete Project reader remains bounded by existing scan/document ceilings.

Inspection is **not receipt replay**. It adds no canonical commit, scheduler transition, Hub event or persistent
content cache. Only safe request identity metadata is retained, as described
below; repeating the same request, including after reconnect, performs a fresh
authorized read. A lost response is simply reopened,
never reconstructed from stored bodies. Errors expose safe codes only, not
confidential text or arbitrary exception content. Later fenced writes use the
returned versions and must independently revalidate them.

`test_library_inspection` exercises real Git and the started Service plus actual
private Unix socket variants: one exact item, direct context/no recursion,
arbitrary-path and cross-Project refusals, revoked/disconnected authority, stale
versions, raw/encoded bounds, inert historical references and no retained bodies.
Cloud EPERM socket skips are explicit, not native acceptance. Hosted CI must run
those cases without skipping. No live provider, production-host authentication
integration, account change or deployment is claimed.

## Request identity

A successful open atomically reserves metadata-only identity and acknowledgement
in the bounded LibraryRecords store. Reusing its request ID with different
queue/content/configuration/authority evidence is rejected. Exact retries still
require a fresh authorized read, including after restart; the acknowledgement is
never a replayable content response. Retention keeps the deduplication identity,
not item/context bodies. Capacity failure refuses disclosure.
