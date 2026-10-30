# Authorized pinned source excerpts (#156)

`uas.library_sources.Resolver.resolve(scope, settings, declaration)` resolves one
`{resource, range, sha256}` source declaration, using T01's admitted settings and
T05's shared reference and credential policy. The result contains only the exact
requested UTF-8 bytes and immutable evidence. It does not fetch, publish, persist
content, browse, invoke a model, run a queue, or provision credentials. Later
import/synthesis owners consume this seam; their integration is separate.

The trusted owner constructs the resolver with one Project-bound source,
`current_scope` and `source_allowed` callbacks. The former must reconstruct a
fresh authenticated `LibraryScope`; the latter must check the current grant for
that exact source. A caller payload cannot supply these callbacks or create its
own Project authority. Checks run before source reads, between Git subprocesses,
and before returning bytes; revocation or uncertainty returns no excerpt.

Two source owners are supported:

- `GitSource`: a preselected service-owned bare clone populated by the existing
  authenticated source-reading owner. It must not be Participant-writable.
  Requests name `https://github.com/<owner>/<repo>/blob/<commit>/<path>` for that
  bound repository. Only exact local commit/tree/blob reads occur. There is no
  credential lookup, fetch, checkout, filter, hook, shell or model operation.
  Partial-clone missing objects fail unavailable rather than triggering fetch.
- `CapturedSource`: an already captured ephemeral UTF-8 snapshot, with its full
  SHA-256 as a literal `/objects/<sha256>/<name>` path segment in its HTTPS source
  reference. The supplied bytes must match that full digest. This is not an HTTP
  client. A mutable URL alone, or a hash merely appended in a query, is unsupported.

Ranges use 1-based inclusive LF-delimited lines, at most the shared T05 ceiling
of 200 lines. CRLF and an absent final newline are retained exactly. The declared
SHA-256 hashes those exact excerpt bytes. The configured `document_bytes` bounds
the whole source before selection, while `body_bytes` bounds the returned excerpt.
Oversized files/ranges are refused, never truncated or silently redacted.

Symlinks, submodules, directories, archives, NUL/binary/control data and invalid
UTF-8 are refused. Repository paths must already be normalized, without traversal,
URL escapes or query/fragment suffixes. Each Git read has a five-second deadline
and a bounded pipe; failure kills and reaps that process without cleanup or writes
to the clone. The clone directory identity is checked and held during each read.
The service-owned object store remains a trusted input, not a new trust boundary
against a hostile root administrator.

`Excerpt.content` is ephemeral private content, excluded from repr and metadata.
`metadata()` emits only Project identity, source-reference digest, immutable object
identity, exact range/hash and byte count. Refusals expose stable codes plus safe
reference/range/hash evidence, never Git stderr, source paths, matched credentials
or raw bodies. The caller may attribute a safe failure to its selected draft; this
resolver does not park drafts or store replay records itself.

Tests use real disposable local Git repositories and bounded local pipe processes,
plus current-authority and snapshot fixtures. They cover actual resolution,
complete T05 gate compatibility, isolation, revocation, missing objects, hashes,
file kinds, exact bytes, limits, subprocess cleanup and private failure handling.
They do not claim actual credentialed source-provider or model execution.

Snapshot syntax is explicit: `https://<canonical-lowercase-authority>/objects/<64 lowercase hex SHA-256>/<normalized-relative-name>`; nested names are allowed. Prefixes before `objects`, Git `blob` paths, encoded paths, traversal, query strings, fragments, and incidental digest segments are not snapshot identities. T05 must independently return `kind: snapshot, pinned: true` for this exact syntax; the resolver has no fallback when that policy support is absent. The digest binds the full captured bytes, not merely the selected excerpt.

Positional repository artifact syntax takes precedence over overlapping snapshot names: for example `objects/<digest>/blob/main/doc.md` is still an unpinned repository reference, not a snapshot. CapturedSource refuses artifact-kind references even when their commit is pinned.
