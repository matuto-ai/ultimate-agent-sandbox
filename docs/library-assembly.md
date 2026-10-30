# Bounded Project synthesis assembly

`uas.library_assembly.Assembler.assemble` is the T16 service seam. The service
supplies a freshly authenticated Project scope/settings reader, current canonical
input SHA, fixed ordered queue IDs, required accepted-concept opaque references
from `library_compiler.catalog`, and explicit necessary accepted index names.
It neither schedules work nor authorizes or invokes a model. T17 owns qualified
profile dispatch and T20 owns eligibility; these tests prove no provider behavior.

The exact immutable returned UTF-8 JSON bytes separate fixed trusted instructions
from typed untrusted drafts, accepted concepts, indexes and exact source quotations.
No tools, browser, repository handle or network capability is supplied. Content
that discusses instructions remains attributed data, not an instruction field.
This is not a proof against semantic prompt injection or a claim of truth.

Only selected pending files and explicitly selected accepted references/indexes
are included. `log.md`, the pending index, unselected drafts, unrelated files,
sibling Projects, history, audit and credentials are not request material. The
service reads one bounded canonical Project snapshot for complete validation;
reading that snapshot is not transmitting all its bytes to a model.

Explicit excerpts must already be in selected draft source entries as `resource`,
`range` and `sha256`. Capture now admits an optional paired range/hash and the
writer preserves them. Existing plain citations remain valid citations, never
implicit fetch requests. Trusted source selection returns a T14 Resolver bound
to a current grant and exact immutable Git object or captured snapshot. There is
no HTTP or source-repository fetch in this seam. Unsupported/unresolved sources,
mutable identities, unsupported types/encoding, range/hash failures, source-size
and blocking secret failures cannot become model input.

The shared settings require new explicit finite limits: `request_files` (initial
64, fixed maximum 512), `request_bytes` (131072, maximum 2097152) and
`request_tokens` (32768, maximum 524288). Existing configured settings must include
these before admission; no hidden fallback changes an existing configuration.
Existing per-document, batch, body and source bounds remain in force. Material
bytes are bounded while assembling, then exact serialized bytes and locally
counted tokens are bounded without truncation. The trusted tokenizer must match
the selected qualified profile, operate locally on exact bytes and not invoke a
model. Qualification must establish its accuracy. Missing/failing/invalid token
counts refuse. The exact serialized payload and its decoded fields are scanned
with the current shared secret policy; authority/configuration are checked again
before release. Returned request metadata contains only IDs, hashes and counts.

## Parking and recovery

Every selected source is processed before any source-failure mutation. Only a
fixed recognized deterministic failure can be attributed to its containing draft;
unknown resolver/infrastructure failure or lost whole-Project authority aborts
without partial content mutation. All attributable failed drafts are parked in
one compiler-validated canonical commit, retaining draft bytes and exact safe
reason in the pending index/log. Unrelated drafts remain unchanged and can be
selected in a subsequent bounded attempt. No partial model request is returned.
Already parked drafts refuse until the separate authorized requeue path acts;
see [Releasing parked work](library-requeue.md).

The assembly attempt ID derives from immutable Project identity, drain ID and
attempt. Its input SHA, selections, settings, scope and original timestamp are
bound by metadata-only operation records. Retry must retain those values.
Publication reconciliation precedes a new mutation, so a lost response/crash
can recover the same parking commit without duplication. Recovered results cite
the commit (callers reread canonical parking state rather than invent reasons).
A ready request settles its metadata intent with its exact request digest, never
raw content. Preparing bytes is not dispatch or model success. An already prepared
attempt cannot later mutate into a parking commit. Failed/uncertain assembly
intents remain available for the lifecycle owner to reconcile rather than erasing
identity state. No raw prompt, source quotation or exception text is logged.

## Verification

Run `PYTHONPATH=.:tests python3 -m unittest test_library_assembly` with repository
requirements installed. Tests use the real enqueue, canonical Git, records,
source resolver, compiler and gate with disposable local targets. They cover
selection/isolation, exact payload/tokenizer, source refusal and durable parking,
no partial commit, current authority/policy, hard limits and lost-response restart.
No deployment, actual target qualification, provider or VM execution is implied.
