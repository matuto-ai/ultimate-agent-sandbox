# Private promotion handoff (T46)

Promotion is an ordinary human-reviewed contribution to the existing guidance
owner, not a Library operation. It neither moves the source document nor gives
it instruction authority. Preparation uses only existing Project processing,
model-provider and tool permissions. There is no export command, queue, global
store, cross-Project credential or automatic publisher.

## Two decisions, before and after disclosure

1. Establish the Project-authorized human, destination owner and exact audience.
   Keep the proposal private if authority or audience is uncertain. Read access,
   Library operator access, model permission and agent confidence are not release
   authority. Credential and secret restrictions cannot be bypassed by approval.
2. Prepare an exact, standalone package: guidance, rationale, conditions and
   limitations, with an explicit inventory of text, attachments, excerpts, links,
   metadata, identifying details and evidence. An empty category is explicit;
   approval of proposal text alone does not release its backing evidence.
3. The Project-authorized human explicitly approves that exact version and
   audience **before** any disclosure through any channel. Retain the genuine
   approval reference privately. Any changed material or audience needs renewed
   approval; rewording private facts does not make them public.
4. Only the approved package is handed to the destination through its ordinary
   contribution process. Public destinations get public references only. Agent
   assistance at the destination needs that destination's separate authorization.
5. The destination's authorized human separately accepts, rejects or defers after
   reviewing correctness, generality, safety and consistency with its guidance.
   One person may hold both roles, but must make both explicit decisions. Agent
   text saying “approved” is never either decision.

Keep the private source trail in existing Project records, not a new store or
frontmatter schema: original concept and Library commit, relevant source pins,
reason to generalize, limitations, exact sanitized package version, audience and
actual disclosure approval. Private Project identities, paths, links, hashes and
excerpts stay private unless expressly included in the permitted release. The
public package must not link back to that private trail.

If a reviewer asks for additional private evidence, obtain specific approval for
that added material and audience, or offer independently reproducible evidence
that does not derive from the withheld material. Otherwise defer or reject.
Denied evidence remains private, including when the guidance itself is accepted.
One Project's success does not establish universal applicability.

## Record only the observed result

Use an ordinary explicit `decision` draft through the existing
[Library capture](library-enqueue.md) path (for example the existing
[Pi tool](pi-library-capture.md)); no promotion-specific API or schema exists.
The draft body should preserve source/package versions, genuine disclosure
approval and audience, destination reference, observed review/commit evidence,
limitations and the actual result. Use plain language such as proposed,
submitted, accepted upstream, rejected, deferred and adoption unknown. Normal
write validation and genuine submitting-Actor provenance remain unchanged;
capture records a claim, it does not authenticate release approval.

`DURABLY_QUEUED` establishes capture publication, not destination acceptance or
activation. `NOT_DURABLE` or unavailable capture leaves the result unrecorded or
uncertain: report that accurately, preserve the original request and exact
payload, and reconcile through ordinary capture retry rather than assuming no
commit exists. Do not pretend the destination decision was undone. An
[archived Project](library-lifecycle.md) refuses new drafts; report the outcome
unrecorded without restoring it or bypassing its freeze to finish the handoff.

Preserve original knowledge and history. Acceptance upstream does not establish
rollout: confirm activation with that owner or leave adoption unknown. A later
correction requires another separately authorized handoff referring to the
accepted version, plus an independent correction in the Project's normal write
path. No watcher, automatic propagation, synchronization, rollback or reseeding
guarantee follows from this process.

## Synthetic rehearsal and evidence limits

The [rehearsal record](testing/library-promotion-rehearsal.md) follows the explicit
synthetic validation requested by #186. Simulated human decisions are scenario
inputs, not genuine approval references and not authority to disclose anything.
The local capture exercise uses disposable Git and synthetic fixtures only; it
cannot prove human authorization, recipient acceptance, native Runtime transport,
production target qualification or adoption. A real handoff must establish its
own authorized people, destination and activation process.
