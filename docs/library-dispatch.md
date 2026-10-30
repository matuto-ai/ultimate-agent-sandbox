# Qualified model dispatch consumer

T17 `uas.library_dispatch.Dispatcher` consumes the exact ephemeral T16 `Request`.
It does not assemble extra material, read a repository, schedule/retry work,
compile a proposal, accept a draft, or change pending state. T19 consumes its
result and validates the full proposal through T18. Malformed envelopes fail
here; semantic quality and complete-tree validity remain separate checks.

## Authority and external evidence

Deployment code supplies fresh trusted readers for authenticated Project scope,
shared settings, exact selected profile, qualification and human authorization.
`Selection` is not a wire request: never construct its proof from model,
Participant, shared settings or untrusted file content. Every `Evidence` binds
its reference, immutable Project identity, complete profile digest and expiry.
Its `qualified` flag represents externally verified evidence, not self-attestation.
T42 must establish this evidence for the actual model/version/corpus and adapter.
No fixture or configured reference activates production processing.

The profile digest binds provider, material version, local/hosted mode, endpoint,
region, retention, data-use terms, no-training rule and shared-hardware status.
Both local and hosted use require human selection and qualification. Hosted use
additionally requires a current Project egress approval reference from settings
AND separate current evidence for the exact digest. Any route, version, terms or
retention change invalidates old proof. The external authority must only approve
zero retention or its explicitly accepted shortest retention. Credentials cannot
appear in endpoint userinfo, query or fragment; profiles never contain secrets.

Before contact and after response, scope, settings, selection, expiry and a
mandatory `current(request)` checker are revalidated. That checker owns current
input SHA and batch/source grants in service composition;
it must return literal true only for the exact request. Separately, the consumer
reads the Project-fenced T16 preparation receipt from the configured operational
store and compares its acknowledged digest with the exact request digest. A
self-hash or boolean callback alone cannot authenticate prepared material. Settings alone cannot
supply those facts. The exact payload hash, Project/settings identity, count,
selected draft IDs, token count, fixed instructions, empty tools and disabled
network are checked. The exact bytes/decoded fields are scanned under current
secret policy. The local tokenizer must be qualified for the selected profile.
No request is truncated. Revocation after contact discards the output, not the
fact that authorized earlier contact occurred.

## Fixed external adapter protocol and bounds

One shared `Gateway` instance belongs to the singleton Library Service, across
all Project dispatchers. It has a fixed mapping from exact profile digests to
operator-owned executable argument tuples, without shell interpretation. No
model or Participant chooses a command, file path, tool or fallback route.
An unlisted digest refuses. Deployment wiring must not create per-Project
independent gateways or duplicate service owners; lifecycle composition owns
that singleton and the external gateway's global capacity qualification.

The fresh adapter receives one JSON object on stdin containing `profile`,
`request` (the exact T16 serialized JSON string), `response_limit` and
`timeout_seconds`; stdout is only raw UTF-8 proposal JSON. Stderr is discarded.
A trusted adapter must enforce exactly the selected endpoint/version/terms,
disable SDK fallback and automatic retries, expose no model tools/browser/files,
and limit remote responses. Provider/credential/server lifecycle remains
external. This subprocess is a bound around trusted adapter code, not an OS
sandbox or proof against a malicious adapter; provider execution occurs outside
Rooms. Credentials are never sent as model input or audit fields.

A nonblocking process stream enforces input/output progress against a monotonic
deadline. Response bytes are bounded by the existing explicit shared
`document_bytes` setting and fixed 1 MiB ceiling, without truncation. Time uses
`attempt_seconds` (initial 120 seconds); request file/byte/token bounds are T16
settings. The adapter is launched with nice +10 in a separate process group;
remaining process-group members are killed and the direct child reaped before releasing the
single capacity slot, on failure, timeout, interruption or success. No Python
fork callbacks are executed from a threaded service.

For shared interactive hardware, an external demand callback is checked before
admission and during streaming. Demand cancels this low-priority unit; at most
one Library call is active through the shared instance. The adapter/gateway
qualification must prove remote cancellation and hardware-side exclusivity
where remote inference survives local process termination. No idleness detector,
provider fallback or automatic retry is introduced. Outage, timeout, malformed
output and capacity refusal leave pending work to T19/T20 recovery.

## Evidence and validation

The mandatory audit sink must persist the pre-contact event or refuse contact.
A successful result carries a second metadata-only event: hashes, counts,
Project/input/settings/selection IDs, profile/version/mode and response digest.
No prompt, document, excerpt, endpoint, raw output or exception text is recorded.
After admitted contact, any failure with no returned event is unresolved at this
seam, never permission to retry the model blindly; drain recovery owns that
state. A post-response audit failure does not release unaudited model output.

`tests/test_library_dispatch.py` runs actual T16/enqueue/Git preparation into a
fresh account-free Python adapter process, including deadline, response bounds,
priority, revocation, profile/terms matching, hosted refusal, malformed JSON,
no-fallback and metadata privacy. No real model, network, account, deployment,
credentials or actual-profile qualification is exercised by these fixtures.
