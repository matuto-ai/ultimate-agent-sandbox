# T46 synthetic private-promotion rehearsal

## Scope and exact scenario

Performed on 2026-10-30 against the existing capture/archive implementation.
This is a manual document walk-through plus a local service/Git exercise, not a
real release. Every person, package, approval reference and destination below is
invented. No real human approved disclosure or accepted guidance; no recipient
was contacted. “Private” here means withheld within the fictional scenario,
not hidden real user material. No real Project source was used.

The fictional source concept is “retry exact operation identity after uncertain
acknowledgement,” version `source-example-v1`, source pin `toy-counter-v1`.
The reason to generalize is avoiding duplicate increments in an idempotent
counter. Its limitation is explicit: this toy does not establish correctness of
other protocols. The private scenario trail holds that concept/version/pin,
reason, limitation, exact package below and fictional decisions D1/A1. A real
trail would instead retain the actual Library commit/source pins and genuine
human approval references; these invented identifiers cannot substitute for them.

**Exact package `synthetic-guide-v1`**, audience **fictional guidance
maintainers**, consists only of these three paragraphs:

> Guidance: when an operation's acknowledgement is uncertain, retain its exact
> identity and payload while reconciling the result, rather than assuming failure.
>
> Rationale and conditions: this avoids duplicate effects when the receiving
> owner supports exact-identity idempotency. Do not apply it to a protocol that
> does not provide that contract. This example does not prove other systems safe.
>
> Independent toy evidence: a counter starting at zero records operation K with
> payload “increment once”; applying that exact recorded operation again leaves
> the counter at one. Reusing K with a different payload is a conflict.

Inventory: the paragraphs above are all text and evidence. Attachments, links,
source excerpts, identifying details and additional metadata are **none**.
The fictional private source trail is not included. A public variant could not
carry private references; this package has no references at all.

## Manual walk-through: observed decisions and limits

The operator walked the package through the documented checks. These are
**simulated scenario inputs and manual conclusions**, not programmatically
verified human permissions or actual destination events.

| Step | Scenario input | Observed rehearsal conclusion |
| --- | --- | --- |
| Negative authority | Read, operator and model-provider permission only; agent says “approved” | No disclosure authority; package remains private in scenario. |
| Exact approval | Fictional Project human D1 approves only the exact v1 paragraphs/inventory for fictional guidance maintainers | The scenario may proceed for that package/audience only; D1 is not real approval. |
| Changed package | Append source context or a new attachment | D1 does not cover it; remain private pending renewed approval. |
| Changed audience | Broaden to the public | D1 does not cover it; remain private pending renewed approval. |
| Secret restriction | Suppose an approval includes prohibited secret material | Approval cannot bypass restrictions; do not disclose it. No secret was inserted into the fixture. |
| Additional evidence | Fictional destination asks for source notes; disclosure is denied | Notes stay private in scenario. The independent counter example already included in v1 is the substitute, not a rephrasing of withheld notes. If insufficient, defer or reject. |
| Separate acceptance | Fictional destination human A1 reviews correctness, generality, safety and consistency, then accepts v1 only | “Accepted upstream” is true only inside the scenario; adoption remains unknown. A1 and D1 remain distinct even if one fictional person holds both roles. |
| Correction | Later limits of v1 need correction | A new exact-package/audience approval and destination review are required; Project correction is independent. No sync/rollback is inferred. |

The toy evidence was manually checked: first K changes zero to one; exact K
replay returns that result without another increment; changed K payload is not
the approved operation. This is a conceptual independent substitute, not a
runtime qualification of a counter service or of recipient acceptance.

## Local outcome capture and archive exercise

Run from the repository with its requirements installed:

```sh
PYTHONPATH=.:tests python3 -m unittest -v test_library_promotion
```

Observed local result: **1 test passed** (approximately 1.4 seconds). The test
uses the existing service fixture, real disposable Git repositories and SQLite,
ordinary `decision` enqueue, and the existing explicit archive owner. The
archive's bounded provider is an inert synthetic subprocess, not a real model.
No external Git recipient, credentials, deployment, VM or account is involved.

The captured body labels every scenario decision synthetic, records its local
source version and package/audience, says actual human approval and destination
evidence are absent, and leaves adoption unknown. It uses existing body text,
not a new status marker or authorization schema. Actual capture provenance is
stamped by the fixture's existing authenticated Actor path; that provenance does
not authenticate D1 or A1.

| Executed step | Observed evidence |
| --- | --- |
| Inject before-publication failure | `NOT_DURABLE`; canonical head unchanged in this particular before-write injection. Outcome initially unrecorded; simulated A1 is not undone. In general this result may mean uncertain publication, so do not assume absence. |
| Retry exact librarian request/payload with new operation ID | `DURABLY_QUEUED`; the complete synthetic outcome body appears in an ordinary draft with original submitting Actor. |
| Explicit archive | `COMMITTED`; canonical Project state is archived and captured draft bytes are retained. |
| Attempt later outcome capture | `REJECTED` / `PROJECT_ARCHIVING` from the retained lifecycle fence, while canonical state is independently verified archived. No new commit or outcome draft; report later outcome unrecorded. No restore or freeze bypass. |
| Inspect retained history | Original source-version root remains readable and unchanged; archived root and earlier draft remain present. |

The exact failure token reflects the existing lifecycle fence, not an assertion
that archive failed. The exercise checks both the canonical archived state and
unchanged head after rejection. The original synthetic source/draft/history are
not moved, erased or reseeded. Temporary fixture cleanup is test cleanup only.

## Acceptance boundary

This validates the documented synthetic handoff and real local capture/freeze
paths requested by #186, not a real promotion. No approval authority is created
by this record or its passing test. Real disclosure, destination acceptance and
activation each still need their actual evidence; none was observed here.
Independent full-diff Standards, Specification and Runtime review and exact
hosted CI are required before merge. No exporter, cross-Project credential,
watcher or publication/synchronization/rollback mechanism was added.
