# Durable bounded Library synthesis attempts

`uas.library_attempts.Attempts` composes the concrete Assembler, qualified
Dispatcher/Gateway, strict compiler, leased Git publisher, and durable records.
It is a service seam for T19, not the T21 startup scheduler or an HTTP endpoint.

## Identity and recovery

A drain first durably fixes its ordered queue IDs, even when assembly parks an
unavailable source without contacting a model. Each numbered attempt records its
original input commit, settings identity, exact request digest/counts, selected
draft IDs, accepted concept references, index selection, and input path/content
hashes before contact. The strict metadata-only manifest has a separate 256 KiB
ceiling (up to 64 drafts and 1024 hashed inputs); generic audit records retain
their existing 4 KiB ceiling. Draft bodies, source excerpts and model output are
not placed in durable attempt records.

An exclusive durable contact reservation precedes spawning the adapter. A crash
after that reservation is conservatively ambiguous: the same attempt never
contacts the model again. A fresh numbered attempt retains the drain's fixed
batch. Raw model output is ephemeral and never replayed after restart.

Publication includes stable operation/drain identity and a validated,
metadata-only canonical receipt with per-draft outcomes. Recovery first searches
canonical history and verifies that exact published tree. It reconstructs the
receipt after a lost push response or process exit before local receipt write,
without another model call or duplicate commit. Original input SHA, actual
publication parent SHA and resulting SHA remain distinct.

## Concurrency, input fencing and budget

The synthesis lock is separate from the publisher's Git lock. Inference holds
neither a Git publication lock nor an SQLite transaction; enqueue and reads
remain available. Compatible head movement is recompiled against the latest
tree, retaining later drafts and unrelated accepted changes. Reuse requires
exact selected draft, accepted document, selected index and resolved source bytes.
Changed inputs discard the ephemeral proposal and require a new numbered attempt.
Source grants, authenticated scope, route and egress authority are rechecked
through publication. Operational settings and filter/limit choices are snapshotted
at attempt start; changing ceilings does not silently alter an admitted request.

The default limits remain eight drafts, 64 KiB of selected draft content and
120 seconds, with one model contact per attempt. A thread-local absolute deadline
bounds Git subprocesses/reads, Git-lock acquisition, SQLite waiting and provider
execution; provider budget is recomputed after the admitted audit callback.
Trusted service callbacks must themselves be bounded; Python callbacks are not
forcibly interrupted. The deadline does not constrain concurrent enqueue threads.

Compilation is atomic: integration, attributable parking, mixed integration and
parking, or parking-only are validated as one complete Project tree. Invalid or
uncertain attribution publishes no partial synthesis.

## Validation and CI

`tests/test_library_attempts.py` uses disposable real Git repositories and the
account-free external Python provider fixture. It exercises actual provider
latency concurrent with enqueue, compatible publication races, authorization
revocation, corrupt proposals, contact reservation, changed inputs, lost push and
receipt responses, and real process exits at intent, admission, provider return
and push. No live provider, model credential, deployment or privileged VM is used.

The automatic unit graph adds a disjoint `synthesis` matrix lane for these
real-Git tests. Existing lane timeouts, exhaustive inventory and downstream gates
are preserved; this avoids adding approximately twenty seconds to existing
near-minute lanes. The full hosted graph must still satisfy the repository's
two-to-three-minute feedback budget.

A restart before contact may reassemble the same attempt only while its pinned
input commit is still current. If the head advanced before any proposal existed,
the caller starts a new numbered attempt on the same fixed batch. This is distinct
from reconciliation of an already returned in-memory proposal: compatible head
advances in that phase never cause a second model call.
