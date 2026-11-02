# Explicit recovery after runner finalization cancellation

The default runtime policy still reads **attempt 1**. Historical baselines always
read attempt 1, including after a recovery. Timing boundaries, the five-sample
median, growth allowance, absolute ceiling, functional inventory and branch
protection are unchanged.

An operator may authorize exactly one complete second attempt when explicitly enumerated
functional jobs were marked cancelled **after every applicable step succeeded**,
including `Complete job`. This is not permission to rerun test failures,
slowdowns, incomplete jobs, partial failed-job subsets or arbitrary later attempts.
The original evidence must be terminal and its complete functional graph must
already satisfy every lane's normal timing limit.

## Authorization and execution

The optional Actions variable `CI_RUNTIME_RECOVERY_APPROVAL` is an operator trust
boundary, not an approval generator. Only set it after explicit authorization for
the specific repository, run, head SHA and second attempt. This code does not
create a variable, grant permissions, request a rerun or infer authorization.
Use the actual authorization reference in the external audit record.

Its JSON object has exactly these fields:

- `version`: integer 1
- `repository`: exact owner/repository
- `run_id`: positive integer for the existing run
- `head_sha`: exact 40-character lowercase hexadecimal SHA
- `attempt`: integer 2
- `cancelled_job_ids`: the exact nonempty list of distinct positive cancelled job IDs,
  bounded by the 28 functional jobs in the current graph
- `approval_reference`: 1–160 letters, digits, underscores, colons or hyphens
- `original_job_conclusions_sha256`: 64 lowercase hexadecimal characters,
  computed from the complete original inventory as specified below

The record is limited to 4096 UTF-8 bytes. Duplicate/extra keys, malformed values,
identity mismatches and missing evidence fail closed. An empty variable retains
the original first-attempt-only behavior. A nonempty record for a different run
fails closed; clear it after the authorized recovery, before unrelated runs.

Rerun **all jobs** of the same run and SHA, not just failed jobs. Each native lane
checks its own complete replacement and original timing. The main accounting
waits for all reusable lanes, then requires the full same-attempt replacement
inventory and successful native budgets. The unchanged final `verify` conjunction
still checks all required results and durable-fit applicability. No automatic
retry or fastest-attempt selection is provided.

## Limits of retroactive recovery

A run executes the workflow and verifier from its immutable commit. Adding this
support in a later commit cannot retrofit an older cancelled run. The new support
commit receives normal first-attempt CI; the older cancelled evidence remains
unchanged. Recovery results are never admitted as historical baseline samples.

Regression tests cover strict records, original post-completion evidence,
functional and timing failures, mixed/incomplete attempts, same-head identity,
durable applicability, native/main sequencing and first-attempt-only baselines.

## Evidence required for optional branches and accounting failures

The approval object also requires `original_job_conclusions_sha256`: SHA-256 of
UTF-8 JSON containing the complete original job inventory as rows
`[id,name,status,conclusion]`, sorted by job ID, with separators `,` and `:` and
ASCII JSON escaping. The digest is computed before any accounting-only copy;
it pins all original conclusions, including accounting and final-verification
jobs. Missing, duplicated, nonterminal or changed inventory fails closed.

Known nonfunctional skips require affirmative proof: unit jobs may skip only
`Report tests not applicable` after the matching real test, dependency install
and applicability detection succeeded (plus the local process smoke in the main
unit job). Claude may skip cache save only after its explicit cache-hit proof,
restore, all acquisitions and actual CLI fixture succeeded. Conversely a cache
miss must save successfully and skip only the complementary cache-hit proof.
No functional test, setup, install or cleanup skip is exempted.

A failed/cancelled original accounting job is not ignored. Its fixed original
job log must contain exactly one bounded structured receipt, matching the
repository, run, head, attempt 1 and lane. Only a typed GitHub evidence-fetch
failure or rejection caused by the explicitly approved functional cancellations
is recoverable. A successful budget receipt may prove a later accounting-job
cancellation. All setup/completion/cleanup evidence must remain successful;
actual functional and timing failures are independently rejected on recomputation.
Missing, unavailable, contradictory or ambiguous receipts fail closed. The
final verification job is derivative and remains unchanged in the pinned digest.

These receipts and cache-hit proofs exist only in commits containing this
implementation. Neither older runs nor their missing evidence can be retrofitted.
Mocked recovery regressions do not establish a real second-attempt API/runner
qualification; that still requires an explicitly authorized complete rerun.
