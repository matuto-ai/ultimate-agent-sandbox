# Bounded Gate-policy compilation

This increment implements only the configuration prerequisite of #73 under #58
and the surviving Gate contract in [#25's resolution](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/25#issuecomment-6397323807).
It does not evaluate a Gate or authorize a protected operation.

## Supported definition

Trusted Project configuration may define a mechanical `artifacts` Gate with a
nonempty bounded list of explicit target-relative paths, each with `type` (`file`
or `directory`) and a boolean `nonempty` requirement. The compiler rejects missing
configuration, duplicate items, absolute/traversing/ambiguous paths, Git metadata,
patterns, unknown fields, unknown guard targets and dangling references. It does
not touch the filesystem. Filesystem containment, symlink rejection, actual
presence/type/content, unchanged exact-revision target proof and helper isolation
remain obligations of a future evaluator, not consequences of lexical checks.

For this one evaluator the accepted contract determines the source
(`supervisor-one-shot-helper`), scope (`exact-head-tree`) and freshness
(`dependency-changes`). Those are compiler outputs, not extra operator knobs or
Participant-selected claims. Dependencies name the Run ID/generation, policy
ID/version, repository and exact head SHA. Guards are derived from the existing
operation-to-Gate mapping, using conjunction, not duplicated configurable rules.
There is no TTL, optional-pass flag, Boolean expression or workflow DAG.

All other evaluator names, including accepted-but-not-yet-implemented `command`,
`diff-claims` and `forge-state`, are explicitly unavailable in this increment.
Attestation and decision definitions are also unavailable until their own complete
compiler contracts exist. Superseded `findings-clear` is not supported. Unknown or
incomplete definitions cannot degrade to fewer checks.

The existing configuration loader compiles the whole policy before returning any
Room configuration. Existing canonical Run admission uses this loader before
provider selection, assignment, Git allocation or native launch, and snapshots
the compiled policy in its existing durable admission/Run records. Exact retries
retain the original policy snapshot; editing configuration is not migration or a
way to rewrite an existing generation. No new ledger or evaluation projection is
introduced. No per-session commands or additional authentication surface exist.

## Intentional fixture migration

Both Rooms in `tests/fixtures/two-rooms.json` now have one explicit
`fixture-artifacts` definition checking `README.md` as a nonempty file. This is
**schema data only**, never evidence that the file was checked or a Gate passed.
It replaces the old incomplete `checks`, `review` and `human-merge` placeholders;
the compiler never guesses commands or identity authority from those IDs.
The oversized-policy refusal test now constructs complete artifact definitions.

Canonical independent review and authorized-human exact-candidate merge remain
separate mandatory workflow responsibilities; this fixture neither implements
nor waives them. No review or human-merge approval is modeled as a placeholder
attestation/decision. Existing `submit-for-review`/`complete` policy mapping names
do not mean those protected operations have been implemented.

## Evidence and limits

Pure configuration tests cover the supported canonical definition and refused
incomplete, unsafe, unsupported and unbound definitions. Admission tests show
failure before provider/Git/native effects and durable exact-retry preservation
of the compiled snapshot after a trusted configuration change. This is not Gate
runtime qualification: no helper execution, evidence collection, Checks,
verdicts, eligibility adjudication, protected-operation advancement or policy
migration is implemented. No native or listener qualification is run locally.
