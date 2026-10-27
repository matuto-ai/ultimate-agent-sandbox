# Bounded Gate policy compilation

The Room configuration loader compiles the complete policy before Run admission.
A generation snapshots that result; edits to installation configuration never
rewrite active policy or inherit evidence through a generation migration.
Compilation performs no execution, identity lookup, provider contact or I/O.

Every definition has a stable ID, kind and validated kind-specific configuration.
`protected_operations` maps `submit-for-review` and `complete` to nonempty Gate ID
lists. The Hub requires their conjunction; no optional flag, skipped branch,
Boolean expression, wall-clock TTL or conditional workflow DAG is supported.
Unknown kinds/evaluators, duplicate IDs, unguarded Gates, dangling references,
unknown fields and unsupported limits fail admission rather than remove checks.

## Mechanical definitions

- `artifacts`: `items` is a nonempty list of at most 128 literal target-relative
  paths, with exact `type` (`file` or `directory`) and boolean `nonempty`.
  Presence is not semantic correctness. Paths reject traversal, Git metadata,
  globs, ambiguous separators, invalid Unicode and filesystem byte/depth excess.
- `diff-claims`: exact `allowed_paths`, `forbidden_paths`, `require_nonempty`.
  Constraints are bounded literal path sets, not shell expressions. A separate
  typed implementer declaration supplies untrusted claimed paths against the
  already authenticated, durably bound base/head subject. It cannot select the
  target, helper, constraints or verdict. The helper reports actual paths; the
  Hub derives exact-set equality and one path-constraint Check per actual path.
- `command`: exact deployment-owned argv, target-relative cwd, timeout, bounded
  environment, process/memory/output bounds and immutable executable identities.
  Only the separately admitted command profile can execute it. No shell
  interpolation, inherited deployment environment, network or Participant
  capability is created. See the command profile's source/runtime qualification
  record for supported dependencies and scratch behavior; policy acceptance alone
  is not evidence that the selected Workstation admits that profile.
- `forge-state`: fixed GitHub Broker observations, with explicit CI selectors,
  producer/context identity, complete-suite/focused/specialized purpose and exact
  head or verified test-merge coverage. Branch requirements are independently
  read and cannot be disabled by the policy. See [Forge Gates](gate-forge-state.md).

`findings-clear` is superseded and remains rejected; there is no evaluator plugin
interface. Artifact/command evidence binds the exact head tree. Diff evidence
binds exact base and head. Forge evidence additionally binds PR identity, selected
CI attempts, relevant branch requirements and provider state. Source, scope,
freshness and guarded operations are compiler consequences, not caller claims.

## Identity definitions

`attestation` and `decision` configurations require `statement_id`, `scope` (`run`
or `head`), nonempty bounded `eligible_actors`, `relationship`,
`required_capability`, explicit `allow_self` and `continuing_authority` booleans.
Relationships are `human`, `participant`, `implementer` or
`independent-reviewer`. Independent review requires head scope, `review`
capability, no self approval and continuing authority. An implementer assertion
must explicitly allow self evidence. Authority and exact contribution history
remain trusted runtime observations, not facts inferred from configured names.

The typed submission accepts only an exact statement/action, bounded note and
bounded evidence references. A decision accepts approve/reject/withdraw;
attestation accepts assert/withdraw. The latest submission per durable identity
supersedes its previous statement. A newer in-flight evaluation blocks fallback;
a rejection or withdrawal does not veto a different eligible identity's terminal
approval. Only mechanical evidence is displayed as verified: identity evidence
is attested or decided.

Historical run-scoped statements without continuing authority are independent of
later head changes. Revision-scoped review and continuing authority are freshly
checked, including later contributor ineligibility. Unknown identity facts fail
closed. The original identity, source, Checks and verdict are immutable.

## Enforcement and evidence

The deep [Gate Hub interface](gate-hub.md) records start/terminal evidence, exact
retries and fresh projections in the existing Room ledger. Gate views are not
transferable approval tokens. The actual protected transition owner must compare
current dependencies while holding its authority fence; no Gate read launches
long-running evaluation implicitly. #74 owns review/candidate/human-merge closure
invariants and is not waived by a mechanical pass.

Pure policy/Hub tests establish deterministic semantics, not process isolation.
Separate connected hosted and native qualification must establish each admitted
helper profile and authenticated Broker channel. Missing or unsupported native
admission remains unavailable, never a synthetic successful evaluation.
