# Issue Management

Repository contract for the shared `/issue-management` skill. Workflow defaults remain in that skill.

- Tracker: GitHub
- Stale claim window: 24 hours
- Closed-issue lifecycle cleanup: repository
- Lifecycle cleanup automation: `.github/workflows/cleanup-closed-issues.yml`
- Dependencies: native GitHub issue dependencies are authoritative; mirror blockers and parentage as explicit `Blocked by: [#N]` and `Parent: [#N]` body lines. Parentage is not a blocker.

## Lifecycle labels

| Role | Label |
| --- | --- |
| review | `agent:review` |
| ready | `agent:ready` |
| claimed | `agent:claimed` |
| blocked | `agent:blocked` |

## Wayfinder labels

| Role | Label |
| --- | --- |
| map | `wayfinder:map` |
| research ticket | `wayfinder:research` |
| prototype ticket | `wayfinder:prototype` |
| grilling ticket | `wayfinder:grilling` |
| task ticket | `wayfinder:task` |

## Delivery labels

| Role | Label |
| --- | --- |
| mechanical | `delivery:mechanical` |
| bounded | `delivery:bounded` |
| cross-cutting | `delivery:cross-cutting` |
| critical | `delivery:critical` |
| unclassified | `delivery:unclassified` |

## Decomposition label

| Role | Label |
| --- | --- |
| decomposed | `spec:decomposed` |

## Candidate review and evidence

For work under successor specification #58, the [human-approved October amendment](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58#issuecomment-6399490386) replaces mandatory separate Standards, Specification, and Runtime reviews with one independent owner covering all three at the exact candidate. Add another independent pass for a named unresolved assurance question. Contribution history determines independence, not a different model, profile, or seat.

Keep explicit positive, negative, failure, recovery, integration, real-runtime, disposable-VM, manual, and target-host obligations. Reuse applicable exact-head evidence; changed dependencies invalidate affected proof. Pending CI remains owned continuation work, not a completed review. Human approval and merge remain human-owned.

When publishing completion or acceptance evidence, inspect actual workflow coverage and effective branch-required checks separately. `validate.sh` and the validation workflow are placeholders until #59 supplies executable checks; green placeholder or docs-exemption results prove no implementation behavior. An unreadable ruleset or protection response is an evidence gap, not proof that requirements are absent.

Before extracting source behavior or changing provider-specific scope, read [the frozen reconciliation and GitHub mapping](../architecture/source-reconciliation.md). Contributor issue labels are development workflow; the future product Hub's lifecycle authority is a separate contract.
