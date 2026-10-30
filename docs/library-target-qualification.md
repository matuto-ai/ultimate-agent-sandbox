# Library canonical target qualification

This is the operator runbook for [#157](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/157),
T41 of [the Library specification](specs/per-project-librarian.md). It is not a
qualification result. No actual target, writer, storage profile or independent
backup has been selected in this document. Missing or invalidated evidence keeps
Library writes blocked.

The Library uses standard Git; no provider API, mandatory hosting platform or new
permission framework is required. The working clone is a reconstructible cache,
not the canonical repository or a backup. The Library does not provision the
repository, credentials, receiving policy or backup service.

## Inputs before a target run

The operator supplies these non-secret identifiers and evidence references. Keep
credentials in the existing external credential process, never this record or
command transcripts. Do not infer a Library target from the source-code repository.

| Input | Required binding |
| --- | --- |
| Canonical repository | Private target URL, immutable repository identity if available, canonical branch, hosting/storage administrator |
| Writer | Actual non-admin Library identity and external credential reference; no credential value |
| Reachable interfaces | All Git transports, web/API/SSH/admin and direct filesystem routes available to that identity; evidence for excluded routes |
| Receiving policy | Effective policy revision and scope across **all Library branch refs**, sole ordinary writer, bypass/admin and deletion restrictions |
| Source repositories | Actual allowed read scope and evidence that the Library identity has no write authority there |
| Storage | Canonical storage host/profile, persistence guarantees and relevant durability configuration; separate working-clone location |
| Recovery | Independent host-loss backup location/failure domain, backup identity, retention/coverage and restore procedure |
| Disposable equivalent | Exact target, identity, branch/ref namespace, storage and independent restore destination; administrative evidence mapping them to the actual target |
| Run authority | Operator approving specific disruptive probes, permitted targets/actions, bounded observation window and cleanup ownership |

A first operator handoff can simply identify the intended private Git target and
independent backup host. The rest can be collected from their authoritative
configuration. A second directory on the same host is not host-loss coverage.
A same-host bare repository is eligible only when independently administered and
the Library identity cannot edit canonical refs or controls directly.

## Sequence and stop conditions

1. **Identify and inspect.** Bind the target, branch, writer, interface inventory,
   policy, storage and backup to a timestamp and implementation revision. Obtain
   administrative evidence where Git cannot reveal effective permissions. A
   configured policy or an unsupported inspection is not a successful probe.
2. **Prepare an approved disposable equivalent.** Use synthetic content only.
   Establish why each tested policy, identity scope and storage property applies
   to the real target. A similar provider name or successful push is insufficient.
   Do not create accounts, expand access or alter actual production controls as a
   side effect of running this procedure.
3. **Exercise the matrix below.** Use the real Library publication/recovery seam
   for normal publication and uncertain outcomes. Use the target's reachable
   interfaces for receiving-side restrictions, not only client-side refusals.
   Record pre/post refs and object/operation identities. Bound processes and
   retain partial results before stopping.
4. **Reconcile before retry.** An interrupted or timed-out operation remains
   unknown until authoritative target history is readable and its stable
   operation identity is located or proven absent. Never generate a new identity
   merely to obtain a successful retry.
5. **Review applicability and enablement separately.** One independent reviewer
   checks the exact evidence and residual risks. Only complete, current evidence
   for the configured target can support write readiness. This runbook does not
   install or implement a readiness switch, or turn a reference ID into proof.

Stop the affected probe if target/identity/policy is ambiguous, the disposable
boundary cannot be proved, unexpected valuable data is found, or execution would
exceed the approved scope. Preserve evidence; do not automatically clean up,
revoke another identity, switch providers or reset the target to get green.

## Required evidence matrix

For every row record `observed`, `failed`, `unknown` or `not run`, with exact
producer/version, time, target/identity, evidence location and result. Only
observed expected behavior satisfies that row. Where a disposable test is used,
record the actual-target applicability evidence separately.

| Property | Probe and expected observation |
| --- | --- |
| Private access | Authenticated Library reader reaches the actual private target; unauthorized reader and writer attempts are denied. Verify the Library identity is the only ordinary writer, keeping trusted administrators explicit. |
| Allowed publication | Publish synthetic Project content through `LibraryGit` to the disposable equivalent. Verify the exact returned commit is canonical and descends from the previous head; record input, parent, result and stable operation identity. |
| Rewrites and ref deletion | As the scoped Library identity, attempt non-fast-forward updates and branch deletion in the approved disposable namespace. Receiver rejects them. Prove controls cover all Library branch refs, not only the configured canonical branch; cover each available interface. |
| Administration and bypass | Show the identity cannot change receiving controls, grant bypass, administer/delete the repository or mutate canonical refs through a direct filesystem path. Use safe administrative evidence for real targets; any destructive negative probe must remain on the specifically approved disposable equivalent. |
| Source isolation | Demonstrate no source-repository write authority. Do not attempt writes to valuable source repositories; use authoritative permissions and an approved disposable equivalent for negative probes. Read access is not write access. |
| Revocation | Through the externally owned credential process, revoke the **disposable** test credential and show subsequent publication fails with no identity/target fallback. Record how that mechanism applies to the actual writer. Do not revoke valuable access to test this row. |
| Lost push outcome | Arrange an approved lost acknowledgement after a real disposable publication. Reopen the service with the same operation identity. Fetch canonical history, recover the exact committed result and prove no duplicate commit; also cover an absent publication and unavailable reconciliation without false success. |
| Process interruption | Interrupt the disposable service at the selected publication/acknowledgement boundary. Reopen against canonical Git and durable operational records, preserve acknowledged content and reconcile in-flight identities before discarding local-only clone state. Record the exact interruption mechanism. |
| Storage interruption | Exercise the approved restart/crash scenario on disposable storage with the selected durability profile. Verify acknowledged canonical objects, refs and operation identities survive. A graceful restart, client fault injection or process kill alone does not establish storage-crash persistence. |
| Independent restore | Take the selected backup containing known acknowledged content/identities, make the original disposable host/storage unavailable, restore into a separate approved destination and verify object/content hashes, refs and recovery identities. Record backup point and any acknowledged operations outside it; do not report a stale restore as lossless. |
| Invalidated evidence | Change or invalidate a bound identity/policy/storage/backup observation in the admission test. The consuming deployment must refuse write readiness rather than reuse stale proof or silently choose another target. If that consumer is not yet available, record this row as not run. |

Do not restore over the live canonical repository for qualification. Restoration
of a backup is not permission to redirect an existing service's pinned target.
Record the expected operational-record recovery path as well as canonical Git:
reconstructing a clone alone does not prove every pending receipt is recoverable.

## Evidence record outline

Store the completed record in the operator's private evidence location. Commit
only intentionally shareable metadata to the software repository. Raw Library
content, credentials and unauthorized source material do not belong in logs.

- Qualification ID, observed time/window, implementation candidate and producer.
- Actual target/branch/identity, policy revision, interface inventory, storage and
  independent backup identities. External credential **reference** only.
- Disposable target and exact approved probe scope, plus administrative mapping
  to the actual target for each applicable property.
- Per matrix row: expectation, actual outcome, sanitized command/result or
  authoritative administrative evidence, pre/post refs and operation identities,
  evidence digest/location, missing coverage and residual administrator trust.
- Recovery: acknowledged commit set, backup point, restored commit/content set,
  unresolved operation identities and any data-loss/recovery limit observed.
- Reviewer, review time, qualified scope, unresolved failures, invalidation
  conditions and the deployment's resulting blocked/ready observation.

Changes to repository/branch, writer authority or credentials, interfaces,
receiving controls, storage/durability or backup/recovery behavior invalidate
affected proof. Recheck their current identity before using the record. Never
reuse a passing result merely because its qualification reference still exists.

## Existing evidence and remaining work

[#153 / PR210](https://github.com/matuto-ai/ultimate-agent-sandbox/pull/210)
implements `uas/library_git.py`. Its `tests/test_library_git.py` exercises a real
disposable local bare Git repository, lease/concurrency, publication, stale-result
refusal, lost/uncertain push reconciliation and clone reconstruction. Those
checks are useful component evidence and should be reused, not copied into a
second test framework.

They do **not** establish authenticated actual-target access, independently
administered policy across every interface, credential revocation, storage-crash
durability or independent host-loss restore. Their same-host directory is not an
independent backup. No additional rehearsal is needed merely to duplicate those
checks. Target-specific probes can only be selected after the operator inputs
above are known.

The initial #157 preparation therefore consists of this bounded procedure and
input/evidence inventory. Actual qualification, deployment admission integration
and the issue's original acceptance remain open until observed and reviewed.
