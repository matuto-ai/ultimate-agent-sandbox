# Exact Forge Gate observations

The `forge-state` Gate uses the existing external GitHub Broker, not a transport
or credential provider in the Hub. Trusted Broker startup may select `gate_actor`
from its external credential store. The existing inherited, held-process-bound
Supervisor channel advertises `gate_enabled` only for that installation. No
Participant command/route or Actor capability spelling can create Gate authority.
The exact Hub origin, Room incarnation and current authorization are checked
before every provider page and again before disclosure.

`GateForgeBrokerClient.observe_target(target, operation_id, authorize=...)` is the
narrow binding read. The target contains repository, immutable PR ID, PR number,
head SHA, base SHA and base ref. The Broker reads the exact PR and current base
branch before and after an exact base/head ancestry observation. The Hub's
separate authorized target owner decides whether to persist the resulting binding;
an ordinary evaluator or Participant cannot install a target.

`GateForgeBrokerClient.observe(target, config, operation_id, authorize=...)`
returns `{observation, audit_reference}`. Provider content contains raw normalized
facts, not Checks, `ok`, a Gate verdict or advancement authority. The Hub validates
the exact schema/correlation/digest and derives immutable Checks. Intent and a
metadata-only terminal record use the existing `ForgeAudit`; no second audit
database or scheduler is introduced. Repeating an uncertain Broker operation
never recontacts GitHub. Lost observation bytes yield explicit unknown evidence,
not a recovered pass. The Hub's existing durable attempt/refresh owner controls
recovery and intentional fresh observation IDs.

## Bounded policy

The exact configuration is `{"ci": [...]}`, containing 1–32 records with:

- `id`: stable lowercase item identifier;
- `kind`: `check-run`, `commit-status`, `actions-workflow` or `actions-job`;
- `producer_id`: immutable App ID, status creator ID, or workflow ID;
- `context`: exact check/status/job name, or the workflow's exact event name;
- `coverage`: `head` or the explicit `head-or-test-merge` rule;
- `purpose`: `complete-suite`, `focused` or `specialized`.

At least one explicit complete-suite requirement is mandatory. Purpose is trusted
policy data, never guessed from names or a green rollup. All configured items are
applicable and required; non-applicable requirements must be absent from the
snapshotted policy. There is no runtime optional/skipped Gate or inference from a
workflow's own claims. A complete-suite workflow must have a nonempty exact-attempt
job list with every job completed successfully; skipped, neutral or absent work
does not demonstrate a complete suite.

Check runs use GitHub's `filter=latest` selection and exact App/name identity;
ambiguous duplicates fail closed. Commit statuses preserve the documented
newest-first enumeration and select the latest per creator/context, not the largest
guessed object ID. Actions select the largest workflow run number per workflow/event,
then read its current attempt, all attempt-qualified jobs and the closing run.
An attempt change is an error. Pending/failed latest work cannot fall back to an
older pass, including a passing job in a still-pending workflow.

A synthetic test-merge result qualifies only when head evidence is absent, policy
explicitly allows it, and the provider independently reads exact ordered parents
`[base_sha, head_sha]`. It cannot override present pending or failed head evidence.
The accepted tested SHA, candidate/base association, producer, context, run, job and
attempt remain in the Check dependencies. Pull-request Actions associations must
match the exact PR and head/base repository identities.

## Required branch checks and freshness

Classic branch protection and all active branch rules are separate observations
from configured CI. A protected branch with unreadable protection, inaccessible
rules, failed pages or an unsupported required rule is unknown/error, never an
empty requirement set. App-pinned requirements must match the exact producer.
An any-producer requirement cannot hide additional same-name statuses/checks
behind one configured pass. Missing policy coverage for a required producer/context
blocks the Gate. Strict base coverage requires current base ancestry or an explicitly
allowed exact test-merge result for every selected item.

Required-workflow, deployment and merge-queue rule types do not silently degrade
to status checks; their unsupported evidence contracts return
`UNSUPPORTED_FORGE_REQUIRED_RULE`. This conservative refusal does not alter branch
protection or permissions. Supported unrelated rule metadata is retained for
observation consistency but does not claim to perform review/merge adjudication.

Each observation rereads PR identity/state, branch requirements and ancestry after
any caller wait; no cached provider response authorizes advancement. Integrity uses
`observation_digest`. Current qualification uses the narrower
`dependencies.dependency_digest`, which includes only the target, relevant native
state, required CI and selected evidence. Unrelated check names or pagination
metadata therefore do not invalidate otherwise unchanged evidence.

Reads are bounded by 30 seconds, 80 requests, 10 pages per collection, 1 MiB raw
input and 48,000 bytes normalized evidence. Failure, truncation, malformed identity,
missing CI, lost authority and unavailable results are never passes. Transport
must enforce its existing per-call I/O deadline; these bounds grant no new network
or account access.

## Evidence scope

`test_gate_forge.py` and `test_gate_forge_hub.py` are pure provider/Hub/Broker/audit
tests with synthetic source and client boundaries. They are not process-authentication
or live-provider evidence. `tests/linux/gate_forge_smoke.py` is a separate hosted-only
real process-channel fixture using distinct UIDs and a pinned fake `gh` executable.
It exercises trusted target binding, immutable Checks, exact retries, restart and
pending-CI blocking without any live account or network. Source Git remains
synthetic, and helper/Workstation confinement is explicitly outside that proof.

GitHub endpoint semantics are documented in the official
[check-runs API](https://docs.github.com/en/rest/checks/runs),
[commit-status API](https://docs.github.com/en/rest/commits/statuses), and
[active branch-rules API](https://docs.github.com/en/rest/repos/rules).
