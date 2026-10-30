# Automatic CI partition headroom (#241)

The full automatic graph retains hard one-minute root jobs and the existing
second-stage integration/smoke dependencies. All test IDs from standard discovery
run exactly once. A new or unlisted module still belongs to `remainder`; no test
is excluded to obtain a passing deadline. Native environment requirements,
assertions, docs-only applicability, permissions and dependencies are unchanged.

## Observed regression

[Postmerge run41047585809](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/41047585809)
completed all311 integration tests in60.074s and all84 synthesis tests in52.524s,
then crossed the one-minute job budget including setup/cleanup. Dependent smoke
jobs were skipped, not proven. The earlier exact-code PR run completed the full
graph in121s, so a single fast run did not establish sufficient margin.

Eight suites summed approximately351 seconds; PR240's15 transport cases add
about7.2 seconds. Nine lanes would average39.8 seconds before setup, leaving little
room for indivisible modules or observed runner variance. Ten parallel lanes
avoid moving the same overload between near-full jobs. They remain one matrix
root in the dependency graph: every matrix member must succeed before existing
second-stage jobs start. No timeouts are raised.

## Measured planning allocation

Approximate suite seconds below derive from timestamp deltas in completed hosted
logs, not guarantees. Setup, queue time and cleanup must be measured separately
from suite time. Estimates retain roughly20 seconds below each job deadline.

| Lane | Estimated suite seconds | Main change |
| --- | ---: | --- |
| remainder |38.3|Move settings to additional; keep existing bounded process smoke|
| slow |37.0|Unchanged|
| integration |36.6|Move service and dispositions out; enqueue and registration in|
| additional |34.2|Move enqueue and Hub out; settings in|
| synthesis |34.1|Move both disposition recovery modules out|
| scheduler |37.3|Move registration out|
| operator |35.1|Move operational records out|
| inspection |33.4|Move disposition native cases out; Hub in|
| lifecycle |29.5|Service plus records; transport fits here when introduced|
| maintenance |31.8|Retention, repair and native repair plus T27 requeue|
| disposition |38.4|All six rejection/adjudication functional, recovery and native modules|

PR240's existing transport module belongs in lifecycle when its source is
composed, with matching explicit partition expectation and full ID inventory.
That changes the lifecycle estimate to36.7 seconds. This correction does not
pretend an absent future module has executed.

`tests/test_ci_partitions.py` checks fixed membership, exact selection, duplicate,
missing, extra and misplaced IDs and discovery failures. `test_vm_ci_policy.py`
checks the actual workflow matrix and unchanged all-root dependency gates. Each
run prints its complete inventory digest. Hosted validation and postmerge runs,
not these estimates, establish the observed complete graph duration (target2–3
minutes). Later growth must be measured again without relaxing coverage.

## T37 repair capacity (#182)

The composed repair run
[41051466124](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/41051466124)
finished all94 operator tests successfully in53.039s, including four actual
private-socket repair cases, but crossed the unchanged one-minute job limit
including setup/cleanup (63s). This is not a qualifying green graph; dependent
jobs were skipped. A prior59s green operator job was insufficient margin.

An eleventh, explicit `maintenance` matrix lane contains only deterministic
repair (21 tests), its native transport (4), and the existing retention module.
Hosted timestamp deltas estimate10.7s +3.2s +9.3s =23.2s suite time, leaving
roughly27s for setup/cleanup and variance under the unchanged60s deadline.
`operator` retains controls and Git-payload tests (about30s suite time);
`disposition` retains its original six modules and `maintenance` gains T27's requeue release module. No existing test is removed,
weakened, or duplicated; future modules still default to remainder. The exact
partition/workflow contract checks include this lane and all downstream jobs
still require every matrix member. No timeout, permission, or runtime-budget
policy changes accompany this test-capacity adjustment.

## T27 requeue capacity (#191)
The requeue release module measured54.8 seconds locally for nine real
Git/SQLite/Service cases: the mixed release, later release of a retained draft,
an unresolved contradiction, model parking whose reason token names a source
failure, stale/archived/busy/revoked refusals, a blocked Project, exact retry
after a settings change, lost acknowledgement and an unknown pre-push outcome.

The first placement put it beside the rejection/adjudication family. The hosted
[validate run41055347618](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/41055347618)
at that head measured the `disposition` partition suite at46.0 seconds and the
whole job at54.0 seconds, while its seven local modules summed246.5 seconds:
about0.19 hosted seconds per local second for these fixture-heavy suites. Two
further cases add roughly3 seconds, so the job would finish near57 of its 60
seconds with setup and cleanup, against this document's planning margin.

The module therefore moves to `maintenance` instead of opening a twelfth lane:
disposition returns to its original six modules,205.5 local seconds and a38.4
second estimate, and maintenance becomes170.2 local seconds and a31.8 second
estimate, joining a lane whose own hosted measurement was21.0 suite seconds in a
29.0 second job. No test was moved out of discovery, excluded or weakened, and
the exact-partition contract still runs every ID once. The next hosted run must
confirm these estimates or rebalance the lanes again.
