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
| disposition |35.8|All six rejection/adjudication functional, recovery and native modules|

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
