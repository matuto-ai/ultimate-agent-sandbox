# Job-private Pi compilation cache

Issue #264 retains fresh official Pi processes, sessions, native assertions and all
139 discovered native test IDs. Only repeated compilation of unchanged JavaScript
is reused via Node24.22.1's built-in module compile cache. No dependency/version
probe, setup cost, fixture execution, process cleanup or API-completion accounting
moves outside the existing job/runtime gate.

`run-tests.sh` atomically creates a private0700 directory in that job's checkout,
refuses preexisting paths, and removes its owned cache on exit. The network guard
validates a real owned private directory before enabling it. Standalone guard use
without the shell-owned directory is uncached. There is no cross-job cache,
network restore, account state, session, receipt or evidence reuse. The cache is
compiled source code, not runtime variable state. Native launch environments and
all network guards remain unchanged.

Node invalidates compiled entries when source changes, and segregates Node
versions. Regression tests exercise fresh process execution twice, source change,
private directory/symlink checks, absent-cache behavior and cached network refusal.
No cache layout is assumed.

Node warns that V8 coverage can become less precise for deserialized functions.
These native gates do not collect V8 coverage. `NODE_V8_COVERAGE` or
`NODE_DISABLE_COMPILE_CACHE=1` bypasses cache creation for the entire shell run,
including clean-environment native children. The helper independently honors
those flags when called directly.

Reference: https://nodejs.org/docs/latest-v24.x/api/module.html#module-compile-cache

## Measurements

Before candidate publication, a local real official Pi partition0 execution
(36 tests, Node24.22.1, pinned Pi1.4.0) passed in40.346s without caching and34.387s
with a cold cache, a5.959s reduction. This is diagnostic local evidence, not a
hosted gate claim; runner variance and full setup still count. The original hosted
failures were62s,59s and66s against57.2s. Exact-head hosted CI must independently
establish eligibility before merge. No reruns or thresholds are changed.

## Measured recovery-shard rebalance

The first hosted cache-only candidate passed all139 native cases but remained
60.0s >57.2s. Native suite times were42.820s (primary),39.053s (default), and
24.893s (recovery). Four independently isolated runtime cases (compaction,
preflush crash, SIGSTOP handoff recovery and slow first flush) therefore move to
the recovery shard. Local individual measurements totaled6.609s for these cases;
an additional runtime-class official version probe in recovery remains counted.
All139 IDs still execute exactly once; future runtime cases default to primary.
No fixture, native assertion or deadline changes. This is substantive balancing
of measured idle capacity, not a rerun of the rejected cache-only candidate.
