# Automatic test efficiency (#256)

This audit starts from `fc29f3f3ea6b643d219ef3c2efd42a51e07bdc46`.
It reduces fixture/setup waste rather than changing the runtime acceptance
policy. Unit partition membership, all-root integration ordering, watchdogs,
first-attempt budget measurement and the real 46-second idle-survival proof
are unchanged. No VM, provider account or installed deployment is exercised.

## Changes and evidence

* Python setup uses `venv --without-pip` and the runner's `pip --python` to
  install the same hash-pinned wheels into that isolated environment. This
  avoids bootstrapping a second copy of pip for every job. `--require-virtualenv`
  fails closed; a subsequent target-interpreter check verifies isolation and
  that both dependencies actually came from the virtual environment. There is
  no system-site-packages inheritance, unpinned dependency or new cache.
  On this cloud executor, venv creation fell from 2.792 to 0.069 seconds.
  Both actual requirements installs and isolation checks passed; total setup
  measured 10.867 versus 5.927 seconds, but downloads make that total a
  non-controlled comparison. Hosted graph measurements remain authoritative.
* The SQLite contention test now bounds only the first, deliberately blocked
  operation with the existing operation-deadline context. Its previous direct
  `PRAGMA busy_timeout=0` was overwritten by the writer's production timeout.
  The test still holds a real competing SQLite write transaction, verifies
  the typed refusal and unchanged pending state, then releases the lock and
  proves the same instance can write. It no longer spends five seconds
  waiting for that expected refusal. Measured focused duration: 5.013 seconds
  before, 0.106 seconds after. The recovery write is outside the expired budget.
* Three account-free Claude gateway fixtures explicitly use a 0.05-second
  server shutdown poll interval instead of Python's default 0.5 seconds.
  This changes neither request handling nor native readiness/cleanup deadlines.
  The socket shutdown and thread join still run. Native execution must be
  validated in the existing pinned CLI/SDK CI, not inferred from local skips.
* Fixture-only mixins stop three classes from inheriting unrelated test cases.
  No assertions were deleted. Standard discovery changes from 5,010 to 4,972
  cases, removing exactly 38 duplicate executions:
  * 14 `ClaudeLibraryRecipeTests` inherited ordinary-profile cases remain in
    `NativeClaudeRecipeTests`. The four Library-profile cases remain.
  * 15 `ManagerActionHostTests` inherited cases called the original owner API,
    not the host adapter. They remain in `ManagerActionsTests`; all nine
    authenticated host-adapter cases remain.
  * Nine `TerminalTests` inherited completed-path cases remain in
    `LocalStopTests`. All sixteen terminal cases, including the distinct
    noncompleted-path override, remain.
  An exact inventory comparison maps each removed ID to its retained original;
  there are no other removals or additions. These duplicates measured about
  0.92 seconds locally, so removing them is coverage hygiene, not the main gain.

## Deliberately retained

Native socket/control/inspection/settings and denial variants that reuse a
test body with different fixtures still exercise different behavior and remain
discovered. Crash-boundary, recovery, backoff and failed-attempt checks remain.
The long idle-service test proves survival beyond previous fixed deadlines and
cannot be replaced with a mock clock. No new runner lane is added: historical
measurements showed that more concurrency can cost more than it saves.

Focused local checks cover the refactored owner/host, recipe and terminal
families, records, partition inventory and workflow policy. Native tests skipped
locally are not passing native evidence. Exact-head hosted functional results,
runtime-budget results and independent review must be recorded in the PR,
followed by postmerge CI; this document alone does not claim those passed.
