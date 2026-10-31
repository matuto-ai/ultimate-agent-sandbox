# Claude native fixture scheduling

The serial parser contract and official CLI probe still finish before the module
workers. Every `tests/test_claude*.py` module is then discovered and executed once,
with at most two workers. Each module retains its own temporary homes and ports.
The native network namespace, pinned installs, test assertions, process deadlines,
and first-attempt runtime-budget calculation are unchanged.

## Measured reason for the ordering hints

In the first attempt of PR #261's Claude run `41239350988`, job `124649775187`,
the functional fixture took 71 seconds and the entire job took 85 seconds,
exceeding its 84.7-second budget. Alphabetical dispatch delayed
`test_claude_sdk_receiver.py` until 20:33:03 UTC. Its nine tests took 34.167 seconds;
the other worker finished at 20:33:06.650, leaving roughly 30.6 seconds of idle tail.

Measured module durations for the largest modules were:

- SDK receiver: 34.167s
- Participant: 17.977s
- SDK: 12.716s
- Readiness: 12.011s
- Runtime: 11.623s
- Library read: 8.068s
- Library capture: 6.508s

The runner now starts those long modules first, in that order, then the remaining
glob-discovered modules. The list controls order, not inclusion; future modules
remain automatically included. A two-worker scheduling calculation using that
run's module durations predicts about 52.4s instead of 67.6s of module work.
This is a model, not a promised hosted runtime: CPU contention, imports and runner
variance can change actual results. Exact-candidate hosted CI remains the gate.

Synthetic runner tests check serial prerequisites, the two-worker cap, priority
startup, exactly-once discovery including an unranked future module, and failure
propagation from both prioritized and unranked modules. No native test is removed
or marked successful merely because it is skipped locally.
