// Disposable test worker: intentionally killed only after a committed tool intent.
import { networkAttempts } from './network-guard.mjs';
import { command, gate, ledger, openFixture, submitAdmission } from './fixture.mjs';
const directory = process.argv[2];
const barrier = { started: gate(), release: gate() };
const admission = ledger(directory, command('admit-1'));
if (!admission.ok) throw new Error(admission.error);
const run = await openFixture(directory, { barrier });
const submission = await submitAdmission(run, admission.result, 'Fix the bounded cart fixture.');
await barrier.started.promise;
process.send({ ready: true, conversationId: run.root.id, submissionId: submission.id,
  guardedNetworkAttempts: networkAttempts.length });
// The parent's IPC channel keeps the worker alive. No graceful Harness.close().
await new Promise(() => {});
