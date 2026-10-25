import '../network-guard.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { fauxAssistantMessage } from '@earendil-works/pi-ai/providers/faux';
import { watchEvents } from '@earendil-works/pi-durable';
import { context, command, ledger, prepare, openFixture, workflow, toolCall, gate, digest, fixed, buggy, submitAdmission } from '../fixture.mjs';
import { networkAttempts } from '../network-guard.mjs';

const artifacts = fileURLToPath(new URL('../artifacts/', import.meta.url));
const barrier = () => ({ started: gate(), release: gate() });
async function directory(name) { await mkdir(artifacts, { recursive: true }); return mkdtemp(join(artifacts, `${name}-`)); }
const testResults = calls => calls.filter(x => typeof x === 'object' && 'exitCode' in x);
async function eventually(check) {
  const until = Date.now() + 3000;
  while (!check()) { if (Date.now() >= until) assert.fail('Observation did not reach final commit'); await new Promise(r => setTimeout(r, 5)); }
}
const admit = (dir, id = 'admit-1', generation = 0) => {
  const admitted = ledger(dir, command(id, 'fixture.admit', generation));
  assert.equal(admitted.ok, true);
  return admitted.result;
};
const submit = submitAdmission;

test('authorized event → actual failing test → patch → passing test, with late observer', { timeout: 15000 }, async () => {
  const dir = await directory('flow');
  await prepare(dir);
  const hold = barrier();
  const run = await openFixture(dir, { barrier: hold });
  const views = [];
  try {
    const invalid = command('wrong-project'); invalid.command.payload.project = 'other-project';
    assert.deepEqual(ledger(dir, invalid), { ok: false, error: 'OUT_OF_SCOPE' });
    assert.deepEqual(ledger(dir, { ...command('unauthorized'), authorized: false }), { ok: false, error: 'FORBIDDEN' });
    const stale = command('stale', 'fixture.admit', 99);
    assert.deepEqual(ledger(dir, stale), { ok: false, error: 'STALE_GENERATION' });
    assert.equal(run.faux.state.callCount, 0);
    const admitted = admit(dir);
    assert.deepEqual(admit(dir), admitted);
    const redelivered = admit(dir, 'same-event-new-command');
    assert.deepEqual(redelivered.result, admitted.result);
    const changedEvent = command('same-event-different-content'); changedEvent.command.payload.text = 'Conflicting source event';
    assert.deepEqual(ledger(dir, changedEvent), { ok: false, error: 'EVENT_CONFLICT' });
    const changed = command('admit-1'); changed.command.payload.text = 'Different event content';
    assert.deepEqual(ledger(dir, changed), { ok: false, error: 'ID_CONFLICT' });
    const first = await run.root.watch(context); views.push(first); first.start(async () => {});
    const submission = await submit(run, admitted);
    await hold.started.promise;
    assert.equal((await submit(run, redelivered)).id, submission.id);
    const second = await run.root.watch(context); views.push(second); second.start(async () => {});
    const stream = await watchEvents(run.harness, run.root.id, context); views.push(stream);
    const events = []; stream.start(async batch => events.push(...batch));
    assert.equal(stream.snapshot.tools[0].name, 'inspect_fixture');
    assert.equal(stream.snapshot.tools[0].status, 'running');
    const bound = ledger(dir, command('bind-1', 'fixture.bind', 0, {
      conversation_id: run.root.id, submission_id: submission.id,
    }));
    assert.equal(bound.ok, true);
    hold.release.resolve();
    const settled = await submission.wait(context);
    assert.equal(settled.status, 'done');
    await run.harness.waitForIdle(context);
    await eventually(() => [first, second].every(v => v.value.entries.some(e => e.id === settled.answer)));
    await eventually(() => events.some(e => e.type === 'tool_execution_end') &&
      events.some(e => e.type === 'message_end') && events.some(e => e.type === 'run_end'));
    assert.deepEqual(first.value.entries, second.value.entries);
    assert.deepEqual(testResults(run.calls).map(x => x.exitCode), [1, 0]);
    assert.equal(await readFile(join(dir, 'cart.mjs'), 'utf8'), fixed);
    assert.equal(run.calls.filter(x => x === 'patch_fixture').length, 1);
    assert.equal(networkAttempts.length, 0);
    const proposal = { state: 'candidate-ready-not-product-complete', delivery: 'local-dry-run-only',
      roomReceipt: admitted, conversationId: run.root.id, submissionId: submission.id,
      candidateSha256: digest(fixed), tests: testResults(run.calls),
      observerEntryIds: first.value.entries.map(x => x.id), observedEventTypes: [...new Set(events.map(x => x.type))],
      modelProvider: 'faux', nativeRuntime: false, networkAttempts: networkAttempts.length };
    await writeFile(join(dir, 'draft-pr.json'), JSON.stringify(proposal, null, 2));
    console.log('FLOW_EVIDENCE', join(dir, 'draft-pr.json'));
  } finally { hold.release.resolve(); for (const v of views) await v.stop(); await run.harness.close(context); }
});

test('Pi requestId dedupe does not replace canonical RoomLedger checks', { timeout: 10000 }, async () => {
  const dir = await directory('dedupe'); await prepare(dir);
  const run = await openFixture(dir, { responses: [fauxAssistantMessage('fixture answer')] });
  try {
    const one = await run.root.submit({ type: 'input', content: 'original', requestId: 'same' }, context);
    await one.wait(context);
    const two = await run.root.submit({ type: 'input', content: 'changed', requestId: 'same' }, context);
    assert.equal(two.id, one.id); assert.equal(run.faux.state.callCount, 1);
  } finally { await run.harness.close(context); }
});

test('busy steer, follow-up, withdrawal and rejection use real inbox', { timeout: 15000 }, async () => {
  const dir = await directory('inbox'); await prepare(dir); const admission = admit(dir); const hold = barrier();
  const seen = [];
  const answer = transcript => { seen.push(JSON.stringify(transcript.messages)); return fauxAssistantMessage('fixture response'); };
  const run = await openFixture(dir, { barrier: hold, responses: [toolCall('inspect_fixture', 'inspect-inbox'), answer, answer] });
  try {
    const first = await submit(run, admission); await hold.started.promise;
    const steer = await run.root.submit({ type: 'input', content: 'STEER: preserve rounding', whenBusy: 'steer' }, context);
    const follow = await run.root.submit({ type: 'input', content: 'FOLLOW: explain tests' }, context);
    const withdrawn = await run.root.submit({ type: 'input', content: 'WITHDRAW: should not reach model' }, context);
    assert.equal(await withdrawn.abort(context), 'aborted');
    await assert.rejects(run.root.submit({ type: 'input', content: 'reject me', whenBusy: 'reject' }, context), /busy/i);
    hold.release.resolve();
    for (const entry of [first, steer, follow]) assert.equal((await entry.wait(context)).status, 'done');
    const removed = await withdrawn.wait(context); assert.equal(removed.status, 'unanswered'); assert.equal(removed.reason, 'aborted');
    assert.equal(seen.length, 2); assert.match(seen[0], /STEER: preserve rounding/); assert.doesNotMatch(seen[0], /FOLLOW: explain tests/);
    assert.match(seen[1], /FOLLOW: explain tests/); assert.doesNotMatch(seen.join(''), /WITHDRAW:/);
  } finally { hold.release.resolve(); await run.harness.close(context); }
});

test('fence, scoped stop, then fresh authorized continue in same conversation', { timeout: 15000 }, async () => {
  const dir = await directory('stop'); await prepare(dir); const admission = admit(dir); const hold = barrier();
  let run = await openFixture(dir, { barrier: hold });
  try {
    const first = await submit(run, admission); await hold.started.promise;
    const conversationId = run.root.id;
    assert.equal(ledger(dir, command('stop-1', 'fixture.fence', 0, {})).ok, true);
    assert.deepEqual(ledger(dir, command('admit-1')), { ok: false, error: 'FORBIDDEN' });
    await run.root.abort(context, { background: true });
    const stopped = await first.wait(context); assert.equal(stopped.status, 'unanswered');
    assert.equal(await readFile(join(dir, 'cart.mjs'), 'utf8'), buggy);
    run.harness.resume(); await run.harness.waitForIdle(context);
    assert.equal(run.calls.includes('patch_fixture'), false);
    await run.harness.close(context);
    assert.equal(ledger(dir, command('enable-1', 'fixture.enable', 1, {})).ok, true);
    const next = admit(dir, 'continue-1', 2);
    run = await openFixture(dir, { generation: 2 });
    assert.equal(run.root.id, conversationId);
    const oldReceipt = ledger(dir, command('admit-1'));
    assert.equal(oldReceipt.ok, true); // Historical idempotent receipt, not fresh authority.
    assert.throws(() => submit(run, oldReceipt.result), /STALE_OR_REVOKED_FIXTURE_ADMISSION/);
    assert.equal(run.faux.state.callCount, 0);
    const resumed = await submit(run, next, 'Continue the same event under fresh authorization.');
    assert.notEqual(resumed.id, first.id); assert.equal((await resumed.wait(context)).status, 'done');
    assert.deepEqual(testResults(run.calls).map(x => x.exitCode), [1, 0]);
  } finally { hold.release.resolve(); await run.harness.close(context); }
});

test('graceful close/reopen resumes pending safe tool without duplicate patch', { timeout: 15000 }, async () => {
  const dir = await directory('reopen'); await prepare(dir); const admission = admit(dir); const hold = barrier();
  let run = await openFixture(dir, { barrier: hold });
  try {
    const first = await submit(run, admission); await hold.started.promise;
    const conversationId = run.root.id; const id = first.id;
    await run.harness.close(context);
    assert.equal(await readFile(join(dir, 'cart.mjs'), 'utf8'), buggy);
    // The model is a scripted test double; its remaining responses are explicitly reconstructed.
    run = await openFixture(dir, { responses: workflow().slice(1) });
    assert.equal(run.root.id, conversationId);
    const existing = await run.harness.submission(id, context);
    assert.equal((await existing.wait(context)).status, 'done');
    assert.equal((await submit(run, admission)).id, id);
    assert.deepEqual(testResults(run.calls).map(x => x.exitCode), [1, 0]);
    assert.equal(run.calls.filter(x => x === 'patch_fixture').length, 1);
    assert.equal(networkAttempts.length, 0);
  } finally { hold.release.resolve(); await run.harness.close(context); }
});

test('SIGKILL of isolated worker recovers committed pending tool in a new Harness', { timeout: 15000 }, async () => {
  const dir = await directory('crash'); await prepare(dir); admit(dir);
  const worker = fork(fileURLToPath(new URL('../crash-worker.mjs', import.meta.url)), [dir], {
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    env: { PATH: '/usr/bin:/bin', HOME: dir },
  });
  let stderr = ''; worker.stderr.on('data', chunk => { stderr += chunk.toString(); });
  let run;
  try {
    const ready = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Worker not ready: ${stderr}`)), 5000);
      worker.once('message', message => { clearTimeout(timer); resolve(message); });
      worker.once('error', error => { clearTimeout(timer); reject(error); });
      worker.once('exit', (code, signal) => { clearTimeout(timer); reject(new Error(`Worker exited early ${code}/${signal}: ${stderr}`)); });
    });
    assert.equal(ready.ready, true);
    assert.equal(ready.guardedNetworkAttempts, 0);
    const exited = once(worker, 'exit'); assert.equal(worker.kill('SIGKILL'), true);
    const [code, signal] = await exited; assert.equal(code, null); assert.equal(signal, 'SIGKILL');
    assert.equal(await readFile(join(dir, 'cart.mjs'), 'utf8'), buggy);
    run = await openFixture(dir, { responses: workflow().slice(1) });
    assert.equal(run.root.id, ready.conversationId);
    const existing = await run.harness.submission(ready.submissionId, context);
    assert.equal((await existing.wait(context)).status, 'done');
    assert.deepEqual(testResults(run.calls).map(x => x.exitCode), [1, 0]);
    assert.equal(run.calls.filter(x => x === 'patch_fixture').length, 1);
    assert.equal(networkAttempts.length, 0);
    await writeFile(join(dir, 'recovery.json'), JSON.stringify({ ...ready, killedWith: signal,
      candidateSha256: digest(fixed), tests: testResults(run.calls), source: 'real-process-kill-before-patch' }, null, 2));
  } finally {
    if (worker.exitCode === null && worker.signalCode === null) worker.kill('SIGKILL');
    if (run) await run.harness.close(context);
  }
});
