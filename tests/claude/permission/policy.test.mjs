import test from 'node:test';
import {EventEmitter} from 'node:events';
import assert from 'node:assert/strict';
import {PermissionSlot, exactRead, permissionProfile, terminatePending} from '../../../runtime/claude/permission-policy.mjs';

function fixture() {
  let attention;
  const abort = new AbortController();
  const slot = new PermissionSlot({sessionId:'session', incarnation:'incarnation',
    invocationId:'invocation', file:'/fixture/nonce', notify: x => { attention = x; }});
  const input = {file_path:'/fixture/nonce'};
  const result = slot.request('Read', input, {signal:abort.signal, requestId:'request', toolUseID:'tool'});
  return {slot, abort, result, input, attention};
}
test('exact read shape; no shell/path/input expansion', () => {
  assert(exactRead('Read', {file_path:'/fixture/nonce'}, '/fixture/nonce'));
  for (const [name, input] of [['Bash', {file_path:'/fixture/nonce'}], ['Read', null],
    ['Read', {file_path:'/fixture/other'}], ['Read', {file_path:'/fixture/nonce', offset:1}]])
    assert(!exactRead(name, input, '/fixture/nonce'));
});
test('pending until exact explicit fixture decision; no persistent permission', async () => {
  const f = fixture(); let settled = false;
  f.result.then(() => { settled = true; });
  await Promise.resolve(); assert.equal(settled, false);
  for (const key of Object.keys(f.attention.identity)) {
    assert.equal(f.slot.decide({...f.attention.identity, [key]:'stale'}, 'allow'), false);
  }
  assert.equal(f.slot.decide({...f.attention.identity, extra:'x'}, 'allow'), false);
  assert.equal(f.slot.decide(f.attention.identity, 'auto'), false);
  f.input.file_path = '/changed-after-prompt';
  assert.equal(f.slot.decide(f.attention.identity, 'allow'), true);
  assert.deepEqual(await f.result, {behavior:'allow', updatedInput:{file_path:'/fixture/nonce'}, toolUseID:'tool'});
  assert.equal(f.slot.decide(f.attention.identity, 'allow'), false);
  assert.equal(f.slot.decide(f.attention.identity, 'deny'), false);
});
test('explicit deny, cancellation and closed process cannot approve', async () => {
  const f = fixture();
  assert(f.slot.decide(f.attention.identity, 'deny'));
  assert.equal((await f.result).behavior, 'deny');
  for (const mode of ['abort', 'close']) {
    const f = fixture();
    if (mode === 'abort') f.abort.abort(); else f.slot.cancel('owned-process-exited');
    assert.equal(f.slot.decide(f.attention.identity, 'allow'), false);
    const outcome = await f.result;
    assert.equal(outcome.behavior, 'deny'); assert.equal(outcome.interrupt, true);
    assert(!outcome.message.includes('User'));
  }
});
test('second request, subagent and malformed native identity fail closed', () => {
  const f = fixture();
  assert.throws(() => f.slot.request('Read', {file_path:'/fixture/nonce'},
    {signal:f.abort.signal, requestId:'next', toolUseID:'next'}));
  f.slot.cancel('test-complete');
  for (const fields of [{requestId:''}, {toolUseID:''}, {agentID:'subagent'}]) {
    const slot = new PermissionSlot({sessionId:'s', incarnation:'i', invocationId:'v', file:'/f', notify:()=>{}});
    assert.throws(() => slot.request('Read', {file_path:'/f'},
      {signal:new AbortController().signal, requestId:'r', toolUseID:'t', ...fields}));
  }
});
test('already aborted or failed attention publication never permits execution', async () => {
  const aborted = new AbortController(); aborted.abort();
  const slot = new PermissionSlot({sessionId:'s', incarnation:'i', invocationId:'v', file:'/f', notify:()=>{}});
  assert.throws(() => slot.request('Read', {file_path:'/f'},
    {signal:aborted.signal, requestId:'r', toolUseID:'t'}));
  const broken = new PermissionSlot({sessionId:'s', incarnation:'i', invocationId:'v', file:'/f',
    notify:()=>{ throw new Error('sink-lost'); }});
  const result = await broken.request('Read', {file_path:'/f'},
    {signal:new AbortController().signal, requestId:'r', toolUseID:'t'});
  assert.equal(result.behavior, 'deny'); assert.equal(result.interrupt, true);
  assert.equal(broken.pending, null); assert.equal(broken.closed, true);
});

test('qualification profile asks for every Read before native auto-approval', () => {
  assert.deepEqual(permissionProfile(), {tools:['Read'], permissionMode:'default',
    permissionPrompts:'host', settings:{permissions:{ask:['Read']}}});
  const mutable = permissionProfile(); mutable.settings.permissions.ask.length = 0;
  assert.deepEqual(permissionProfile().settings.permissions.ask, ['Read']);
});

test('pending close kills owned child before callback settlement or SDK disposal', async () => {
  const f = fixture(); const child = new EventEmitter(); const order = [];
  child.exitCode = null; child.signalCode = null;
  child.kill = signal => { order.push(signal); return true; };
  let timeout; let settled = false;
  f.result.then(() => { settled = true; order.push('settled'); });
  terminatePending({slot:f.slot, child, reason:'owned-process-exited',
    dispose:() => order.push('dispose'), fail:() => order.push('fail'),
    schedule:fn => { timeout = fn; return 1; }, unschedule:() => {}});
  await Promise.resolve(); assert.equal(settled, false);
  assert.equal(f.slot.decide(f.attention.identity, 'allow'), false);
  assert.deepEqual(order, ['SIGKILL']);
  child.signalCode = 'SIGKILL'; child.emit('exit', null, 'SIGKILL');
  await f.result;
  assert.deepEqual(order, ['SIGKILL', 'dispose', 'settled']);
  timeout(); assert(!order.includes('fail'));
});
test('failed pending termination times out without callback resolution or graceful close', async () => {
  for (const throws of [false, true]) {
    const f = fixture(); const child = new EventEmitter();
    child.exitCode = null; child.signalCode = null;
    child.kill = () => { if (throws) throw Error('kill failed'); return false; };
    let timeout, failed = false, settled = false;
    f.result.then(() => { settled = true; });
    terminatePending({slot:f.slot, child, reason:'close',
      dispose:() => assert.fail('must not gracefully release pending request'),
      fail:() => { failed = true; }, schedule:fn => { timeout = fn; return 1; }, unschedule:() => {}});
    timeout(); child.emit('exit'); await Promise.resolve();
    assert(failed); assert.equal(settled, false); assert.equal(child.listenerCount('exit'), 0);
    assert.equal(f.slot.decide(f.attention.identity, 'deny'), false);
  }
});

test('already exited native child disposes once without post-exit signaling', async () => {
  for (const status of [{exitCode:0, signalCode:null}, {exitCode:null, signalCode:'SIGTERM'}]) {
    const f = fixture(); const child = Object.assign(new EventEmitter(), status);
    child.kill = () => assert.fail('must never signal reaped native');
    let disposed = 0, timeout;
    terminatePending({slot:f.slot, child, reason:'native-exited', dispose:() => { disposed++; },
      fail:() => assert.fail('already exited'), schedule:fn => { timeout = fn; return 1; }, unschedule:() => {}});
    child.emit('exit'); timeout();
    assert.equal(disposed, 1); assert.equal((await f.result).message, 'native-exited');
    assert.equal(child.listenerCount('exit'), 0);
  }
});
test('controller, signals and error shutdown use the same pending exit barrier', async () => {
  for (const reason of ['fixture-controller-close', 'fixture-host-terminated',
    'fixture-host-interrupted', 'fixture-output-loss', 'fixture-unhandled-error']) {
    const f = fixture(); const child = Object.assign(new EventEmitter(), {exitCode:null, signalCode:null});
    let disposed = 0;
    // Mimic runner native-exit callback: recursive shutdown sees closing and
    // returns; the helper exit listener must still run and dispose exactly once.
    let closing = true;
    child.on('exit', () => { if (closing) return; assert.fail('unexpected restart'); });
    child.kill = () => { child.signalCode = 'SIGKILL'; child.emit('exit'); return true; };
    terminatePending({slot:f.slot, child, reason, dispose:() => { disposed++; },
      fail:() => assert.fail('termination failed'), schedule:() => 1, unschedule:() => {}});
    assert.equal(disposed, 1); assert.equal((await f.result).message, reason);
    assert.equal(f.slot.decide(f.attention.identity, 'allow'), false);
  }
});

test('termination owns settlement despite original signal abort before native exit', async () => {
  const f = fixture(); const child = Object.assign(new EventEmitter(), {exitCode:null, signalCode:null});
  child.kill = () => true;
  let disposed = 0, settled = false;
  f.result.then(() => { settled = true; });
  terminatePending({slot:f.slot, child, reason:'controller-close', dispose:() => { disposed++; },
    fail:() => assert.fail('unexpected timeout'), schedule:() => 1, unschedule:() => {}});
  f.abort.abort(); await Promise.resolve();
  assert.equal(settled, false); assert.equal(disposed, 0); assert(f.slot.pending);
  child.signalCode = 'SIGKILL'; child.emit('exit', null, 'SIGKILL');
  assert.equal((await f.result).message, 'controller-close');
  assert.equal(disposed, 1); child.emit('exit'); assert.equal(disposed, 1);
});
test('termination timeout retains unresolved callback even after late native abort', async () => {
  const f = fixture(); const child = Object.assign(new EventEmitter(), {exitCode:null, signalCode:null});
  child.kill = () => false;
  let timeout, failures = 0, settled = false;
  f.result.then(() => { settled = true; });
  terminatePending({slot:f.slot, child, reason:'controller-close', dispose:() => assert.fail('no graceful close'),
    fail:() => { failures++; }, schedule:fn => { timeout = fn; return 1; }, unschedule:() => {}});
  timeout(); f.abort.abort(); child.emit('exit'); await Promise.resolve();
  assert.equal(failures, 1); assert.equal(settled, false); assert(f.slot.pending);
  assert.equal(f.slot.decide(f.attention.identity, 'allow'), false);
});
