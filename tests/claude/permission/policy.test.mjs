import test from 'node:test';
import assert from 'node:assert/strict';
import {PermissionSlot, exactRead} from './policy.mjs';

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
