import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {closeOwned, collectListing, validateLoopback} from '../../runtime/claude/sdk-resources.mjs';
import {MAX_FRAME} from '../../runtime/claude/sdk-policy.mjs';

test('namespace interface guard rejects extra interfaces including down or IPv6-only ones', () => {
  const devices = 'Inter-| Receive | Transmit\n face | bytes | bytes\n lo: 0 0\n';
  assert.doesNotThrow(() => validateLoopback(devices, 'Iface Destination\n', ':: :: lo\n'));
  for (const extra of ['eth0', 'down0', 'ipv6only0'])
    assert.throws(() => validateLoopback(devices + ` ${extra}: 0 0\n`, 'Iface Destination\n', ''), /namespace-required/);
  assert.throws(() => validateLoopback(devices, 'Iface Destination\neth0 0\n', ''), /external-route/);
  assert.throws(() => validateLoopback(devices, 'Iface Destination\n', ':: :: eth0\n'), /external-route/);
  assert.throws(() => validateLoopback('lo', '', ''), /network-schema/);
  assert.throws(() => validateLoopback('x'.repeat(MAX_FRAME + 1), '', ''), /network-schema/);
});

test('synchronous SDK/input/query-child close failures cannot bypass final native disposition', () => {
  const events = []; let final;
  closeOwned({
    input: {end() { events.push('input'); throw Error('injected input close'); }},
    queries: [{kill() { events.push('listing'); throw Error('injected listing kill'); }}],
    query: {close() { events.push('sdk'); throw Error('injected SDK close'); }},
    child: {exitCode: null, kill(signal) { events.push(signal); throw Error('injected native kill'); }},
    finish: () => events.push('finished'),
    schedule: (callback, delay) => { assert.equal(delay, 2200); events.push('timer'); final = callback; return {}; }
  });
  assert.deepEqual(events, ['timer', 'input', 'listing', 'sdk']);
  assert.throws(final, /injected native kill/);
  assert.deepEqual(events.slice(-2), ['SIGKILL', 'finished']);
});

function child() {
  const p = new EventEmitter(); p.stdout = new PassThrough(); p.stderr = new PassThrough();
  p.kills = 0; p.kill = () => { p.kills++; }; return p;
}
test('listing spawn error promptly removes tracking and clears its timer', async () => {
  const p = child(), tracked = new Set();
  const result = collectListing(p, tracked, 20);
  p.emit('error', Error('injected spawn failure'));
  await assert.rejects(result, /injected spawn failure/);
  assert.equal(tracked.size, 0);
  await new Promise(resolve => setTimeout(resolve, 35));
  assert.equal(p.kills, 0);
  p.emit('close', -1); // Late close cannot resolve/reject twice or re-add tracking.
});
test('listing success, invalid output, output cap and timeout all release tracking', async () => {
  for (const mode of ['success', 'invalid', 'oversized', 'timeout']) {
    const p = child(), tracked = new Set(); const result = collectListing(p, tracked, 20);
    if (mode === 'success') { p.stdout.end('[]'); p.emit('close', 0); assert.deepEqual(await result, []); }
    else {
      if (mode === 'invalid') { p.stdout.end('{'); p.emit('close', 0); }
      if (mode === 'oversized') p.stderr.write(Buffer.alloc(MAX_FRAME + 1));
      await assert.rejects(result, /listing-/);
      if (['oversized', 'timeout'].includes(mode)) assert.equal(p.kills, 1);
    }
    assert.equal(tracked.size, 0);
  }
});
