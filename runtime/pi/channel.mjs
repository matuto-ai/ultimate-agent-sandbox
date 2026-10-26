// Linux fixture only. Raw inherited SOCK_SEQPACKET, never a Node stream/socket.
// Kernel credentials remain per record at the Supervisor's recvmsg endpoint.
import { readSync, writeSync, closeSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';

export const MAX_PACKET = 65536;
export const MAX_REPLY = 65536;
const retryable = error => ['EAGAIN', 'EWOULDBLOCK', 'EINTR'].includes(error.code);

export function seqpacketChannel(fd, { timeoutMs = 2000, maxQueued = 4 } = {}) {
  if (!Number.isInteger(fd) || fd < 3 || !Number.isInteger(timeoutMs) || timeoutMs < 1
      || timeoutMs > 10000 || !Number.isInteger(maxQueued) || maxQueued < 1 || maxQueued > 16) {
    throw Error('invalid fixture channel configuration');
  }
  let fenced = false, closed = false, queued = 0, tail = Promise.resolve();
  const fail = reason => { fenced = true; throw Error(`fixture peer channel fenced: ${reason}`); };
  function check(deadline, signal) {
    if (fenced) throw Error('fixture peer channel fenced; replace process');
    if (signal?.aborted) fail('request aborted; outcome may be unknown');
    if (performance.now() >= deadline) fail('deadline; outcome may be unknown');
  }
  async function exchange(envelope, deadline, signal) {
    check(deadline, signal);
    const requestId = randomUUID().replaceAll('-', '');
    const packet = Buffer.from(JSON.stringify({ request_id: requestId, envelope }));
    if (packet.length > MAX_PACKET) throw Error('fixture peer packet too large');
    for (;;) {
      check(deadline, signal);
      try {
        // Exactly one record. Never write a remainder as a second packet.
        if (writeSync(fd, packet, 0, packet.length, null) !== packet.length) fail('short record write');
        break;
      } catch (error) {
        if (!retryable(error)) fail(error.message);
        await delay(Math.min(5, Math.max(1, deadline - performance.now())));
      }
    }
    // +1 detects overlength even when read(2) discards a packet's remainder.
    // A MAX-sized buffer could accept an oversized JSON-prefix packet silently.
    const buffer = Buffer.alloc(MAX_REPLY + 1);
    for (;;) {
      check(deadline, signal);
      let count;
      try { count = readSync(fd, buffer, 0, buffer.length, null); }
      catch (error) {
        if (!retryable(error)) fail(error.message);
        await delay(Math.min(5, Math.max(1, deadline - performance.now())));
        continue;
      }
      if (!count || count > MAX_REPLY) fail('EOF or oversized reply');
      let reply;
      try { reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, count))); }
      catch { fail('invalid reply'); }
      if (!reply || typeof reply !== 'object' || Array.isArray(reply)
          || reply.request_id !== requestId || typeof reply.ok !== 'boolean'
          || (reply.ok ? !reply.receipt || typeof reply.receipt !== 'object' || Array.isArray(reply.receipt) : typeof reply.error !== 'string')
          || Object.keys(reply).sort().join(',') !== (reply.ok ? 'ok,receipt,request_id' : 'error,ok,request_id')) {
        fail('uncorrelated or malformed reply');
      }
      return reply;
    }
  }
  return {
    request(envelope, { signal, timeoutMs: requestTimeoutMs = timeoutMs } = {}) {
      if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 45000) {
        return Promise.reject(Error('invalid fixture request deadline'));
      }
      if (fenced) return Promise.reject(Error('fixture peer channel fenced; replace process'));
      if (queued >= maxQueued) return Promise.reject(Error('fixture peer queue full'));
      queued++;
      const deadline = performance.now() + requestTimeoutMs;
      const task = tail.then(() => exchange(envelope, deadline, signal));
      tail = task.catch(() => {});
      return task.finally(() => { queued--; });
    },
    close() {
      if (closed) return;
      closed = true;
      fenced = true;
      try { closeSync(fd); } catch { /* Already closed by native shutdown. */ }
    },
    get fenced() { return fenced; },
  };
}
