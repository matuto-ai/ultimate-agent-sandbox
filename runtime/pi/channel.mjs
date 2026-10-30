// Linux fixture only. Raw inherited SOCK_SEQPACKET, never a Node stream/socket.
// Kernel credentials remain per record at the Supervisor's recvmsg endpoint.
import { readSync, writeSync, closeSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';

export const MAX_PACKET = 65536;
export const MAX_REPLY = 1048576;
export const MAX_REQUEST = 1114112;
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
    if (packet.length > MAX_REQUEST || (packet.length > MAX_PACKET && !['forge-write','forge-reconcile','library.enqueue'].includes(envelope.kind))) throw Error('fixture peer packet too large');
    const packets = packet.length <= MAX_PACKET ? [packet] : Array.from({ length: Math.ceil(packet.length / 40000) }, (_, index) =>
      Buffer.from(JSON.stringify({ ...(envelope.kind==='library.enqueue'?{kind:'library.enqueue'}:{}), request_id: requestId, index, count: Math.ceil(packet.length / 40000),
        sha256: createHash('sha256').update(packet).digest('hex'), data: packet.subarray(index * 40000, (index + 1) * 40000).toString('base64') })));
    for (const frame of packets) for (;;) {
      check(deadline, signal);
      try {
        if (writeSync(fd, frame, 0, frame.length, null) !== frame.length) fail('short record write');
        break;
      } catch (error) {
        if (!retryable(error)) fail(error.message);
        await delay(Math.min(5, Math.max(1, deadline - performance.now())));
      }
    }
    // +1 detects overlength even when read(2) discards a packet's remainder.
    // A MAX-sized buffer could accept an oversized JSON-prefix packet silently.
    const buffer = Buffer.alloc(MAX_PACKET + 1);
    let chunks = [], chunkBytes = 0, chunkScope = null;
    for (;;) {
      check(deadline, signal);
      let count;
      try { count = readSync(fd, buffer, 0, buffer.length, null); }
      catch (error) {
        if (!retryable(error)) fail(error.message);
        await delay(Math.min(5, Math.max(1, deadline - performance.now())));
        continue;
      }
      if (!count || count > MAX_PACKET) fail('EOF or oversized reply');
      let reply;
      try { reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, count))); }
      catch { fail('invalid reply'); }
      if (reply && typeof reply === 'object' && Object.hasOwn(reply, 'data')) {
        if (!['forge-read','forge-write','forge-reconcile'].includes(envelope.kind) || Object.keys(reply).sort().join(',') !== 'count,data,index,request_id,sha256'
            || reply.request_id !== requestId || !Number.isInteger(reply.index) || reply.index !== chunks.length
            || !Number.isInteger(reply.count) || reply.count < 1 || reply.count > 27
            || typeof reply.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(reply.sha256)
            || typeof reply.data !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(reply.data)) {
          fail('invalid read chunk');
        }
        const scope = `${reply.count}:${reply.sha256}`;
        if (chunkScope !== null && chunkScope !== scope) fail('changed read chunks');
        chunkScope = scope;
        const part = Buffer.from(reply.data, 'base64');
        if (part.length > 40000 || (reply.index + 1 < reply.count && part.length !== 40000)) fail('invalid chunk size');
        chunkBytes += part.length;
        if (chunkBytes > MAX_REPLY) fail('oversized read response');
        chunks.push(part);
        if (chunks.length < reply.count) continue;
        const joined = Buffer.concat(chunks);
        if (createHash('sha256').update(joined).digest('hex') !== reply.sha256) fail('read response digest mismatch');
        try { reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(joined)); }
        catch { fail('invalid assembled read response'); }
      } else if (chunks.length) fail('incomplete read chunks');
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
