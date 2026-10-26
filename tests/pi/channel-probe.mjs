// Test-only real Node child receiving a duplicate of Pi's authority descriptor.
// No claim that a transferable descriptor grants the parent's badge.
import { readSync, writeSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
const fd = Number(process.argv[2]);
const data = Buffer.from(process.argv[3], 'base64url');
const deadline = Date.now() + 2000;
for (;;) {
  try { if (writeSync(fd, data) !== data.length) throw Error('short write'); break; }
  catch (e) { if (e.code !== 'EAGAIN' || Date.now() > deadline) throw e; await delay(5); }
}
process.stdout.write(JSON.stringify({ sent: true, pid: process.pid }) + '\n');
for (;;) {
  try {
    const buffer = Buffer.alloc(65537), n = readSync(fd, buffer, 0, buffer.length, null);
    process.stdout.write(buffer.subarray(0, n).toString() + '\n');
    break;
  } catch (e) { if (e.code !== 'EAGAIN' || Date.now() > deadline) throw e; await delay(5); }
}
