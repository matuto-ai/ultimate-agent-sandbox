// Disposable actual Node transport probe; no Pi/native acceptance claims here.
import { seqpacketChannel } from '../../runtime/pi/channel.mjs';
const [fd, mode, argument] = process.argv.slice(2);
const channel = seqpacketChannel(Number(fd), { timeoutMs: 250 });
let ticks = 0;
const timer = setInterval(() => ticks++, 5);
try {
  const envelope = mode === 'size' ? { data: 'x'.repeat(Number(argument)) } : { test: mode };
  if (mode === 'queue') {
    const results = await Promise.allSettled(Array.from({ length: 5 }, () => channel.request(envelope)));
    process.stdout.write(JSON.stringify({ results, ticks, fenced: channel.fenced }) + '\n');
  } else {
    let result, error;
    try { result = await channel.request(envelope); } catch (caught) { error = caught.message; }
    let second;
    if (mode === 'twice') {
      try { second = await channel.request(envelope); } catch (caught) { second = caught.message; }
    }
    process.stdout.write(JSON.stringify({ result, error, second, ticks, fenced: channel.fenced }) + '\n');
  }
} finally { clearInterval(timer); channel.close(); }
