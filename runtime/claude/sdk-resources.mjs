// Resource guards for the fixed SDK fixture host, independently fault-testable.
import {MAX_FRAME} from './sdk-policy.mjs';

export function closeOwned({input, queries, query, child, finish, schedule = setTimeout}) {
  // Install the final disposition BEFORE any third-party/library cleanup.
  const timer = schedule(() => {
    try { if (child?.exitCode === null) child.kill('SIGKILL'); }
    finally { finish(); }
  }, 2200);
  timer.unref?.();
  try { input?.end(); } catch {}
  for (const process of queries) { try { process.kill('SIGKILL'); } catch {} }
  try { query?.close(); } catch {}
  return timer;
}

export function collectListing(process, tracked, timeout = 1500) {
  tracked.add(process);
  let size = 0; const chunks = [];
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (error, value) => {
      if (settled) return;
      settled = true; clearTimeout(timer); tracked.delete(process);
      if (error) reject(error); else resolve(value);
    };
    const kill = () => { try { process.kill('SIGKILL'); } catch {} };
    const timer = setTimeout(() => { kill(); done(new Error('listing-timeout')); }, timeout);
    const collect = (data, stdout) => {
      if (settled) return;
      size += data.length;
      if (size > MAX_FRAME) { kill(); done(new Error('listing-output-limit')); }
      else if (stdout) chunks.push(data);
    };
    process.stdout.on('data', data => collect(data, true));
    process.stderr.on('data', data => collect(data, false));
    process.once('error', error => done(error));
    process.once('close', code => {
      if (settled) return;
      if (code !== 0) return done(new Error('listing-failed'));
      try { done(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { done(new Error('listing-schema')); }
    });
  });
}
