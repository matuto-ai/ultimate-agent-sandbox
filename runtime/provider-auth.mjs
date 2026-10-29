// Fixed native auth input. Never import ambient environment or print errors/data.
import * as fs from 'node:fs';
import path from 'node:path';

export function readProviderAuth(file, kind, provider, io = fs, uid = process.getuid()) {
  if (typeof file !== 'string' || !/^\/[A-Za-z0-9_./-]+\/providers\/[a-z][a-z0-9-]{0,63}\/(token|auth\.json)$/.test(file)
      || file.includes('/../') || file.includes('/./') || file.includes('//')) throw Error('provider-auth-unavailable');
  const parent = path.dirname(file);
  const info = io.lstatSync(parent);
  if (io.realpathSync(parent) !== parent || !info.isDirectory() || info.uid !== uid || info.mode & 0o077)
    throw Error('provider-auth-unavailable');
  const fd = io.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const node = io.fstatSync(fd);
    if (!node.isFile() || node.uid !== uid || node.mode & 0o077 || node.nlink !== 1
        || node.size < 1 || node.size > 16384) throw Error('provider-auth-unavailable');
    // Explicit bounded read even if another Room-local process grows the file.
    const bytes = Buffer.alloc(16385);
    let length = 0;
    while (length < bytes.length) {
      const n = io.readSync(fd, bytes, length, bytes.length - length, null);
      if (!n) break;
      length += n;
    }
    if (length > 16384) throw Error('provider-auth-unavailable');
    const value = bytes.subarray(0, length).toString('utf8'); bytes.fill(0);
    if (kind === 'claude-oauth-token' && file.endsWith('/token')) {
      const token = value.replace(/\n$/, '');
      if (!/^[\x21-\x7e]{16,8192}$/.test(token)) throw Error('provider-auth-unavailable');
      return token;
    }
    if (kind !== 'pi-oauth-json' || !file.endsWith('/auth.json')) throw Error('provider-auth-unavailable');
    const data = JSON.parse(value);
    if (!data || Array.isArray(data) || Object.keys(data).length !== 1 || !Object.hasOwn(data, provider))
      throw Error('provider-auth-unavailable');
    const auth = data[provider];
    if (!auth || auth.type !== 'oauth' || typeof auth.access !== 'string' || !auth.access
        || typeof auth.refresh !== 'string' || !auth.refresh || !Number.isFinite(auth.expires))
      throw Error('provider-auth-unavailable');
    // Native Pi owns refresh and its shared file lock. Return no credential bytes.
    return undefined;
  } finally { io.closeSync(fd); }
}
