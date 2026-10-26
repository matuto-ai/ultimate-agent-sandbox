// No dependencies or network: reject non-registry acquisition before npm runs.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const read = async name => JSON.parse(await readFile(new URL(name, import.meta.url), 'utf8'));
const manifest = await read('package.json');
const lock = await read('package-lock.json');
assert.equal(lock.lockfileVersion, 3);
assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
for (const [name, version] of Object.entries(manifest.dependencies)) {
  assert.match(name, /^@earendil-works\/(pi-ai|pi-coding-agent)$/);
  assert.equal(version, '1.4.0');
}
for (const [path, item] of Object.entries(lock.packages)) {
  if (!path) continue;
  assert.ok(path.startsWith('node_modules/'));
  const url = new URL(item.resolved);
  assert.equal(url.origin, 'https://registry.npmjs.org');
  assert.equal(url.username, ''); assert.equal(url.password, '');
  assert.match(item.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
  assert.equal(item.link, undefined);
}
console.log(`Verified official-registry URLs and SHA-512 integrities for ${Object.keys(lock.packages).length - 1} locked dependencies.`);
