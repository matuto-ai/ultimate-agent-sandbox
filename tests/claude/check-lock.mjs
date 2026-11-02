import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
// Native probes already target the Linux x64 glibc binary explicitly. Do not
// silently acquire another platform or rely on optional platform selection.
assert.equal(process.platform, 'linux', 'Claude fixture requires Linux x64 glibc');
assert.equal(process.arch, 'x64', 'Claude fixture requires Linux x64 glibc');
assert(process.report.getReport().header.glibcVersionRuntime,
  'Claude fixture requires Linux x64 glibc');
const manifest = JSON.parse(readFileSync(new URL('./package.json', import.meta.url)));
const expected = {'@anthropic-ai/claude-code': '2.1.310',
  '@anthropic-ai/claude-code-linux-x64': '2.1.310'};
assert.deepEqual(manifest.dependencies, expected);
const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url)));
assert.equal(lock.lockfileVersion, 3);
assert.deepEqual(lock.packages[''].dependencies, expected);
const binary = lock.packages['node_modules/@anthropic-ai/claude-code-linux-x64'];
assert.equal(binary.optional, undefined);
assert.deepEqual(binary.os, ['linux']);
assert.deepEqual(binary.cpu, ['x64']);
assert.equal(binary.integrity,
  'sha512-CuzpJrMBbqaR3+1SiLrBtPV3w/cFvcqBfhe9kNskzZ2Fm6KXa7v0l7tM+Ln6l5QLb79WoU0CcacXnYtsygbe6A==');
for (const [name, item] of Object.entries(lock.packages)) {
  if (!name) continue;
  assert.match(name, /^node_modules\/@anthropic-ai\/claude-code(?:-[a-z0-9-]+)?$/);
  assert.equal(item.version, '2.1.310');
  assert(item.resolved.startsWith('https://registry.npmjs.org/@anthropic-ai/'));
  assert.match(item.integrity, /^sha512-[A-Za-z0-9+/]+=*$/);
}
assert.equal(lock.packages['node_modules/@anthropic-ai/claude-code'].integrity,
  'sha512-EySpBwaocdU1nc9r7JH+GOlnMsbXc764d3HX7NL8fr7qqdxz2MiXI9hqf/rzeE/XgU23HHFltIqhb+Fq6G1CVw==');
