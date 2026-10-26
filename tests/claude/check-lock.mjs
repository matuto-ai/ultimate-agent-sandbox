import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url)));
assert.equal(lock.lockfileVersion, 3);
assert.equal(lock.packages[''].dependencies['@anthropic-ai/claude-code'], '2.1.310');
for (const [name, item] of Object.entries(lock.packages)) {
  if (!name) continue;
  assert.match(name, /^node_modules\/@anthropic-ai\/claude-code(?:-[a-z0-9-]+)?$/);
  assert.equal(item.version, '2.1.310');
  assert(item.resolved.startsWith('https://registry.npmjs.org/@anthropic-ai/'));
  assert.match(item.integrity, /^sha512-[A-Za-z0-9+/]+=*$/);
}
assert.equal(lock.packages['node_modules/@anthropic-ai/claude-code'].integrity,
  'sha512-EySpBwaocdU1nc9r7JH+GOlnMsbXc764d3HX7NL8fr7qqdxz2MiXI9hqf/rzeE/XgU23HHFltIqhb+Fq6G1CVw==');
