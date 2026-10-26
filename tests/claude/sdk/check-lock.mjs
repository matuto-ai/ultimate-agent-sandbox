import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url)));
assert.equal(lock.lockfileVersion, 3);
assert.equal(lock.packages[''].dependencies['@anthropic-ai/claude-agent-sdk'], '0.3.310');
for (const [name, item] of Object.entries(lock.packages)) {
  if (!name) continue;
  assert.match(name, /^node_modules\/@anthropic-ai\/claude-agent-sdk(?:-[a-z0-9-]+)?$/);
  assert.equal(item.version, '0.3.310');
  assert(item.resolved.startsWith('https://registry.npmjs.org/@anthropic-ai/'));
  assert.match(item.integrity, /^sha512-[A-Za-z0-9+/]+=*$/);
}
assert.equal(lock.packages['node_modules/@anthropic-ai/claude-agent-sdk'].integrity,
  'sha512-fo+sr+9Ks73P001f6XKRQlyzfIBAJMgXArLUkH5Tu98NikRDZeGtFQVj23d5/hj2ijpFgzffrr4fHywY9qUkoQ==');
