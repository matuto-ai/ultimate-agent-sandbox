// Build-stage only. Fixed inventory is generated from the reviewed recipe source.
// No runtime launch, account access, network, or final image identity here.
import {readFileSync, lstatSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const all = JSON.parse(readFileSync('/build/native-inventory.json', 'utf8'));
const canonical = x => JSON.stringify(x, (_, v) => v && !Array.isArray(v) && typeof v === 'object'
  ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : v);
for (const runtime of ['pi', 'claude']) {
  const {paths, ...metadata} = all[runtime];
  const artifacts = {};
  for (const file of paths) {
    if (!file.startsWith('/opt/uas/') || file.includes('/../')) throw Error('invalid-artifact');
    const info = lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink()) throw Error('nonregular-artifact');
    artifacts[file] = createHash('sha256').update(readFileSync(file)).digest('hex');
  }
  writeFileSync(`/opt/uas/${runtime}-manifest.json`, canonical({...metadata, artifacts}), {flag:'wx', mode:0o444});
}
