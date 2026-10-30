import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const read=p=>JSON.parse(readFileSync(new URL(p,import.meta.url)));
const lock=read('./package-lock.json'), pi=read('../../pi/package-lock.json');
assert.equal(lock.lockfileVersion,3);
assert.deepEqual(Object.keys(lock.packages).sort(),['','node_modules/yaml']);
assert.deepEqual(lock.packages['node_modules/yaml'],pi.packages['node_modules/yaml']);
assert.deepEqual(read('./package.json').dependencies,{yaml:pi.packages['node_modules/yaml'].version});
