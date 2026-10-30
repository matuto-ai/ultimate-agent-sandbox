// Hosted import compatibility, not provider/native lifecycle qualification.
// Runs in existing network-denied Pi CI, with no auth store construction.
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const root=process.env.UAS_PI_INSTALL+'/node_modules/@earendil-works/pi-coding-agent';
const sdk=await import(pathToFileURL(root+'/dist/index.js'));
for(const name of ['ModelRuntime','SettingsManager','SessionManager','createAgentSessionServices',
    'createAgentSessionFromServices','createAgentSessionRuntime','runRpcMode']) assert.equal(typeof sdk[name],'function',name);
// Deliberately pinned internal compatibility surface, not package public export.
const native=await import(pathToFileURL(root+'/dist/core/auth-storage.js'));
assert.equal(typeof native.FileAuthStorageBackend,'function');
assert.equal(typeof native.FileAuthStorageBackend.prototype.withLockAsync,'function');
assert.equal(typeof sdk.ModelRuntime.create,'function');
assert.equal(typeof sdk.SettingsManager.inMemory,'function');
