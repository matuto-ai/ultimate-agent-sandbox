// Evaluate the actual entry body with controlled native boundaries; no SDK/provider.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../../../runtime/pi/native-entry.mjs',import.meta.url),'utf8');
const body=source.replace(/^import .*;\n/gm,'');
for(const cwd of ['/wrong','/owned/checkout']) {
  let auth=0, exits=[], errors=[];
  const denied=()=>{throw Error('unexpected-effect');};
  const sandbox={Error,process:{argv:['node','entry','/owned/checkout','/runtime/sessions','provider','model','/runtime/auth'],
    env:{UAS_PI_NATIVE:'1',UAS_PI_PEER_FD:'3',UAS_PI_FORGE_FD:'4'},cwd:()=>cwd,
    stderr:{write:x=>errors.push(x)},exit:x=>exits.push(x)},
    fstatSync:()=>({isSocket:()=>true}),mkdirSync:denied,realpathSync:denied,lstatSync:denied,
    readProviderAuth:()=>{auth++;throw Error('controlled-auth-stop');},oauthStore:denied,path:{dirname:denied}};
  await vm.runInNewContext('(async()=>{'+body+'})()',sandbox,{timeout:1000});
  assert.equal(auth,cwd==='/wrong'?0:1);
  assert.deepEqual(exits,[125]);assert.deepEqual(errors,['native-pi-provider-startup-unavailable\n']);
}
