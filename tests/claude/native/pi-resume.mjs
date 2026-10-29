// Actual entry body, controlled filesystem/SDK only. Never load credentials or a provider.
// Hosted test: this file is not evidence that the selected image ran.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
const source=readFileSync(new URL('../../../runtime/pi/native-entry.mjs',import.meta.url),'utf8');
const body=source.replace(/^import .*;\n/gm,'')
  .replace("await import('/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/dist/index.js')",'injectedSDK')
  .replace("await import('/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/dist/core/auth-storage.js')",'({FileAuthStorageBackend:InjectedBackend})');
const cwd='/owned/checkout', sessions='/runtime/contexts/1/sessions', file=sessions+'/prior.jsonl', id='prior-session';
async function run(change={}) {
  const header={type:'session',version:3,id,cwd,...change.header};
  const bytes=Buffer.from(change.bytes ?? JSON.stringify(header)+'\n');
  const calls={open:0,create:0,mkdir:0,closed:0,rpc:0,models:0}, exits=[], errors=[];
  let sdkOpened=false, runtimeOptions;
  const info=()=>({dev:1,ino:2,size:bytes.length+(change.changed && sdkOpened?1:0),mtimeMs:1,ctimeMs:1,
    uid:1000,mode:change.writableFile?0o100664:0o100644,nlink:1,isFile:()=>true});
  const directory={uid:1000,mode:0o40700,isDirectory:()=>true};
  const manager={getSessionId:()=>change.resultId ?? id,getSessionFile:()=>file,getSessionDir:()=>sessions,
    getCwd:()=>cwd,getHeader:()=>header};
  const sdk={SessionManager:{
    open:(...args)=>{calls.open++;assert.deepEqual(args,[file,sessions,cwd]);sdkOpened=true;return manager;},
    create:(...args)=>{calls.create++;assert.deepEqual(args,[cwd,sessions]);return manager;}},
    ModelRuntime:{create:async()=>{calls.models++;return {getModel:(provider,id)=>({provider,id})};}},
    SettingsManager:{inMemory:value=>value},
    createAgentSessionServices:async options=>{
      assert.equal(JSON.stringify(options.settingsManager),'{}');
      for (const flag of ['noExtensions','noSkills','noPromptTemplates','noThemes','noContextFiles'])
        assert.equal(options.resourceLoaderOptions[flag],true);
      return {diagnostics:[]};
    },
    createAgentSessionFromServices:async()=>({session:{},modelFallbackMessage:false}),
    createAgentSessionRuntime:async(factory,options)=>{runtimeOptions=options;return await factory(options);},
    runRpcMode:async()=>{calls.rpc++;}};
  const argv=['node','entry',cwd,sessions,'provider','model','/runtime/auth'];
  if (!change.fresh) argv.push(file,id);
  if (change.partial) argv.pop();
  const sandbox={Error,Buffer,path,injectedSDK:sdk,InjectedBackend:class {},AbortSignal:{timeout:()=>({})},
    process:{argv,env:{UAS_PI_NATIVE:'1',UAS_PI_PEER_FD:'3',UAS_PI_FORGE_FD:'4'},
      cwd:()=>cwd,getuid:()=>1000,stderr:{write:value=>errors.push(value)},exit:value=>exits.push(value)},
    constants:{O_RDONLY:1,O_NOFOLLOW:2,O_NONBLOCK:4},
    mkdirSync:(name,options)=>{assert.equal(name,'/runtime/contexts/1/agent');assert.equal(options.mode,0o700);calls.mkdir++;},
    realpathSync:name=>change.alias && name===file?'/other/file.jsonl':name,
    lstatSync:name=>name===file?info():name===sessions?{...directory,mode:change.writableSessions?0o40775:0o40755}:directory,
    fstatSync:fd=>fd===9?info():{isSocket:()=>true},
    openSync:(name,flags)=>{assert.equal(name,file);assert.equal(flags,7);if(change.missing)throw Error('missing');return 9;},
    closeSync:fd=>{assert.equal(fd,9);calls.closed++;},
    readSync:(fd,target,offset,length,position)=>{assert.equal(fd,9);return bytes.copy(target,offset,position,position+length);},
    readProviderAuth:()=>({}),oauthStore:()=>({})};
  await vm.runInNewContext('(async()=>{'+body+'})()',sandbox,{timeout:1000});
  return {calls,exits,errors,runtimeOptions};
}
const success=await run();
assert.deepEqual(success.calls,{open:1,create:0,mkdir:0,closed:1,rpc:1,models:1});
assert.deepEqual(success.exits,[]);
assert.equal(JSON.stringify(success.runtimeOptions.sessionStartEvent),JSON.stringify({type:'session_start',reason:'resume'}));
const fresh=await run({fresh:true});
assert.deepEqual(fresh.calls,{open:0,create:1,mkdir:1,closed:0,rpc:1,models:1});
assert.equal(fresh.runtimeOptions.sessionStartEvent,undefined);
for (const change of [{missing:true},{bytes:''},{bytes:'not-json\n'},
    {bytes:JSON.stringify({type:'session',version:3,id,cwd})},
    {header:{version:2}},{header:{id:'other'}},{header:{cwd:'/other'}},
    {header:{type:'message'}},{alias:true},{partial:true},{writableFile:true},{writableSessions:true}]) {
  const failed=await run(change);
  assert.equal(failed.calls.open,0,JSON.stringify(change));
  assert.equal(failed.calls.create,0);assert.equal(failed.calls.rpc,0);assert.equal(failed.calls.models,0);
  assert.deepEqual(failed.exits,[125]);assert.deepEqual(failed.errors,['native-pi-provider-startup-unavailable\n']);
}
for (const change of [{resultId:'fallback-session'},{changed:true}]) {
  const failed=await run(change);
  assert.equal(failed.calls.open,1);assert.equal(failed.calls.create,0);assert.equal(failed.calls.rpc,0);
  assert.equal(failed.calls.models,0);assert.equal(failed.calls.closed,1);assert.deepEqual(failed.exits,[125]);
}
