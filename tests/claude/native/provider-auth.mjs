// Pure fixed-auth validation: synthetic bytes only, no files/processes/providers.
import assert from 'node:assert/strict';
import {readProviderAuth} from '../../../runtime/provider-auth.mjs';
function source(text,changes={}) {
  let cursor=0,closed=false;
  return {lstatSync:()=>({isDirectory:()=>true,uid:42,mode:0o700}),realpathSync:x=>x,
    openSync:()=>7,fstatSync:()=>({isFile:()=>true,uid:42,mode:0o600,nlink:1,size:Buffer.byteLength(text),...changes}),
    readSync:(_fd,buffer,offset,length)=>{const data=Buffer.from(text);const n=Math.min(length,data.length-cursor);data.copy(buffer,offset,cursor,cursor+n);cursor+=n;return n;},
    closeSync:()=>{closed=true;},get closed(){return closed;}};
}
const token='/runtime/providers/subscription/token';
const io=source('synthetic-oauth-token-123\n');
assert.equal(readProviderAuth(token,'claude-oauth-token',undefined,io,42),'synthetic-oauth-token-123');
assert.equal(io.closed,true);
for(const change of [{uid:0},{mode:0o644},{isFile:()=>false},{nlink:2},{size:17000}]) {
 const f=source('synthetic-oauth-token-123',change);
 assert.throws(()=>readProviderAuth(token,'claude-oauth-token',undefined,f,42));assert.equal(f.closed,true);
}
const auth={"openai-codex":{type:'oauth',access:'synthetic-access',refresh:'synthetic-refresh',expires:1}};
assert.equal(readProviderAuth('/runtime/providers/subscription/auth.json','pi-oauth-json','openai-codex',source(JSON.stringify(auth)),42),undefined);
assert.throws(()=>readProviderAuth('/runtime/providers/subscription/auth.json','pi-oauth-json','anthropic',source(JSON.stringify(auth)),42));
assert.throws(()=>readProviderAuth('/runtime/providers/../token','claude-oauth-token',undefined,source('synthetic-oauth-token-123'),42));
assert.throws(()=>readProviderAuth(token,'claude-oauth-token',undefined,source('x'.repeat(17000),{size:10}),42));

import {oauthStore} from '../../../runtime/pi/provider-store.mjs';
let saved=JSON.stringify(auth), writes=0, locked=false, checks=0;
const backend={withLockAsync:async fn=>{locked=true;try{const result=await fn(saved);if(result.next!==undefined){saved=result.next;writes++;}return result.result;}finally{locked=false;}}};
const store=oauthStore(backend,'openai-codex',()=>{checks++;});
assert.equal((await store.read('openai-codex')).type,'oauth');
assert.equal(await store.read('anthropic'),undefined);
await store.modify('openai-codex',async current=>{assert.equal(locked,true);return {...current,access:'fresh-synthetic',expires:2};});
assert.equal(writes,1);assert.equal((await store.read('openai-codex')).access,'fresh-synthetic');
saved=JSON.stringify({'openai-codex':{type:'api_key',key:'!must-never-execute'}});
await assert.rejects(()=>store.read('openai-codex'),/provider-auth-unavailable/);
await assert.rejects(()=>store.modify('openai-codex',()=>{throw Error('must-not-be-called');}),/provider-auth-unavailable/);
assert.equal(writes,1);assert.ok(checks>=5);
saved='{}';await assert.rejects(()=>store.list(),/provider-auth-unavailable/);
