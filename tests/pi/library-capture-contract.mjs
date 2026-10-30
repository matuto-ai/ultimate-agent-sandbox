import assert from 'node:assert/strict';
import {libraryCaptureTool} from '../../runtime/pi/extension.mjs';
const input={request_id:'same-id',capture:{type:'context',title:'Exact_title',body:'Exact body\n',sources:[]}};
const receipt={outcome:'NOT_DURABLE',request_id:'same-id',reason:'LIBRARY_UNAVAILABLE',retryable:true,
  queue_id:null,path:null,published_sha:null,projection_sha:null,visible:false};
const calls=[]; const tool=libraryCaptureTool({request:async (e,o)=>{calls.push([e,o]);return {ok:true,receipt};}});
const a=await tool.execute('call',input);const b=await tool.execute('call',input);
assert.deepEqual(calls[0][0].capture,input.capture);assert.equal(calls[0][0].request_id,input.request_id);
assert.notEqual(a.details.command_id,b.details.command_id);assert.equal(a.details.outcome,'NOT_DURABLE');
assert.equal(a.details.retryable,true);assert.equal(calls[0][1].timeoutMs,45000);
for(const channel of [null,{request:async()=>{throw Error('SECRET');}},{request:async()=>({ok:true,receipt:{...receipt,outcome:'DURABLY_QUEUED'}})},
 {request:async()=>({ok:true,receipt:{...receipt,request_id:'other'}})}, {request:async()=>({ok:false,error:'SECRET details'})}]) {
 const r=await libraryCaptureTool(channel).execute('call',input);
 assert.equal(r.details.status,'TRANSPORT_UNAVAILABLE');assert.equal(r.details.request_id,'same-id');
 assert.equal('outcome' in r.details,false);assert.equal(JSON.stringify(r).includes('SECRET'),false);
}
for(const key of ['project_id','actor_id','path','status','frontmatter','request_id']) {
 const r=await tool.execute('call',{...input,capture:{...input.capture,[key]:'wrong'}});
 assert.equal(r.details.status,'ADAPTER_REJECTED');assert.equal('outcome' in r.details,false);
}
const no=await libraryCaptureTool({request:async()=>({ok:false,error:'FORBIDDEN'})}).execute('call',input);
assert.equal(no.details.status,'HUB_REFUSED');assert.equal(no.details.retryable,false);assert.equal('outcome' in no.details,false);
console.log('Pi explicit capture adapter contracts passed');
