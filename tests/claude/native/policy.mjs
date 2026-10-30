// Pure JS tests; no process/socket/SDK/client creation.
import assert from 'node:assert/strict';
import {nativeOptions,NativeToolState,TOOL_NAMES,requireMcp} from '../../../runtime/claude/native-policy.mjs';
import {envelope,invoke,negotiateProtocol} from '../../../runtime/claude/mcp-tools.mjs';
const session='11111111-1111-4111-8111-111111111111', id='22222222-2222-4222-8222-222222222222';
const p=nativeOptions({binary:'/opt/uas/claude/claude',cwd:'/project',home:'/runtime',model:'claude-sonnet-4-6',sessionId:session,helper:'/opt/uas/bin/claude-mcp-connector',endpoint:'/transport/peer'});
assert.equal(p.maxTurns,16); assert.deepEqual(p.settingSources,[]); assert.equal(p.strictMcpConfig,true); assert.deepEqual(p.tools,[]);
assert.equal(p.mcpServers.uas.command,'/opt/uas/bin/claude-mcp-connector');
assert.throws(()=>nativeOptions({...p,binary:'/project/evil'}));
assert.throws(()=>requireMcp([])); assert.throws(()=>requireMcp([{name:'other',status:'connected'}]));
const state=new NativeToolState(session);
state.event({type:'system',subtype:'init',session_id:session,claude_code_version:'2.1.310',tools:[...TOOL_NAMES],mcp_servers:[{name:'uas',status:'connected'}]});
assert.equal(state.initialized,true); state.begin(id,'request');
state.event({type:'user',session_id:session,uuid:id,isReplay:true,parent_tool_use_id:null,message:{role:'user',content:'request'}});
state.event({type:'assistant',session_id:session,user_message_uuid:id,parent_tool_use_id:null,message:{role:'assistant',content:[{type:'tool_use',name:'mcp__uas__gh',id:'tool1'}]}});
assert.equal(state.state(),'busy');
state.event({type:'user',session_id:session,parent_tool_use_id:null,message:{role:'user',content:[{type:'tool_result',tool_use_id:'tool1',content:'ok'}]}});
assert.equal(state.tools.size,0); assert.equal(state.fenced,null);
state.event({type:'assistant',session_id:session,parent_tool_use_id:null,message:{role:'assistant',content:[{type:'text',text:'done'}]}});
assert.equal(state.fenced,null);
state.event({type:'user',session_id:session,parent_tool_use_id:null,message:{role:'user',content:[{type:'tool_result',tool_use_id:'unknown'}]}});
assert.equal(state.fenced,'unmatched-tool-result');
assert.throws(()=>envelope('uas_peer',{id:'op',run_id:'run',generation:1,kind:'message',payload:{},actor:'forged'}));
assert.throws(()=>envelope('shell',{id:'op'}));
assert.deepEqual(envelope('uas_review',{id:'op',run_id:'run',generation:1,kind:'review-result',payload:{}}),{id:'op',run_id:'run',generation:1,kind:'review-result',payload:{}});
const original={id:'op',argv:['gh','pr','comment','1','--body-file','-'],body:'text'};
const rec=envelope('gh',{...original,id:'reconcile',reconcile:{operation_id:'op',audit_reference:'audit'}});
assert.equal(rec.mutation.id,'op'); assert.equal(rec.kind,'forge-reconcile'); assert.equal(rec.mutation.body,'text');
const result=await invoke({request:async()=>({ok:true,receipt:{reconciliation:{status:'UNKNOWN'}}})},'gh',{...original,id:'reconcile',reconcile:{operation_id:'op',audit_reference:'audit'}});
assert.equal(result.isError,true);
console.log('native Claude pure policy contracts passed');

assert.equal(negotiateProtocol('2025-11-25'),'2025-11-25');
assert.equal(negotiateProtocol('2025-06-18'),'2025-06-18');
assert.equal(negotiateProtocol('future'),'2025-11-25');
assert.throws(()=>negotiateProtocol(null));

let contacted=false, refused=false;
try { await invoke({request:async()=>{contacted=true;}},'gh',{id:'large',argv:['pr','comment','1','--body-file','-'],body:'x'.repeat(65536)}); } catch { refused=true; }
assert.equal(refused,true); assert.equal(contacted,false);

// Provider token remains native-only; fixed MCP environment is not a spread.
const authenticated=nativeOptions({binary:'/opt/uas/claude/claude',cwd:'/project',home:'/runtime',model:'claude-sonnet-4-6',sessionId:session,helper:'/opt/uas/bin/claude-mcp-connector',endpoint:'/transport/peer',providerToken:'fixture-token-not-real-123'});
assert.equal(authenticated.env.CLAUDE_CODE_OAUTH_TOKEN,'fixture-token-not-real-123');
assert.equal(authenticated.mcpServers.uas.env.CLAUDE_CODE_OAUTH_TOKEN,undefined);

// Narrow Library profile does not grow the default native or tool-less profiles.
const {LIBRARY_TOOL_NAMES,profileTools}=await import('../../../runtime/claude/native-policy.mjs');
const {toolsForProfile,invokeProfile}=await import('../../../runtime/claude/mcp-tools.mjs');
const libraryOptions=nativeOptions({binary:'/opt/uas/claude/claude',cwd:'/project',home:'/runtime',model:'claude-sonnet-4-6',sessionId:session,helper:'/opt/uas/bin/claude-mcp-connector',endpoint:'/transport/peer',profile:'library-capture-v1'});
assert.deepEqual(libraryOptions.allowedTools,['mcp__uas__library_enqueue']);
assert.deepEqual(libraryOptions.tools,[]);
assert.deepEqual(libraryOptions.mcpServers.uas.args,['/transport/peer','library-capture-v1']);
assert.deepEqual(TOOL_NAMES,['mcp__uas__uas_peer','mcp__uas__uas_review','mcp__uas__gh']);
assert.throws(()=>profileTools('unqualified'));
assert.deepEqual(toolsForProfile('library-capture-v1').map(x=>x.name),['library_enqueue']);
await assert.rejects(()=>invokeProfile({},'gh',{},'library-capture-v1'));
await assert.rejects(()=>invokeProfile({},'library_enqueue',{},'native-v1'));
const init={type:'system',subtype:'init',session_id:session,claude_code_version:'2.1.310',tools:[...LIBRARY_TOOL_NAMES],mcp_servers:[{name:'uas',status:'connected'}]};
const libraryState=new NativeToolState(session,'library-capture-v1');libraryState.event(init);
assert.equal(libraryState.initialized,true);assert.equal(libraryState.fenced,null);
for(const tools of [[],[...TOOL_NAMES],[...LIBRARY_TOOL_NAMES,'Bash'],[...LIBRARY_TOOL_NAMES,...LIBRARY_TOOL_NAMES]]){
  const denied=new NativeToolState(session,'library-capture-v1');denied.event({...init,tools});
  assert.equal(denied.fenced,'unsupported-native-profile');
}
const requests=[];
const capture={type:'context',title:'Exact_title',body:'Explicit **body**',sources:[]};
const channel={request:async envelope=>{requests.push(envelope);return {ok:true,receipt:{request_id:envelope.request_id,outcome:'NOT_DURABLE',reason:'TRANSPORT_UNCERTAIN',retryable:true,queue_id:null,path:null,published_sha:null,projection_sha:null,visible:false}};}};
for(let i=0;i<2;i++){
 const response=await invokeProfile(channel,'library_enqueue',{request_id:'stable-request',capture},'library-capture-v1');
 const data=JSON.parse(response.content[0].text);assert.equal(data.outcome,'NOT_DURABLE');assert.equal(response.isError,true);
}
assert.notEqual(requests[0].id,requests[1].id);assert.equal(requests[0].request_id,requests[1].request_id);
assert.deepEqual(requests[0].capture,capture);assert.deepEqual(requests[1].capture,capture);
const absent=JSON.parse((await invokeProfile(null,'library_enqueue',{request_id:'stable-request',capture},'library-capture-v1')).content[0].text);
assert.equal(absent.status,'TRANSPORT_UNAVAILABLE');assert.equal(Object.hasOwn(absent,'outcome'),false);
const noPath=JSON.parse((await invokeProfile(channel,'library_enqueue',{request_id:'stable-request',capture,project:'/elsewhere'},'library-capture-v1')).content[0].text);
assert.equal(noPath.status,'ADAPTER_REJECTED');assert.equal(requests.length,2);

await import('./library-read-policy.mjs');
