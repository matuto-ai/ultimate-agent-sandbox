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
