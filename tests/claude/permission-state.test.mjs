// Pure recorded-shape reducer regressions, not native qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import {PermissionNativeState} from '../../runtime/claude/permission-state.mjs';
const session = '11111111-1111-4111-8111-111111111111';
const invocation = '22222222-2222-4222-8222-222222222222';
const identity = {sessionId:session, invocationId:invocation, incarnation:'host', toolUseID:'tool-1'};
const e = value => ({session_id:session,...value});
const replay = e({type:'user',uuid:invocation,isReplay:true,parent_tool_use_id:null,message:{role:'user',content:'peer'}});
const tool = () => e({type:'user', parent_tool_use_id:null,
  message:{role:'user',content:[{type:'tool_result',tool_use_id:'tool-1',content:'nonce'}]},
  tool_use_result:{type:'text',file:{filePath:'/fixture/nonce'}},
  tool_result_meta:[{id:'tool-1',permission_decision:{decision:'accept',source:'user_temporary'}}]});
const terminal = e({type:'result',user_message_uuid:invocation,subtype:'success',is_error:false,
  stop_reason:'end_turn',terminal_reason:'completed',queued_turn_count:0,permission_denials:[]});
function waiting() {
  const s = new PermissionNativeState(session,'/fixture/nonce','host');
  s.begin(invocation,'peer');
  s.event(e({type:'system',subtype:'init',claude_code_version:'2.1.310',tools:['Read'],mcp_servers:[]}));
  s.event(replay);
  s.event(e({type:'system',subtype:'session_state_changed',state:'requires_action'}));
  assert.equal(s.state(),'ambiguous'); assert.equal(s.fenced,null);
  s.permission({identity,toolName:'Read',input:{file_path:'/fixture/nonce'}});
  return s;
}
test('allow and tool result cannot clear attention; terminal still requires fresh independent idle', () => {
  const s=waiting(); s.decided(identity,'allow'); assert.equal(s.state(),'ambiguous');
  s.event(e({type:'system',subtype:'session_state_changed',state:'running'}));
  s.event(tool()); assert.equal(s.ack,replay); assert.equal(s.state(),'ambiguous');
  s.event(terminal); assert.equal(s.pending,null); assert.equal(s.state(),'busy');
  s.event(e({type:'system',subtype:'session_state_changed',state:'idle'}));
  assert.equal(s.state(),null); // Not safe: host still must perform fresh control + listing.
});
test('denial without matched result cannot recover',()=>{const s=waiting();s.decided(identity,'deny');s.event(terminal);assert.ok(s.fenced);});
test('missing tool result, wrong correlation, duplicate and forged replay fence',()=>{
  const mutations=[t=>{t.message.content[0].tool_use_id='other';},t=>{t.isReplay=true;},
    t=>{t.tool_use_result.file.filePath='/other';},t=>{t.tool_result_meta[0].permission_decision.source='config';}];
  for(const mutate of mutations){const s=waiting();s.decided(identity,'allow');const t=tool();mutate(t);s.event(t);assert.ok(s.fenced);}
  const s=waiting();s.decided(identity,'allow');s.event(terminal);assert.ok(s.fenced);
  const d=waiting();d.decided(identity,'allow');d.event(tool());d.event(tool());assert.ok(d.fenced);
});
test('permission never clears irreversible fence or authorizes second permission',()=>{
  const s=waiting();s.hold('transport');s.decided(identity,'allow');s.event(tool());s.event(terminal);assert.equal(s.fenced,'transport');
  const d=waiting();d.permission({identity,toolName:'Read',input:{file_path:'/fixture/nonce'}});assert.ok(d.fenced);
});

import {hostDiagnostic, writeHostDiagnostic} from '../../runtime/claude/sdk-diagnostics.mjs';
test('host diagnostic contains only fixed codes, never arbitrary error or secret text',()=>{
  const hostile='Authorization: Bearer fixture-only-secret\n\x1b[31m token=secret /private/file';
  assert.deepEqual(hostDiagnostic(hostile,hostile,hostile),{
    type:'fixture-host-diagnostic',reason:'unavailable',fence:'unavailable',exit_code:null});
  assert.deepEqual(hostDiagnostic('native-initialize-timeout',2,'sdk-stream-failed'),{
    type:'fixture-host-diagnostic',reason:'native-initialize-timeout',fence:'sdk-stream-failed',exit_code:2});
});

import {Writable} from 'node:stream';
test('synchronous and asynchronous diagnostic output failures cannot interrupt cleanup', async()=>{
  for (const asynchronous of [false, true]) {
    let cleanupStarted=false, cleanupFinished=false;
    const stream = new Writable({write(chunk, encoding, callback) {
      if (asynchronous) queueMicrotask(()=>callback(new Error('EPIPE')));
      else throw new Error('synchronous closed stderr');
    }});
    writeHostDiagnostic(stream,'startup-failed',2,null);
    cleanupStarted=true;
    // Let a real Writable emit its asynchronous error while cleanup is pending.
    await new Promise(resolve=>setImmediate(resolve));
    cleanupFinished=true;
    assert.equal(cleanupStarted && cleanupFinished,true);
    // The listener must survive more than the first error (not once()).
    assert.doesNotThrow(()=>stream.emit('error',new Error('late EPIPE')));
    stream.destroy();
  }
});
const continuation = () => e({type:'assistant',parent_tool_use_id:null,
  message:{role:'assistant',content:[{type:'text',text:'Any fixture text is not identity or authority.'}]}});
test('one optional-UUID post-tool text continuation leaves ACK/pending/attention untouched',()=>{
  const s=waiting();s.decided(identity,'allow');s.event(tool());
  const pending=s.pending;s.event(continuation());
  assert.equal(s.fenced,null);assert.equal(s.pending,pending);assert.equal(s.ack,replay);
  assert.equal(s.state(),'ambiguous');
  s.event(terminal);assert.equal(s.fenced,null);assert.equal(s.pending,null);
  assert.notEqual(s.state(),'safe'); // Independent fresh probe still required.
});
test('continuation cannot introduce wrong identity, tools, duplicate or pre-tool activity',()=>{
  const mutations=[e=>{e.user_message_uuid='wrong';},e=>{e.user_message_uuid=null;},
    e=>{e.user_message_uuids=['other'];},e=>{e.session_id='other';},
    e=>{delete e.parent_tool_use_id;},e=>{e.parent_tool_use_id='subagent';},
    e=>{e.message.content=[{type:'tool_use',id:'new-tool'}];},
    e=>{e.message.content.push({type:'text',text:'extra'});}];
  for(const mutate of mutations){const s=waiting();s.decided(identity,'allow');s.event(tool());
    const frame=continuation();mutate(frame);s.event(frame);assert.ok(s.fenced);assert.equal(s.ack,replay);}
  const early=waiting();early.decided(identity,'allow');early.event(continuation());assert.ok(early.fenced);
  const duplicate=waiting();duplicate.decided(identity,'allow');duplicate.event(tool());
  duplicate.event(continuation());duplicate.event(continuation());assert.ok(duplicate.fenced);
});

import {DENIAL_MESSAGE} from '../../runtime/claude/permission-policy.mjs';
const deniedTool = () => e({type:'user',parent_tool_use_id:null,
  message:{role:'user',content:[{type:'tool_result',tool_use_id:'tool-1',is_error:true,content:DENIAL_MESSAGE}]},
  tool_use_result:'Error: '+DENIAL_MESSAGE,
  tool_result_meta:[{id:'tool-1',non_execution_kind:'permission-rule',permission_decision:{decision:'reject',source:'user_reject'}}]});
const deniedTerminal = () => ({...terminal,permission_denials:[{tool_name:'Read',tool_use_id:'tool-1',tool_input:{file_path:'/fixture/nonce'}}]});
test('exact denial completes only its invocation, preserves evidence and needs independent idle',()=>{
  const s=waiting();s.decided(identity,'deny');s.event(deniedTool());
  assert.equal(s.ack,replay);assert.equal(s.state(),'ambiguous');
  s.event(continuation());const result=deniedTerminal();const before=JSON.stringify(result);s.event(result);
  assert.equal(s.fenced,null);assert.equal(s.pending,null);assert.equal(s.completed,invocation);
  assert.equal(JSON.stringify(result),before);assert.equal(s.ack,replay);assert.notEqual(s.state(),'safe');
  s.event(e({type:'system',subtype:'session_state_changed',state:'idle'}));assert.equal(s.state(),null);
  const next='33333333-3333-4333-8333-333333333333';s.begin(next,'next');
  s.event({...replay,uuid:next,message:{role:'user',content:'next'}});
  s.event({...terminal,user_message_uuid:next});assert.equal(s.fenced,null);assert.equal(s.pending,null);
});
test('denied result rejects arbitrary errors, cancellation, metadata mismatch and opposite decision',()=>{
  const mutations=[t=>{t.message.content[0].is_error=false;},t=>{t.message.content[0].content='cancelled';},
    t=>{t.tool_use_result='Error: cancelled';},t=>{t.tool_result_meta[0].permission_decision.source='config';},
    t=>{delete t.tool_result_meta[0].non_execution_kind;},t=>{t.tool_result_meta.push(t.tool_result_meta[0]);},
    t=>{t.tool_result_meta[0]=null;},t=>{t.message.content[0].tool_use_id='other';},t=>{t.isReplay=true;}];
  for(const mutate of mutations){const s=waiting();s.decided(identity,'deny');const t=deniedTool();mutate(t);s.event(t);assert.ok(s.fenced);assert.equal(s.ack,replay);}
  const s=waiting();s.decided(identity,'allow');s.event(deniedTool());assert.ok(s.fenced);
  const d=waiting();d.decided(identity,'deny');d.event(deniedTool());d.event(deniedTool());assert.ok(d.fenced);
});
test('denied terminal requires one exact authoritative denial and original replay',()=>{
  const mutations=[t=>{delete t.permission_denials;},t=>{t.permission_denials=[];},
    t=>{t.permission_denials.push(t.permission_denials[0]);},t=>{t.permission_denials[0].tool_name='Write';},
    t=>{t.permission_denials[0].tool_use_id='other';},t=>{t.permission_denials[0].tool_input.file_path='/other';},
    t=>{t.permission_denials[0].tool_input.limit=1;},t=>{t.permission_denials[0].extra=true;},
    t=>{t.user_message_uuid='other';},t=>{t.queued_turn_count=1;},t=>{t.terminal_reason='interrupted';},
    t=>{t.is_error=true;},t=>{t.stop_reason='tool_use';}];
  for(const mutate of mutations){const s=waiting();s.decided(identity,'deny');s.event(deniedTool());const t=deniedTerminal();mutate(t);s.event(t);assert.ok(s.fenced);}
  const s=waiting();s.decided(identity,'deny');s.event(deniedTool());s.ack=null;s.event(deniedTerminal());assert.ok(s.fenced);
});
test('matched deny cannot clear irreversible or advisory permission fences',()=>{
  for(const reason of ['transport','native-identity','unknown-native-event','journal']){
    const s=waiting();s.decided(identity,'deny');s.hold(reason);s.event(deniedTool());s.event(deniedTerminal());assert.equal(s.fenced,reason);
  }
  const s=waiting();s.decided(identity,'deny');s.event(e({type:'system',subtype:'permission_denied'}));
  s.event(deniedTool());s.event(deniedTerminal());assert.ok(s.fenced);
});
