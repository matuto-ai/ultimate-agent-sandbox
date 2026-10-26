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
test('denial cannot recover',()=>{const s=waiting();s.decided(identity,'deny');s.event(terminal);assert.ok(s.fenced);});
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
