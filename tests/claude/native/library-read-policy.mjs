// Cheap policy/filesystem checks, not official CLI execution proof.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {makeLibraryReadPermission,makeLibraryReadToolPolicy,LIBRARY_SCAN_COMMAND,LIBRARY_READ_PROFILE,LIBRARY_READ_GUIDANCE} from '../../../runtime/claude/library-read.mjs';
import {nativeOptions,NativeToolState,profileTools,requireMcp} from '../../../runtime/claude/native-policy.mjs';
const session='11111111-1111-4111-8111-111111111111', uuid='22222222-2222-4222-8222-222222222222';
const args={binary:'/opt/uas/claude/claude',cwd:'/project/repo',home:'/runtime/home',model:'claude-sonnet-4-6',sessionId:session,helper:'/opt/uas/bin/claude-mcp-connector',endpoint:'/transport/peer'};
const options=nativeOptions({...args,profile:LIBRARY_READ_PROFILE});
assert.equal(options.cwd,'/project/reference'); assert.equal(nativeOptions(args).cwd,'/project/repo');
assert(Object.hasOwn(options.extraArgs,'restricted'));
assert.deepEqual(options.tools,['Read','Bash']); assert.deepEqual(options.allowedTools,[]);
assert.deepEqual(options.settings.permissions.ask,['Read','Bash']); assert.equal(options.permissionPrompts,'host');
assert.deepEqual(options.mcpServers,{}); assert.deepEqual(options.settingSources,[]);
assert.equal(options.systemPrompt.append,LIBRARY_READ_GUIDANCE);
assert.deepEqual(nativeOptions(args).tools,[]); assert.deepEqual(nativeOptions({...args,profile:'library-capture-v1'}).tools,[]);
requireMcp([],LIBRARY_READ_PROFILE); assert.throws(()=>requireMcp([{name:'uas',status:'connected'}],LIBRARY_READ_PROFILE));
assert.throws(()=>requireMcp([]));
const makeState=()=>{const s=new NativeToolState(session,LIBRARY_READ_PROFILE);
  s.event({type:'system',subtype:'init',session_id:session,claude_code_version:'2.1.310',tools:profileTools(LIBRARY_READ_PROFILE),mcp_servers:[]});return s;};
const readTurn=(name,input)=>{const s=makeState();s.begin(uuid,'read');
  s.event({type:'user',session_id:session,uuid,isReplay:true,parent_tool_use_id:null,message:{role:'user',content:'read'}});
  s.event({type:'assistant',session_id:session,user_message_uuid:uuid,parent_tool_use_id:null,message:{role:'assistant',content:[{type:'tool_use',id:'tool',name,input}]}});
  s.event({type:'system',subtype:'session_state_changed',session_id:session,state:'requires_action'});return s;};
let state=makeState(); assert(state.initialized); assert.equal(state.state(),null);
state.begin(uuid,'explicit lookup');
state.event({type:'user',session_id:session,uuid,isReplay:true,parent_tool_use_id:null,message:{role:'user',content:'explicit lookup'}});
state.event({type:'assistant',session_id:session,user_message_uuid:uuid,parent_tool_use_id:null,message:{role:'assistant',content:[{type:'tool_use',id:'read1',name:'Read'}]}});
assert.equal(state.state(),'busy');
state.event({type:'result',session_id:session}); assert.equal(state.fenced,'unresolved-tool-call');
state=makeState();state.event({type:'system',subtype:'session_state_changed',session_id:session,state:'requires_action'});
assert.equal(state.state(),'ambiguous'); // no relaxation for unattended prompts
const reference=fs.mkdtempSync(path.join(os.tmpdir(),'uas-read-policy-'));
const generation=path.join(reference,'.library-snapshots','a'.repeat(32));
fs.mkdirSync(path.join(generation,'library','pending'),{recursive:true});
fs.writeFileSync(path.join(generation,'library.snapshot.json'),JSON.stringify({commit_sha:'b'.repeat(40)}));
fs.writeFileSync(path.join(generation,'library','index.md'),'AUTHORED');
fs.mkdirSync(path.join(generation,'library','context'));
fs.writeFileSync(path.join(generation,'library','context','with space.md'),'LEGAL SPACE PATH');
fs.writeFileSync(path.join(generation,'library','pending','draft.md'),'DRAFT');
fs.symlinkSync(path.relative(reference,path.join(generation,'library')),path.join(reference,'library'));
fs.symlinkSync(path.relative(reference,path.join(generation,'library.snapshot.json')),path.join(reference,'library.snapshot.json'));
const permission=makeLibraryReadPermission({reference});
const context={signal:new AbortController().signal,requestId:'request',toolUseID:'tool'};
const allowed=(name,input,ctx=context)=>permission(name,input,ctx).behavior==='allow';
try {
  for(const relative of ['library/index.md','library/pending/draft.md','library/context/with space.md','library.snapshot.json']) {
    const input={file_path:path.join(reference,relative)};
    const decision=permission('Read',input,context);
    assert.equal(decision.behavior,'allow');assert.equal(decision.updatedInput.file_path,path.join(generation,relative));
    assert.equal(input.file_path,path.join(reference,relative));
  }
  for(const file of ['/etc/passwd',reference+'/library/../outside.md',reference+'/library//index.md',reference+'/library/.git/config',reference+'/library/index.md/..',reference+'/library/context/with\tspace.md',reference+'/library/context/with\nspace.md',generation+'/library/index.md',reference+'/../other/library/index.md'])
    assert(!allowed('Read',{file_path:file}),file);
  assert(allowed('Read',{file_path:reference+'/library/index.md',offset:1,limit:2000}));
  for(const extra of [{offset:0},{offset:1048577},{limit:0},{limit:2001},{offset:1.5},{limit:'10'},{pages:'1'}])
    assert(!allowed('Read',{file_path:reference+'/library/index.md',...extra}));
  const readInput={file_path:reference+'/library/index.md'};
  const active=readTurn('Read',readInput);const toolPolicy=makeLibraryReadToolPolicy(active,{reference});
  assert.equal(active.state(),'ambiguous');assert.equal(active.fenced,null);
  const accepted=toolPolicy('Read',readInput,context);assert.equal(accepted.behavior,'allow');
  assert.equal(active.state(),'ambiguous');assert.equal(active.fenced,null);
  active.event({type:'system',subtype:'session_state_changed',session_id:session,state:'running'});
  assert.equal(active.state(),'ambiguous');
  const readResult={type:'user',session_id:session,parent_tool_use_id:null,message:{role:'user',content:[{type:'tool_result',tool_use_id:'tool',content:'AUTHORED'}]},
    tool_result_meta:[{id:'tool',permission_decision:{decision:'accept',source:'user_temporary'}}],
    tool_use_result:{type:'text',file:{filePath:accepted.updatedInput.file_path}}};
  active.event(readResult);assert.equal(active.fenced,null);assert.equal(active.state(),'busy');
  active.event({type:'result',session_id:session,user_message_uuid:uuid,subtype:'success',is_error:false,stop_reason:'end_turn',terminal_reason:'completed',queued_turn_count:0,permission_denials:[]});
  assert.equal(active.pending,null);assert.equal(active.state(),'busy');
  active.event({type:'system',subtype:'session_state_changed',session_id:session,state:'idle'});
  assert.equal(active.state(),null); // still not safe without fresh host listing/control
  for(const bad of [{...context,toolUseID:'other'}, {...context,agentID:'nested'}]) {
    const s=readTurn('Read',readInput), policy=makeLibraryReadToolPolicy(s,{reference});
    assert.equal(policy('Read',readInput,bad).behavior,'deny');assert(s.fenced);
  }
  for(const change of [r=>r.tool_result_meta[0].permission_decision.source='config',r=>r.tool_use_result.file.filePath='/etc/passwd',r=>r.message.content[0].tool_use_id='other']) {
    const s=readTurn('Read',readInput), policy=makeLibraryReadToolPolicy(s,{reference});
    assert.equal(policy('Read',readInput,context).behavior,'allow');const result=structuredClone(readResult);change(result);s.event(result);assert(s.fenced);
  }
  const duplicate=readTurn('Read',readInput), duplicatePolicy=makeLibraryReadToolPolicy(duplicate,{reference});
  assert.equal(duplicatePolicy('Read',readInput,context).behavior,'allow');assert.equal(duplicatePolicy('Read',readInput,context).behavior,'deny');assert(duplicate.fenced);
  const changed=readTurn('Read',readInput), changedPolicy=makeLibraryReadToolPolicy(changed,{reference});
  assert.equal(changedPolicy('Read',{file_path:reference+'/library/pending/draft.md'},context).behavior,'deny');assert(changed.fenced);
  const unresolved=readTurn('Read',readInput);
  unresolved.event({type:'system',subtype:'session_state_changed',session_id:session,state:'running'});assert.equal(unresolved.fenced,'unresolved-read-permission');
  const denied=readTurn('Bash',{command:'cat /etc/passwd'});
  assert.equal(makeLibraryReadToolPolicy(denied,{reference})('Bash',{command:'cat /etc/passwd'},context).behavior,'deny');assert(denied.fenced);
  const outside=makeState();outside.event({type:'system',subtype:'permission_denied',session_id:session});assert(outside.fenced);
  const concurrent=readTurn('Read',readInput);concurrent.event({type:'assistant',session_id:session,parent_tool_use_id:null,message:{role:'assistant',content:[{type:'tool_use',id:'tool2',name:'Read',input:readInput}]}});assert.equal(concurrent.fenced,'concurrent-read-tools');

  assert(!allowed('Write',{file_path:reference+'/library/index.md'}));
  assert(!allowed('Read',{file_path:reference+'/library/index.md'},{...context,agentID:'subagent'}));
  assert(!allowed('Read',{file_path:reference+'/library/index.md'},{...context,signal:{aborted:true}}));
  assert(!allowed('Read',{file_path:reference+'/library/index.md'},{...context,requestId:''}));
  fs.symlinkSync('/etc/passwd',path.join(generation,'library','link.md'));
  assert(!allowed('Read',{file_path:reference+'/library/link.md'}));
  fs.symlinkSync('/tmp',path.join(generation,'library','linked-dir'));
  assert(!allowed('Read',{file_path:reference+'/library/linked-dir/outside.md'}));
  for(const suffix of [" 'Mixed Case' 'literal$;`chars`'", " 'área'",Array(16).fill(" 'word'").join('')])
    assert(allowed('Bash',{command:LIBRARY_SCAN_COMMAND+suffix}));
  for(const suffix of [''," 'term'; cat /etc/passwd"," 'term'\ncat /etc/passwd",' "term"'," 'a' ' '",Array(17).fill(" 'word'").join('')," '"+'x'.repeat(129)+"'"," --root /tmp 'term'"," 'term' > /tmp/out"])
    assert(!allowed('Bash',{command:LIBRARY_SCAN_COMMAND+suffix}),suffix);
  assert(!allowed('Bash',{command:LIBRARY_SCAN_COMMAND+" 'term'",run_in_background:true}));
  assert(!allowed('Bash',{command:'cat '+reference+'/library/index.md'}));
  // A refresh after authorization cannot redirect the returned immutable path.
  const pinned=permission('Read',{file_path:reference+'/library/index.md'},context);
  fs.unlinkSync(reference+'/library');fs.symlinkSync('/etc',reference+'/library');
  assert.equal(fs.readFileSync(pinned.updatedInput.file_path,'utf8'),'AUTHORED');
  assert(!allowed('Read',{file_path:reference+'/library/index.md'}));
  fs.unlinkSync(reference+'/library.snapshot.json');
  assert(!allowed('Read',{file_path:reference+'/library.snapshot.json'}));
} finally {fs.rmSync(reference,{recursive:true,force:true});}
console.log('Claude Library native-read policy/filesystem contracts passed');
