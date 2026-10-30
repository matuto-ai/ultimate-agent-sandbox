// Existing Field Notes check: VM/DOM contracts, plus opt-in hosted Chrome proof.
// Node built-ins only. No downloads, browser framework, server, or live accounts.
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path');
const assert = require('node:assert/strict'), {pathToFileURL} = require('node:url');
const args = process.argv.slice(2);
if (!args.includes('--fixtures') || !args[args.indexOf('--fixtures')+1]) throw Error('--fixtures DIRECTORY is required');
const root = path.resolve(args[args.indexOf('--fixtures')+1]);
const documents = Object.fromEntries(['connected','disconnected','catching-up','reconnected','library-current','library-stale','library-stale-reconnected'].map(name=>[name,fs.readFileSync(path.join(root,name+'.html'),'utf8')]));
const dataFor = html=>JSON.parse(html.match(/<script type="application\/json" id="manager-data">([\s\S]*?)<\/script>/)[1]);
const data = dataFor(documents.connected), project = 'deployment/alpha/stream-alpha', run = 'run-alpha';
const routes = ['projects','inbox','health','project','room','run'];

function boot(theme,page,name='connected',replacement=null,selectedProject=project) {
  const elements=new Map(), listeners=new Map();
  const get=id=>{if(!elements.has(id))elements.set(id,{id,innerHTML:'',textContent:'',hidden:id==='drawer',open:false,isConnected:true,
    focus(){document.activeElement=this;},showModal(){this.open=true;},close(){this.open=false;},addEventListener(type,fn){listeners.set(id+':'+type,fn);}});return elements.get(id);};
  get('manager-data').textContent=JSON.stringify(replacement||dataFor(documents[name]));
  let url=new URL('file:///manager.html?'+new URLSearchParams({variant:theme,page,project:selectedProject,run}));
  const location={get href(){return url.href;},get search(){return url.search;}};
  const document={body:{className:''},title:'',activeElement:null,getElementById:get,querySelector(){return get('h1');},addEventListener(type,fn){listeners.set(type,fn);}};
  class FixedDate extends Date {static now(){return Date.parse((replacement||dataFor(documents[name])).generated_at);}}
  const context={URL,URLSearchParams,location,document,Date:FixedDate,history:{pushState(_,__,value){url=new URL(value,url);},replaceState(_,__,value){url=new URL(value,url);}},window:{addEventListener(type,fn){listeners.set(type,fn);}},requestAnimationFrame(fn){fn();},setInterval(fn){listeners.set("interval",fn);return 1;}};
  vm.createContext(context);
  vm.runInContext(documents[name].match(/<script>([\s\S]*?)<\/script>/)[1],context,{filename:'manager-ui-prototype.html',timeout:1000});
  return {context,get,document,listeners};
}
let count=0;
for(const theme of ['C','D'])for(const route of routes){
  const result=boot(theme,route), html=result.get('app').innerHTML;
  assert(html.includes('<h1')&&html.includes('Project and Run hierarchy')&&!html.includes('undefined'));
  assert.equal(result.document.body.className,'v-'+theme);
  if(route==='run'){
    assert(html.includes('Run journey')&&html.includes('CHANGES REQUESTED')&&html.includes('Gate ledger'));
    assert.equal((html.match(/journey-step feedback/g)||[]).length,1,'human control must not invent a new review return');
    assert(html.includes('Open in GitHub')&&html.includes('disabled aria-describedby'));
    assert(!html.includes('data-status="pass"'),'historical pass must not become current pass');
  }count++;
}
for(const name of ['disconnected','catching-up']){
  const html=boot('C','run',name).get('app').innerHTML;
  assert(html.includes('data-status="stale"')&&html.includes(`data-status="${name==='catching-up'?'catching-up':'disconnected'}"`));
  assert(!html.includes('class="status good" data-status="disconnected"'));
}
// Library metadata stays attached to the selected authenticated Room only.
for(const name of Object.keys(documents)){
  const ui=boot('C','project',name),html=ui.get('app').innerHTML;
  assert(html.includes('Library operations')&&html.includes('library-service')&&html.includes('BLOCKED'));
  assert(html.includes('data-library-actions')&&html.includes('data-library-settings'));
  assert(!html.includes('data-status="healthy"'));
  const expected=name==='library-current'?'current':['disconnected','catching-up','library-stale','library-stale-reconnected'].includes(name)?'stale':'unknown';
  assert(ui.context.sourceLine(ui.context.stateFor().project,"library").includes(`data-status="${expected}"`),name+': literal Library freshness');
  const isolated=structuredClone(dataFor(documents[name]));isolated.rooms=isolated.rooms.filter(room=>room.metadata.project_id==='beta');
  const missing=boot('D','project',name,isolated,'deployment/beta/stream-beta').get('app').innerHTML;
  assert(missing.includes('Library observation unknown or unavailable'));
  assert(!missing.includes('github.com/1001')&&!missing.includes('drain-alpha'),'cross-Project metadata leaked');
}
const aging=boot('C','project','library-current');
const agingProject=aging.context.stateFor().project,agingSource=agingProject.view.projection.sections.library;
agingSource.observed_at=new Date(Date.parse(data.generated_at)-29000).toISOString();
assert.equal(aging.context.libraryQuality(agingProject,agingSource),'current');
vm.runInContext('Date.now = () => '+(Date.parse(data.generated_at)+2000),aging.context);
assert.equal(aging.context.libraryQuality(agingProject,agingSource),'stale','source TTL expires before fresh Hub TTL');
aging.listeners.get('interval')();
assert(aging.get('app').innerHTML.match(/<section class="library-operations"[\s\S]*?data-status="stale"/),'retained visible Library provenance must age without a new document');
const metadataOnly=structuredClone(data);
metadataOnly.rooms[0].view.projection.sections.library.value['github.com/1001'].title='CONTENT_SENTINEL_180';
assert(!boot('C','project','connected',metadataOnly).get('app').innerHTML.includes('CONTENT_SENTINEL_180'),'render must whitelist metadata');
const interaction=boot('C','run');
interaction.context.projectDetail(project);assert(interaction.get('drawer-body').innerHTML.includes('Configured Project binding'));
interaction.context.personDetail('alice',project);assert(interaction.get('drawer-body').innerHTML.includes('remaining')&&interaction.get('drawer-body').innerHTML.includes('capabilities'));
interaction.context.healthProject(project);assert(interaction.get('drawer-body').innerHTML.includes('PARTIAL_MUTATION')&&interaction.get('drawer-body').innerHTML.includes('/srv/project/alpha'));
interaction.context.gateDetail(0,project,run);assert(interaction.get('drawer-body').innerHTML.includes('independent check'));
interaction.context.openAttention(project+':'+run);assert(interaction.get('item-dialog').open&&interaction.get('item-body').innerHTML.includes('disabled aria-describedby'));
interaction.context.installDocument(dataFor(documents.disconnected));assert(!interaction.get('item-dialog').open&&interaction.get('drawer').hidden);
interaction.context.installDocument(dataFor(documents.reconnected));assert(interaction.get('app').innerHTML.includes('run.resumed'));
const hostile=structuredClone(data);hostile.rooms[0].metadata.project_id='<img src=x onerror="globalThis.pwned=true">';
assert(boot('C','projects','connected',hostile).get('app').innerHTML.includes('&lt;img'));
for(const freshness of ['unknown','stale','current']){
  const fallback=structuredClone(data),sections=fallback.rooms[0].view.projection.sections;
  sections.attention.value={};sections.review.freshness=freshness;
  sections.review.value[run].state='READY_FOR_HUMAN';
  const html=boot('C','inbox','connected',fallback).get('app').innerHTML;
  if(freshness!=='current')assert(!html.includes('folio-case-code">CURRENT'),'review freshness must not inherit snapshot freshness');
  assert(html.includes(`folio-case-code">${freshness.toUpperCase()}`));
}
for(const html of Object.values(documents))assert(!/Approve candidate|Request confirmed|Math\.random|fetch\(|XMLHttpRequest/.test(html));
console.log(`manager Field Notes: ${count} light/dark routes and live interaction contracts passed (VM/DOM, not browser proof)`);

// Pure ownership bookkeeping: an error without a PID is a terminal failed
// spawn; an error from an existing child never pretends the child has exited.
function trackChild(child,onFailure){
  let ended=false,closed=false,resolveStop,resolveClose;
  const stopped=new Promise(resolve=>{resolveStop=resolve;});
  const closedPromise=new Promise(resolve=>{resolveClose=resolve;});
  const terminal=()=>{if(!ended){ended=true;resolveStop();}};
  const close=()=>{terminal();if(!closed){closed=true;resolveClose();}};
  child.once('exit',(code,signal)=>{terminal();onFailure(Error(`Chrome exited ${code}/${signal}`));});
  child.once('close',close);
  child.on('error',error=>{if(!child.pid)close();onFailure(error);});
  return {get ended(){return ended;},get closed(){return closed;},stopped,closedPromise};
}
// CDP's key string/code alone is not a complete native keyboard gesture.
// Supply Escape's virtual key and release it, including across successive dialogs.
async function pressEscape(send){
  const key={key:'Escape',code:'Escape',windowsVirtualKeyCode:27,nativeVirtualKeyCode:27,modifiers:0};
  try { await send('Input.dispatchKeyEvent',{...key,type:'keyDown'}); }
  finally { await send('Input.dispatchKeyEvent',{...key,type:'keyUp'}); }
}
function boundedWait(promise,milliseconds){
  let timer;
  return Promise.race([promise,new Promise(resolve=>{timer=setTimeout(resolve,milliseconds);})]).finally(()=>clearTimeout(timer));
}
async function closeOwnedBrowser(child,lifetime,graceful,profile,{wait=boundedWait,remove=path=>fs.rmSync(path,{recursive:true,force:true,maxRetries:3,retryDelay:100})}={}){
  if(child&&lifetime&&!lifetime.closed){
    // Browser.close lets Chrome own its descendant shutdown and profile flush.
    // A closed pipe during the request is expected; termination is checked next.
    if(graceful&&!lifetime.ended){try{await wait(graceful().catch(()=>{}),500);}catch(_){}}
    await wait(lifetime.closedPromise,1000);
    if(!lifetime.ended){child.kill('SIGTERM');await wait(lifetime.closedPromise,500);}
    if(!lifetime.ended){child.kill('SIGKILL');await wait(lifetime.closedPromise,500);}
    if(!lifetime.closed)throw Error('Owned Chrome close unconfirmed; profile retained');
  }
  if(profile)remove(profile);
}
async function ownershipContract(){
  function fake(pid){const listeners=new Map();return {pid,on(name,fn){listeners.set(name,fn);},once(name,fn){listeners.set(name,fn);},emit(name,...args){listeners.get(name)(...args);}};}
  const failed=fake(undefined),failures=[];
  const missing=trackChild(failed,error=>failures.push(error.message));failed.emit('error',Error('EACCES'));await missing.stopped;
  assert(missing.ended&&failures.includes('EACCES'));
  const running=fake(17),owned=trackChild(running,()=>{});running.emit('error',Error('temporary error'));assert(!owned.ended);running.emit('exit',0,null);await owned.stopped;assert(owned.ended);
  assert(!owned.closed,'exit alone does not close inherited pipes');running.emit('close');await owned.closedPromise;assert(owned.closed);
  const events=[];await pressEscape(async(method,value)=>events.push([method,value]));
  assert.deepEqual(events.map(item=>item[1].type),['keyDown','keyUp']);assert(events.every(item=>item[1].windowsVirtualKeyCode===27&&item[1].nativeVirtualKeyCode===27));
  const failedKeys=[];await assert.rejects(pressEscape(async(_,value)=>{failedKeys.push(value.type);if(value.type==='keyDown')throw Error('input failed');}),/input failed/);assert.deepEqual(failedKeys,['keyDown','keyUp']);
  const trace=[],browser=fake(21),state=trackChild(browser,()=>{});browser.kill=signal=>{trace.push(signal);browser.emit('close');};
  await closeOwnedBrowser(browser,state,async()=>{trace.push('Browser.close');browser.emit('exit',0,null);browser.emit('close');},'/owned',{wait:async promise=>promise,remove:path=>trace.push('remove '+path)});
  assert.deepEqual(trace,['Browser.close','remove /owned']);
  const stuck=fake(22),stuckState=trackChild(stuck,()=>{}),signals=[];stuck.kill=signal=>signals.push(signal);
  await assert.rejects(closeOwnedBrowser(stuck,stuckState,async()=>{throw Error('broken pipe');},'/owned',{wait:async()=>{},remove:()=>{throw Error('must not remove live profile');}}),/close unconfirmed/);assert.deepEqual(signals,['SIGTERM','SIGKILL']);
  const exited=fake(23),openPipes=trackChild(exited,()=>{});exited.kill=()=>{throw Error('must not signal exited PID');};
  exited.emit('exit',0,null);
  await assert.rejects(closeOwnedBrowser(exited,openPipes,()=>{throw Error('must not command exited browser');},'/owned',
    {wait:async()=>{},remove:()=>{throw Error('must retain profile while pipes remain open');}}),/close unconfirmed/);
  await assert.rejects(closeOwnedBrowser(null,null,null,'/owned',{remove:()=>{throw Error('ENOTEMPTY');}}),/ENOTEMPTY/);

}

async function actionContract(){
  const ui=boot('C','run'), sent=[];
  const current={run_id:run,generation:1,observed_version:'a'.repeat(64)};
  let eligible=true, action='pause', fail=false, defer=null;
  const binding={inspect:async packet=>({operation_id:packet.operation_id,outcome:'unknown'}),view:async()=>({status:'available',scope:{deployment_id:'deployment',room_id:'alpha',instance_id:'instance-alpha'},current,actions:[{action,object_id:run,eligible,reason:eligible?null:'FORBIDDEN'}]}), lifecycle:async()=>({status:'unavailable',reason:'FORBIDDEN'}),replacement:async()=>({status:'unavailable',reason:'FORBIDDEN'}),execute:async packet=>{sent.push(packet);if(defer)await defer;if(fail)throw Error('lost');return {operation_id:packet.operation_id,outcome:'confirmed',reason:null,current};}};
  let serial=0;ui.context.crypto={randomUUID:()=>`op-${++serial}`};
  ui.context.installActionHost(project,binding);
  await ui.context.openActionPanel(project,'run',run);
  ui.get('action-reason').value='Human requested pause';
  let release; defer=new Promise(resolve=>{release=resolve;});
  const pending=ui.context.submitHumanAction('pause');
  await ui.context.submitHumanAction('pause'); assert.equal(sent.length,1,'double click must not duplicate');
  ui.context.closeItem();release();await pending;defer=null;
  assert(!ui.get('item-dialog').open,'late receipt must not reopen dialog');
  assert.deepEqual(JSON.parse(JSON.stringify(sent[0])),{version:1,operation_id:'op-1',action:'pause',deployment_id:'deployment',room_id:'alpha',instance_id:'instance-alpha',run_id:run,generation:1,object_id:run,observed_version:'a'.repeat(64),payload:{reason:'human-pause'}});
  eligible=false;await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction('pause');assert.equal(sent.length,1);
  eligible=true;fail=true;await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction('pause');assert.equal(sent.length,2);assert(ui.get('item-body').innerHTML.includes('unknown'));
  await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction('pause');assert.equal(sent.length,2,'unknown must not create replacement mutation');
  action='open-github';fail=true;await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction(action);assert.equal(sent.length,3);
  action='pause';await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction(action);assert.equal(sent.length,3,'read-only link must not erase unresolved mutation');
  action='reconcile-changes';await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction(action);assert.equal(sent.length,4);
  binding.execute=async packet=>{sent.push(packet);return {operation_id:packet.operation_id,outcome:'confirmed',reason:null,current,receipt:{operation_id:'op-2',status:'confirmed'}};};
  action='reconcile-changes';fail=false;await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction(action);assert.equal(sent.length,5);assert.deepEqual(JSON.parse(JSON.stringify(sent[4].payload)),{});
  for(const name of ['resume','request-changes','add-rounds','waive-cap','override-review','open-github']){
    action=name;await ui.context.openActionPanel(project,'run',run);ui.get('action-reason').value='Review explanation';ui.get('action-rounds').value='2';await ui.context.submitHumanAction(name);
    const payload=JSON.parse(JSON.stringify(sent.at(-1).payload));
    assert.deepEqual(payload,name==='resume'?{reason:'human-resume'}:name==='request-changes'?{body:'Review explanation'}:name==='open-github'?{}:{reason:'Review explanation',rounds:name==='add-rounds'?2:null});
  }
  binding.lifecycle=async()=>({status:'available',scope:{deployment_id:'deployment',room_id:'alpha',instance_id:'instance-alpha'},current:{instance_id:'instance-alpha',observed_version:'b'.repeat(64)},actions:[{action:'start',object_id:'instance-alpha',eligible:true}]});
  await ui.context.openActionPanel(project,'lifecycle');await ui.context.submitHumanAction('start');
  assert.equal(sent.at(-1).run_id,null);assert.equal(sent.at(-1).generation,null);assert.equal(sent.at(-1).object_id,'instance-alpha');assert.deepEqual(JSON.parse(JSON.stringify(sent.at(-1).payload)),{});
  binding.replacement=async()=>({status:'available',scope:{deployment_id:'deployment',room_id:'alpha',instance_id:'instance-alpha'},current:null,actions:[],replacement:{participant_id:'failed-seat',run_id:run,generation:1,observed_version:'c'.repeat(64),eligible:true,candidates:[{participant_id:'next-seat'}],selection:null}});
  await ui.context.openActionPanel(project,'replacement','failed-seat');ui.get('action-replacement').value='next-seat';await ui.context.submitHumanAction('select-replacement');
  assert.equal(sent.at(-1).object_id,'failed-seat');assert.deepEqual(JSON.parse(JSON.stringify(sent.at(-1).payload)),{participant_id:'next-seat'});
  action='pause';binding.execute=async packet=>{sent.push(packet);throw Error('lost local reply');};
  await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction(action);const original=sent.at(-1),beforeInspection=sent.length;let inspected;
  binding.inspect=async packet=>{inspected=packet;return {operation_id:packet.operation_id,outcome:'confirmed',receipt:{operation_id:packet.operation_id,status:'confirmed',read_only:true}};};
  await ui.context.openActionPanel(project,'run',run);await ui.context.inspectHumanOutcome();assert.equal(inspected,original);assert.equal(sent.length,beforeInspection,'inspection cannot execute another mutation');
  action='resume';binding.execute=async packet=>{sent.push(packet);return {operation_id:packet.operation_id,outcome:'confirmed'};};
  await ui.context.openActionPanel(project,'run',run);await ui.context.submitHumanAction(action);assert.equal(sent.length,beforeInspection+1,'confirmed owner inspection permits fresh eligible action');
  ui.context.installActionHost(project,null);await ui.context.openActionPanel(project,'run',run);assert(!ui.get('item-dialog').open);
  const late=boot('C','run');let resolveView;binding.view=()=>new Promise(resolve=>{resolveView=resolve;});late.context.installActionHost(project,binding);
  const reading=late.context.openActionPanel(project,'run',run);late.context.closeItem();resolveView({status:'available',scope:{deployment_id:'deployment',room_id:'alpha'},current,actions:[]});await reading;assert(!late.get('item-dialog').open);
  for(const invalid of [undefined,'accepted','pending']){
    const malformed=boot('C','run');let writes=0,sequence=0;
    malformed.context.crypto={randomUUID:()=>`malformed-${++sequence}`};
    malformed.context.installActionHost(project,{...binding,view:async()=>({status:'available',scope:{deployment_id:'deployment',room_id:'alpha',instance_id:'instance-alpha'},current,actions:[{action:'pause',object_id:run,eligible:true}]}),execute:async packet=>{writes++;return {operation_id:packet.operation_id,outcome:invalid};}});
    await malformed.context.openActionPanel(project,'run',run);await malformed.context.submitHumanAction('pause');
    assert(malformed.get('item-body').innerHTML.includes('unknown'));
    await malformed.context.openActionPanel(project,'run',run);await malformed.context.submitHumanAction('pause');assert.equal(writes,1,'malformed outcome must retain unresolved original mutation');
  }
  console.log('Manager actions: typed scope, owner denial, duplicate click, unknown preservation and late response contracts passed');
}

// Only the first read-only startup probe receives the cold-start allowance.
// Injected timers keep this contract testable without a browser or real waits.
function commandTimer({first,method,id=null,reject,onTimeout,set=setTimeout,clear=clearTimeout}){
  const milliseconds=first&&method==='Browser.getVersion'?10000:5000;
  const timer=set(()=>{onTimeout();reject(Object.assign(Error('CDP timeout: '+method),{code:'CDP_COMMAND_TIMEOUT',method,commandId:id,first}));},milliseconds);
  return {milliseconds,cancel:()=>clear(timer)};
}
function timerContract(){
  for(const [first,method,expected] of [[true,'Browser.getVersion',10000],[false,'Browser.getVersion',5000],[true,'Target.createTarget',5000],[false,'Runtime.evaluate',5000]]){
    let callback,delay,cleared=false,timedOut=false,error;
    const timer=commandTimer({first,method,id:1,reject:value=>{error=value;},onTimeout:()=>{timedOut=true;},set:(fn,ms)=>{callback=fn;delay=ms;return 7;},clear:id=>{assert.equal(id,7);cleared=true;}});
    assert.equal(delay,expected);assert.equal(timer.milliseconds,expected);callback();assert(timedOut&&error.message==='CDP timeout: '+method);timer.cancel();assert(cleared);
    assert.equal(error.code,'CDP_COMMAND_TIMEOUT');assert.equal(error.commandId,1);assert.equal(error.method,method);assert.equal(error.first,first);
  }
}

// Bounded, observational only: never probes an executable, environment or pipe.
// Keep the failure-time snapshot distinct from exit/close caused by cleanup.
function browserDiagnostics(executable,nodeVersion,now=Date.now){
  const began=now(),events=[];let dropped=0,phase='spawn',phaseBegan=began,received=0,version=null,exit=null,close=null;
  const elapsed=()=>Math.max(0,now()-began),text=value=>typeof value==='string'?value.slice(0,160):null;
  const facts=value=>Object.fromEntries(Object.entries(value).filter(([_,v])=>v===null||typeof v==='boolean'||typeof v==='string'||Number.isSafeInteger(v)).map(([k,v])=>[k,typeof v==='string'?text(v):v]));
  const record=(event,value={})=>{if(events.length<32)events.push({event,elapsed_ms:elapsed(),...facts(value)});else dropped++;};
  return {
    record,
    phase(value){phase=text(value);phaseBegan=now();record('phase',{phase});},
    received(bytes){received=Math.min(Number.MAX_SAFE_INTEGER,received+bytes);},
    version(value){version={product:text(value?.product),protocolVersion:text(value?.protocolVersion),jsVersion:text(value?.jsVersion)};record('browser-version-observed');},
    exit(code,signal){exit={code:Number.isSafeInteger(code)?code:null,signal:text(signal),elapsed_ms:elapsed()};record('child-exit',exit);},
    close(code,signal){close={code:Number.isSafeInteger(code)?code:null,signal:text(signal),elapsed_ms:elapsed()};record('child-close',close);},
    snapshot(){return JSON.parse(JSON.stringify({executable:text(executable),node_version:text(nodeVersion),browser_version:version,phase,elapsed_ms:elapsed(),phase_elapsed_ms:Math.max(0,now()-phaseBegan),received_bytes:received,exit,close,events,dropped_events:dropped}));}
  };
}
function writeDiagnosticPipe(pipe,wire,id,diagnostics){
  diagnostics.record('pipe-write',{id,bytes:Buffer.byteLength(wire)});
  try{
    const accepted=pipe.write(wire,error=>diagnostics.record('pipe-write-complete',{id,error:error?.message||null,code:error?.code||null}));
    diagnostics.record('pipe-write-return',{id,accepted});
  }catch(error){diagnostics.record('pipe-write-threw',{id,error:error.message,code:error.code||null});throw error;}
}
function diagnosticsContract(){
  let time=100;const details=browserDiagnostics('/usr/bin/google-chrome','v24.22.1',()=>time);
  assert.equal(details.snapshot().browser_version,null);assert.equal(details.snapshot().received_bytes,0);
  time=105;details.record('spawn',{pid:17});details.phase('Browser.getVersion');
  details.record('pipe-write',{id:1,bytes:42});details.record('pipe-write-return',{id:1,accepted:true});
  time=108;details.record('pipe-write-complete',{id:1,error:null});details.received(7);details.received(11);
  time=111;const before=details.snapshot();assert.equal(before.phase_elapsed_ms,6);assert.equal(before.elapsed_ms,11);assert.equal(before.received_bytes,18);assert.equal(before.exit,null);
  time=120;details.exit(0,null);details.close(0,null);details.version({product:'Chrome/test',protocolVersion:'1.3',jsVersion:'test',unwanted:'not stored'});
  assert.equal(before.exit,null,'failure snapshot must not acquire cleanup exit');
  const after=details.snapshot();assert.equal(after.exit.elapsed_ms,20);assert.equal(after.close.code,0);assert.equal(after.browser_version.product,'Chrome/test');assert(!('unwanted' in after.browser_version));
  details.record('pipe-error',{error:'x'.repeat(1000),code:'EPIPE'});
  assert.equal(details.snapshot().events.at(-1).error.length,160);
  for(let n=0;n<100;n++)details.record('extra');assert.equal(details.snapshot().events.length,32);assert(details.snapshot().dropped_events>0);
  before.events.push({event:'tampered'});assert(!details.snapshot().events.some(event=>event.event==='tampered'));
  const writes=browserDiagnostics('/usr/bin/chromium','test',()=>time);let finish;
  writeDiagnosticPipe({write(wire,callback){assert.equal(wire,'opaque-payload');finish=callback;return false;}},'opaque-payload',1,writes);
  assert.deepEqual(writes.snapshot().events.map(e=>e.event),['pipe-write','pipe-write-return']);
  assert.equal(writes.snapshot().events[1].accepted,false);finish();assert.equal(writes.snapshot().events.at(-1).error,null);
  writeDiagnosticPipe({write(_,callback){callback(Object.assign(Error('closed'),{code:'EPIPE'}));return false;}},'opaque-payload',2,writes);
  assert(writes.snapshot().events.some(e=>e.event==='pipe-write-complete'&&e.code==='EPIPE'));
  assert.throws(()=>writeDiagnosticPipe({write(){throw Error('sync write failed');}},'opaque-payload',3,writes),/sync write failed/);
  assert.equal(writes.snapshot().events.at(-1).event,'pipe-write-threw');
  assert(!JSON.stringify(writes.snapshot()).includes('opaque-payload'),'never record CDP payload');
}

// Use the installed browser ELF, not the distribution shell wrapper. Chromium's
// wrapper starts stdout/stderr cat children which can inherit the CDP pipes.
// Puppeteer's system stable-channel path is the same fixed executable. This
// removes wrapper lifetime ambiguity; it does not diagnose every startup stall.
function chromeExecutable(io=fs){
  const executable='/opt/google/chrome/chrome';
  let fd;
  try{
    fd=io.openSync(executable,io.constants.O_RDONLY|io.constants.O_NOFOLLOW|io.constants.O_NONBLOCK);
    const stat=io.fstatSync(fd),header=Buffer.alloc(4);
    if(!stat.isFile()||(stat.mode&0o111)===0||io.readSync(fd,header,0,4,0)!==4||!header.equals(Buffer.from([0x7f,0x45,0x4c,0x46])))
      throw Error('Preinstalled Chrome must be an executable regular ELF; wrapper fallback forbidden');
    return executable;
  }finally{if(fd!==undefined)io.closeSync(fd);}
}
function executableContract(){
  const expected='/opt/google/chrome/chrome';
  for(const scenario of ['elf','script','short','nonregular','nonexecutable','missing','symlink']){
    let opens=0,closes=0,reads=0;
    const io={constants:{O_RDONLY:0,O_NOFOLLOW:1,O_NONBLOCK:2},
      openSync(file,flags){opens++;assert.equal(file,expected);assert.equal(flags,3);
        if(scenario==='missing'||scenario==='symlink')throw Error(scenario);return 19;},
      fstatSync(fd){assert.equal(fd,19);return {isFile:()=>scenario!=='nonregular',mode:scenario==='nonexecutable'?0o644:0o755};},
      readSync(fd,buffer,offset,length,position){reads++;assert.deepEqual([fd,offset,length,position],[19,0,4,0]);
        Buffer.from(scenario==='script'?'#!/b':'\x7fELF','binary').copy(buffer);return scenario==='short'?3:4;},
      closeSync(fd){assert.equal(fd,19);closes++;}};
    if(scenario==='elf')assert.equal(chromeExecutable(io),expected);
    else assert.throws(()=>chromeExecutable(io));
    assert.equal(opens,1);assert.equal(closes,['missing','symlink'].includes(scenario)?0:1);
    if(['missing','symlink','nonregular','nonexecutable'].includes(scenario))assert.equal(reads,0);
  }
}

// One absolute budget for both startup attempts and all UI work. Cleanup may
// still reclaim the owned child after expiry, but expiry can never yield proof.
function browserBudget(onExpire,{now=Date.now,set=setTimeout,clear=clearTimeout}={}){
  const end=now()+35000;let expired=false;
  const error=()=>Object.assign(Error('Browser proof deadline exceeded'),{code:'BROWSER_DEADLINE'});
  const timer=set(()=>{expired=true;onExpire(error());},35000);
  return {check(){if(expired||now()>=end)throw error();},remaining:()=>Math.max(0,end-now()),cancel:()=>clear(timer)};
}
function recoverableStartup(number,error,serial,snapshot){
  if(number!==0||serial!==1||error.code!=='CDP_COMMAND_TIMEOUT'||error.method!=='Browser.getVersion'||error.commandId!==1||error.first!==true)return false;
  if(snapshot.phase!=='Browser.getVersion'||snapshot.received_bytes!==0||snapshot.browser_version!==null||snapshot.exit!==null||snapshot.close!==null||snapshot.dropped_events!==0)return false;
  const events=snapshot.events,spawn=events.find(event=>event.event==='spawn-return');
  if(!Number.isSafeInteger(spawn?.pid)||spawn.pid<=0||!events.some(event=>event.event==='spawn-event'&&event.pid===spawn.pid))return false;
  if(events.some(event=>['child-error','write-pipe-error','read-pipe-error','pipe-write-threw','protocol-error'].includes(event.event)||event.event==='pipe-write-complete'&&(event.error!==null||event.code!==null)))return false;
  return events.some(event=>event.event==='pipe-write-complete'&&event.id===1&&event.error===null&&event.code===null);
}
// The coordinator knows no browser flags or UI operations. Only the initial
// read-only probe can be replaced, after the exact attempt's cleanup confirms.
async function startOwnedBrowser(create,budget,attempts){
  for(let number=0;number<2;number++){
    budget.check();
    const attempt=create(number);attempts.push(attempt);
    try{
      await attempt.open();
      const version=await attempt.command('Browser.getVersion');attempt.check();budget.check();
      attempt.diagnostics.version(version);
      return {attempt,version};
    }catch(error){
      const before=attempt.captureFailure(error);
      if(!recoverableStartup(number,error,attempt.serial,before.diagnostics))throw error;
      try{
        const cleanup=await attempt.close();
        if(cleanup.status!=='confirmed'||!cleanup.child_closed||!cleanup.profile_removed)throw Error('Startup cleanup unconfirmed');
      }
      catch(cleanupError){throw new Error(error.message+'; cleanup: '+cleanupError.message,{cause:error});}
      // Never reuse a profile, child, or pending map; keep the original deadline.
      // A cleanup-caused pipe reset cannot rewrite the failure-time classification.
      attempt.check();budget.check();
      if(budget.remaining()<=10000)throw Error('Insufficient browser startup budget after cleanup');
    }
  }
  throw Error('Browser startup attempts exhausted');
}
function ownedBrowserAttempt(chrome,number,budget,spawn,temporaryDirectory){
  const diagnostics=browserDiagnostics(chrome,process.version),pending=new Map();
  let profile=null,child=null,lifetime=null,serial=0,buffer='',errors='',failure=null,closing=null,protocolFailure=null;
  let cleanup={status:'not-started',child_closed:false,profile_removed:false};
  const rejectPending=error=>{for(const item of pending.values()){item.timer.cancel();item.reject(error);}pending.clear();};
  const check=()=>{budget.check();if(protocolFailure)throw protocolFailure;};
  const captureFailure=error=>{
    if(!failure)failure={error:error.message.slice(0,4096),diagnostics:diagnostics.snapshot()};
    return failure;
  };
  const command=(method,params={},sessionId)=>new Promise((resolve,reject)=>{
    check();
    if(!lifetime||lifetime.ended)return reject(Error('Chrome stopped: '+errors.slice(-2000)));
    const first=serial===0,id=++serial;diagnostics.phase(method);
    const timer=commandTimer({first,method,id,reject,onTimeout:()=>pending.delete(id)});
    pending.set(id,{resolve,reject,timer});
    const wire=JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0';
    writeDiagnosticPipe(child.stdio[3],wire,id,diagnostics);
  });
  return {
    diagnostics,command,check,captureFailure,get serial(){return serial;},
    async open(){
      budget.check();
      profile=fs.mkdtempSync(path.join(temporaryDirectory,'uas-manager-chrome-'));
      child=spawn(chrome,['--headless=new','--remote-debugging-pipe','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-sync','--no-first-run','--no-default-browser-check','--metrics-recording-only','--password-store=basic','--use-mock-keychain',`--user-data-dir=${profile}`,'about:blank'],{stdio:['ignore','ignore','pipe','pipe','pipe'],shell:false});
      diagnostics.record('spawn-return',{pid:child.pid||null});
      child.once('spawn',()=>diagnostics.record('spawn-event',{pid:child.pid||null}));
      child.once('exit',(code,signal)=>diagnostics.exit(code,signal));
      child.once('close',(code,signal)=>diagnostics.close(code,signal));
      child.on('error',error=>diagnostics.record('child-error',{code:error.code||null,error:error.message}));
      lifetime=trackChild(child,rejectPending);
      if(!child.pid){await lifetime.stopped;throw Error('Chrome spawn failed before acquiring a process');}
      child.stderr.on('data',chunk=>{errors=(errors+chunk).slice(-8192);});
      child.stdio[3].on('error',error=>{diagnostics.record('write-pipe-error',{code:error.code||null,error:error.message});rejectPending(error);});
      child.stdio[4].on('error',error=>{diagnostics.record('read-pipe-error',{code:error.code||null,error:error.message});rejectPending(error);});
      child.stdio[4].on('data',chunk=>{
        diagnostics.received(chunk.length);buffer+=chunk.toString();
        if(buffer.length>16*1024*1024){child.kill('SIGKILL');return;}
        let boundary;
        while((boundary=buffer.indexOf('\0'))>=0){
          const raw=buffer.slice(0,boundary);buffer=buffer.slice(boundary+1);if(!raw)continue;
          let message;
          try{message=JSON.parse(raw);}
          catch(_){
            protocolFailure=Object.assign(Error('Malformed CDP response'),{code:'CDP_PROTOCOL_ERROR'});
            diagnostics.record('protocol-error',{error:protocolFailure.message});captureFailure(protocolFailure);rejectPending(protocolFailure);return;
          }
          const item=pending.get(message?.id);
          if(item){pending.delete(message.id);item.timer.cancel();message.error?item.reject(Error(JSON.stringify(message.error))):item.resolve(message.result);}
        }
      });
    },
    abort(error){
      rejectPending(error);
      if(child&&lifetime&&!lifetime.ended){try{child.kill('SIGKILL');}catch(killError){diagnostics.record('deadline-kill-error',{error:killError.message});}}
    },
    close(){
      if(!closing)closing=(async()=>{
        cleanup={status:'pending',child_closed:false,profile_removed:false};
        try{
          await closeOwnedBrowser(child,lifetime,()=>command('Browser.close'),profile,{remove:ownedProfile=>{
            fs.rmSync(ownedProfile,{recursive:true,force:true,maxRetries:3,retryDelay:100});cleanup.profile_removed=true;
          }});
          cleanup.status='confirmed';
        }catch(error){cleanup.status='failed';cleanup.error=error.message;throw error;}
        finally{cleanup.child_closed=lifetime?.closed===true;rejectPending(Error('Browser session closed'));}
        return {...cleanup};
      })();
      return closing;
    },
    receipt(){return {attempt:number,status:failure||cleanup.status!=='confirmed'?'failed':'passed',failure,stderr:errors,cleanup:{...cleanup},diagnostics:diagnostics.snapshot()};}
  };
}
async function startupRecoveryContract(){
  const timeout=()=>Object.assign(Error('CDP timeout: Browser.getVersion'),{code:'CDP_COMMAND_TIMEOUT',method:'Browser.getVersion',commandId:1,first:true});
  const snapshot=()=>({phase:'Browser.getVersion',received_bytes:0,browser_version:null,exit:null,close:null,dropped_events:0,
    events:[{event:'spawn-return',pid:17},{event:'spawn-event',pid:17},{event:'pipe-write-complete',id:1,error:null,code:null}]});
  assert(recoverableStartup(0,timeout(),1,snapshot()));
  for(const [number,serial,error] of [[1,1,timeout()],[0,2,timeout()],[0,1,Error('CDP timeout: Browser.getVersion')],
    ...[{code:'OTHER'},{method:'Runtime.evaluate'},{commandId:2},{first:false}].map(change=>[0,1,Object.assign(timeout(),change)])])assert(!recoverableStartup(number,error,serial,snapshot()));
  for(const change of [{phase:'Runtime.evaluate'},{received_bytes:1},{browser_version:{}},{exit:{}},{close:{}},{dropped_events:1}])assert(!recoverableStartup(0,timeout(),1,{...snapshot(),...change}));
  for(const event of ['child-error','write-pipe-error','read-pipe-error','pipe-write-threw','protocol-error']){
    const observed=snapshot();observed.events.push({event});assert(!recoverableStartup(0,timeout(),1,observed));
  }
  for(const mode of ['no-spawn','wrong-pid','no-write-complete','write-error']){
    const observed=snapshot();
    if(mode==='no-spawn')observed.events.splice(1,1);
    if(mode==='wrong-pid')observed.events[1].pid=18;
    if(mode==='no-write-complete')observed.events.pop();
    if(mode==='write-error')observed.events.at(-1).code='EPIPE';
    assert(!recoverableStartup(0,timeout(),1,observed));
  }
  async function scenario(mode){
    let time=0,scheduled=0,cleared=0,expired=0,fire;const trace=[],attempts=[];
    const budget=browserBudget(()=>{expired++;},{now:()=>time,set:(fn,ms)=>{assert.equal(ms,35000);scheduled++;fire=fn;return 19;},clear:id=>{assert.equal(id,19);cleared++;}});
    const create=number=>{
      const observed=snapshot();let failure=null;
      return {serial:1,check:()=>budget.check(),diagnostics:{version(){trace.push('version '+number);}},
        open(){trace.push('open '+number);if(mode==='spawn-error')throw Error('spawn failed');},
        async command(method){assert.equal(method,'Browser.getVersion');trace.push('probe '+number);time+=number?850:10000;
          if(number===0||mode==='second-timeout')throw timeout();return {product:'Chrome/test'};},
        captureFailure(error){failure={error:error.message,diagnostics:structuredClone(observed)};return failure;},
        async close(){trace.push('close '+number);time+=1500;observed.events.push({event:'write-pipe-error',code:'ECONNRESET'});
          if(mode==='cleanup-throws')throw Error('profile retained');
          if(mode==='budget-expired'){time=35000;fire();}
          if(mode==='budget-short')time=25000;
          return {status:mode==='cleanup-pending'?'pending':'confirmed',child_closed:mode!=='no-close',profile_removed:mode!=='no-removal'};},
        get failure(){return failure;}};
    };
    let result,caught;
    try{result=await startOwnedBrowser(create,budget,attempts);}
    catch(error){caught=error;}
    finally{budget.cancel();assert.equal(scheduled,1,'one original deadline only');assert.equal(cleared,1);}
    if(mode==='success'){
      assert.ifError(caught);assert.equal(result.version.product,'Chrome/test');assert.equal(attempts.length,2);
      assert.deepEqual(trace,['open 0','probe 0','close 0','open 1','probe 1','version 1']);
      assert.equal(budget.remaining(),22650);assert(!attempts[0].failure.diagnostics.events.some(event=>event.event==='write-pipe-error'));
      // UI/protocol failures after the returned probe are not inside the coordinator.
      await assert.rejects(Promise.reject(Error('UI assertion failed')),/UI assertion/);assert.equal(attempts.length,2);
    }else{
      assert(caught,'negative startup scenario must fail');
      assert.equal(attempts.length,mode==='second-timeout'?2:1);
      assert(!trace.includes('version 1'));assert.equal(expired,mode==='budget-expired'?1:0);
    }
  }
  for(const mode of ['success','second-timeout','spawn-error','cleanup-throws','cleanup-pending','no-close','no-removal','budget-expired','budget-short'])await scenario(mode);
}

async function browserCheck(){
  if(process.env.GITHUB_ACTIONS!=='true'||process.env.RUNNER_OS!=='Linux'||process.env.UAS_MANAGER_BROWSER_TEST!=='1')throw Error('Explicit hosted Linux browser guard required');
  const os=require('node:os'),{spawn}=require('node:child_process');
  const chrome=chromeExecutable();
  const output=path.join(root,'browser-proof'),attempts=[];
  const started=Date.now();let current=null,proof=null,failure=null,failurePhase=null,failureElapsed=null,failureDiagnostics=null,expired=null;
  const budget=browserBudget(error=>{expired=error;current?.abort(error);});
  try{
    fs.mkdirSync(output);
    const opened=await startOwnedBrowser(number=>{
      current=ownedBrowserAttempt(chrome,number,budget,spawn,os.tmpdir());return current;
    },budget,attempts);
    const {version}=opened,command=current.command;
    const target=await command('Target.createTarget',{url:'about:blank'});
    const {sessionId}=await command('Target.attachToTarget',{targetId:target.targetId,flatten:true});
    const send=(method,params)=>command(method,params,sessionId);
    const evaluate=async expression=>{const result=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw Error(JSON.stringify(result.exceptionDetails));return result.result.value;};
    await send('Page.enable');await send('Runtime.enable');await send('Network.enable');
    await send('Network.setBlockedURLs',{urls:['http://*','https://*','ws://*','wss://*']});
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
    const receipts=[],screenshots=[];
    for(const theme of ['C','D'])for(const route of routes){
      const url=pathToFileURL(path.join(root,'connected.html'));url.search=new URLSearchParams({variant:theme,page:route,project,run}).toString();
      const navigation=await send('Page.navigate',{url:url.href});assert(!navigation.errorText);
      await evaluate(`new Promise((resolve,reject)=>{const end=Date.now()+2500;function check(){if(location.href===${JSON.stringify(url.href)}&&document.readyState==='complete'&&document.querySelector('main h1'))resolve(true);else if(Date.now()>end)reject(new Error('missing render'));else setTimeout(check,15)}check()})`);
      const measured=await evaluate(`({theme:document.body.className,heading:document.querySelector('main h1').textContent,width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,nav:!!document.querySelector('nav[aria-label="Project and Run hierarchy"]'),controls:[...document.querySelectorAll('button')].filter(button=>/Request changes|Pause Run/.test(button.textContent)).every(button=>button.disabled)})`);
      assert.equal(measured.theme,'v-'+theme);assert(measured.heading&&measured.nav&&measured.controls);assert(measured.scroll<=measured.width+1,theme+'/'+route+': overflow');
      const accessibility=await send('Accessibility.getFullAXTree');
      assert(accessibility.nodes.some(node=>node.role?.value==='heading'&&node.name?.value===measured.heading));
      assert(accessibility.nodes.some(node=>node.role?.value==='navigation'&&node.name?.value==='Project and Run hierarchy'));
      if(route==='projects'||route==='run'||route==='project'){const name=`${theme}-${route}.png`,shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(output,name),Buffer.from(shot.data,'base64'));screenshots.push(name);}
      receipts.push({theme,route,...measured,accessibility:'heading-and-navigation-present'});
    }
    await evaluate(`document.querySelector('[data-gate-index]').click();new Promise(resolve=>requestAnimationFrame(resolve))`);
    assert(await evaluate(`!document.getElementById('drawer').hidden&&document.activeElement.id==='drawer-title'`));
    await pressEscape(send);await evaluate(`new Promise((resolve,reject)=>{const end=Date.now()+500;function check(){if(document.getElementById('drawer').hidden)resolve(true);else if(Date.now()>end)reject(Error('Escape did not close drawer'));else requestAnimationFrame(check)}check()})`);assert(await evaluate(`document.getElementById('drawer').hidden`));
    await evaluate(`document.querySelector('[data-attention]').click();new Promise(resolve=>requestAnimationFrame(resolve))`);assert(await evaluate(`document.getElementById('item-dialog').open&&document.activeElement.id==='item-title'`));
    await pressEscape(send);await evaluate(`new Promise((resolve,reject)=>{const end=Date.now()+500;function check(){if(!document.getElementById('item-dialog').open)resolve(true);else if(Date.now()>end)reject(Error('Escape did not close dialog'));else requestAnimationFrame(check)}check()})`);assert(await evaluate(`!document.getElementById('item-dialog').open`));
    await evaluate(`document.querySelector('a[data-nav][href*="page=health"]').click()`);assert.equal(await evaluate(`new URLSearchParams(location.search).get('page')`),'health');
    await evaluate(`history.back();new Promise(resolve=>setTimeout(resolve,80))`);assert.equal(await evaluate(`new URLSearchParams(location.search).get('page')`),'run');
    await evaluate(`installDocument(${JSON.stringify(dataFor(documents.disconnected))})`);assert(await evaluate(`!!document.querySelector('[data-status="disconnected"]')`));
    await evaluate(`installDocument(${JSON.stringify(dataFor(documents.reconnected))})`);assert(await evaluate(`document.querySelector('.run-journey').textContent.includes('run.resumed')`));
    await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});assert(await evaluate(`document.documentElement.scrollWidth<=document.documentElement.clientWidth+1`),'mobile Run overflow');
    const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(output,'D-run-mobile.png'),Buffer.from(shot.data,'base64'));screenshots.push('D-run-mobile.png');
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
    await evaluate(`globalThis.actionProof={sent:[],finish:null};installActionHost(${JSON.stringify(project)},{inspect:async packet=>({operation_id:packet.operation_id,outcome:'unknown'}),view:async()=>({status:'available',scope:{deployment_id:'deployment',room_id:'alpha',instance_id:'instance-alpha'},current:{run_id:${JSON.stringify(run)},generation:1,observed_version:'a'.repeat(64)},actions:[{action:'pause',object_id:${JSON.stringify(run)},eligible:true,reason:null}]}),lifecycle:async()=>({status:'unavailable',reason:'FORBIDDEN'}),replacement:async()=>({status:'unavailable',reason:'FORBIDDEN'}),execute:packet=>{actionProof.sent.push(packet);return new Promise((resolve,reject)=>{actionProof.finish=()=>reject(Error('response lost'))})}});document.querySelector('[data-action-panel]').click();new Promise(resolve=>requestAnimationFrame(resolve))`);
    assert(await evaluate(`document.getElementById('item-dialog').open&&document.activeElement.id==='item-title'&&!document.querySelector('[data-human-action="pause"]').disabled`));
    const actionShot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(output,'D-human-controls.png'),Buffer.from(actionShot.data,'base64'));screenshots.push('D-human-controls.png');
    await evaluate(`{const button=document.querySelector('[data-human-action="pause"]');button.click();button.click();}new Promise(resolve=>requestAnimationFrame(resolve))`);
    assert(await evaluate(`actionProof.sent.length===1&&actionProof.sent[0].payload.reason==='human-pause'&&actionProof.sent[0].room_id==='alpha'`));
    await evaluate(`actionProof.finish();new Promise(resolve=>requestAnimationFrame(resolve))`);
    assert(await evaluate(`document.getElementById('item-body').textContent.includes('unknown')`));
    await evaluate(`document.querySelector('#item-actions [data-action-panel]').click();new Promise(resolve=>requestAnimationFrame(resolve))`);
    await evaluate(`document.querySelector('[data-human-action="pause"]').click();new Promise(resolve=>requestAnimationFrame(resolve))`);
    assert(await evaluate(`actionProof.sent.length===1&&document.getElementById('item-body').textContent.includes('Previous outcome unknown')`));
    await evaluate(`installDocument(${JSON.stringify(dataFor(documents.disconnected))})`);
    assert(await evaluate(`!document.getElementById('item-dialog').open&&document.querySelector('[data-action-panel]').disabled`));
    await evaluate(`installActionHost(${JSON.stringify(project)},null)`);
    // Repeated real navigation and interrupted refresh on the existing Project route.
    await evaluate(`document.querySelector('a[data-nav][href*="page=project&"]').click()`);
    for(const name of ['library-current','library-stale','disconnected','library-stale-reconnected','reconnected','reconnected']){
      await evaluate(`installDocument(${JSON.stringify(dataFor(documents[name]))})`);
      const library=await evaluate(`({text:document.querySelector('.library-operations').textContent,controls:document.querySelectorAll('.library-operations button,.library-operations input').length})`);
      assert(library.text.includes('BLOCKED')&&library.text.includes('library-service')&&library.controls===0);
      const expected=name==='library-current'?'current':['library-stale','disconnected','library-stale-reconnected'].includes(name)?'stale':'unknown';
      assert(library.text.includes('data '+expected),name+': Library freshness after refresh');
    }
    const showLibrary=async selector=>{
      await evaluate(`{const target=document.querySelector(${JSON.stringify(selector)});window.scrollTo(0,window.scrollY+target.getBoundingClientRect().top-110);}new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))`);
      assert(await evaluate(`{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();r.top>=90&&r.top<innerHeight-40}`),'Library evidence target must be visible below sticky navigation');
    };
    await showLibrary('.library-operations');
    const libraryShot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(output,'D-library.png'),Buffer.from(libraryShot.data,'base64'));screenshots.push('D-library.png');
    await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    assert(await evaluate(`document.documentElement.scrollWidth<=document.documentElement.clientWidth+1`),'mobile Library overflow');
    await showLibrary('.library-operations');
    const libraryMobile=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(output,'D-library-mobile.png'),Buffer.from(libraryMobile.data,'base64'));screenshots.push('D-library-mobile.png');
    await showLibrary('[data-library-actions]');
    const libraryAttachments=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(output,'D-library-attachments-mobile.png'),Buffer.from(libraryAttachments.data,'base64'));screenshots.push('D-library-attachments-mobile.png');
    proof={status:'passed',browser:version,executable:chrome,sandbox:'enabled; no bypass flags',network:'HTTP/HTTPS/WS/WSS blocked; no server',routes:receipts,interactions:['drawer-click-Escape','dialog-focus-Escape','navigation-Back','live-disconnect-reconnect','mobile-layout','opt-in-human-controls-click','typed-action-double-click','unknown-no-repeat','disconnect-closes-controls','library-current-stale-disconnect-repeated-reconnect','library-mobile-layout'],action_evidence:'Chrome with injected controlled host adapter; actual Python host-owner integration is separately tested',screenshots,pixel_review:'pending independent inspection'};
  }catch(error){
    failure=error;failureElapsed=Math.max(0,Date.now()-started);
    const observed=current?.captureFailure(error);
    failureDiagnostics=observed?.diagnostics||null;failurePhase=failureDiagnostics?.phase||'spawn';
  }finally{
    try { await current?.close(); }
    catch(cleanupError){
      if(failure&&!failure.message.includes(cleanupError.message))failure=new Error(failure.message+'; cleanup: '+cleanupError.message,{cause:failure});
      else if(!failure)failure=cleanupError;
    }
    if(!failure){try{current?.check();budget.check();}catch(error){failure=error;}}
    budget.cancel();
  }
  const records=attempts.map(attempt=>attempt.receipt()),last=records.at(-1);
  if(failure||expired){
    failure=failure||expired;
    if(fs.existsSync(output))fs.writeFileSync(path.join(output,'failure.json'),JSON.stringify({status:'failed',phase:failurePhase||'cleanup',elapsed_ms:failureElapsed===null?Math.max(0,Date.now()-started):failureElapsed,error:failure.message.slice(0,4096),stderr:last?.stderr||'',diagnostics:{at_failure:failureDiagnostics,after_cleanup:last?.diagnostics||null},attempts:records},null,2));
    throw failure;
  }
  // Never publish a success receipt before actual child termination/cleanup.
  fs.writeFileSync(path.join(output,'receipt.json'),JSON.stringify({...proof,lifecycle:'terminated-and-profile-removed',diagnostics:last.diagnostics,startup_recoveries:records.length-1,attempts:records},null,2));
  console.log(`manager real-browser proof: ${proof.routes.length} routes; ${proof.browser.product}; ${output}/receipt.json`);
}
executableContract();
timerContract();
diagnosticsContract();
ownershipContract().then(startupRecoveryContract).then(()=>require('./test-startup-recovery.cjs')()).then(actionContract).then(()=>args.includes('--browser')?browserCheck():undefined).catch(error=>{console.error(error);process.exitCode=1;});
