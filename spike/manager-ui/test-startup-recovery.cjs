// Automatic transport regression contracts using virtual time and owned-process doubles.
// No browser, subprocess, socket, permission, or network operation is executed.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const {EventEmitter}=require('node:events');
const source=fs.readFileSync(path.join(__dirname,'check.cjs'),'utf8');
const helpers=source.slice(source.indexOf('// Pure ownership bookkeeping:'),source.indexOf('async function actionContract'))+
  source.slice(source.indexOf('// Only the first read-only startup probe'),source.indexOf('async function browserCheck'));
function environment(modes=['silent','healthy'],options={}){
  let time=0,sequence=0,profiles=0;const timers=new Map(),trace=[],children=[],removed=[];
  const set=(fn,delay)=>{const id=++sequence;timers.set(id,{fn,at:time+delay,delay});trace.push(['timer',delay]);return id;};
  const clear=id=>timers.delete(id);
  class Clock extends Date{static now(){return time;}}
  const mockfs={mkdtempSync(prefix){const profile=prefix+(++profiles);trace.push(['profile',profile]);return profile;},
    rmSync(profile){if(options.removeError)throw Error('ENOTEMPTY');removed.push(profile);trace.push(['remove',profile]);}};
  const spawn=(executable,args,configuration)=>{
    assert.equal(executable,'/opt/google/chrome/chrome');assert(!args.some(arg=>arg.includes('no-sandbox')));
    assert.equal(JSON.stringify(configuration.stdio),JSON.stringify(['ignore','ignore','pipe','pipe','pipe']));assert.equal(configuration.shell,false);
    const number=children.length,mode=modes[number]||'unexpected';assert.notEqual(mode,'unexpected');
    const child=new EventEmitter();child.pid=mode==='failed-spawn'?undefined:700+number;child.stderr=new EventEmitter();child.stdio=[null,null,child.stderr,new EventEmitter(),new EventEmitter()];
    child.arguments=args;child.mode=mode;children.push(child);trace.push(['spawn',number]);
    if(mode==='failed-spawn'){
      child.stderr=null;child.stdio=[];
      Promise.resolve().then(()=>child.emit('error',Object.assign(Error('EACCES'),{code:'EACCES'})));return child;
    }
    Promise.resolve().then(()=>child.emit('spawn'));
    const end=signal=>{
      if(mode==='no-close'){child.emit('exit',null,signal);return;}
      child.stdio[3].emit('error',Object.assign(Error('read ECONNRESET'),{code:'ECONNRESET'}));
      child.emit('exit',signal?null:0,signal);child.emit('close',signal?null:0,signal);
    };
    child.kill=signal=>{trace.push(['kill',number,signal]);Promise.resolve().then(()=>end(signal));return true;};
    child.stdio[3].write=(wire,callback)=>{
      const message=JSON.parse(wire.slice(0,-1));trace.push(['write',number,message.method]);
      Promise.resolve().then(()=>callback(mode==='write-error'?Object.assign(Error('write failed'),{code:'EPIPE'}):undefined));
      if(mode==='partial')Promise.resolve().then(()=>child.stdio[4].emit('data',Buffer.from('{')));
      if(mode==='malformed')Promise.resolve().then(()=>child.stdio[4].emit('data',Buffer.from('bad\0')));
      if(mode==='malformed-during-close'&&message.method==='Browser.close')Promise.resolve().then(()=>child.stdio[4].emit('data',Buffer.from('bad\0')));
      if(mode==='valid-then-malformed')Promise.resolve().then(()=>child.stdio[4].emit('data',Buffer.from(JSON.stringify({id:message.id,result:{product:'Chrome/test'}})+'\0bad\0')));
      if(mode==='healthy'||mode==='healthy-silent-close'){
        if(message.method==='Browser.getVersion')set(()=>child.stdio[4].emit('data',Buffer.from(JSON.stringify({id:message.id,result:{product:'Chrome/test'}})+'\0')),850);
        else if(message.method==='Browser.close'){if(mode==='healthy')Promise.resolve().then(()=>end(null));}
        else Promise.resolve().then(()=>child.stdio[4].emit('data',Buffer.from(JSON.stringify({id:message.id,error:{message:'UI assertion fixture'}})+'\0')));
      }
      return true;
    };
    return child;
  };
  const context=vm.createContext({assert,Buffer,structuredClone,fs:mockfs,path,process:{version:'v-test'},Date:Clock,setTimeout:set,clearTimeout:clear});
  vm.runInContext(helpers+'\nglobalThis.api={browserBudget,ownedBrowserAttempt,startOwnedBrowser,ownershipContract,timerContract,diagnosticsContract,executableContract,startupRecoveryContract};',context);
  let current=null;const attempts=[],budget=context.api.browserBudget(error=>current?.abort(error));
  const start=()=>context.api.startOwnedBrowser(number=>{current=context.api.ownedBrowserAttempt('/opt/google/chrome/chrome',number,budget,spawn,'/mock');return current;},budget,attempts);
  async function settle(promise){
    let done=false,result,error;promise.then(value=>{done=true;result=value;},value=>{done=true;error=value;});
    for(let steps=0;!done&&steps<100;steps++){
      for(let flush=0;flush<30;flush++)await Promise.resolve();
      if(done)break;
      const next=[...timers].sort((a,b)=>a[1].at-b[1].at)[0];assert(next,'pending without a virtual timer');
      timers.delete(next[0]);time=next[1].at;next[1].fn();
    }
    assert(done,'virtual operation did not settle');if(error)throw error;return result;
  }
  return {api:context.api,start,settle,attempts,budget,trace,children,removed,close:()=>current?.close(),advance:value=>{assert(value>=time);time=value;},get time(){return time;}};
}
async function startupTransportContract(){
  const contracts=environment();contracts.budget.cancel();
  contracts.api.timerContract();contracts.api.diagnosticsContract();contracts.api.executableContract();
  await contracts.api.ownershipContract();await contracts.api.startupRecoveryContract();
  const success=environment();const opened=await success.settle(success.start());
  assert.equal(opened.version.product,'Chrome/test');assert.equal(success.time,12350);assert.equal(success.children.length,2);
  assert.equal(success.trace.filter(item=>item[0]==='timer'&&item[1]===35000).length,1);
  const first=success.attempts[0].receipt();assert.equal(first.failure.diagnostics.received_bytes,0);
  assert(!first.failure.diagnostics.events.some(event=>event.event==='write-pipe-error'));
  assert(first.diagnostics.events.some(event=>event.event==='write-pipe-error'));
  assert.equal(first.cleanup.child_closed,true);assert.equal(first.cleanup.profile_removed,true);
  assert.equal(success.removed.length,1);assert.notEqual(success.children[0].arguments.at(-2),success.children[1].arguments.at(-2));
  await assert.rejects(success.settle(opened.attempt.command('Runtime.evaluate')),/UI assertion fixture/);
  assert.equal(success.children.length,2,'UI failure cannot start another child');
  await success.settle(success.close());assert.equal(success.removed.length,2);success.budget.check();success.budget.cancel();
  const firstSuccess=environment(['healthy']);await firstSuccess.settle(firstSuccess.start());
  assert.equal(firstSuccess.children.length,1);await firstSuccess.settle(firstSuccess.close());firstSuccess.budget.cancel();
  const lateCleanup=environment(['healthy-silent-close']);await lateCleanup.settle(lateCleanup.start());
  lateCleanup.advance(34900);await lateCleanup.settle(lateCleanup.close());
  assert.equal(lateCleanup.time,35000);assert.equal(lateCleanup.attempts[0].receipt().cleanup.child_closed,true);
  assert(lateCleanup.trace.some(item=>item[0]==='kill'&&item[2]==='SIGKILL'));assert.throws(()=>lateCleanup.budget.check(),/deadline exceeded/);
  assert.equal(lateCleanup.children.length,1);lateCleanup.budget.cancel();
  for(const [modes,options,expected] of [
    [['silent','silent'],{},2],[['partial'],{},1],[['malformed'],{},1],[['malformed-during-close'],{},1],[['valid-then-malformed'],{},1],[['failed-spawn'],{},1],[['write-error'],{},1],[['no-close'],{},1],[['silent'],{removeError:true},1]
  ]){
    const test=environment(modes,options);await assert.rejects(test.settle(test.start()));
    assert.equal(test.children.length,expected,modes.join(','));
    try{await test.settle(test.close());}catch(error){assert(/close unconfirmed|ENOTEMPTY/.test(error.message));}
    test.budget.cancel();
  }
  console.log('Manager startup recovery: virtual process/pipe/deadline contracts passed (mocks, not browser proof)');
}
module.exports=startupTransportContract;
if(require.main===module)startupTransportContract().catch(error=>{console.error(error);process.exitCode=1;});

