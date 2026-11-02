// Fixture process/cleanup contracts only: no browser or child is launched.
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),assert=require('node:assert/strict');
const source=fs.readFileSync(path.join(__dirname,'check.cjs'),'utf8');
const helper=source.slice(source.indexOf('async function freshLibraryDocuments('),source.indexOf('async function freshLibraryDocumentContract('));
module.exports=async()=>{
  for(const outcome of ['success','producer-failure','deadline','initial-expired','large-budget']){
    const events=[];let callback,checks=0,options;
    const budget={remaining:()=>outcome==='large-budget'?9000:500,check(){checks++;if(outcome==='initial-expired'||outcome==='deadline'&&checks===2)throw Error('original deadline');}};
    const context={process:{env:{}},path,fs:{mkdtempSync(){events.push('create');return '/tmp/owned-fixture';},
      readFileSync(file){events.push('read');return 'fresh '+path.basename(file);},
      rmSync(directory,settings){assert.equal(directory,'/tmp/owned-fixture');assert(settings.recursive&&settings.force);events.push('remove');}},
      require(name){if(name==='node:os')return {tmpdir:()=>'/tmp'};
        assert.equal(name,'node:child_process');return {execFile(command,args,configuration,done){
          assert.equal(command,'python3');assert(args[0].endsWith('/tests/test_manager_ui.py'));
          assert.equal(args[1],'--write-browser-fixtures');assert.equal(args[2],'/tmp/owned-fixture/documents');
          options=configuration;callback=done;events.push('spawn');}};}};
    vm.createContext(context);vm.runInContext(helper,context);
    const waiting=context.freshLibraryDocuments(budget);
    if(outcome==='initial-expired'){await assert.rejects(waiting,/original deadline/);assert.deepEqual(events,[]);continue;}
    assert.deepEqual(events,['create','spawn']);assert.equal(options.timeout,outcome==='large-budget'?2000:500);
    assert.equal(options.killSignal,'SIGKILL','only the owned producer is killed at its absolute allowance');
    callback(outcome==='producer-failure'?Error('producer stopped'):null);
    if(['success','large-budget'].includes(outcome))assert.deepEqual(Object.keys(await waiting),['connected','reconnected']);
    else await assert.rejects(waiting,/producer stopped|original deadline/);
    assert.equal(events.at(-1),'remove','owned directory removed only after child callback');
    if(!['success','large-budget'].includes(outcome))assert(!events.includes('read'),'failed/expired acquisition cannot return fixture');
  }
};
if(require.main===module)module.exports().catch(error=>{console.error(error);process.exitCode=1;});
