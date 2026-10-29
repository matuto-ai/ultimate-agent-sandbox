// Hosted public Pi 1.4.0 SDK contract, not a selected native-image qualification.
// Existing Pi CI supplies exact locked modules and denies network. No provider/auth is created.
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const root=process.env.UAS_PI_INSTALL+'/node_modules/@earendil-works/pi-coding-agent';
assert.equal(JSON.parse(readFileSync(root+'/package.json','utf8')).version,'1.4.0');
const {SessionManager}=await import(pathToFileURL(root+'/dist/index.js'));
assert.equal(typeof SessionManager.open,'function');
const directory=mkdtempSync(path.join(tmpdir(),'uas-pi-public-resume-'));
try {
  const sessions=path.join(directory,'sessions');mkdirSync(sessions,{mode:0o700});
  const file=path.join(sessions,'exact-prior.jsonl'),id='00000000-0000-4000-8000-000000000001';
  const timestamp='2026-10-28T00:00:00.000Z';
  const contents=JSON.stringify({type:'session',version:3,id,timestamp,cwd:directory})+'\n'
    +JSON.stringify({type:'message',id:'abc12345',parentId:null,timestamp,
      message:{role:'user',content:[{type:'text',text:'retained prior work'}],timestamp:1}})+'\n';
  writeFileSync(file,contents,{mode:0o600,flag:'wx'});
  for (let attempt=0;attempt<2;attempt++) {
    // Exact documented overload in pinned official source 4a080252f06caf63a525d7873c5d94d3c23887e0.
    const manager=SessionManager.open(file,sessions,directory);
    assert.equal(manager.getSessionId(),id);assert.equal(manager.getSessionFile(),file);
    assert.equal(manager.getSessionDir(),sessions);assert.equal(manager.getCwd(),directory);
    assert.equal(manager.getHeader().version,3);assert.equal(manager.getEntryCount(),1);
    assert.equal(manager.buildSessionContext().messages[0].content[0].text,'retained prior work');
    assert.equal(readFileSync(file,'utf8'),contents);
  }
} finally { rmSync(directory,{recursive:true,force:true}); }
