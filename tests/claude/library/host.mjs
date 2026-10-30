// Fixture-only native path/provider substitutions. Actual pinned SDK/CLI and
// production Library profile/reducer/MCP server execute; no live inference.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createInterface} from 'node:readline';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {nativeOptions,NativeToolState,requireMcp} from '../../../runtime/claude/native-policy.mjs';
import {BINARY_SHA256,CLI_VERSION,SDK_VERSION} from '../../../runtime/claude/sdk-policy.mjs';
const [sdk,binary,root,home,url,key,session,endpoint,python,node,repo]=process.argv.slice(2);
const pkg=JSON.parse(readFileSync(sdk+'/node_modules/@anthropic-ai/claude-agent-sdk/package.json'));
if(pkg.version!==SDK_VERSION || pkg.claudeCodeVersion!==CLI_VERSION
  || createHash('sha256').update(readFileSync(binary)).digest('hex')!==BINARY_SHA256)throw Error('unqualified fixture binary');
const {query:createQuery}=await import(pathToFileURL(sdk+'/node_modules/@anthropic-ai/claude-agent-sdk/sdk.mjs'));
const profile='library-capture-v1';
const options=nativeOptions({binary:'/opt/uas/claude/claude',cwd:'/project/repo',home:'/runtime/home',
  model:'claude-sonnet-4-6',sessionId:session,helper:'/opt/uas/bin/claude-mcp-connector',endpoint:'/transport/peer',profile});
const state=new NativeToolState(session,profile);
let resolve, queued, closed=false, query, child;
const prompt={ [Symbol.asyncIterator](){return this;},next(){
  if(queued){const v=queued;queued=null;return Promise.resolve({value:v,done:false});}
  if(closed)return Promise.resolve({done:true});return new Promise(r=>resolve=r);
}};
const write=v=>{const line=JSON.stringify(v)+'\n';
  if(Buffer.byteLength(line)>262144)throw Error('native-frame-limit');
  process.stdout.write(line);};
function close(){if(closed)return;closed=true;resolve?.({done:true});try{query?.close();}catch{}
  setTimeout(()=>process.exit(0),150).unref();}
process.on('SIGTERM',close);process.on('SIGINT',close);
query=createQuery({prompt,options:{...options,pathToClaudeCodeExecutable:binary,cwd:root,
  env:{...options.env,HOME:home,CLAUDE_CONFIG_DIR:home+'/config',ANTHROPIC_BASE_URL:url,ANTHROPIC_API_KEY:key},
  mcpServers:{uas:{type:'stdio',command:python,args:[repo+'/tests/claude/library/connector.py',endpoint,node,repo,profile],
    env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}}},
  canUseTool:async()=>({behavior:'deny',message:'outside qualified Library fixture profile'}),
  spawnClaudeCodeProcess:o=>{child=spawn(o.command,o.args,{cwd:o.cwd,env:o.env,signal:o.signal,stdio:['pipe','pipe','pipe']});
    child.stderr.on('data',()=>{});write({type:'spawn',pid:child.pid});return child;}
}});
(async()=>{try{for await(const event of query){state.event(event);write({type:'native',event,fence:state.fenced});}}
  catch{write({type:'failure',reason:'native-stream'});}finally{close();}})();
const init=await query.initializationResult();
if(init.claude_code_version!==CLI_VERSION)throw Error('wrong CLI initialization');
// initializationResult acknowledges the CLI control channel, not asynchronous
// MCP startup. Keep the exact production readiness check; never promote pending.
const startupDeadline=performance.now()+5000;
for (;;) {
  const statuses=await query.mcpServerStatus();
  write({type:'mcp-startup',servers:statuses.map(x=>({name:x.name,status:x.status}))});
  if(statuses.length===1 && statuses[0].name==='uas' && statuses[0].status==='connected'){
    requireMcp(statuses);break;
  }
  if(performance.now()>=startupDeadline || statuses.some(x=>x.name!=='uas'
      || !['pending','connected'].includes(x.status)))throw Error('fixture-mcp-startup-failed');
  await delay(50);
}
write({type:'ready',pid:child.pid,profile,allowedTools:options.allowedTools,tools:options.tools,session});
const reader=createInterface({input:process.stdin});
for await(const line of reader){
  const cmd=JSON.parse(line);
  if(cmd.op==='close'){close();break;}
  if(cmd.op!=='send' || state.fenced || state.pending)throw Error('not ready');
  requireMcp(await query.mcpServerStatus());
  state.begin(cmd.uuid,cmd.content);
  const value={type:'user',uuid:cmd.uuid,session_id:session,parent_tool_use_id:null,message:{role:'user',content:cmd.content}};
  if(resolve){const r=resolve;resolve=null;r({value,done:false});}else queued=value;
}
close();
