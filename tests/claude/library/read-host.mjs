// Exact official SDK/CLI, production policy and reducer; fixture paths/provider only.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createInterface} from 'node:readline';
import {spawn} from 'node:child_process';
import {nativeOptions,NativeToolState,requireMcp} from '../../../runtime/claude/native-policy.mjs';
import {makeLibraryReadToolPolicy} from '../../../runtime/claude/library-read.mjs';
import {BINARY_SHA256,CLI_VERSION,SDK_VERSION} from '../../../runtime/claude/sdk-policy.mjs';
import {validateLoopback} from '../../../runtime/claude/sdk-resources.mjs';
const [sdk,binary,root,home,url,key,session,reference,command]=process.argv.slice(2);
validateLoopback(...['/proc/net/dev','/proc/net/route','/proc/net/ipv6_route'].map(p=>readFileSync(p,'utf8')));
const endpoint=new URL(url);
if(endpoint.protocol!=='http:'||endpoint.hostname!=='127.0.0.1'||!endpoint.port||endpoint.username||endpoint.password||endpoint.pathname!=='/'||endpoint.search||endpoint.hash)throw Error('loopback fixture required');
const pkg=JSON.parse(readFileSync(sdk+'/node_modules/@anthropic-ai/claude-agent-sdk/package.json'));
if(pkg.version!==SDK_VERSION||pkg.claudeCodeVersion!==CLI_VERSION||createHash('sha256').update(readFileSync(binary)).digest('hex')!==BINARY_SHA256)throw Error('unqualified fixture binary');
const {query:createQuery}=await import(pathToFileURL(sdk+'/node_modules/@anthropic-ai/claude-agent-sdk/sdk.mjs'));
const profile='library-read-v1';
const options=nativeOptions({binary:'/opt/uas/claude/claude',cwd:'/project/repo',home:'/runtime/home',model:'claude-sonnet-4-6',sessionId:session,helper:'/opt/uas/bin/claude-mcp-connector',endpoint:'/transport/peer',profile});
const state=new NativeToolState(session,profile);
let resolve,queued,closed=false,query,child;
const prompt={ [Symbol.asyncIterator](){return this;},next(){if(queued){const v=queued;queued=null;return Promise.resolve({value:v,done:false});}if(closed)return Promise.resolve({done:true});return new Promise(r=>resolve=r);}};
const write=v=>{const line=JSON.stringify(v)+'\n';if(Buffer.byteLength(line)>262144)throw Error('frame bound');process.stdout.write(line);};
function close(){if(closed)return;closed=true;resolve?.({done:true});try{query?.close();}catch{}setTimeout(()=>process.exit(0),150).unref();}
process.on('SIGTERM',close);process.on('SIGINT',close);
const permit=makeLibraryReadToolPolicy(state,{reference,command});
query=createQuery({prompt,options:{...options,pathToClaudeCodeExecutable:binary,cwd:root,
  env:{...options.env,HOME:home,CLAUDE_CONFIG_DIR:home+'/config',ANTHROPIC_BASE_URL:url,ANTHROPIC_API_KEY:key},
  canUseTool:async(name,input,context)=>{const result=await permit(name,input,context);write({type:'permission',name,input,result});return result;},
  spawnClaudeCodeProcess:o=>{child=spawn(o.command,o.args,{cwd:o.cwd,env:o.env,signal:o.signal,stdio:['pipe','pipe','pipe']});child.stderr.on('data',()=>{});write({type:'spawn',pid:child.pid});return child;}}});
(async()=>{try{for await(const event of query){state.event(event);write({type:'native',event,fence:state.fenced});}}catch(e){write({type:'failure',reason:String(e)});}finally{close();}})();
const init=await query.initializationResult();if(init.claude_code_version!==CLI_VERSION)throw Error('wrong version');
requireMcp(await query.mcpServerStatus(),profile);
write({type:'ready',pid:child.pid,tools:options.tools,allowedTools:options.allowedTools,session});
for await(const line of createInterface({input:process.stdin})){
 const cmd=JSON.parse(line);if(cmd.op==='close'){close();break;}
 if(cmd.op!=='send'||state.fenced||state.pending)throw Error('not ready');
 requireMcp(await query.mcpServerStatus(),profile);state.begin(cmd.uuid,cmd.content);
 const value={type:'user',uuid:cmd.uuid,session_id:session,parent_tool_use_id:null,message:{role:'user',content:cmd.content}};
 if(resolve){const r=resolve;resolve=null;r({value,done:false});}else queued=value;
}
close();
