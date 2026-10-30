// Fixed SDK stdio MCP server; bridge FD3 was admitted before this same-task exec.
import {readSync} from 'node:fs';
import {seqpacketChannel} from '../pi/channel.mjs';
import {toolsForProfile,invokeProfile,negotiateProtocol} from './mcp-tools.mjs';
const profile=process.argv[2] ?? 'native-v1';
if (process.argv.length > 3) throw Error('invalid-profile-arguments');
const tools=toolsForProfile(profile);
const channel=seqpacketChannel(3,{maxQueued:1});
const forgeChannel=seqpacketChannel(4,{maxQueued:1});
let buffer=Buffer.alloc(0), initialized=false, active=false, closed=false, pendingOutput=0;
let admitted=false, activationTimer; const activationDeadline=Date.now()+30000;
const LIMIT=1114112;
function stop() { if (closed) return; closed=true; clearTimeout(activationTimer); channel.close(); forgeChannel.close(); process.stdin.destroy(); process.exitCode=1; }
function write(value) {
  if (closed) return;
  const wire=JSON.stringify(value)+'\n'; const size=Buffer.byteLength(wire);
  if (size>LIMIT || pendingOutput+size>2*LIMIT) return stop();
  pendingOutput+=size; process.stdout.write(wire,()=>{pendingOutput-=size;});
}
function error(id,code,message) { write({jsonrpc:'2.0',id,error:{code,message}}); }
async function handle(r) {
  if (!r || typeof r!=='object' || Array.isArray(r) || r.jsonrpc!=='2.0'
      || typeof r.method!=='string' || Object.keys(r).some(k=>!['jsonrpc','id','method','params'].includes(k))) return stop();
  if (!Object.hasOwn(r,'id')) {
    if (r.method==='notifications/initialized' && initialized) return;
    // Cancellation after an uncertain write cannot authorize replay.
    return stop();
  }
  const id=r.id;
  if (!(typeof id==='string' && id.length<=128 || Number.isSafeInteger(id))) return stop();
  if (r.method==='initialize') {
    if (initialized || typeof r.params?.protocolVersion !== 'string' || r.params.protocolVersion.length>64)
      return error(id,-32602,'unsupported initialization');
    initialized=true;
    return write({jsonrpc:'2.0',id,result:{protocolVersion:negotiateProtocol(r.params.protocolVersion),
      capabilities:{tools:{}},serverInfo:{name:'uas',version:'1.0.0'}}});
  }
  if (!initialized) return error(id,-32000,'not initialized');
  if (r.method==='ping') return write({jsonrpc:'2.0',id,result:{}});
  if (r.method==='tools/list') return write({jsonrpc:'2.0',id,result:{tools}});
  if (r.method!=='tools/call') return error(id,-32601,'unsupported method');
  if (!admitted) return error(id,-32000,'native helper not admitted');
  if (active) return error(id,-32000,'tool call in progress');
  if (!r.params || Object.keys(r.params).some(k=>!['name','arguments','_meta'].includes(k))) return error(id,-32602,'invalid call');
  active=true;
  try { write({jsonrpc:'2.0',id,result:await invokeProfile(['gh','uas_review'].includes(r.params.name) ? forgeChannel : channel,r.params.name,r.params.arguments,profile)}); }
  catch { error(id,-32000,(channel.fenced || forgeChannel.fenced) ? 'channel outcome uncertain; reconcile through canonical owner' : 'invalid tool request'); }
  finally { active=false; if (channel.fenced || forgeChannel.fenced) stop(); }
}
process.stdin.on('data',data=>{
  if (closed) return;
  buffer=Buffer.concat([buffer,data]); if (buffer.length>LIMIT) return stop();
  let index;
  while ((index=buffer.indexOf(10))>=0) {
    const line=buffer.subarray(0,index); buffer=buffer.subarray(index+1);
    let request; try { request=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(line)); } catch { return stop(); }
    handle(request).catch(stop);
  }
});
process.stdin.on('end',stop); process.stdin.on('error',stop); process.stdout.on('error',stop);
process.on('SIGTERM',stop); process.on('SIGINT',stop);

// Local MCP initialization grants no action authority. Only the canonical Hub's
// post-ADMIT record opens calls; arbitrary data/EOF/timeouts fail closed.
function awaitActivation() {
  if (closed || admitted) return;
  const bytes=Buffer.alloc(64);
  try {
    const n=readSync(3,bytes,0,bytes.length,null);
    if (n!==20 || bytes.subarray(0,n).toString('ascii')!=='UAS-HELPER-ACTIVE-1\n') return stop();
    admitted=true; return;
  } catch(error) { if (!['EAGAIN','EWOULDBLOCK','EINTR'].includes(error.code)) return stop(); }
  if (Date.now()>=activationDeadline) return stop();
  activationTimer=setTimeout(awaitActivation,10);
}
awaitActivation();
