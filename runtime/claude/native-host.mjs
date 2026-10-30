// Explicit native SDK host. Supervisor separately admits actual bootstrap/native child.
// Host PID is cleanup ownership only; no native or helper authority is inferred here.
import {spawn} from 'node:child_process';
import {createHash, randomUUID} from 'node:crypto';
import {createReadStream, readFileSync, lstatSync, realpathSync, writeSync, openSync, fstatSync, closeSync, constants, mkdirSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import {BINARY_SHA256, CLI_VERSION, SDK_VERSION, MAX_FRAME, UUID, NativeState, listingState} from './sdk-policy.mjs';
import {closeOwned, collectListing, validateLoopback, nativeDeadline, CONTROL_DEADLINE} from './sdk-resources.mjs';

import {readProviderAuth} from '../provider-auth.mjs';
import {makeLibraryReadToolPolicy, LIBRARY_READ_PROFILE} from './library-read.mjs';
import {nativeOptions, NativeToolState, requireMcp} from './native-policy.mjs';
import {writeHostDiagnostic, nativeDiagnostic, lifecycleDiagnostic} from './sdk-diagnostics.mjs';

const [cwd, home, endpoint, model, sessionId, resume, manifestFile, manifestDigest, ...optional] = process.argv.slice(2);
const profile = ['library-capture-v1',LIBRARY_READ_PROFILE].includes(optional.at(-1)) ? optional.pop() : 'native-v1';
const authPath = optional[0];
const sdkRoot='/opt/uas/claude-sdk', binary='/opt/uas/claude/claude';
const bootstrap='/opt/uas/bin/claude-native-bootstrap', helper='/opt/uas/bin/claude-mcp-connector';

let query, child, state, input, closing = false, outputBytes = 0, commandActive = false;

let kernelStart, listingStart = null;
let phase = 'configuration', initializationStart, initializationMs = null;
let shutdownRecord, beforeCleanup, cleanupStarted = false, cleanupFailures = 0, forcedKill = false;
const readKernel = () => kernelIdentity().state;
const failure = () => { cleanupFailures = Math.min(255, cleanupFailures + 1); };
process.once('exit', () => {
  // Synchronous bounded diagnostic-only output cannot keep the host alive or
  // be lost when the existing cleanup timer calls process.exit().
  const lifecycle = lifecycleDiagnostic({phase, initializationMs, before:beforeCleanup,
    child, readKernel, queries, failures:cleanupFailures, forcedKill, cleanupStarted});
  writeHostDiagnostic({on() {}, write: wire => writeSync(2, wire)},
    shutdownRecord?.reason, shutdownRecord?.code, shutdownRecord?.fence, lifecycle);
});
const queries = new Set();
const write = value => {
  const wire = JSON.stringify(value) + '\n';
  const size = Buffer.byteLength(wire);
  if (size > MAX_FRAME || outputBytes + size > 2 * MAX_FRAME) return shutdown('output-limit', 2);
  outputBytes += size;
  process.stdout.write(wire, () => { outputBytes -= size; });
};
function shutdown(reason, code = 0) {
  if (closing) return;
  closing = true; process.exitCode = code;
  shutdownRecord = {reason, code, fence:state?.fenced};
  if (initializationStart !== undefined && initializationMs === null)
    initializationMs = Math.min(60000, Math.max(0, Math.round(performance.now() - initializationStart)));
  beforeCleanup = nativeDiagnostic(child, readKernel);
  cleanupStarted = true;
  state?.hold(reason);
  closeOwned({input, queries, query, child, onFailure:failure,
    onForcedKill:()=>{forcedKill=true;}, finish:()=>process.exit(code)});
  process.stdin.pause();
}
process.on('SIGTERM', () => shutdown('host-terminated'));
process.on('SIGINT', () => shutdown('host-interrupted'));
process.stdout.on('error', () => shutdown('output-loss', 2));
process.on('unhandledRejection', () => shutdown('unexpected-host-error', 2));

function kernelIdentity() {
  if (!child || child.exitCode !== null || child.signalCode !== null) throw new Error('native-process-lost');
  const stat = readFileSync(`/proc/${child.pid}/stat`, 'utf8');
  const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  if (kernelStart !== undefined && fields[19] !== kernelStart) throw new Error('native-process-replaced');
  return {start: fields[19], state: fields[0]};
}
function deadline(promise, reason) {
  return nativeDeadline(promise, reason, reason => { state.hold(reason); shutdown(reason, 2); });
}

function makeInput() {
  let resolve, queued = null, done = false;
  return {
    [Symbol.asyncIterator]() { return this; },
    next() {
      if (queued !== null) { const value = queued; queued = null; return Promise.resolve({value, done: false}); }
      if (done) return Promise.resolve({done: true});
      return new Promise(r => { resolve = r; });
    },
    push(value) {
      if (done || queued !== null) throw new Error('input-slot-unavailable');
      if (resolve) { const r = resolve; resolve = null; r({value, done: false}); } else queued = value;
    },
    end() { done = true; queued = null; resolve?.({done: true}); resolve = null; }
  };
}
async function publicListing(env) {
  const p = spawn(binary, ['agents', '--json', '--all', '--setting-sources', ''],
    {cwd, env, stdio: ['ignore', 'pipe', 'pipe']});
  return await collectListing(p, queries, CONTROL_DEADLINE);
}
async function sample(env) {
  kernelIdentity();
  if (state.fenced) return {state: 'ambiguous', reason: state.fenced};
  // Public SDK method sends its own correlated request; empty MCP status is
  // liveness, never idle. Do not handcraft or intercept its control protocol.
  const statuses = await deadline(query.mcpServerStatus(), 'native-control-timeout');
  requireMcp(statuses,profile);
  const rows = await publicListing(env);
  const identity = kernelIdentity();
  if (['T', 't', 'Z', 'X', 'D'].includes(identity.state)) return {state: 'ambiguous', reason: 'kernel-unavailable'};
  const listing = listingState(rows, child.pid, sessionId, listingStart);
  if (listing.startedAt !== undefined) listingStart ??= listing.startedAt;
  return {state: state.state() ?? listing.state, reason: state.fenced ?? listing.reason,
    pid: child.pid, session_id: sessionId, native_state: state.nativeState,
    liveness: 'fresh-public-mcpServerStatus', revision: state.revision};
}
async function main() {
  if (![10,11,12].includes(process.argv.length) || optional.length > 1 || !UUID.test(sessionId) || !['0','1'].includes(resume)
      || !/^[0-9a-f]{64}$/.test(manifestDigest)) throw Error('invalid-native-configuration');
  if (manifestFile!=='/opt/uas/claude-manifest.json') throw Error('invalid-manifest-path');
  const fd=openSync(manifestFile,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  let manifest;
  try {
    const info=fstatSync(fd);
    if (!info.isFile() || info.size<1 || info.size>16384 || info.mode & 0o022) throw Error('invalid-native-manifest');
    const bytes=readFileSync(fd);
    if (createHash('sha256').update(bytes).digest('hex')!==manifestDigest) throw Error('manifest-digest');
    manifest=JSON.parse(bytes.toString('utf8'));
  } finally { closeSync(fd); }
  if (manifest.runtime!=='claude' || manifest.runtime_version!==CLI_VERSION || manifest.sdk_version!==SDK_VERSION)
    throw Error('native-version-mismatch');
  // Supervisor independently verifies image/mount provenance. These checks bind
  // the files actually loaded, not a label or a participant success flag.
  for (const file of ['/opt/uas/bin/claude-host-bootstrap',bootstrap,helper,binary,'/opt/uas/node/bin/node',
      '/opt/uas/claude-sdk/node_modules/@anthropic-ai/claude-agent-sdk/package.json',
      '/opt/uas/claude-sdk/node_modules/@anthropic-ai/claude-agent-sdk/sdk.mjs',
      '/opt/uas/runtime/claude/native-host.mjs','/opt/uas/runtime/claude/native-policy.mjs',
      '/opt/uas/runtime/claude/library-read.mjs','/opt/uas/runtime/pi/library-scan.mjs',
      '/opt/uas/pi/node_modules/yaml/package.json','/opt/uas/pi/node_modules/yaml/dist/index.js',
      '/opt/uas/runtime/claude/mcp-server.mjs','/opt/uas/runtime/claude/mcp-tools.mjs',
      '/opt/uas/runtime/claude/sdk-policy.mjs','/opt/uas/runtime/claude/sdk-resources.mjs',
      '/opt/uas/runtime/claude/sdk-diagnostics.mjs','/opt/uas/runtime/pi/channel.mjs','/opt/uas/runtime/library-capture.mjs','/opt/uas/runtime/provider-auth.mjs']) {
    if (realpathSync(file)!==file || !lstatSync(file).isFile() || lstatSync(file).mode & 0o022)
      throw Error('mutable-native-payload');
    const digest=createHash('sha256'); for await (const data of createReadStream(file)) digest.update(data);
    if (digest.digest('hex')!==manifest.artifacts?.[file]) throw Error('native-payload-mismatch');
  }
  const challenge=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>finish(Error('rendezvous-timeout')),8000);
    function finish(error,value) { clearTimeout(timer); process.stdin.off('readable',ready); process.stdin.off('end',ended); process.stdin.off('error',ended); error ? reject(error) : resolve(value); }
    function ready() { const value=process.stdin.read(32); if(value!==null) finish(null,value); }
    function ended() { finish(Error('rendezvous-input-lost')); }
    process.stdin.on('readable',ready); process.stdin.once('end',ended); process.stdin.once('error',ended); ready();
  });
  const packageRoot = path.join(sdkRoot, 'node_modules/@anthropic-ai/claude-agent-sdk');
  const pkg = JSON.parse(readFileSync(path.join(packageRoot, 'package.json')));
  if (pkg.version !== SDK_VERSION || pkg.claudeCodeVersion !== CLI_VERSION) throw new Error('unqualified-sdk');
  const hash = createHash('sha256');
  for await (const data of createReadStream(binary)) hash.update(data);
  if (hash.digest('hex') !== BINARY_SHA256) throw new Error('unqualified-binary');
  // Fresh launch must not adopt an existing HOME/session store. Never delete,
  // clean, overwrite or quietly reuse a prior attempt. Provisioning/auth is a
  // separate owner concern; lack of provider auth remains a real blocker.
  if (resume!=='0' || realpathSync(path.dirname(home))!==path.dirname(home)) throw Error('fresh-context-required');
  const parent=lstatSync(path.dirname(home));
  if (!parent.isDirectory() || parent.uid!==process.getuid() || parent.mode & 0o077) throw Error('private-context-parent-required');
  mkdirSync(home,{mode:0o700}); // EEXIST (including symlinks) is terminal for this attempt.
  const {query: createQuery} = await import(pathToFileURL(path.join(packageRoot, 'sdk.mjs')));
  const providerToken=authPath === undefined ? undefined : readProviderAuth(authPath,'claude-oauth-token');
  const options=nativeOptions({binary,cwd,home,model,sessionId,helper,endpoint,resume:resume==='1',providerToken,profile});
  const env=options.env;
  state=new NativeToolState(sessionId,profile); input=makeInput();
  const readPermission=makeLibraryReadToolPolicy(state);
  phase='native-initialize'; initializationStart=performance.now();
  query=createQuery({prompt:input,options:{...options,
    canUseTool: async (name,value,context) => {
      if (profile === LIBRARY_READ_PROFILE) return readPermission(name,value,context);
      state.hold('needs-input'); return {behavior:'deny',message:'Tool outside fixed native profile'};
    },
    spawnClaudeCodeProcess: options => {
      if (child) throw new Error('duplicate-native-spawn');
      if (options.command !== binary || options.cwd !== cwd) throw Error('unexpected-sdk-spawn');
      child = spawn(bootstrap, [endpoint, options.command, ...options.args], {cwd:options.cwd, env:options.env,
        signal:options.signal, stdio:['pipe','pipe','pipe','pipe']});
      child.stdio[3].on('error',()=>shutdown('rendezvous-loss',2));
      child.stdio[3].end(challenge,()=>challenge.fill(0));
      // Ownership only: expose the fixed child before initialization so a
      // Supervisor Stop can retain a pidfd even during a cold-start timeout.
      const identity = kernelIdentity();
      write({type: 'native-spawned', host_pid: process.pid, native_pid: child.pid,
        native_start: identity.start, session_id: sessionId});
      // Drain native diagnostics without retaining or exposing arbitrary content.
      child.stderr.on('data', () => {});
      child.once('exit', () => { state.hold('native-process-lost'); write({type: 'native-exit'}); });
      return child;
    }
  }});
  (async () => {
    try { for await (const event of query) { state.event(event); write({type: 'native', event, fence: state.fenced}); } }
    catch { state.hold('sdk-stream-failed'); }
    finally { if (!closing) shutdown('sdk-stream-ended', 2); }
  })();
  const init = await deadline(query.initializationResult(), 'native-initialize-timeout');
  if (init.claude_code_version !== CLI_VERSION) throw new Error('unsupported-initialization');
  initializationMs = Math.min(60000, Math.max(0, Math.round(performance.now() - initializationStart)));
  kernelStart = kernelIdentity().start;
  phase = 'ready';
  write({type: 'host-ready', host_pid: process.pid, native_pid: child.pid, native_start: kernelStart, session_id: sessionId,
    sdk_version: SDK_VERSION, cli_version: CLI_VERSION, authority:'native-child-awaits-supervisor-admission',fresh_context:'exclusive-new-home-explicit-session-no-input'});
  let buffer = Buffer.alloc(0);
  process.stdin.on('data', data => {
    if (closing) return;
    buffer = Buffer.concat([buffer, data]);
    if (buffer.length > MAX_FRAME) return shutdown('input-limit', 2);
    let index;
    while ((index = buffer.indexOf(10)) >= 0) {
      const line = buffer.subarray(0, index); buffer = buffer.subarray(index + 1);
      let command;
      try { command = JSON.parse(line.toString('utf8')); } catch { return shutdown('invalid-command', 2); }
      if (!command || typeof command.id !== 'string' || !UUID.test(command.id) || !['probe','send','close'].includes(command.op)
          || commandActive) return shutdown('invalid-or-concurrent-command', 2);
      commandActive = true;
      (async () => {
        try {
          if (command.op === 'close') { write({type: 'reply', id: command.id, closed: true}); shutdown('closed'); return; }
          const observation = await sample(env);
          if (command.op === 'probe') write({type: 'reply', id: command.id, ...observation});
          else {
            if (typeof command.uuid !== 'string' || !UUID.test(command.uuid) || typeof command.content !== 'string'
                || Buffer.byteLength(command.content) > MAX_FRAME / 2 || command.session_id !== sessionId)
              throw new Error('invalid-send-identity');
            if (observation.state !== 'safe' || state.state() !== null || closing) {
              write({type: 'reply', id: command.id, not_applied: true, ...observation}); return;
            }
            kernelIdentity();
            state.begin(command.uuid, command.content);
            input.push({type: 'user', uuid: command.uuid, session_id: sessionId,
              parent_tool_use_id: null, message: {role: 'user', content: command.content}});
            write({type: 'reply', id: command.id, released: true}); // NOT a receipt.
          }
        } catch (error) {
          state.hold('host-command-failed');
          write({type: 'reply', id: command.id, state: 'ambiguous', error:'native-host-command-failed'});
          shutdown('host-command-failed', 2);
        } finally { commandActive = false; }
      })();
    }
  });
  process.stdin.once('end', () => shutdown('input-closed'));
}
main().catch(() => {
  shutdown('startup-failed', 2); process.exitCode = 2;
});
