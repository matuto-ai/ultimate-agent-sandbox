// Account-free fixed fixture only. SDK owns Claude's stream; this is not a
// Supervisor-owned native process or a generic launcher/protocol proxy.
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createReadStream, readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import {BINARY_SHA256, CLI_VERSION, SDK_VERSION, MAX_FRAME, UUID, NativeState, listingState} from './sdk-policy.mjs';
import {closeOwned, collectListing, validateLoopback} from './sdk-resources.mjs';

const [sdkRoot, binary, cwd, home, gateway, key, sessionId, resume] = process.argv.slice(2);
let query, child, state, input, closing = false, outputBytes = 0, commandActive = false;
let kernelStart, listingStart = null;
let stderrTail = '';
const queries = new Set();
const DEADLINE = 1500;
const write = value => {
  const wire = JSON.stringify(value) + '\n';
  const size = Buffer.byteLength(wire);
  if (size > MAX_FRAME || outputBytes + size > 2 * MAX_FRAME) return shutdown('output-limit', 2);
  outputBytes += size;
  process.stdout.write(wire, () => { outputBytes -= size; });
};
function shutdown(reason, code = 0) {
  if (closing) return;
  closing = true; process.exitCode = code; state?.hold(reason);
  // SDK first gets its documented graceful-close window; only owned children.
  closeOwned({input, queries, query, child, finish: () => process.exit(code)});
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
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => { state.hold(reason); shutdown(reason, 2); reject(new Error(reason)); }, DEADLINE);
  })]).finally(() => clearTimeout(timer));
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
  return await collectListing(p, queries, DEADLINE);
}
async function sample(env) {
  kernelIdentity();
  if (state.fenced) return {state: 'ambiguous', reason: state.fenced};
  // Public SDK method sends its own correlated request; empty MCP status is
  // liveness, never idle. Do not handcraft or intercept its control protocol.
  const statuses = await deadline(query.mcpServerStatus(), 'native-control-timeout');
  if (!Array.isArray(statuses) || statuses.length) throw new Error('unexpected-mcp-profile');
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
  if (process.argv.length !== 10 || !UUID.test(sessionId) || !['0', '1'].includes(resume)
      || !key?.startsWith('fixture-only-')) throw new Error('invalid-fixed-fixture-configuration');
  const url = new URL(gateway);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port
      || url.username || url.password || url.pathname !== '/' || url.search || url.hash)
    throw new Error('fixture-loopback-only');
  validateLoopback(...['/proc/net/dev', '/proc/net/route', '/proc/net/ipv6_route']
    .map(file => readFileSync(file, 'utf8')));
  const packageRoot = path.join(sdkRoot, 'node_modules/@anthropic-ai/claude-agent-sdk');
  const pkg = JSON.parse(readFileSync(path.join(packageRoot, 'package.json')));
  if (pkg.version !== SDK_VERSION || pkg.claudeCodeVersion !== CLI_VERSION) throw new Error('unqualified-sdk');
  const hash = createHash('sha256');
  for await (const data of createReadStream(binary)) hash.update(data);
  if (hash.digest('hex') !== BINARY_SHA256) throw new Error('unqualified-binary');
  const {query: createQuery} = await import(pathToFileURL(path.join(packageRoot, 'sdk.mjs')));
  const env = {PATH: '/usr/bin:/bin', HOME: home, CLAUDE_CONFIG_DIR: path.join(home, 'config'),
    ANTHROPIC_BASE_URL: gateway, ANTHROPIC_API_KEY: key,
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS: '1'};
  state = new NativeState(sessionId); input = makeInput();
  query = createQuery({prompt: input, options: {
    pathToClaudeCodeExecutable: binary, cwd, env, tools: [], mcpServers: {}, strictMcpConfig: true,
    settingSources: [], disallowedTools: ['mcp__*'], permissionMode: 'default', model: 'claude-sonnet-4-6',
    ...(resume === '1' ? {resume: sessionId} : {sessionId}),
    extraArgs: {bare: null, restricted: null, 'replay-user-messages': null},
    spawnClaudeCodeProcess: options => {
      if (child) throw new Error('duplicate-native-spawn');
      child = spawn(options.command, options.args, {cwd: options.cwd, env: options.env,
        signal: options.signal, stdio: ['pipe', 'pipe', 'pipe']});
      child.stderr.on('data', data => { stderrTail = (stderrTail + data.toString('utf8')).slice(-4096); });
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
  kernelStart = kernelIdentity().start;
  write({type: 'host-ready', host_pid: process.pid, native_pid: child.pid, native_start: kernelStart, session_id: sessionId,
    sdk_version: SDK_VERSION, cli_version: CLI_VERSION, authority: 'sdk-host-owned-fixture-only'});
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
      if (!command || typeof command.id !== 'string' || !UUID.test(command.id) || !['probe', 'send', 'close'].includes(command.op)
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
          write({type: 'reply', id: command.id, state: 'ambiguous', error: error.message});
          shutdown('host-command-failed', 2);
        } finally { commandActive = false; }
      })();
    }
  });
  process.stdin.once('end', () => shutdown('input-closed'));
}
main().catch(error => {
  process.stderr.write(String(error.message).slice(0,512) + '\n' + stderrTail);
  shutdown('startup-failed', 2); process.exitCode = 2;
});
