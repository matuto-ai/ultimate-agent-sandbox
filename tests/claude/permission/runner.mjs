// Deliberate native qualification only. This is NOT a Participant receiver.
import {spawn} from 'node:child_process';
import {createHash, randomUUID} from 'node:crypto';
import {createReadStream, readFileSync, lstatSync, realpathSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {PermissionSlot, exactRead} from './policy.mjs';
import {validateLoopback, closeOwned} from '../../../runtime/claude/sdk-resources.mjs';
import {BINARY_SHA256, CLI_VERSION, SDK_VERSION, MAX_FRAME, UUID} from '../../../runtime/claude/sdk-policy.mjs';

const [sdkRoot, binary, cwd, home, gateway, key, sessionId, file] = process.argv.slice(2);
const incarnation = randomUUID();
let child, query, slot, input, closing = false, started = false, outputBytes = 0;
function write(value) {
  if (closing) return;
  const wire = JSON.stringify(value) + '\n';
  const length = Buffer.byteLength(wire);
  if (length > MAX_FRAME || outputBytes + length > 2 * MAX_FRAME) return shutdown('output-limit', 2);
  outputBytes += length;
  process.stdout.write(wire, () => { outputBytes -= length; });
}
function shutdown(reason, code = 0) {
  if (closing) return;
  closing = true; process.exitCode = code; slot?.cancel(reason);
  closeOwned({input, query, child, queries:new Set(), finish:() => process.exit(code)});
  process.stdin.pause();
}
process.on('SIGTERM', () => shutdown('fixture-host-terminated'));
process.on('SIGINT', () => shutdown('fixture-host-interrupted'));
process.on('unhandledRejection', () => shutdown('fixture-unhandled-error', 2));
process.stdout.on('error', () => shutdown('fixture-output-loss', 2));
// Human waits do not belong in this bounded test runner.
setTimeout(() => shutdown('fixture-deadline', 2), 30000).unref();
function source() {
  let resolve, queued, done = false;
  return {
    [Symbol.asyncIterator]() { return this; },
    next() {
      if (queued !== undefined) { const value = queued; queued = undefined; return Promise.resolve({done:false,value}); }
      return done ? Promise.resolve({done:true}) : new Promise(r => { resolve = r; });
    },
    push(value) { if (done || queued !== undefined) throw new Error('fixture-input-not-ready');
      if (!resolve) { queued = value; return; }
      const r = resolve; resolve = null; r({done:false, value}); },
    end() { done = true; queued = undefined; resolve?.({done:true}); resolve = null; }
  };
}
async function main() {
  if (process.argv.length !== 10 || !UUID.test(sessionId) || !key?.startsWith('fixture-only-'))
    throw new Error('invalid-fixed-fixture');
  validateLoopback(...['/proc/net/dev', '/proc/net/route', '/proc/net/ipv6_route'].map(p => readFileSync(p, 'utf8')));
  const url = new URL(gateway);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) throw new Error('fixture-loopback-required');
  if (realpathSync(cwd) !== cwd || path.dirname(file) !== cwd || lstatSync(file).isSymbolicLink()
      || !lstatSync(file).isFile() || lstatSync(file).size > 1024) throw new Error('invalid-nonce-file');
  const packageRoot = path.join(sdkRoot, 'node_modules/@anthropic-ai/claude-agent-sdk');
  const pkg = JSON.parse(readFileSync(path.join(packageRoot, 'package.json')));
  if (pkg.version !== SDK_VERSION || pkg.claudeCodeVersion !== CLI_VERSION) throw new Error('unqualified-sdk');
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(binary)) hash.update(bytes);
  if (hash.digest('hex') !== BINARY_SHA256) throw new Error('unqualified-native-binary');
  const {query:createQuery} = await import(pathToFileURL(path.join(packageRoot, 'sdk.mjs')));
  input = source();
  query = createQuery({prompt:input, options:{
    pathToClaudeCodeExecutable:binary, cwd, sessionId, tools:['Read'],
    mcpServers:{}, strictMcpConfig:true, disallowedTools:['mcp__*'], settingSources:[],
    permissionMode:'default', permissionPrompts:'host', model:'claude-sonnet-4-6',
    extraArgs:{bare:null, restricted:null, 'replay-user-messages':null},
    env:{PATH:'/usr/bin:/bin', HOME:home, CLAUDE_CONFIG_DIR:path.join(home,'config'),
      ANTHROPIC_BASE_URL:gateway, ANTHROPIC_API_KEY:key, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:'1',
      CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS:'1'},
    hooks:{PreToolUse:[{hooks:[async event => ({hookSpecificOutput:{hookEventName:'PreToolUse',
      permissionDecision:exactRead(event.tool_name, event.tool_input, file) ? 'ask' : 'deny',
      permissionDecisionReason:'Fixed qualification Read requires explicit fixture-controller decision'}})]}]},
    canUseTool:(name, value, options) => {
      if (!slot) throw new Error('permission-before-invocation');
      return slot.request(name, value, options);
    },
    spawnClaudeCodeProcess: options => {
      if (child) throw new Error('duplicate-native-spawn');
      child = spawn(options.command, options.args, {cwd:options.cwd, env:options.env,
        signal:options.signal, stdio:['pipe','pipe','pipe']});
      child.stderr.on('data', () => {}); // Never expose unbounded native diagnostics.
      child.once('exit', () => { write({type:'native-exit'}); shutdown('native-exited'); });
      return child;
    }
  }});
  (async () => {
    try {
      for await (const event of query) {
        if (event.session_id !== sessionId) throw new Error('native-session-mismatch');
        if (event.type === 'system' && event.subtype === 'init'
            && (event.claude_code_version !== CLI_VERSION || JSON.stringify(event.tools) !== '["Read"]'
              || !Array.isArray(event.mcp_servers) || event.mcp_servers.length
              || event.mcp_server_errors?.length || event.plugin_errors?.length))
          throw new Error('unexpected-native-profile');
        write({type:'native',event});
      }
      shutdown('native-stream-ended');
    } catch (error) { write({type:'fixture-error',reason:String(error.message).slice(0,256)}); shutdown('native-stream-failed', 2); }
  })();
  const init = await query.initializationResult();
  if (init.claude_code_version !== CLI_VERSION || closing) throw new Error('unqualified-initialization');
  const fields = readFileSync(`/proc/${child.pid}/stat`, 'utf8').split(')').at(-1).trim().split(/\s+/);
  write({type:'ready', native_pid:child.pid, native_start:fields[19], session_id:sessionId, incarnation});
  let buffer = Buffer.alloc(0);
  process.stdin.on('data', data => {
    if (closing) return;
    buffer = Buffer.concat([buffer,data]);
    if (buffer.length > MAX_FRAME) return shutdown('input-limit', 2);
    let index;
    while ((index = buffer.indexOf(10)) >= 0) {
      const line = buffer.subarray(0,index); buffer = buffer.subarray(index+1);
      try {
        const command = JSON.parse(line);
        if (!command || !UUID.test(command.id)) throw new Error('invalid-command');
        let accepted = false;
        // One invocation for the entire fixture lifetime, NOT an idle/attention gate.
        if (command.op === 'start' && !started && UUID.test(command.uuid)
            && typeof command.content === 'string' && Buffer.byteLength(command.content) < 4096) {
          started = true;
          slot = new PermissionSlot({sessionId, incarnation, invocationId:command.uuid, file, notify:write});
          input.push({type:'user', uuid:command.uuid, session_id:sessionId, parent_tool_use_id:null,
            message:{role:'user', content:command.content}});
          accepted = true; // Test input release only, NOT a Runtime delivery receipt.
        } else if (command.op === 'decision') accepted = slot?.decide(command.identity,command.behavior) ?? false;
        else if (command.op === 'close') {
          write({type:'reply',id:command.id,accepted:true}); shutdown('fixture-controller-close'); return;
        }
        write({type:'reply',id:command.id,accepted});
      } catch { shutdown('fixture-command-error', 2); }
    }
  });
  process.stdin.on('end', () => shutdown('fixture-controller-lost'));
}
main().catch(error => { process.stderr.write(String(error.message).slice(0,256)+'\n'); shutdown('fixture-startup-failed',2); });
