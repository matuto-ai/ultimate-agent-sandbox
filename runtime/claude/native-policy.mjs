// Opt-in native MCP profile. The tool-less fixture policy is intentionally untouched.
import {NativeState, CLI_VERSION} from './sdk-policy.mjs';
export const SERVER = 'uas';
export const TOOL_NAMES = Object.freeze(['mcp__uas__uas_peer', 'mcp__uas__uas_review', 'mcp__uas__gh']);
export const LIBRARY_TOOL_NAMES = Object.freeze(['mcp__uas__library_enqueue']);
export function profileTools(profile = 'native-v1') {
  if (profile === 'native-v1') return TOOL_NAMES;
  if (profile === 'library-capture-v1') return LIBRARY_TOOL_NAMES;
  throw Error('unqualified-native-profile');
}
const exact = (actual, wanted) => Array.isArray(actual) && actual.length === wanted.length
  && new Set(actual).size === actual.length && actual.every(x => wanted.includes(x));
export function requireMcp(statuses) {
  if (!Array.isArray(statuses) || statuses.length !== 1 || statuses[0]?.name !== SERVER
      || statuses[0]?.status !== 'connected') throw Error('native-mcp-unavailable');
}
export function nativeOptions({binary, cwd, home, model, sessionId, helper, endpoint, resume = false, providerToken, profile = 'native-v1'}) {
  const names = profileTools(profile);
  if (binary !== '/opt/uas/claude/claude' || helper !== '/opt/uas/bin/claude-mcp-connector'
      || typeof model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(model)
      || ![cwd, home, endpoint].every(x => typeof x === 'string' && x.startsWith('/')
        && !x.includes('/../') && !x.includes('/./') && !x.includes('//') && !/[\x00-\x20\x7f]/.test(x))
      || typeof resume !== 'boolean' || (providerToken !== undefined && (typeof providerToken !== 'string' || !/^[\x21-\x7e]{16,8192}$/.test(providerToken)))) throw Error('native-profile-invalid');
  // No spread of ambient process.env, user settings, plugins or caller tools.
  return {pathToClaudeCodeExecutable: binary, cwd,
    env: {PATH:'/opt/uas/node/bin:/usr/bin:/bin', HOME:home, CLAUDE_CONFIG_DIR:home + '/config',
      ...(providerToken === undefined ? {} : {CLAUDE_CODE_OAUTH_TOKEN:providerToken}),
      LANG:'C.UTF-8', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:'1', CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS:'1'},
    tools:[], mcpServers:{uas:{type:'stdio',command:helper,args:[endpoint,...(profile === 'native-v1' ? [] : [profile])],env:{PATH:'/opt/uas/node/bin:/usr/bin:/bin',LANG:'C.UTF-8'}}},
    strictMcpConfig:true, settingSources:[], allowedTools:[...names], permissionMode:'default', maxTurns:16, model,
    ...(resume ? {resume:sessionId} : {sessionId}),
    extraArgs:{bare:null, restricted:null, 'replay-user-messages':null}};
}
export class NativeToolState extends NativeState {
  constructor(sessionId, profile = 'native-v1') { super(sessionId); this.allowed = profileTools(profile); this.tools = new Set(); this.seenTools=new Set(); this.turnBound=false; this.frames=0; }
  begin(uuid,content) { super.begin(uuid,content); this.turnBound=false; this.frames=0; this.seenTools.clear(); }
  event(e) {
    if (this.fenced) return;
    if (!e || e.session_id !== this.sessionId) return this.hold('native-identity');
    if (e.type === 'system' && e.subtype === 'init') {
      if (e.claude_code_version !== CLI_VERSION || !exact(e.tools, this.allowed)
          || e.mcp_server_errors?.length || e.plugin_errors?.length) return this.hold('unsupported-native-profile');
      try { requireMcp(e.mcp_servers); } catch { return this.hold('unsupported-native-profile'); }
      this.initialized = true; this.revision++; return;
    }
    if (e.type === 'assistant') {
      if (!this.pending || !this.ack || e.parent_tool_use_id !== null || e.error !== undefined
          || e.message?.role!=='assistant' || ++this.frames>1024
          || (Object.hasOwn(e,'user_message_uuid') ? e.user_message_uuid!==this.pending.uuid : !this.turnBound)
          || (Object.hasOwn(e,'user_message_uuids') && JSON.stringify(e.user_message_uuids)!==JSON.stringify([this.pending.uuid])))
        return this.hold('unexpected-active-turn');
      this.turnBound=true;
      const content = e.message?.content;
      if (!Array.isArray(content)) return this.hold('invalid-assistant-content');
      for (const block of content) {
        if (block.type !== 'tool_use') continue;
        if (!this.allowed.includes(block.name) || typeof block.id !== 'string' || !block.id || this.seenTools.has(block.id)
            || this.tools.size >= 8) return this.hold('unsupported-tool-call');
        this.tools.add(block.id); this.seenTools.add(block.id);
      }
      this.revision++; return; // Subsequent frames need no repeated SDK first-frame stamp.
    } else if (e.type === 'tool_progress') {
      if (!this.pending || !this.tools.has(e.tool_use_id) || !this.allowed.includes(e.tool_name) || e.parent_tool_use_id!==null) return this.hold('unmatched-tool-progress');
      this.revision++; return;
    } else if (e.type === 'tool_use_summary') {
      if (!this.pending || !Array.isArray(e.preceding_tool_use_ids) || e.preceding_tool_use_ids.length>8 || !e.preceding_tool_use_ids.every(id=>this.seenTools.has(id))) return this.hold('unmatched-tool-summary');
      this.revision++; return;
    } else if (e.type === 'user' && Array.isArray(e.message?.content)) {
      if (!this.pending || e.parent_tool_use_id !== null || e.message.role !== 'user'
          || !e.message.content.length) return this.hold('unexpected-tool-result');
      for (const block of e.message.content) {
        if (block.type !== 'tool_result' || !this.tools.delete(block.tool_use_id))
          return this.hold('unmatched-tool-result');
      }
      this.revision++; return;
    } else if (e.type === 'result' && this.tools.size) return this.hold('unresolved-tool-call');
    super.event(e);
  }
  state() { return this.fenced ? 'ambiguous' : this.tools.size ? 'busy' : super.state(); }
}
