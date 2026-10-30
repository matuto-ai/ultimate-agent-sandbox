// Opt-in native MCP profile. The tool-less fixture policy is intentionally untouched.
import {NativeState, CLI_VERSION} from './sdk-policy.mjs';
import {LIBRARY_READ_PROFILE, LIBRARY_READ_TOOLS, LIBRARY_READ_GUIDANCE} from './library-read.mjs';
export const SERVER = 'uas';
export const TOOL_NAMES = Object.freeze(['mcp__uas__uas_peer', 'mcp__uas__uas_review', 'mcp__uas__gh']);
export const LIBRARY_TOOL_NAMES = Object.freeze(['mcp__uas__library_enqueue']);
export function profileTools(profile = 'native-v1') {
  if (profile === 'native-v1') return TOOL_NAMES;
  if (profile === LIBRARY_READ_PROFILE) return LIBRARY_READ_TOOLS;
  if (profile === 'library-capture-v1') return LIBRARY_TOOL_NAMES;
  throw Error('unqualified-native-profile');
}
const canonical = value => JSON.stringify(value, (_key,item)=>item && typeof item==='object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])) : item);
const exact = (actual, wanted) => Array.isArray(actual) && actual.length === wanted.length
  && new Set(actual).size === actual.length && actual.every(x => wanted.includes(x));
export function requireMcp(statuses, profile = 'native-v1') {
  if (profile === LIBRARY_READ_PROFILE) {
    if (!Array.isArray(statuses) || statuses.length) throw Error('unexpected-native-mcp');
    return;
  }
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
  return {pathToClaudeCodeExecutable: binary, cwd:profile === LIBRARY_READ_PROFILE ? '/project/reference' : cwd,
    env: {PATH:'/opt/uas/node/bin:/usr/bin:/bin', HOME:home, CLAUDE_CONFIG_DIR:home + '/config',
      ...(providerToken === undefined ? {} : {CLAUDE_CODE_OAUTH_TOKEN:providerToken}),
      LANG:'C.UTF-8', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:'1', CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS:'1'},
    tools:profile === LIBRARY_READ_PROFILE ? [...LIBRARY_READ_TOOLS] : [], mcpServers:profile === LIBRARY_READ_PROFILE ? {} : {uas:{type:'stdio',command:helper,args:[endpoint,...(profile === 'native-v1' ? [] : [profile])],env:{PATH:'/opt/uas/node/bin:/usr/bin:/bin',LANG:'C.UTF-8'}}},
    strictMcpConfig:true, settingSources:[], allowedTools:profile === LIBRARY_READ_PROFILE ? [] : [...names], permissionMode:'default', maxTurns:16, model,
    ...(profile === LIBRARY_READ_PROFILE ? {permissionPrompts:'host', disallowedTools:['mcp__*'],
      settings:{permissions:{ask:[...LIBRARY_READ_TOOLS]}},
      systemPrompt:{type:'preset',preset:'claude_code',append:LIBRARY_READ_GUIDANCE}} : {}),
    ...(resume ? {resume:sessionId} : {sessionId}),
    extraArgs:{bare:null, restricted:null, 'replay-user-messages':null}};
}
export class NativeToolState extends NativeState {
  constructor(sessionId, profile = 'native-v1') { super(sessionId); this.profile = profile; this.allowed = profileTools(profile); this.tools = new Set(); this.seenTools=new Set(); this.turnBound=false; this.frames=0; this.toolInputs=new Map(); this.readPermission=null; }
  begin(uuid,content) { super.begin(uuid,content); this.turnBound=false; this.frames=0; this.seenTools.clear(); this.toolInputs.clear(); this.readPermission=null; }
  // A native ask notification is not human attention for this one profile only
  // when the exact observed tool is synchronously handled by our fixed policy.
  decideLibraryRead(name,input,context,decision) {
    const p=this.readPermission, call=this.toolInputs.get(context?.toolUseID);
    if (this.fenced || this.profile!==LIBRARY_READ_PROFILE || !this.pending || !this.ack
        || !p || p.decision || this.tools.size!==1 || p.id!==context?.toolUseID
        || !call || call.name!==name || call.input!==canonical(input)
        || decision.behavior!=='allow') { this.hold('unmatched-read-permission'); return false; }
    p.decision='allow'; p.requestId=context.requestId; p.input=decision.updatedInput;
    this.revision++; return true;
  }
  event(e) {
    if (this.fenced) return;
    if (!e || e.session_id !== this.sessionId) return this.hold('native-identity');
    if (e.type === 'system' && e.subtype === 'init') {
      if (e.claude_code_version !== CLI_VERSION || !exact(e.tools, this.allowed)
          || e.mcp_server_errors?.length || e.plugin_errors?.length) return this.hold('unsupported-native-profile');
      try { requireMcp(e.mcp_servers, this.profile); } catch { return this.hold('unsupported-native-profile'); }
      this.initialized = true; this.revision++; return;
    }
    if (this.profile===LIBRARY_READ_PROFILE && e.type==='system' && e.subtype==='session_state_changed') {
      if (e.state==='requires_action') {
        if (!this.pending || !this.ack || this.tools.size!==1 || this.readPermission)
          return this.hold('unexpected-read-attention');
        this.readPermission={id:[...this.tools][0],decision:null};
        this.nativeState=e.state;this.revision++;return;
      }
      if (this.readPermission && this.readPermission.decision!=='allow')
        return this.hold('unresolved-read-permission');
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
        if (this.profile===LIBRARY_READ_PROFILE && this.tools.size) return this.hold('concurrent-read-tools');
        this.tools.add(block.id); this.seenTools.add(block.id);
        if (this.profile===LIBRARY_READ_PROFILE) this.toolInputs.set(block.id,{name:block.name,input:canonical(block.input)});
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
      if (this.profile===LIBRARY_READ_PROFILE) {
        const p=this.readPermission, block=e.message.content[0], meta=e.tool_result_meta;
        const call=this.toolInputs.get(block?.tool_use_id);
        if (Object.hasOwn(e,'isReplay') || e.message.content.length!==1 || !p || p.decision!=='allow'
            || block.tool_use_id!==p.id || !call || !Array.isArray(meta) || meta.length!==1
            || meta[0]?.id!==p.id || meta[0]?.permission_decision?.decision!=='accept'
            || meta[0]?.permission_decision?.source!=='user_temporary'
            || (call.name==='Read' && !block.is_error && e.tool_use_result?.file?.filePath!==p.input.file_path))
          return this.hold('unmatched-read-result');
        this.readPermission=null;this.toolInputs.delete(p.id);
      }
      for (const block of e.message.content) {
        if (block.type !== 'tool_result' || !this.tools.delete(block.tool_use_id))
          return this.hold('unmatched-tool-result');
      }
      this.revision++; return;
    } else if (e.type === 'result' && (this.tools.size || this.readPermission)) return this.hold('unresolved-tool-call');
    super.event(e);
  }
  state() { return this.fenced || this.readPermission ? 'ambiguous' : this.tools.size ? 'busy' : super.state(); }
}
