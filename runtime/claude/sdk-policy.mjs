// Fixed tool-less fixture policy. Public native evidence, never connection=idle.
export const CLI_VERSION = '2.1.310';
export const SDK_VERSION = '0.3.310';
export const BINARY_SHA256 = 'b73676430af12f97316a798b8371f81d640f90a58bdcb8f3ce56a835bb47df56';
export const MAX_FRAME = 256 * 1024;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function listingState(rows, pid, sessionId, startedAt) {
  if (!Array.isArray(rows) || rows.length > 64 || rows.some(x => !x || typeof x !== 'object' || Array.isArray(x)))
    return {state: 'ambiguous', reason: 'listing-schema'};
  const related = rows.filter(x => x.pid === pid || x.sessionId === sessionId);
  if (related.length !== 1 || related[0].pid !== pid || related[0].sessionId !== sessionId)
    return {state: 'ambiguous', reason: 'missing-duplicate-or-mismatched-identity'};
  const row = related[0];
  if (!Number.isSafeInteger(row.startedAt) || (startedAt !== null && row.startedAt !== startedAt))
    return {state: 'ambiguous', reason: 'replaced-start-identity'};
  if (row.kind !== 'interactive' || row.state !== undefined || row.waitingFor !== undefined)
    return {state: 'ambiguous', reason: 'background-or-attention'};
  if (!['idle', 'busy', 'waiting'].includes(row.status))
    return {state: 'ambiguous', reason: 'unknown-status'};
  return {state: row.status === 'idle' ? 'safe' : row.status === 'busy' ? 'busy' : 'ambiguous',
    reason: 'native-listing-' + row.status, startedAt: row.startedAt};
}

export function exactAck(event, sessionId, pending) {
  return !!pending && typeof pending.uuid === 'string' && UUID.test(pending.uuid) && typeof pending.content === 'string'
    && event?.type === 'user' && event.session_id === sessionId && event.uuid === pending.uuid
    && event.isReplay === true && event.parent_tool_use_id === null
    && event.message?.role === 'user' && event.message?.content === pending?.content
    && Object.keys(event.message).length === 2;
}

export class NativeState {
  constructor(sessionId) {
    this.sessionId = sessionId;
    this.pending = null;
    this.ack = null;
    this.completed = null;
    this.nativeState = null;
    this.initialized = false;
    this.fenced = null;
    this.revision = 0;
  }
  hold(reason) { this.fenced ??= reason; this.revision++; }
  begin(uuid, content) {
    if (this.fenced || this.pending || typeof uuid !== 'string' || !UUID.test(uuid) || typeof content !== 'string')
      throw new Error('no invocation slot or invalid input');
    this.pending = {uuid, content}; this.ack = null; this.revision++;
  }
  event(e) {
    if (this.fenced) return;
    if (!e || e.session_id !== this.sessionId) return this.hold('native-identity');
    this.revision++;
    if (e.type === 'system' && e.subtype === 'init') {
      if (e.claude_code_version !== CLI_VERSION || !Array.isArray(e.tools) || e.tools.length
          || !Array.isArray(e.mcp_servers) || e.mcp_servers.length || e.mcp_server_errors?.length
          || e.plugin_errors?.length) return this.hold('unsupported-profile');
      this.initialized = true;
    } else if (e.type === 'system' && e.subtype === 'session_state_changed') {
      if (!['idle', 'running', 'requires_action'].includes(e.state)) return this.hold('unknown-state');
      this.nativeState = e.state;
      if (e.state === 'requires_action') this.hold('needs-input');
    } else if (e.type === 'user') {
      if (!exactAck(e, this.sessionId, this.pending)) return this.hold('unmatched-ack');
      this.ack = e;
    } else if (e.type === 'assistant') {
      if (!this.pending || e.user_message_uuid !== this.pending.uuid || e.parent_tool_use_id !== null)
        this.hold('unexpected-active-turn');
    } else if (e.type === 'command_lifecycle') {
      if (e.state === 'completed' && this.completed !== null && e.command_uuid === this.completed) return;
      if (!this.pending || e.command_uuid !== this.pending.uuid || !['queued', 'started', 'completed'].includes(e.state))
        this.hold('unexpected-active-turn');
    } else if (e.type === 'result') {
      if (!this.initialized || !this.pending || !this.ack || e.user_message_uuid !== this.pending.uuid
          || e.subtype !== 'success' || e.is_error !== false || e.stop_reason !== 'end_turn'
          || e.terminal_reason !== 'completed' || e.queued_turn_count !== 0
          || !Array.isArray(e.permission_denials) || e.permission_denials.length)
        return this.hold('unknown-or-attention-result');
      this.completed = this.pending.uuid; this.pending = null;
    } else if (!(e.type === 'system' && e.subtype === 'ui_invalidate')) this.hold('unknown-native-event');
  }
  state() {
    if (this.fenced) return 'ambiguous';
    if (this.pending || this.nativeState === 'running') return 'busy';
    return null; // Only a separate fresh liveness + exact idle sample can allow input.
  }
}
