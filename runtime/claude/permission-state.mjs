// Explicit nonce-Read diagnostic only; default NativeState remains tool-less.
import {NativeState, CLI_VERSION} from './sdk-policy.mjs';

export class PermissionNativeState extends NativeState {
  constructor(sessionId, file, incarnation) {
    super(sessionId);
    this.file = file; this.incarnation = incarnation;
    this.attention = null; this.decision = null; this.toolResult = false;
    this.needsInput = false; this.continuationSeen = false;
  }
  permission(frame) {
    if (this.fenced) return;
    const i = frame.identity;
    if (this.attention || !this.pending || i.sessionId !== this.sessionId
        || i.incarnation !== this.incarnation || i.invocationId !== this.pending.uuid
        || frame.toolName !== 'Read' || frame.input.file_path !== this.file)
      return this.hold('unexpected-permission');
    this.attention = i; this.needsInput = true; this.revision++;
  }
  decided(identity, behavior) {
    if (this.fenced || this.decision || !this.attention
        || JSON.stringify(identity) !== JSON.stringify(this.attention)
        || !['allow', 'deny'].includes(behavior)) return this.hold('unexpected-permission-decision');
    this.decision = behavior; this.revision++;
  }
  event(e) {
    if (this.fenced) return;
    if (!e || e.session_id !== this.sessionId) return this.hold('native-identity');
    if (e.type === 'system' && e.subtype === 'init') {
      if (e.claude_code_version !== CLI_VERSION || JSON.stringify(e.tools) !== '["Read"]'
          || !Array.isArray(e.mcp_servers) || e.mcp_servers.length || e.mcp_server_errors?.length
          || e.plugin_errors?.length) return this.hold('unsupported-profile');
      this.initialized = true; this.revision++; return;
    }
    if (e.type === 'system' && e.subtype === 'session_state_changed' && e.state === 'requires_action') {
      if (!this.pending || this.decision || this.completed) return this.hold('unexpected-attention');
      this.needsInput = true; this.nativeState = e.state; this.revision++; return;
    }
    if (e.type === 'user' && !Object.hasOwn(e, 'isReplay')) {
      const blocks = e.message?.content, meta = e.tool_result_meta;
      if (!this.pending || this.pending.uuid !== this.attention?.invocationId
          || this.decision !== 'allow' || this.toolResult || e.parent_tool_use_id !== null
          || e.message?.role !== 'user' || !Array.isArray(blocks) || blocks.length !== 1
          || blocks[0].type !== 'tool_result' || blocks[0].tool_use_id !== this.attention.toolUseID
          || typeof blocks[0].content !== 'string' || (Object.hasOwn(blocks[0], 'is_error') && blocks[0].is_error !== false)
          || e.tool_use_result?.type !== 'text' || e.tool_use_result.file?.filePath !== this.file
          || !Array.isArray(meta) || meta.length !== 1 || meta[0].id !== this.attention.toolUseID
          || meta[0].permission_decision?.decision !== 'accept'
          || meta[0].permission_decision?.source !== 'user_temporary')
        return this.hold('unmatched-permission-result');
      this.toolResult = true; this.revision++; return; // Never an ACK.
    }
    if (e.type === 'assistant' && this.toolResult && this.pending?.uuid === this.attention?.invocationId) {
      const blocks = e.message?.content;
      // Public SDK stamps only the first assistant frame. This one bounded
      // text continuation carries no receipt/readiness authority of its own.
      if (this.decision !== 'allow' || this.continuationSeen || !this.ack
          || (Object.hasOwn(e, 'user_message_uuid') && e.user_message_uuid !== this.pending.uuid)
          || (Object.hasOwn(e, 'user_message_uuids')
              && JSON.stringify(e.user_message_uuids) !== JSON.stringify([this.pending.uuid]))
          || e.parent_tool_use_id !== null || e.message?.role !== 'assistant' || e.error !== undefined
          || !Array.isArray(blocks) || blocks.length !== 1 || blocks[0]?.type !== 'text'
          || typeof blocks[0].text !== 'string' || Object.keys(blocks[0]).length !== 2)
        return this.hold('unexpected-active-turn');
      this.continuationSeen = true; this.revision++; return;
    }
    if (e.type === 'result' && this.needsInput) {
      if (this.decision !== 'allow' || !this.toolResult || !this.attention
          || this.pending?.uuid !== this.attention.invocationId)
        return this.hold('unresolved-permission-result');
      super.event(e);
      if (!this.fenced && !this.pending) this.needsInput = false;
      return;
    }
    super.event(e);
  }
  state() {
    if (this.fenced || this.needsInput) return 'ambiguous';
    return super.state();
  }
}
