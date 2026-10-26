// Explicit nonce-Read diagnostic only; default NativeState remains tool-less.
import {DENIAL_MESSAGE} from './permission-policy.mjs';
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
      const block = Array.isArray(blocks) && blocks.length === 1 ? blocks[0] : null;
      if (!this.pending || this.pending.uuid !== this.attention?.invocationId
          || !['allow', 'deny'].includes(this.decision) || this.toolResult || e.parent_tool_use_id !== null
          || e.message?.role !== 'user' || !block || block.type !== 'tool_result'
          || block.tool_use_id !== this.attention.toolUseID || typeof block.content !== 'string')
        return this.hold('unmatched-permission-result');
      if (this.decision === 'allow') {
        if ((Object.hasOwn(block, 'is_error') && block.is_error !== false)
            || e.tool_use_result?.type !== 'text' || e.tool_use_result.file?.filePath !== this.file
            || !Array.isArray(meta) || meta.length !== 1 || meta[0].id !== this.attention.toolUseID
            || meta[0].permission_decision?.decision !== 'accept'
            || meta[0].permission_decision?.source !== 'user_temporary')
          return this.hold('unmatched-permission-result');
      } else {
        // Supplementary pinned-native observation, not a documented SDK field.
        if (block.is_error !== true || block.content !== DENIAL_MESSAGE
            || e.tool_use_result !== 'Error: ' + DENIAL_MESSAGE
            || !Array.isArray(meta) || meta.length !== 1
            || !meta[0] || typeof meta[0] !== 'object' || Object.keys(meta[0]).sort().join(',') !== 'id,non_execution_kind,permission_decision'
            || meta[0].id !== this.attention.toolUseID || meta[0].non_execution_kind !== 'permission-rule'
            || !meta[0].permission_decision
            || Object.keys(meta[0].permission_decision).sort().join(',') !== 'decision,source'
            || meta[0].permission_decision.decision !== 'reject'
            || meta[0].permission_decision.source !== 'user_reject')
          return this.hold('unmatched-permission-result');
      }
      this.toolResult = true; this.revision++; return; // Never an ACK.
    }
    if (e.type === 'assistant' && this.toolResult && this.pending?.uuid === this.attention?.invocationId) {
      const blocks = e.message?.content;
      // Public SDK stamps only the first assistant frame. This one bounded
      // text continuation carries no receipt/readiness authority of its own.
      if (!['allow', 'deny'].includes(this.decision) || this.continuationSeen || !this.ack
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
      if (!['allow', 'deny'].includes(this.decision) || !this.toolResult || !this.attention
          || this.pending?.uuid !== this.attention.invocationId)
        return this.hold('unresolved-permission-result');
      if (this.decision === 'deny') {
        // Preserve the actual denial. Only this one diagnostic invocation may
        // complete with its exact authoritative denial record; never clear a fence.
        const denials = e.permission_denials;
        const denial = Array.isArray(denials) && denials.length === 1 ? denials[0] : null;
        if (!this.initialized || !this.ack || e.user_message_uuid !== this.pending.uuid
            || e.subtype !== 'success' || e.is_error !== false || e.stop_reason !== 'end_turn'
            || e.terminal_reason !== 'completed' || e.queued_turn_count !== 0
            || !denial || Object.keys(denial).sort().join(',') !== 'tool_input,tool_name,tool_use_id'
            || denial.tool_name !== 'Read' || denial.tool_use_id !== this.attention.toolUseID
            || JSON.stringify(denial.tool_input) !== JSON.stringify({file_path:this.file}))
          return this.hold('unresolved-permission-result');
        this.completed = this.pending.uuid; this.pending = null; this.revision++;
      } else super.event(e);
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
