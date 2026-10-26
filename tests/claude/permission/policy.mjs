// Qualification-only one-shot callback correlation. Not Hub or human authority.
import {createHash} from 'node:crypto';

// Public transient flag settings, not user/project configuration writes.
// Ask rules precede native in-working-directory Read auto-approval.
export function permissionProfile() {
  return {tools:['Read'], permissionMode:'default', permissionPrompts:'host',
    settings:{permissions:{ask:['Read']}}};
}

export function exactRead(toolName, input, file) {
  return toolName === 'Read' && input !== null && typeof input === 'object'
    && !Array.isArray(input) && Object.keys(input).length === 1 && input.file_path === file;
}
const token = value => typeof value === 'string' && value.length > 0 && value.length <= 256;
const sameIdentity = (a, b) => a !== null && typeof a === 'object' && !Array.isArray(a)
  && Object.keys(a).length === Object.keys(b).length
  && Object.keys(b).every(key => a[key] === b[key]);

export class PermissionSlot {
  constructor({sessionId, incarnation, invocationId, file, notify}) {
    if (![sessionId, incarnation, invocationId, file].every(token)) throw new Error('invalid-fixture-scope');
    Object.assign(this, {sessionId, incarnation, invocationId, file, notify});
    this.used = false; this.pending = null; this.closed = false;
  }
  request(toolName, input, {signal, requestId, toolUseID, agentID}) {
    if (this.used || this.closed || signal.aborted || agentID !== undefined
        || !token(requestId) || !token(toolUseID) || !exactRead(toolName, input, this.file))
      throw new Error('unexpected-permission-request');
    this.used = true;
    const approvedInput = Object.freeze({file_path: this.file});
    const identity = Object.freeze({sessionId: this.sessionId, incarnation: this.incarnation,
      invocationId: this.invocationId, requestId, toolUseID,
      inputDigest: createHash('sha256').update(JSON.stringify(approvedInput)).digest('hex')});
    return new Promise(resolve => {
      const abort = () => this.cancel('fixture-operation-cancelled');
      this.pending = {identity, approvedInput, resolve, signal, abort};
      signal.addEventListener('abort', abort, {once: true});
      // Recheck after listener installation; never leave an aborted request live.
      if (signal.aborted) abort();
      else {
        try { this.notify({type: 'attention', identity, toolName, input: approvedInput}); }
        catch { this.cancel('fixture-notification-failed'); }
      }
    });
  }
  decide(identity, behavior) {
    const pending = this.pending;
    if (this.closed || !pending || pending.signal.aborted || !sameIdentity(identity, pending.identity)
        || !['allow', 'deny'].includes(behavior)) return false;
    this.pending = null;
    pending.signal.removeEventListener('abort', pending.abort);
    pending.resolve(behavior === 'allow'
      ? {behavior, updatedInput: pending.approvedInput, toolUseID: pending.identity.toolUseID}
      : {behavior, message: 'Explicit fixture-controller denial; not human authorization',
          toolUseID: pending.identity.toolUseID});
    return true;
  }
  cancel(reason) {
    this.closed = true;
    const pending = this.pending;
    this.pending = null;
    if (!pending) return;
    pending.signal.removeEventListener('abort', pending.abort);
    pending.resolve({behavior: 'deny', message: reason, interrupt: true,
      toolUseID: pending.identity.toolUseID});
  }
}
