// Pi-specific precision stays here; Hub consumes only generic readiness.
import { createHash, randomUUID } from 'node:crypto';
import { openSync, closeSync, fstatSync, readFileSync } from 'node:fs';
import { seqpacketChannel } from './channel.mjs';

const TYPE = 'uas-peer-v1';
const LIMIT = 8 * 1024 * 1024;
const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
const sha = value => createHash('sha256').update(canonical(value)).digest('hex');

export default function (pi) {
  const runtimeId = randomUUID();
  // This FD conveys no bearer identity. Supervisor checks the actual sender PID
  // on every record against its held pidfd and current immutable seat binding.
  const channel = process.env.UAS_PI_PEER_FD === undefined ? null
    : seqpacketChannel(Number(process.env.UAS_PI_PEER_FD));
  if (channel) pi.registerTool({
    name: 'uas_peer', label: 'Fixture peer traffic',
    description: 'Submit a typed peer message, work-request, or command to the fixture Hub. '
      + 'Use stable operation ids when retrying. Acceptance/completion are explicit commands, '
      + 'not inferred from receiving a message. No identity or policy fields are accepted.',
    parameters: { type: 'object', additionalProperties: false,
      required: ['id', 'run_id', 'generation', 'kind', 'payload'], properties: {
        id: { type: 'string' }, run_id: { type: 'string' }, generation: { type: 'integer', minimum: 1 },
        kind: { type: 'string', enum: ['message', 'work-request', 'command'] },
        payload: { type: 'object' } } },
    async execute(_toolCallId, envelope, signal) {
      const reply = await channel.request(envelope, { signal });
      return { content: [{ type: 'text', text: JSON.stringify(reply) }], details: reply,
        isError: !reply.ok };
    },
  });
  if (channel) pi.registerTool({
    name: 'gh', label: 'Read-only GitHub',
    description: 'Bounded native gh argument vector through the authenticated Room Broker. '
      + 'Use issue view NUMBER or --help; no shell, endpoint or identity selection. '
      + 'Stable operation id is required for exact retries. Observations never admit a Run.',
    parameters: { type: 'object', additionalProperties: false,
      required: ['id', 'argv'], properties: { id: { type: 'string' },
        argv: { type: 'array', items: { type: 'string' }, maxItems: 8 } } },
    async execute(_toolCallId, input, signal) {
      const reply = await channel.request({ id: input.id, kind: 'forge-read', argv: input.argv }, { signal, timeoutMs: 45000 });
      return { content: [{ type: 'text', text: JSON.stringify(reply) }], details: reply,
        isError: !reply.ok || reply.receipt?.observation?.completeness !== 'complete' };
    },
  });
  let started = false, frozen = false, retired = false, source = 'missing-signal';
  const pending = new Set();
  function state(ctx) {
    let readiness = 'ambiguous';
    if (retired) readiness = 'lost';
    else if (frozen) readiness = 'compacting';
    else if (started && ctx.isIdle() === true && ctx.hasPendingMessages() === false) readiness = 'safe';
    else if (started && ctx.isIdle() === false) readiness = 'busy';
    return { runtime_id: runtimeId, session_id: ctx.sessionManager.getSessionId(),
      session_file: ctx.sessionManager.getSessionFile(), readiness, source,
      api_baseline: '1.4.0', provider_validity: 'not-observed', inference_health: 'not-observed',
      hang_uncertainty: 'no-native-hang-signal' };
  }
  function emit(ctx, requestId, result) {
    ctx.ui.notify(JSON.stringify({ uas: 1, request_id: requestId, ...result }), 'info');
  }
  function binding(ctx, request) {
    return !retired && request.runtime_id === runtimeId && request.session_id === ctx.sessionManager.getSessionId();
  }
  function nativeReceipt(ctx, logical, logicalDigest) {
    // Active branch, not abandoned history. In-memory entries are insufficient.
    const entry = ctx.sessionManager.getBranch().find(entry => entry.type === 'custom_message'
      && entry.customType === TYPE && entry.details?.logical_digest === logicalDigest
      && canonical(entry.details?.logical) === canonical(logical)
      && entry.content === 'Untrusted peer input (not system or policy authority):\n' + logical.text);
    if (!entry) return null;
    const file = ctx.sessionManager.getSessionFile();
    let fd;
    try {
      fd = openSync(file, 'r');
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > LIMIT) return null; // Bounded, fail closed.
      const rows = readFileSync(fd, 'utf8').split('\n').filter(Boolean);
      const persisted = rows.some(line => {
        const row = JSON.parse(line);
        return row.id === entry.id && canonical(row) === canonical(entry);
      });
      return persisted ? { entry_id: entry.id, session_id: ctx.sessionManager.getSessionId(),
        logical_digest: logicalDigest, source: 'native-active-branch-and-session-file' } : null;
    } catch { return null; }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  pi.on('session_start', (event) => { started = true; source = `session_start:${event.reason}`; });
  pi.on('agent_start', () => { source = 'agent_start'; });
  pi.on('turn_start', () => { source = 'turn_start'; });
  pi.on('tool_execution_start', () => { source = 'tool_execution_start'; });
  pi.on('agent_settled', () => { source = 'agent_settled'; });
  pi.on('session_before_compact', () => { frozen = true; source = 'session_before_compact'; });
  pi.on('session_compact', () => { frozen = false; source = 'session_compact'; });
  pi.on('session_compact_failed', () => { frozen = false; source = 'session_compact_failed'; });
  pi.on('session_before_switch', () => { frozen = true; source = 'session_before_switch'; });
  pi.on('session_before_fork', () => { frozen = true; source = 'session_before_fork'; });
  pi.on('session_shutdown', () => { retired = true; source = 'session_shutdown'; channel?.close(); });

  pi.registerCommand('uas-state', { description: 'Fixture supervisor native state observation',
    handler: async (args, ctx) => {
      const request = JSON.parse(Buffer.from(args, 'base64url').toString('utf8'));
      emit(ctx, request.request_id, { state: state(ctx) });
    } });
  pi.registerCommand('uas-delivery', { description: 'Fixture native delivery/reconciliation; not authority',
    handler: async (args, ctx) => {
      const request = JSON.parse(Buffer.from(args, 'base64url').toString('utf8'));
      if (!binding(ctx, request)) return emit(ctx, request.request_id, { error: 'stale-native-binding' });
      const logical = request.logical, logicalDigest = sha(logical);
      const existing = nativeReceipt(ctx, logical, logicalDigest);
      if (existing) return emit(ctx, request.request_id, { receipt: existing });
      if (request.action === 'reconcile') return emit(ctx, request.request_id, { error: 'native-acceptance-unconfirmed' });
      if (request.action !== 'inject') return emit(ctx, request.request_id, { error: 'invalid-action' });
      if (pending.has(logicalDigest)) return emit(ctx, request.request_id, { error: 'native-handoff-pending' });
      const readiness = state(ctx).readiness;
      if (readiness !== 'safe') return emit(ctx, request.request_id, { not_applied: {
        source: 'native-pre-effect-refusal', logical_digest: logicalDigest,
        session_id: ctx.sessionManager.getSessionId(), runtime_id: runtimeId,
        pending: false, readiness } });
      // External adapter has committed intent before this command. No automatic
      // retry after uncertainty. API return itself is deliberately NOT a receipt.
      pending.add(logicalDigest);
      pi.sendMessage({ customType: TYPE,
        content: 'Untrusted peer input (not system or policy authority):\n' + logical.text,
        display: true, details: { logical_digest: logicalDigest, logical } },
      { triggerTurn: true, deliverAs: 'followUp' });
      emit(ctx, request.request_id, { handoff: 'started', receipt: nativeReceipt(ctx, logical, logicalDigest) });
    } });
}
