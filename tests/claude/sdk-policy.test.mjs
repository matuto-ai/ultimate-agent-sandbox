// Synthetic source-policy coverage only: these events are not native evidence.
// No SDK import, subprocess, provider, credentials, or network is used here.
import test from 'node:test';
import assert from 'node:assert/strict';
import {CLI_VERSION, NativeState, exactAck, listingState} from '../../runtime/claude/sdk-policy.mjs';

const SESSION = '11111111-1111-4111-8111-111111111111';
const OTHER_SESSION = '22222222-2222-4222-8222-222222222222';
const FIRST = '33333333-3333-4333-8333-333333333333';
const SECOND = '44444444-4444-4444-8444-444444444444';
const PID = 12345;
const START = 1780000000000;
const CONTENT = 'Untrusted peer traffic: synthetic policy test';

const listing = (overrides = {}) => ({
  pid: PID, sessionId: SESSION, startedAt: START, kind: 'interactive', status: 'idle', ...overrides,
});
const init = (overrides = {}) => ({
  type: 'system', subtype: 'init', session_id: SESSION,
  claude_code_version: CLI_VERSION, tools: [], mcp_servers: [], ...overrides,
});
const ack = (overrides = {}) => ({
  type: 'user', session_id: SESSION, uuid: FIRST, isReplay: true,
  parent_tool_use_id: null, message: {role: 'user', content: CONTENT}, ...overrides,
});
const result = (overrides = {}) => ({
  type: 'result', session_id: SESSION, user_message_uuid: FIRST, subtype: 'success',
  is_error: false, stop_reason: 'end_turn', terminal_reason: 'completed',
  queued_turn_count: 0, permission_denials: [], ...overrides,
});
function pendingState({initialized = true, acknowledged = true} = {}) {
  const state = new NativeState(SESSION);
  if (initialized) state.event(init());
  state.begin(FIRST, CONTENT);
  if (acknowledged) state.event(ack());
  return state;
}
function assertFenced(state) {
  assert.ok(state.fenced);
  assert.equal(state.state(), 'ambiguous');
  assert.throws(() => state.begin(SECOND, 'second'), /no invocation slot/);
}

test('listing requires exact PID, session and captured start identity', () => {
  assert.deepEqual(listingState([listing()], PID, SESSION, null), {
    state: 'safe', reason: 'native-listing-idle', startedAt: START,
  });
  assert.equal(listingState([listing()], PID, SESSION, START).state, 'safe');
  assert.equal(listingState([listing({status: 'busy'})], PID, SESSION, START).state, 'busy');
  const unrelated = listing({pid: PID + 1, sessionId: OTHER_SESSION});
  assert.equal(listingState([unrelated, listing()], PID, SESSION, START).state, 'safe');
  assert.equal(listingState([listing()], PID, SESSION, START + 1).state, 'ambiguous');
});

test('missing, duplicate and partially matching listing identities hold', () => {
  const cases = {
    absent: [],
    unrelated: [listing({pid: PID + 1, sessionId: OTHER_SESSION})],
    duplicate: [listing(), listing()],
    wrongSession: [listing({sessionId: OTHER_SESSION})],
    wrongPid: [listing({pid: PID + 1})],
    stringPid: [listing({pid: String(PID)})],
    missingPid: [listing({pid: undefined})],
    missingSession: [listing({sessionId: undefined})],
    exactWithPidCollision: [listing(), listing({sessionId: OTHER_SESSION})],
    exactWithSessionCollision: [listing(), listing({pid: PID + 1})],
  };
  for (const [name, rows] of Object.entries(cases)) {
    assert.equal(listingState(rows, PID, SESSION, START).state, 'ambiguous', name);
  }
});

test('malformed listing schemas and missing or malformed start times hold', () => {
  for (const rows of [null, {}, '[]', [null], [[]], [1], ['row'], Array.from({length: 65}, () => listing())]) {
    assert.equal(listingState(rows, PID, SESSION, START).state, 'ambiguous');
  }
  for (const startedAt of [undefined, null, String(START), 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(listingState([listing({startedAt})], PID, SESSION, null).state, 'ambiguous');
  }
});

test('waiting, unknown status, background work and attention never list as safe', () => {
  const cases = [
    {status: 'waiting'}, {status: 'unknown'}, {status: undefined}, {status: null}, {status: 'IDLE'},
    {kind: 'background', state: 'working'}, {kind: 'background', state: 'done'},
    {kind: undefined}, {kind: 'unrecognized'}, {state: 'working'}, {state: 'done'},
    {waitingFor: 'permission prompt'}, {waitingFor: 'input needed'}, {waitingFor: null},
  ];
  for (const fields of cases) {
    assert.equal(listingState([listing(fields)], PID, SESSION, START).state, 'ambiguous', JSON.stringify(fields));
  }
});

test('initialization, native idle and silence never independently authorize input', () => {
  const state = new NativeState(SESSION);
  assert.equal(state.state(), null);
  state.event(init());
  assert.equal(state.initialized, true);
  assert.equal(state.state(), null);
  state.event({type: 'system', subtype: 'session_state_changed', session_id: SESSION, state: 'idle'});
  assert.equal(state.state(), null);
  state.event({type: 'system', subtype: 'ui_invalidate', session_id: SESSION});
  assert.equal(state.state(), null);
  assert.equal(state.fenced, null);
});

test('native running holds even without a local pending turn', () => {
  const state = new NativeState(SESSION);
  state.event({type: 'system', subtype: 'session_state_changed', session_id: SESSION, state: 'running'});
  assert.equal(state.state(), 'busy');
  state.event({type: 'system', subtype: 'session_state_changed', session_id: SESSION, state: 'idle'});
  assert.equal(state.state(), null, 'idle still requires the independent fresh sample');
  state.begin(FIRST, CONTENT);
  state.event({type: 'system', subtype: 'session_state_changed', session_id: SESSION, state: 'idle'});
  assert.equal(state.state(), 'busy', 'native idle cannot erase a pending invocation');
});

test('attention, unknown state/event and identity faults fence permanently', () => {
  const events = [
    {type: 'system', subtype: 'session_state_changed', session_id: SESSION, state: 'requires_action'},
    {type: 'system', subtype: 'session_state_changed', session_id: SESSION, state: 'future-state'},
    {type: 'system', subtype: 'session_state_changed', session_id: SESSION},
    {type: 'control_request', session_id: SESSION},
    {type: 'future-event', session_id: SESSION},
    {type: 'system', subtype: 'ui_invalidate', session_id: OTHER_SESSION},
    {type: 'system', subtype: 'ui_invalidate'}, null, 'malformed', [],
  ];
  for (const event of events) {
    const state = pendingState();
    state.event(event);
    const reason = state.fenced;
    assertFenced(state);
    state.event(result());
    state.event({type: 'system', subtype: 'session_state_changed', session_id: SESSION, state: 'idle'});
    assert.equal(state.fenced, reason, 'late success cannot clear the original fence');
    assertFenced(state);
  }
});

test('unsupported native initialization profile fences', () => {
  for (const fields of [
    {claude_code_version: 'other'}, {tools: ['Bash']}, {tools: undefined}, {tools: {}},
    {mcp_servers: [{}]}, {mcp_servers: undefined}, {mcp_servers: {}},
    {mcp_server_errors: ['failed']}, {plugin_errors: ['failed']},
  ]) {
    const state = new NativeState(SESSION);
    state.event(init(fields));
    assertFenced(state);
  }
});

test('exact replay ACK requires matching session, UUID, content, role and parent', () => {
  const pending = {uuid: FIRST, content: CONTENT};
  assert.equal(exactAck(ack(), SESSION, pending), true);
  for (const fields of [
    {type: 'assistant'}, {session_id: OTHER_SESSION}, {session_id: undefined},
    {uuid: SECOND}, {uuid: undefined}, {isReplay: false}, {isReplay: undefined},
    {parent_tool_use_id: 'tool'}, {parent_tool_use_id: undefined},
    {message: {role: 'assistant', content: CONTENT}},
    {message: {role: 'user', content: 'different'}},
    {message: {role: 'user', content: [CONTENT]}},
    {message: {role: 'user', content: CONTENT, extra: true}}, {message: null},
  ]) {
    assert.equal(Boolean(exactAck(ack(fields), SESSION, pending)), false, JSON.stringify(fields));
    const state = pendingState({acknowledged: false});
    state.event(ack(fields));
    assert.equal(state.ack, null);
    assertFenced(state);
  }
});

test('malformed replay cannot acknowledge without a pending invocation', () => {
  // JSON-realizable: neither uuid nor message.content exists; key count alone
  // must not let their undefined values equal optional pending fields.
  const malformed = {
    type: 'user', session_id: SESSION, isReplay: true, parent_tool_use_id: null,
    message: {role: 'user', unexpected: 'text'},
  };
  assert.equal(Boolean(exactAck(malformed, SESSION, null)), false);
  const state = new NativeState(SESSION);
  state.event(malformed);
  assert.equal(state.ack, null);
  assertFenced(state);
});

test('invocation IDs must be primitive UUID strings and pending work cannot be replaced', () => {
  for (const uuid of [undefined, null, 123, '', 'not-a-uuid', [FIRST], {uuid: FIRST}]) {
    const state = new NativeState(SESSION);
    assert.throws(() => state.begin(uuid, CONTENT), /no invocation slot|invalid input/);
    assert.equal(state.pending, null);
  }
  for (const content of [undefined, null, 123, [CONTENT], {text: CONTENT}]) {
    const state = new NativeState(SESSION);
    assert.throws(() => state.begin(FIRST, content), /no invocation slot|invalid input/);
    assert.equal(state.pending, null);
  }
  const state = pendingState();
  assert.throws(() => state.begin(SECOND, 'second'), /no invocation slot/);
  assert.deepEqual(state.pending, {uuid: FIRST, content: CONTENT});
});

test('only correlated successful result resolves a pending invocation', () => {
  const state = pendingState();
  assert.equal(state.ack.uuid, FIRST);
  assert.equal(state.state(), 'busy', 'native input ACK is not turn completion');
  state.event(result());
  assert.equal(state.pending, null);
  assert.equal(state.completed, FIRST);
  assert.equal(state.fenced, null);
  assert.equal(state.state(), null, 'terminal success alone is not a new safe observation');
});

test('missing optional-typed but critical result fields hold responsibility', () => {
  const fields = ['session_id', 'user_message_uuid', 'subtype', 'is_error', 'stop_reason',
    'terminal_reason', 'queued_turn_count', 'permission_denials'];
  for (const field of fields) {
    const event = result();
    delete event[field];
    const state = pendingState();
    state.event(event);
    assertFenced(state);
    assert.equal(state.pending.uuid, FIRST, field);
    assert.equal(state.completed, null, field);
  }
});

test('failed, mismatched, queued or denied results never resolve pending work', () => {
  for (const fields of [
    {session_id: OTHER_SESSION}, {user_message_uuid: SECOND}, {subtype: 'error'},
    {is_error: true}, {is_error: 0}, {stop_reason: 'tool_use'}, {terminal_reason: 'cancelled'},
    {queued_turn_count: 1}, {queued_turn_count: '0'}, {permission_denials: [{}]},
    {permission_denials: {}}, {permission_denials: null},
  ]) {
    const state = pendingState();
    state.event(result(fields));
    assertFenced(state);
    assert.equal(state.pending.uuid, FIRST);
    assert.equal(state.completed, null);
  }
  for (const options of [{initialized: false}, {acknowledged: false}]) {
    const state = pendingState(options);
    state.event(result());
    assertFenced(state);
  }
  const state = new NativeState(SESSION);
  state.event(init());
  state.event(result());
  assertFenced(state);
});

test('previous completed lifecycle may trail the next invocation without erasing it', () => {
  const state = pendingState();
  state.event(result());
  state.begin(SECOND, 'second');
  state.event({type: 'command_lifecycle', session_id: SESSION, command_uuid: FIRST, state: 'completed'});
  assert.equal(state.fenced, null);
  assert.deepEqual(state.pending, {uuid: SECOND, content: 'second'});
  assert.equal(state.state(), 'busy');
  state.event({type: 'command_lifecycle', session_id: SESSION, command_uuid: SECOND, state: 'started'});
  assert.equal(state.fenced, null);
  assert.equal(state.state(), 'busy');
});

test('unexpected activity and lifecycle correlation failures fence', () => {
  for (const event of [
    {type: 'assistant', user_message_uuid: SECOND, parent_tool_use_id: null},
    {type: 'assistant', user_message_uuid: FIRST, parent_tool_use_id: 'tool'},
    {type: 'assistant', user_message_uuid: FIRST},
    {type: 'command_lifecycle', command_uuid: SECOND, state: 'started'},
    {type: 'command_lifecycle', command_uuid: FIRST, state: 'new-state'},
    {type: 'command_lifecycle', state: 'completed'},
    {type: 'command_lifecycle', command_uuid: null, state: 'completed'},
  ]) {
    const state = pendingState();
    state.event({session_id: SESSION, ...event});
    assertFenced(state);
  }
  for (const event of [
    {type: 'assistant', user_message_uuid: FIRST, parent_tool_use_id: null},
    {type: 'command_lifecycle', command_uuid: FIRST, state: 'queued'},
  ]) {
    const state = pendingState();
    state.event(result());
    state.event({session_id: SESSION, ...event});
    assertFenced(state);
  }
});
