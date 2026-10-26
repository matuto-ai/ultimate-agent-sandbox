// Fixed codes only: never SDK error text, argv, environment or session content.
const reasons = new Set(['output-limit', 'host-terminated', 'host-interrupted', 'output-loss',
  'unexpected-host-error', 'native-control-timeout', 'native-initialize-timeout',
  'sdk-stream-ended', 'input-limit', 'invalid-command', 'invalid-or-concurrent-command',
  'closed', 'host-command-failed', 'input-closed', 'startup-failed']);
const fences = new Set(['sdk-stream-failed', 'native-process-lost', 'native-control-timeout',
  'native-initialize-timeout', 'native-identity', 'unsupported-profile', 'unknown-state',
  'needs-input', 'unmatched-ack', 'unexpected-active-turn', 'unknown-or-attention-result',
  'unknown-native-event']);
export function hostDiagnostic(reason, code, fence) {
  return {type:'fixture-host-diagnostic', reason:reasons.has(reason) ? reason : 'unavailable',
    fence:fences.has(fence) ? fence : 'unavailable',
    exit_code:Number.isInteger(code) && code >= 0 && code <= 255 ? code : null};
}

// stderr is diagnostic-only. Keep an error listener for the stream lifetime:
// asynchronous EPIPE can arrive after write() returns or during owned cleanup.
export function writeHostDiagnostic(stream, reason, code, fence, lifecycle) {
  try {
    stream.on('error', () => {});
    stream.write(JSON.stringify({...hostDiagnostic(reason, code, fence),
      ...(lifecycle ? {lifecycle:boundedLifecycle(lifecycle)} : {})}) + '\n');
  } catch {} // Synchronous failure likewise cannot prevent owned cleanup.
}

const signals = new Set(['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGABRT', 'SIGSEGV',
  'SIGBUS', 'SIGILL', 'SIGPIPE', 'SIGTRAP', 'SIGSYS', 'SIGXCPU', 'SIGXFSZ']);
const kernels = new Set(['R', 'S', 'D', 'Z', 'T', 't', 'X', 'I']);
const integer = (value, max) => Number.isInteger(value) && value >= 0 && value <= max ? value : null;
export function nativeDiagnostic(child, readKernel = () => null) {
  if (!child) return {state:'not-spawned', exit_code:null, signal:null, kernel:null};
  try {
    const code = integer(child.exitCode, 255);
    const signal = signals.has(child.signalCode) ? child.signalCode : null;
    const live = child.exitCode === null && child.signalCode === null;
    let kernel = null;
    if (live) { try { const value = readKernel(); kernel = kernels.has(value) ? value : null; } catch {} }
    return {state:live ? 'live' : code !== null || signal !== null ? 'exited' : 'unavailable',
      exit_code:code, signal, kernel};
  } catch { return {state:'unavailable', exit_code:null, signal:null, kernel:null}; }
}

// No process control: observe the existing owned lifecycle, never extend it.
export function lifecycleDiagnostic({phase, initializationMs, before, child,
  readKernel, queries = [], failures = 0, forcedKill = false, cleanupStarted = false}) {
  const final = nativeDiagnostic(child, readKernel);
  let complete = false;
  try { complete = cleanupStarted && failures === 0
    && ['not-spawned', 'exited'].includes(final.state)
    && [...queries].every(p => p.exitCode !== null || p.signalCode !== null); } catch {}
  return {phase:['configuration','native-initialize','ready'].includes(phase) ? phase : 'unavailable',
    initialization_ms:integer(initializationMs, 60000),
    before_cleanup:before ? {
      state:['not-spawned','live','exited'].includes(before.state) ? before.state : 'unavailable',
      exit_code:integer(before.exit_code,255), signal:signals.has(before.signal) ? before.signal : null,
      kernel:kernels.has(before.kernel) ? before.kernel : null} : nativeDiagnostic({}), final_native:final,
    cleanup:!cleanupStarted ? 'unavailable' : complete ? 'complete' : 'incomplete',
    cleanup_failures:integer(failures,255) ?? 255, forced_kill:forcedKill === true};
}

function boundedNative(value) {
  return {state:['not-spawned','live','exited'].includes(value?.state) ? value.state : 'unavailable',
    exit_code:integer(value?.exit_code,255), signal:signals.has(value?.signal) ? value.signal : null,
    kernel:kernels.has(value?.kernel) ? value.kernel : null};
}
function boundedLifecycle(value) {
  return {phase:['configuration','native-initialize','ready'].includes(value.phase) ? value.phase : 'unavailable',
    initialization_ms:integer(value.initialization_ms,60000),
    before_cleanup:boundedNative(value.before_cleanup), final_native:boundedNative(value.final_native),
    cleanup:['complete','incomplete'].includes(value.cleanup) ? value.cleanup : 'unavailable',
    cleanup_failures:integer(value.cleanup_failures,255) ?? 255, forced_kill:value.forced_kill === true};
}
