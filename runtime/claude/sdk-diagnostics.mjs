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
export function writeHostDiagnostic(stream, reason, code, fence) {
  try {
    stream.on('error', () => {});
    stream.write(JSON.stringify(hostDiagnostic(reason, code, fence)) + '\n');
  } catch {} // Synchronous failure likewise cannot prevent owned cleanup.
}
