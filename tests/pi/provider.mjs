// Test-only official faux provider. It runs actual Pi, not a mock Pi process.
import { pathToFileURL, fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { writeSync } from 'node:fs';
export default async function (pi) {
  const { fauxProvider, fauxAssistantMessage, fauxToolCall } = await import(pathToFileURL(process.env.UAS_PI_FAUX_MODULE).href);
  const faux = fauxProvider({ tokensPerSecond: 100000 });
  let delay = 0;
  const response = async (_context, options) => {
    await new Promise(resolve => {
      const timer = setTimeout(resolve, delay);
      options?.signal?.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true });
    });
    return fauxAssistantMessage('Account-free fixture response.');
  };
  faux.setResponses(Array.from({ length: 200 }, () => response));
  pi.registerProvider(faux.provider);
  pi.registerCommand('fixture-tools', { description: 'Script official faux provider tool calls', handler: async args => {
    const envelopes = JSON.parse(Buffer.from(args, 'base64url').toString('utf8'));
    if (!Array.isArray(envelopes) || envelopes.length > 16) throw Error('invalid scripted tools');
    faux.setResponses([...envelopes.map(envelope => fauxAssistantMessage(
      fauxToolCall('uas_peer', envelope), { stopReason: 'toolUse' })), response]);
  } });
  if (process.env.UAS_PI_PEER_FD) pi.registerCommand('fixture-peer-probe', {
    description: 'Test-only inherited descriptor attack', handler: async (args, ctx) => {
      const request = JSON.parse(Buffer.from(args, 'base64url').toString('utf8'));
      const fd = Number(process.env.UAS_PI_PEER_FD);
      const data = Buffer.from(request.packet, 'base64url');
      if (data.length > 131072) throw Error('test probe too large');
      if (request.mode === 'raw') {
        const count = writeSync(fd, data);
        ctx.ui.notify(JSON.stringify({ fixture_probe: true, sent: count, pid: process.pid }));
        return;
      }
      if (!['fork', 'handoff'].includes(request.mode)) throw Error('invalid probe');
      const path = fileURLToPath(new URL(request.mode === 'fork' ? './channel-probe.mjs' : './handoff-probe.py', import.meta.url));
      const child = request.mode === 'fork'
        ? spawn(process.execPath, [path, '3', request.packet], { stdio: ['ignore', 'pipe', 'pipe', fd] })
        : spawn('/usr/bin/python3', ['-I', path, 'send', '3', process.execPath, request.packet],
          { stdio: ['ignore', 'pipe', 'pipe', fd] });
      // Don't await child completion: the harness must receive and reply on its
      // ledger-owning thread while actual Pi continues servicing native RPC.
      child.stdout.on('data', data => ctx.ui.notify(JSON.stringify({ fixture_probe: true, mode: request.mode, data: data.toString() })));
      child.stderr.on('data', data => ctx.ui.notify(JSON.stringify({ fixture_probe_error: data.toString() })));
      child.on('error', error => ctx.ui.notify(JSON.stringify({ fixture_probe_error: error.message })));
    } });
  pi.registerCommand('fixture-delay' , { description: 'Set account-free response delay', handler: async args => {
    delay = Number(args); if (!Number.isInteger(delay) || delay < 0 || delay > 60000) throw Error('invalid delay');
  } });
}
