// Test-only official faux provider. It runs actual Pi, not a mock Pi process.
import { pathToFileURL } from 'node:url';
export default async function (pi) {
  const { fauxProvider, fauxAssistantMessage } = await import(pathToFileURL(process.env.UAS_PI_FAUX_MODULE).href);
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
  pi.registerCommand('fixture-delay', { description: 'Set account-free response delay', handler: async args => {
    delay = Number(args); if (!Number.isInteger(delay) || delay < 0 || delay > 60000) throw Error('invalid delay');
  } });
}
