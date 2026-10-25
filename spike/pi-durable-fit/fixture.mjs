import './network-guard.mjs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKGROUND_CONTEXT } from '@earendil-works/chord/context';
import { Type } from '@earendil-works/pi-ai';
import { createModels } from '@earendil-works/pi-ai/models';
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from '@earendil-works/pi-ai/providers/faux';
import { createRegistry, defineExtension, defineTool, Harness } from '@earendil-works/pi-durable';
import { openNodeSqliteStorage } from '@earendil-works/pi-durable/storage/sqlite/node';

export const context = BACKGROUND_CONTEXT;
const here = fileURLToPath(new URL('.', import.meta.url));
export const buggy = 'export const total = items => items.reduce((sum, item) => sum + item.price * (1 - item.discount.percent / 100), 0);\n';
export const fixed = 'export const total = items => items.reduce((sum, item) => sum + item.price * (1 - (item.discount?.percent ?? 0) / 100), 0);\n';
export const digest = text => createHash('sha256').update(text).digest('hex');
export const gate = () => Promise.withResolvers();
export const toolCall = (name, id) => fauxAssistantMessage(
  [fauxToolCall(name, {}, { id })], { stopReason: 'toolUse' });
export const workflow = () => [toolCall('inspect_fixture', 'inspect-1'),
  toolCall('test_fixture', 'test-fail'), toolCall('patch_fixture', 'patch-1'),
  toolCall('test_fixture', 'test-pass'), fauxAssistantMessage('Fixture fixed and tested; human delivery decision required.')];

export function ledger(directory, request) {
  const child = spawnSync('/usr/bin/python3', ['-I', '-B', join(here, 'ledger_fixture.py'),
    join(directory, 'room.sqlite')], { input: JSON.stringify(request), encoding: 'utf8',
    timeout: 10_000, maxBuffer: 1_048_576, env: { PATH: '/usr/bin:/bin', HOME: directory } });
  if (child.error || child.status !== 0) throw child.error ?? new Error(child.stderr);
  return JSON.parse(child.stdout);
}
export function command(id, kind = 'fixture.admit', generation = 0, payload = {
  event_id: 'event-1', project: 'fixture-project', text: 'Cart total crashes for undiscounted items.',
}) {
  return { action: 'apply', command: { id, kind, generation, target: 'fixture-project', payload } };
}
export function submitAdmission(run, receipt, content = 'Investigate the fixture event, fix only cart.mjs, then test.') {
  // RoomLedger intentionally returns old receipts for exact authorized retries.
  // Revalidate their current generation before enabling any new Pi execution.
  const current = ledger(run.directory, { action: 'snapshot' }).result.state;
  if (current.enabled !== true || current.generation !== receipt.result.generation) {
    throw new Error('STALE_OR_REVOKED_FIXTURE_ADMISSION');
  }
  return run.root.submit({ type: 'input', requestId: receipt.result.request_id, content }, context);
}
export async function prepare(directory) {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'cart.mjs'), buggy);
  await writeFile(join(directory, 'cart.test.mjs'), `import assert from 'node:assert/strict';\nimport { total } from './cart.mjs';\nassert.equal(total([{price: 100}, {price: 100, discount: {percent: 10}}]), 190);\nassert.equal(total([]), 0);\nconsole.log('cart regression checks passed');\n`);
}
export async function openFixture(directory, { responses = workflow(), barrier, generation = 0 } = {}) {
  const calls = [];
  const faux = fauxProvider();
  faux.setResponses(responses);
  const models = createModels();
  models.setProvider(faux.provider); // Deliberately no real provider or auth loader.
  const registry = createRegistry();
  function checkAuthority() {
    const current = ledger(directory, { action: 'snapshot' }).result.state;
    if (current.enabled !== true || current.generation !== generation) throw new Error('STALE_OR_REVOKED_FIXTURE_AUTHORITY');
  }
  const tool = (name, execute, replay) => defineTool({ name, description: name,
    parameters: Type.Object({}), ...(replay ? { replay } : {}),
    execute: async (_args, api, ctx) => {
      checkAuthority();
      calls.push(name);
      const result = await execute(api, ctx);
      return { output: [{ type: 'text', text: JSON.stringify(result) }] };
    } });
  registry.install(defineExtension({ name: 'bounded-fixture', tools: [
    tool('inspect_fixture', async (api, ctx) => {
      const source = await readFile(join(directory, 'cart.mjs'), 'utf8');
      api.output('Inspecting only cart.mjs\n');
      if (barrier) {
        barrier.started.resolve();
        await new Promise((resolve, reject) => {
          const abort = () => reject(new Error('FIXTURE_INSPECTION_ABORTED'));
          if (ctx.abortSignal?.aborted) return abort();
          ctx.abortSignal?.addEventListener('abort', abort, { once: true });
          barrier.release.promise.then(resolve, reject).finally(() => ctx.abortSignal?.removeEventListener('abort', abort));
        });
      }
      return { source, digest: digest(source) };
    }, 'safe'),
    tool('test_fixture', async () => {
      const child = spawnSync(process.execPath, ['--test', join(directory, 'cart.test.mjs')], {
        cwd: directory, timeout: 5000, maxBuffer: 65536, encoding: 'utf8',
        env: { PATH: '/usr/bin:/bin', HOME: directory },
      });
      if (child.error) throw child.error;
      const result = { exitCode: child.status, stdout: child.stdout, stderr: child.stderr };
      calls.push(result);
      return result;
    }, 'safe'),
    tool('patch_fixture', async () => {
      const path = join(directory, 'cart.mjs');
      if (await readFile(path, 'utf8') !== buggy) throw new Error('UNEXPECTED_FIXTURE_CONTENT');
      checkAuthority();
      await writeFile(path, fixed);
      return { digest: digest(fixed) };
    }),
  ] }));
  const harness = await Harness.open(await openNodeSqliteStorage(join(directory, 'pi.sqlite')),
    { models, registry }, context);
  const root = await harness.root(context, { agent: { model: { provider: 'faux', modelId: 'faux-1' } } });
  return { harness, root, faux, calls, directory };
}
