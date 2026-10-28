// Fixed public Pi 1.4.0 SDK composition, in the bootstrap's exact Node task.
// Persistent provider auth only; no old HOME, settings, plugins or session import.
import {mkdirSync, realpathSync, lstatSync} from 'node:fs';
import path from 'node:path';
import {readProviderAuth} from '../provider-auth.mjs';
import {oauthStore} from './provider-store.mjs';

const [cwd, sessions, provider, modelId, authPath] = process.argv.slice(2);
try {
  if (process.argv.length !== 7 || ![cwd,sessions,authPath].every(x => typeof x === 'string' && x.startsWith('/'))
      || ![provider,modelId].every(x => /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(x))) throw Error();
  readProviderAuth(authPath,'pi-oauth-json',provider);
  const context = path.dirname(sessions), agentDir = context + '/agent';
  const parent = lstatSync(context);
  if (realpathSync(context) !== context || !parent.isDirectory() || parent.uid !== process.getuid() || parent.mode & 0o077)
    throw Error();
  mkdirSync(agentDir,{mode:0o700}); // EEXIST refuses old context/settings adoption.
  // SDK helpers using getAgentDir() must see the same fresh directory.
  process.env.PI_CODING_AGENT_DIR=agentDir;
  const sdk = await import('/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/dist/index.js');
  const {FileAuthStorageBackend}=await import('/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/dist/core/auth-storage.js');
  const credentials=oauthStore(new FileAuthStorageBackend(authPath),provider,
    ()=>readProviderAuth(authPath,'pi-oauth-json',provider));
  const models = await sdk.ModelRuntime.create({credentials,modelsPath:null,allowModelNetwork:false,
    modelsStorePath:agentDir+'/models-cache.json',signal:AbortSignal.timeout(15000)});
  const model = models.getModel(provider,modelId);
  if (!model || model.provider !== provider || model.id !== modelId) throw Error();
  const factory = async ({cwd:requestedCwd,agentDir:requestedDir,sessionManager,sessionStartEvent}) => {
    if (requestedCwd !== cwd || requestedDir !== agentDir) throw Error('native-context-change-denied');
    const services = await sdk.createAgentSessionServices({cwd,agentDir,modelRuntime:models,
      settingsManager:sdk.SettingsManager.inMemory({}),resourceLoaderOptions:{
        noExtensions:true,noSkills:true,noPromptTemplates:true,noThemes:true,noContextFiles:true,
        additionalExtensionPaths:['/opt/uas/runtime/pi/extension.mjs']}});
    const result = await sdk.createAgentSessionFromServices({services,sessionManager,sessionStartEvent,model});
    if (result.modelFallbackMessage) throw Error('native-model-fallback-denied');
    return {...result,services,diagnostics:services.diagnostics};
  };
  const runtime = await sdk.createAgentSessionRuntime(factory,{cwd,agentDir,
    sessionManager:sdk.SessionManager.create(cwd,sessions)});
  await sdk.runRpcMode(runtime);
} catch {
  // Native auth/provider exceptions may contain sensitive details; do not echo.
  process.stderr.write('native-pi-provider-startup-unavailable\n'); process.exit(125);
}
