// Fixed public Pi 1.4.0 SDK composition, in the bootstrap's exact Node task.
// Persistent provider auth only; exact retained-owner resume is not session discovery.
import {mkdirSync, realpathSync, lstatSync, fstatSync, openSync, closeSync, readSync, constants} from 'node:fs';
import path from 'node:path';
import {readProviderAuth} from '../provider-auth.mjs';
import {oauthStore} from './provider-store.mjs';

const [cwd, sessions, provider, modelId, authPath, resumeFile, resumeId] = process.argv.slice(2);
const resumed = process.argv.length === 9;
let resumeFd;
try {
  if (process.env.UAS_PI_NATIVE !== '1' || process.env.UAS_PI_PEER_FD !== '3'
      || process.env.UAS_PI_FORGE_FD !== '4' || !fstatSync(3).isSocket() || !fstatSync(4).isSocket()) throw Error();
  if (![7,9].includes(process.argv.length) || ![cwd,sessions,authPath].every(x => typeof x === 'string' && x.startsWith('/'))
      || ![provider,modelId].every(x => /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(x))) throw Error();
  if (resumed && (typeof resumeFile !== 'string' || path.dirname(resumeFile) !== sessions
      || !resumeFile.endsWith('.jsonl') || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(resumeId))) throw Error();
  // Fixed bootstrap must have entered the exact owned checkout before SDK load.
  if (process.cwd() !== cwd) throw Error();
  readProviderAuth(authPath,'pi-oauth-json',provider);
  const context = path.dirname(sessions), agentDir = context + '/agent';
  const parent = lstatSync(context);
  if (realpathSync(context) !== context || !parent.isDirectory() || parent.uid !== process.getuid() || parent.mode & 0o077)
    throw Error();
  const ownedDirectory = (directory, forbiddenMode) => {
    const info = lstatSync(directory);
    if (realpathSync(directory) !== directory || !info.isDirectory() || info.uid !== process.getuid()
        || info.mode & forbiddenMode) throw Error('native-resume-directory-denied');
  };
  // SDK-created sessions may use normal umask modes; the enclosing context is
  // already owner-only. Never alter permissions or accept writable shared state.
  if (resumed) { ownedDirectory(agentDir,0o077); ownedDirectory(sessions,0o022); }
  else mkdirSync(agentDir,{mode:0o700}); // Initial admission refuses old context/settings adoption.
  // SDK helpers use this exact context; no settings/plugins/context files are loaded.
  process.env.PI_CODING_AGENT_DIR=agentDir;
  let resumeStat;
  const sameFile = info => ['dev','ino','size','mtimeMs','ctimeMs'].every(key => info[key] === resumeStat[key]);
  if (resumed) {
    if (realpathSync(resumeFile) !== resumeFile) throw Error('native-resume-path-denied');
    resumeFd=openSync(resumeFile,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    resumeStat=fstatSync(resumeFd);
    if (!resumeStat.isFile() || resumeStat.uid !== process.getuid() || resumeStat.mode & 0o022
        || resumeStat.nlink !== 1 || resumeStat.size < 1 || !sameFile(lstatSync(resumeFile))) throw Error('native-resume-file-denied');
    // The public SDK initializes missing/empty files and migrates old headers.
    // Refuse those cases before open(), including its unterminated-line repair.
    const head=Buffer.alloc(16384), tail=Buffer.alloc(1);
    const count=readSync(resumeFd,head,0,head.length,0), newline=head.indexOf(10,0);
    if (newline < 0 || newline >= count || readSync(resumeFd,tail,0,1,resumeStat.size-1)!==1
        || tail[0]!==10) throw Error('native-resume-header-denied');
    const header=JSON.parse(head.subarray(0,newline).toString('utf8'));
    if (header.type!=='session' || header.version!==3 || header.id!==resumeId || header.cwd!==cwd)
      throw Error('native-resume-session-denied');
    if (!sameFile(fstatSync(resumeFd)) || !sameFile(lstatSync(resumeFile))) throw Error('native-resume-file-changed');
  }
  const sdk = await import('/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/dist/index.js');
  let sessionManager;
  if (resumed) sessionManager=sdk.SessionManager.open(resumeFile,sessions,cwd);
  if (resumed && (sessionManager.getSessionId()!==resumeId || sessionManager.getSessionFile()!==resumeFile
      || sessionManager.getSessionDir()!==sessions || sessionManager.getCwd()!==cwd
      || sessionManager.getHeader()?.version!==3 || sessionManager.getHeader()?.cwd!==cwd
      || !sameFile(fstatSync(resumeFd)) || !sameFile(lstatSync(resumeFile)))) throw Error('native-resume-result-denied');
  if (resumeFd !== undefined) { closeSync(resumeFd); resumeFd=undefined; }
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
  if (!resumed) sessionManager=sdk.SessionManager.create(cwd,sessions);
  const runtime = await sdk.createAgentSessionRuntime(factory,{cwd,agentDir,
    sessionManager,...(resumed ? {sessionStartEvent:{type:'session_start',reason:'resume'}} : {})});
  await sdk.runRpcMode(runtime);
} catch {
  // Native auth/provider exceptions may contain sensitive details; do not echo.
  process.stderr.write('native-pi-provider-startup-unavailable\n'); process.exit(125);
} finally {
  if (resumeFd !== undefined) closeSync(resumeFd);
}
