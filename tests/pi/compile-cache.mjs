// Test-only compiled-code reuse, never process/session/fixture state.
import { lstatSync } from 'node:fs';
import { enableCompileCache, constants } from 'node:module';
import { fileURLToPath } from 'node:url';

export function enableJobCompileCache(directory = fileURLToPath(new URL('./.compile-cache/', import.meta.url))) {
  // V8 coverage can be less precise for deserialized functions. Never optimize it.
  if (process.env.NODE_V8_COVERAGE || process.env.NODE_DISABLE_COMPILE_CACHE === '1') return false;
  let stat;
  try { stat = lstatSync(directory); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700) {
    throw new Error('Pi compile cache must be an owned private real directory');
  }
  const result = enableCompileCache(directory);
  if (result.status !== constants.compileCacheStatus.ENABLED) {
    throw new Error('Pi compile cache could not be enabled exclusively: ' + result.status);
  }
  return true;
}
