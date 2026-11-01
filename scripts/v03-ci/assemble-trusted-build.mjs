/**
 * Operator-only offline builder of the SHUN_V03_BUILD_FILE trust envelope.
 *
 * Usage:
 *   node scripts/v03-ci/assemble-trusted-build.mjs <absolute-spec.json> <absolute-output.json>
 *   SHA256 printed on stdout is pinned separately as SHUN_V03_BUILD_SHA256.
 *
 * NO npm downloads, source generation, HTTP requests, test fixture fallback,
 * signing private keys, or effect execution. The operator supplies the exact
 * immutable PUBLIC SDK K/S and reviewed Shun B/C module artifacts.
 */
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

const SHA = /^[a-f0-9]{64}$/;
const roles = ['kernel-primary', 'standard-primary', 'business', 'capability'];
function sha(data) { return createHash('sha256').update(data).digest('hex'); }

function pinnedFile(path, hash, max = 4_194_304) {
  if (!isAbsolute(path) || !SHA.test(hash)) throw new Error('PINNED_SOURCE_REQUIRED');
  const file = resolve(path), stat = lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(file) !== file ||
      stat.size > max) throw new Error('PINNED_SOURCE_FILE_REFUSED');
  const data = readFileSync(file);
  if (sha(data) !== hash) throw new Error('PINNED_SOURCE_SHA_MISMATCH');
  return data;
}
const [specArg,outArg,...extra] = process.argv.slice(2);
if (!specArg || !outArg || extra.length !== 0 ||
    !isAbsolute(specArg) || !isAbsolute(outArg) || existsSync(outArg)) {
  throw new Error('V03_ASSEMBLE_ARGS_REFUSED');
}
// The spec itself must be supplied through a trusted local Host process,
// never copied from UI/Planner bytes. Every module also has a pinned hash.
const spec = JSON.parse(readFileSync(resolve(specArg), 'utf8'));
if (!spec || typeof spec !== 'object' || !Array.isArray(spec.modules) ||
    spec.modules.length < 4 || spec.modules.length > 10 ||
    spec.targetProfile !== 'node24-esm/1' ||
    !Array.isArray(spec.routes) || spec.routes.length < 1 ||
    !spec.hardBudget || !spec.appId || !spec.audience || !spec.buildId) {
  throw new Error('V03_ASSEMBLE_SPEC_INVALID');
}
const actualRoles = new Set();
const actualIds = new Set();
const modules = spec.modules.map((entry) => {
  if (!entry || !entry.module || typeof entry.module !== 'object' ||
      !roles.includes(entry.module.role) ||
      (entry.module.role !== 'business' && entry.module.role !== 'capability' &&
        actualRoles.has(entry.module.role)) ||
      !entry.module.packageId || actualIds.has(entry.module.packageId) ||
      typeof entry.sourceFile !== 'string' || !SHA.test(entry.sourceSha256) ||
      !['PUBLIC_DOMAIN_PACKAGE_V0103','SHUN_TRUSTED_DOMAIN_PACKAGE'].includes(entry.provenance) ||
      ((entry.module.role === 'kernel-primary' || entry.module.role === 'standard-primary')
        !== (entry.provenance === 'PUBLIC_DOMAIN_PACKAGE_V0103'))) {
    throw new Error('V03_ASSEMBLE_MODULE_IDENTITY_REFUSED');
  }
  actualRoles.add(entry.module.role);
  actualIds.add(entry.module.packageId);
  const source = pinnedFile(entry.sourceFile, entry.sourceSha256).toString('utf8');
  if (source.includes('BINDING_REQUIRED_AT_ACTIVATION') ||
      source.includes('SEMANTIC_BINDING_REQUIRED_AT_ACTIVATION')) {
    throw new Error('V03_ASSEMBLE_PLACEHOLDER_REFUSED');
  }
  const { moduleSource: discardedSource, ...metadata } = entry.module;
  void discardedSource;
  return {
    module: { ...metadata, moduleSource: source, moduleSha256: entry.sourceSha256 },
    approvedSha256: entry.sourceSha256,
  };
});
if (roles.some((role) => !actualRoles.has(role))) {
  throw new Error('V03_ASSEMBLE_MISSING_ROLE');
}
const output = {
  appId: spec.appId, audience: spec.audience, buildId: spec.buildId,
  targetProfile: spec.targetProfile, modules, routes: spec.routes,
  hardBudget: spec.hardBudget,
};
const bytes = Buffer.from(JSON.stringify(output, null, 2) + '\n', 'utf8');
writeFileSync(outArg, bytes, { flag: 'wx' });
console.log(JSON.stringify({ output: outArg, sha256: sha(bytes),
  selectedModules: modules.map((m) => ({ packageId: m.module.packageId,
    role: m.module.role, moduleSha256: m.approvedSha256 })) }));
