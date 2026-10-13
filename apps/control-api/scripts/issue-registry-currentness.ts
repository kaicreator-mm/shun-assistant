// Trusted operator/host-side Registry fact issuer. NEVER imported or invoked
// by control-api's HTTP/candidate Goal path. Requires an Ed25519 private key
// readable only to the independently configured Windows issuer identity.
// The matching PUBLIC key alone is available to the real ControlBackend.
// Run on a trusted Windows Build Host after the signer key ACL is pinned.
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { availableParallelism, release, totalmem } from 'node:os';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { canonicalJson } from '@shun/contracts';
import { type RegistrySnapshot, snapshotFactsRevision } from '@shun/resolver';
import { ISSUANCE_SCHEMA, verifyRegistryIssuance } from '../src/real-storage/registry-issuance.ts';
import { createStorageRegistrySnapshot } from '../src/real-storage/registry-snapshot.ts';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`ISSUER_MISSING_${name}`);
  return value;
}
function within(root: string, path: string): boolean {
  const r = relative(root, path);
  return (
    r === '' || (!isAbsolute(r) && r !== '..' && !r.startsWith('..\\') && !r.startsWith('../'))
  );
}
async function regularNoAlias(path: string): Promise<string> {
  const canonicalPath = resolve(path);
  const info = await fs.lstat(canonicalPath);
  if (!info.isFile() || info.isSymbolicLink())
    throw new Error(`ISSUER_FILE_NOT_REGULAR_${canonicalPath}`);
  const real = await fs.realpath(canonicalPath);
  if (real.toLowerCase() !== canonicalPath.toLowerCase()) throw new Error('ISSUER_FILE_ALIAS');
  return canonicalPath;
}

if (process.platform !== 'win32') throw new Error('ISSUER_REAL_WINDOWS_ONLY');
const workspace = resolve(required('SHUN_ISSUER_WORKSPACE'));
const workspaceInfo = await fs.lstat(workspace);
if (!workspaceInfo.isDirectory() || workspaceInfo.isSymbolicLink())
  throw new Error('ISSUER_ROOT_UNTRUSTED');
if ((await fs.realpath(workspace)).toLowerCase() !== workspace.toLowerCase())
  throw new Error('ISSUER_ROOT_ALIAS');
const destination = resolve(required('SHUN_REGISTRY_CURRENTNESS_FILE'));
const publicKeyPath = await regularNoAlias(required('SHUN_REGISTRY_PUBLIC_KEY_FILE'));
const privateKeyPath = await regularNoAlias(required('SHUN_ISSUER_PRIVATE_KEY_FILE'));
if ([destination, publicKeyPath, privateKeyPath].some((x) => within(workspace, x))) {
  throw new Error('ISSUER_KEY_OR_EVIDENCE_INSIDE_DESTRUCTIVE_SCOPE');
}
if (publicKeyPath === privateKeyPath || destination === privateKeyPath)
  throw new Error('ISSUER_KEY_PATH_COLLISION');
const outputParent = dirname(destination);
const dirStat = await fs.lstat(outputParent);
if (!dirStat.isDirectory() || dirStat.isSymbolicLink())
  throw new Error('ISSUER_OUTPUT_PARENT_NOT_TRUSTED');
if ((await fs.realpath(outputParent)).toLowerCase() !== outputParent.toLowerCase()) {
  throw new Error('ISSUER_OUTPUT_PARENT_ALIAS');
}
const privateKey = createPrivateKey(await fs.readFile(privateKeyPath, 'utf8'));
if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('ISSUER_KEY_NOT_ED25519');
const publicPem = await fs.readFile(publicKeyPath, 'utf8');
const derivedPublic = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
const expectedPublic = createPublicKey(publicPem).export({ type: 'spki', format: 'der' });
if (!Buffer.from(derivedPublic).equals(Buffer.from(expectedPublic))) {
  throw new Error('ISSUER_OPERATOR_PINNED_PUBLIC_KEY_MISMATCH');
}
const arch = process.arch === 'x64' ? 'X64' : process.arch === 'arm64' ? 'ARM64' : null;
if (!arch) throw new Error('ISSUER_UNSUPPORTED_ARCH');
const disk = await fs.statfs(workspace);
// The protected operator signer may run elevated while the receiving
// ControlBackend runs unelevated. The signer issues the OPERATOR-EXPECTED
// process privilege mode; the candidate checks this against a fresh OS token
// observation before accepting the signed fact snapshot. Never assume that
// the signer's own token describes the receiving process.
const privilegeModeRaw = required('SHUN_ISSUER_TARGET_PRIVILEGE_MODE');
if (!['STANDARD_USER', 'FILTERED_ADMIN', 'ELEVATED_ADMIN'].includes(privilegeModeRaw)) {
  throw new Error('ISSUER_INVALID_TARGET_PRIVILEGE_MODE');
}
const privilegeMode = privilegeModeRaw as RegistrySnapshot['environment']['privilegeMode'];
const now = new Date().toISOString();
const environment: RegistrySnapshot['environment'] = {
  environmentId: `shun-real-storage-${process.arch}`,
  backendKind: 'LOCAL_WINDOWS',
  os: `WINDOWS-${release()}`,
  arch,
  observationRevision: `issuer:${now}`,
  runtimeCapabilities: ['windows-storage-metadata'],
  privilegeMode,
  guiSession: true,
  filesystemCapabilities: ['read', 'write'],
  networkPolicy: 'OFFLINE',
  resources: {
    cpuCores: Math.max(1, availableParallelism()),
    memoryMb: Math.max(1, Math.floor(totalmem() / (1024 * 1024))),
    freeDiskMb: Math.max(0, Math.floor(Number(disk.bavail * disk.bsize) / (1024 * 1024))),
  },
};
const snapshot = createStorageRegistrySnapshot(environment);
const body = {
  schema: ISSUANCE_SCHEMA,
  workspace,
  issuedAt: now,
  expiresAt: new Date(Date.parse(now) + 60_000).toISOString(),
  snapshot,
  currentRevision: snapshotFactsRevision(snapshot),
};
const envelope = {
  ...body,
  signature: sign(null, Buffer.from(canonicalJson(body), 'utf8'), privateKey).toString('base64'),
};
// Issuer confirms its own output is internally valid; runtime still checks
// independent pinned public key/current revision at resolution/effect time.
verifyRegistryIssuance(envelope, publicPem, workspace, now);
const tmp = `${destination}.issuer-${process.pid}.tmp`;
let written = false;
try {
  const handle = await fs.open(tmp, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(envelope)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(tmp, destination);
  written = true;
} finally {
  if (!written) await fs.rm(tmp, { force: true });
}
console.log(`ISSUER_OK revision=${body.currentRevision} expires=${body.expiresAt}`);
console.log(`ISSUER_OUTPUT=${destination}`);
console.log('ISSUER_REQUIRES_WINDOWS_DACL_AND_PROCESS_IDENTITY_VALIDATION=YES');
