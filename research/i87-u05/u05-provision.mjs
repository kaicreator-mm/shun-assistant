// Provision a clean non-developer user sandbox:
//   <root>/workspace/    — the C-003 scan root (fixture files, canaries)
//   <root>/state/        — shun.sqlite location (outside workspace)
//   <root>/registry/     — operator-issued currentness + pinned public key
//   <root>/evidence/     — real backend evidence dir
//   <root>/keys/         — issuer private key + secrets (operator side)
//   <root>/tmp/          — redirected TEMP/TMP for the server process
// Writes <root>/env.json (trusted env recipe) and <root>/canaries.json.
import { generateKeyPairSync, randomBytes, createPublicKey, createHash } from 'node:crypto';
import { mkdir, writeFile, appendFile } from 'node:fs/promises';
import * as path from 'node:path';
import { ev, writeJson, sha256File } from './u05-lib.mjs';

const root = process.argv[2];
if (!root) throw new Error('usage: node u05-provision.mjs <sandboxRoot>');
const workspace = path.join(root, 'workspace');

async function put(rel, content) {
  const full = path.join(workspace, rel);
  await mkdir(path.dirname(full), { recursive: true });
  await writeFile(full, content, 'utf8');
  return full;
}

async function main() {
  for (const d of ['workspace', 'state', 'registry', 'evidence', 'keys', 'tmp', 'logs']) {
    await mkdir(path.join(root, d), { recursive: true });
  }
  await ev('provision.start', 'RUN', { root });

  // --- workspace fixture ---
  // Protected canary (declared protected asset) + decoy "cache" marker INSIDE the
  // protected tree (classification order check: PROTECTED beats disposable marker).
  const canaryRel = 'protected-keep/canary.txt';
  const decoyRel = 'protected-keep/cache/decoy.bin';
  const canary = await put(canaryRel, `SHUN U05 PROTECTED CANARY ${randomBytes(8).toString('hex')}\n`);
  const decoy = await put(decoyRel, `protected decoy that looks like cache ${randomBytes(16).toString('hex')}\n`);
  // Deletable CACHE/TEMP fixtures
  const deletable = [];
  for (let i = 0; i < 5; i++) {
    deletable.push(await put(`cache/blob-${i}.tmp`, 'x'.repeat(4096 + i * 512)));
  }
  for (let i = 0; i < 3; i++) {
    deletable.push(await put(`npm-cache/content-v2/${i}.json`, 'y'.repeat(2048 + i * 256)));
  }
  for (let i = 0; i < 2; i++) {
    deletable.push(await put(`temp/session-${i}.log`, 'z'.repeat(1024 + i * 128)));
  }
  // User content that must survive
  const userPhoto = await put('Media Library/vacation photo.jpg', 'JPEGDATA-not-really'.repeat(50));
  const userNotes = await put('notes.txt', 'user created loose root file - never disposable\n');

  // --- keys ---
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privFile = path.join(root, 'keys', 'issuer-private-key.pem');
  const pubFile = path.join(root, 'registry', 'registry-public-key.pem');
  await writeFile(privFile, privPem, 'utf8');
  await writeFile(pubFile, pubPem, 'utf8');
  const spkiDer = createPublicKey(pubPem).export({ type: 'spki', format: 'der' });
  const spkiSha256 = createHash('sha256').update(spkiDer).digest('hex');

  // --- secrets (distinct authority secrets, never reused) ---
  const issuanceSecret = randomBytes(32).toString('hex');
  const integritySecret = randomBytes(32).toString('hex');
  if (issuanceSecret === integritySecret) throw new Error('secret collision');

  const env = {
    SHUN_CONTROL_MODE: 'real-storage',
    SHUN_REAL_STORAGE_ROOT: workspace,
    SHUN_REAL_STORAGE_PROTECTED: JSON.stringify([canary]),
    SHUN_REAL_STORAGE_DATABASE: path.join(root, 'state', 'shun.sqlite'),
    SHUN_REGISTRY_CURRENTNESS_FILE: path.join(root, 'registry', 'currentness.json'),
    SHUN_REGISTRY_PUBLIC_KEY_FILE: pubFile,
    SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256: spkiSha256,
    SHUN_REAL_STORAGE_EVIDENCE_DIR: path.join(root, 'evidence'),
    SHUN_CONTROLLER_ISSUANCE_SECRET: issuanceSecret,
    SHUN_GRANT_INTEGRITY_SECRET: integritySecret,
  };
  await writeJson(path.join(root, 'env.json'), env);
  await writeFile(path.join(root, 'keys', 'secrets.json'), JSON.stringify({ issuanceSecret, integritySecret }, null, 2), 'utf8');

  const canaries = {
    protected: [
      { rel: canaryRel, full: canary, sha256: await sha256File(canary) },
      { rel: decoyRel, full: decoy, sha256: await sha256File(decoy) },
    ],
    userContent: [
      { rel: 'Media Library/vacation photo.jpg', full: userPhoto, sha256: await sha256File(userPhoto) },
      { rel: 'notes.txt', full: userNotes, sha256: await sha256File(userNotes) },
    ],
    deletable: await Promise.all(
      deletable.map(async (f) => ({ rel: path.relative(workspace, f), full: f, sha256: await sha256File(f) })),
    ),
  };
  await writeJson(path.join(root, 'canaries.json'), canaries);
  await appendFile(path.join(root, 'logs', 'provision.log'), `provisioned ${new Date().toISOString()}\n`);
  await ev('provision', 'OK', {
    root,
    workspace,
    protectedCount: canaries.protected.length,
    deletableCount: canaries.deletable.length,
    spkiSha256,
  });
  console.log(JSON.stringify({ ok: true, root, spkiSha256, workspace }, null, 2));
}

main().catch(async (err) => {
  await ev('provision', 'FAIL', { error: String(err), root });
  console.error(err);
  process.exit(1);
});
