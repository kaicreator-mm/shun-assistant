// T09 P01: offline distribution integrity, not an installer or an OS signature.
// Sign only on an operator-controlled build host. Neither private key nor trust
// root may come from the packaged browser, UI or an unsigned bundle field.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA = 'shun/portable-v0.2/manifest-v1';
const MANIFEST = 'shun-manifest.json';
const SIGNATURE = 'shun-manifest.sig';
const SHA = /^[0-9a-f]{64}$/;

function refuse() {
  throw new Error('SHUN_PORTABLE_BUNDLE_REFUSED');
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function inside(parent, child) {
  const rel = relative(parent, child);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

function fileBytes(path) {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) return refuse();
  return readFileSync(path);
}

function bundleFiles(root) {
  if (!lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) refuse();
  const files = [];
  function visit(dir, prefix = '') {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      // Only the two top-level envelope files are excluded from coverage.
      if (!prefix && (rel === MANIFEST || rel === SIGNATURE)) continue;
      if (entry.isSymbolicLink()) refuse(); // including junctions
      const path = join(dir, entry.name);
      if (entry.isDirectory()) visit(path, rel);
      else if (entry.isFile()) {
        const bytes = fileBytes(path);
        files.push({ path: rel, size: bytes.length, sha256: sha256(bytes) });
      } else refuse();
    }
  }
  visit(root);
  // Code-point ordering, independent of the Windows user's locale.
  return files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

export function publicKeyFingerprint(publicKey) {
  // Node's createPublicKey rejects an already-public KeyObject; accept the
  // trusted object returned by createPublicKey(privateKey) as-is.
  const key =
    publicKey && typeof publicKey === 'object' && publicKey.type === 'public'
      ? publicKey
      : createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519') refuse();
  return sha256(key.export({ type: 'spki', format: 'der' }));
}

function canonicalManifest(root, keyPin) {
  return Buffer.from(
    JSON.stringify({ schema: SCHEMA, signerSpkiSha256: keyPin, files: bundleFiles(root) }) + '\n',
    'utf8',
  );
}

function requireExternalKey(root, keyPath) {
  const path = resolve(keyPath);
  if (path === root || inside(root, path)) refuse();
  return fileBytes(path);
}

export function signBundle(rootPath, privateKeyPath) {
  const root = resolve(rootPath);
  const secret = createPrivateKey(requireExternalKey(root, privateKeyPath));
  if (secret.asymmetricKeyType !== 'ed25519') refuse();
  const pin = publicKeyFingerprint(createPublicKey(secret));
  const bytes = canonicalManifest(root, pin);
  const signature = sign(null, bytes, secret);
  writeFileSync(join(root, MANIFEST), bytes, { flag: 'w' });
  writeFileSync(join(root, SIGNATURE), signature.toString('base64') + '\n', { flag: 'w' });
  return { signerSpkiSha256: pin, entries: bundleFiles(root).length };
}

export function verifyBundle(rootPath, publicKeyPath, expectedSpkiSha256) {
  const root = resolve(rootPath);
  if (!SHA.test(expectedSpkiSha256 ?? '')) refuse();
  const publicKey = createPublicKey(requireExternalKey(root, publicKeyPath));
  const pin = publicKeyFingerprint(publicKey);
  if (pin !== expectedSpkiSha256) refuse();
  // Never accept an unsigned manifest-supplied verification key or pin.
  const bytes = fileBytes(join(root, MANIFEST));
  const rawSignature = fileBytes(join(root, SIGNATURE)).toString('utf8');
  if (!/^[A-Za-z0-9+/]{86}==\n?$/.test(rawSignature)) refuse();
  const signature = Buffer.from(rawSignature.trimEnd(), 'base64');
  if (signature.length !== 64 || !verify(null, bytes, publicKey, signature)) refuse();
  // Regeneration also refuses extra files, missing files, links and byte drift.
  const expected = canonicalManifest(root, pin);
  if (!bytes.equals(expected)) refuse();
  return { signerSpkiSha256: pin, entries: bundleFiles(root).length };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const [mode, ...args] = process.argv.slice(2);
    if (mode === 'sign' && args.length === 2) {
      console.log(JSON.stringify(signBundle(args[0], args[1])));
    } else if (mode === 'verify' && args.length === 3) {
      console.log(JSON.stringify(verifyBundle(args[0], args[1], args[2])));
    } else {
      refuse();
    }
  } catch {
    // A failure must not print private paths, PEM contents or untrusted fields.
    console.error('SHUN_PORTABLE_BUNDLE_REFUSED');
    process.exitCode = 1;
  }
}
