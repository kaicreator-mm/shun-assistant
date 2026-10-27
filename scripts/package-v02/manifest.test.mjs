import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, test } from 'node:test';
import { publicKeyFingerprint, signBundle, verifyBundle } from './manifest.mjs';

const temporary = [];
afterEach(() => {
  for (const dir of temporary.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'shun-v02-package-'));
  temporary.push(dir);
  const root = join(dir, 'portable');
  mkdirSync(join(root, 'native'), { recursive: true });
  writeFileSync(join(root, 'node.exe'), 'fake node executable for unit fixtures only');
  writeFileSync(join(root, 'native', 'broker.exe'), 'fixture');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const secret = join(dir, 'operator-private.pem');
  const publicFile = join(dir, 'operator-public.pem');
  writeFileSync(secret, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  writeFileSync(publicFile, publicKey.export({ type: 'spki', format: 'pem' }));
  const pin = publicKeyFingerprint(publicKey);
  return { root, secret, publicFile, pin };
}

function refusal(fn) {
  assert.throws(fn, /SHUN_PORTABLE_BUNDLE_REFUSED/);
}

test('operator signature and complete canonical manifest are deterministic and verify', () => {
  const { root, secret, publicFile, pin } = fixture();
  assert.deepEqual(signBundle(root, secret), { signerSpkiSha256: pin, entries: 2 });
  const first = readFileSync(join(root, 'shun-manifest.json'));
  const firstSignature = readFileSync(join(root, 'shun-manifest.sig'));
  assert.deepEqual(signBundle(root, secret), { signerSpkiSha256: pin, entries: 2 });
  assert.deepEqual(readFileSync(join(root, 'shun-manifest.json')), first);
  assert.deepEqual(readFileSync(join(root, 'shun-manifest.sig')), firstSignature);
  assert.deepEqual(verifyBundle(root, publicFile, pin), { signerSpkiSha256: pin, entries: 2 });
});

test('tampered bytes and extra/unlisted files are both rejected', () => {
  const { root, secret, publicFile, pin } = fixture();
  signBundle(root, secret);
  writeFileSync(join(root, 'node.exe'), 'modified Node executable');
  refusal(() => verifyBundle(root, publicFile, pin));
  signBundle(root, secret);
  writeFileSync(join(root, 'extra.dll'), 'unexpected');
  refusal(() => verifyBundle(root, publicFile, pin));
});

test('signature mutation and any replacement operator key or pin are rejected', () => {
  const { root, secret, publicFile, pin } = fixture();
  signBundle(root, secret);
  const oldSig = readFileSync(join(root, 'shun-manifest.sig'), 'utf8');
  writeFileSync(join(root, 'shun-manifest.sig'), `${oldSig[0] === 'A' ? 'B' : 'A'}${oldSig.slice(1)}`);
  refusal(() => verifyBundle(root, publicFile, pin));
  signBundle(root, secret);
  refusal(() => verifyBundle(root, publicFile, '0'.repeat(64)));
  const second = fixture();
  refusal(() => verifyBundle(root, second.publicFile, second.pin));
});

test('operator signing private key cannot be read from inside the package', () => {
  const { root, secret } = fixture();
  const nestedKey = join(root, 'local-private.pem');
  writeFileSync(nestedKey, readFileSync(secret));
  refusal(() => signBundle(root, nestedKey));
});

test('file or directory symlinks are denied whenever supported by the test host', (context) => {
  const { root, secret, publicFile, pin } = fixture();
  const link = join(root, 'alias.dll');
  try {
    symlinkSync(join(root, 'node.exe'), link, 'file');
  } catch {
    context.skip('this Windows account cannot create file symlinks');
    return;
  }
  refusal(() => signBundle(root, secret));
  rmSync(link);
  signBundle(root, secret);
  symlinkSync(join(root, 'node.exe'), link, 'file');
  refusal(() => verifyBundle(root, publicFile, pin));
});
