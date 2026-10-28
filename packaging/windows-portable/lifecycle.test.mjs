import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, test } from 'node:test';
import { publicKeyFingerprint, signBundle } from '../../scripts/package-v02/manifest.mjs';
import { installSignedCore, perUserLayout, uninstallCore } from './lifecycle.mjs';

const fixtures = [];
afterEach(() => {
  for (const path of fixtures.splice(0)) rmSync(path, { recursive: true, force: true });
});
function fixture() {
  const temp = mkdtempSync(join(tmpdir(), 'shun-lifecycle-'));
  fixtures.push(temp);
  const stage = join(temp, 'stage-1');
  const stage2 = join(temp, 'stage-2');
  const layout = perUserLayout(join(temp, 'local-appdata'));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const secret = join(temp, 'operator-private.pem');
  const pub = join(temp, 'operator-public.pem');
  writeFileSync(secret, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  writeFileSync(pub, publicKey.export({ type: 'spki', format: 'pem' }));
  const pin = publicKeyFingerprint(publicKey);
  function makeStage(root, version) {
    for (const rel of ['app/native/broker', 'app/native/host', 'app/native/impl']) {
      mkdirSync(join(root, rel), { recursive: true });
    }
    for (const name of [
      'node.exe',
      'app/native/control.mjs',
      'app/native/broker/shun-consent-broker.exe',
      'app/native/host/shun_consent_host.node',
      'app/native/impl/shun_win32_impl.node',
      'shun-core.cmd',
    ]) {
      writeFileSync(join(root, name), `fixture-${version}`);
    }
    signBundle(root, secret);
  }
  return { temp, stage, stage2, layout, secret, pub, pin, makeStage };
}

test('install then upgrade preserves independent state and uninstall never deletes it', () => {
  const { stage, stage2, layout, pub, pin, makeStage } = fixture();
  makeStage(stage, 'v1');
  assert.deepEqual(installSignedCore({
    stageDir: stage, publicKeyPath: pub, trustedSpkiPin: pin, layout,
  }), { operation: 'INSTALL', statePreserved: true, signed: true });
  writeFileSync(join(layout.state, 'user-canary.json'), '{"keep":true}');
  makeStage(stage2, 'v2');
  assert.deepEqual(installSignedCore({
    stageDir: stage2, publicKeyPath: pub, trustedSpkiPin: pin, layout,
  }), { operation: 'UPGRADE', statePreserved: true, signed: true });
  assert.equal(readFileSync(join(layout.core, 'node.exe'), 'utf8'), 'fixture-v2');
  assert.equal(readFileSync(join(layout.state, 'user-canary.json'), 'utf8'), '{"keep":true}');
  assert.deepEqual(uninstallCore({ layout }), {
    operation: 'UNINSTALL_CORE_ONLY', statePreserved: true,
  });
  assert.equal(existsSync(layout.core), false);
  assert.equal(readFileSync(join(layout.state, 'user-canary.json'), 'utf8'), '{"keep":true}');
});

test('unsigned or modified payload is refused before an accepted install changes state', () => {
  const { stage, stage2, layout, pub, pin, makeStage } = fixture();
  makeStage(stage, 'v1');
  installSignedCore({ stageDir: stage, publicKeyPath: pub, trustedSpkiPin: pin, layout });
  writeFileSync(join(layout.state, 'user-canary.txt'), 'USER_DATA');
  makeStage(stage2, 'v2');
  writeFileSync(join(stage2, 'node.exe'), 'tampered-after-sign');
  assert.throws(() => installSignedCore({
    stageDir: stage2, publicKeyPath: pub, trustedSpkiPin: pin, layout,
  }));
  assert.equal(readFileSync(join(layout.core, 'node.exe'), 'utf8'), 'fixture-v1');
  assert.equal(readFileSync(join(layout.state, 'user-canary.txt'), 'utf8'), 'USER_DATA');
});

test('source must not overlap the destination runtime or user state', () => {
  const { stage, layout, pub, pin, makeStage } = fixture();
  makeStage(stage, 'v1');
  installSignedCore({ stageDir: stage, publicKeyPath: pub, trustedSpkiPin: pin, layout });
  assert.throws(() => installSignedCore({
    stageDir: layout.core, publicKeyPath: pub, trustedSpkiPin: pin, layout,
  }));
  assert.equal(existsSync(join(layout.core, 'node.exe')), true);
});
