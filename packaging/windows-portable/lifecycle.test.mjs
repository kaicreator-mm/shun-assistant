import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
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

test('exported entrypoints refuse state-as-core and sibling-as-core without touching canaries', () => {
  const { stage, layout, pub, pin, makeStage } = fixture();
  makeStage(stage, 'v1');
  installSignedCore({ stageDir: stage, publicKeyPath: pub, trustedSpkiPin: pin, layout });
  writeFileSync(join(layout.state, 'must-survive.txt'), 'STATE_CANARY');

  const dangerous = [
    { ...layout, core: layout.state },
    { ...layout, core: join(layout.root, 'unrelated') },
  ];
  mkdirSync(join(layout.root, 'unrelated'));
  writeFileSync(join(layout.root, 'unrelated', 'must-survive.txt'), 'OTHER_CANARY');
  for (const bad of dangerous) {
    assert.throws(() => uninstallCore({ layout: bad }), /SHUN_PORTABLE_LIFECYCLE_REFUSED/);
    assert.throws(() => installSignedCore({
      stageDir: stage, publicKeyPath: pub, trustedSpkiPin: pin, layout: bad,
    }), /SHUN_PORTABLE_LIFECYCLE_REFUSED/);
  }
  assert.equal(readFileSync(join(layout.state, 'must-survive.txt'), 'utf8'), 'STATE_CANARY');
  assert.equal(
    readFileSync(join(layout.root, 'unrelated', 'must-survive.txt'), 'utf8'),
    'OTHER_CANARY',
  );
  assert.equal(readFileSync(join(layout.core, 'node.exe'), 'utf8'), 'fixture-v1');
});

test('failure after moving old Core rolls it back, preserving state', () => {
  const { stage, stage2, layout, pub, pin, makeStage } = fixture();
  makeStage(stage, 'v1');
  makeStage(stage2, 'v2');
  installSignedCore({ stageDir: stage, publicKeyPath: pub, trustedSpkiPin: pin, layout });
  writeFileSync(join(layout.state, 'must-survive.txt'), 'STATE_CANARY');
  const realRename = fs.renameSync;
  let injected = false;
  try {
    fs.renameSync = (src, dest) => {
      if (!injected && String(src).includes('core.next-') && dest === layout.core) {
        injected = true;
        throw new Error('INJECTED_RENAME_FAILURE');
      }
      return realRename(src, dest);
    };
    syncBuiltinESMExports();
    assert.throws(() => installSignedCore({
      stageDir: stage2, publicKeyPath: pub, trustedSpkiPin: pin, layout,
    }), /SHUN_PORTABLE_LIFECYCLE_REFUSED/);
  } finally {
    fs.renameSync = realRename;
    syncBuiltinESMExports();
  }
  assert.equal(injected, true);
  assert.equal(readFileSync(join(layout.core, 'node.exe'), 'utf8'), 'fixture-v1');
  assert.equal(readFileSync(join(layout.state, 'must-survive.txt'), 'utf8'), 'STATE_CANARY');
});

test('a symlink-parent/.. alias cannot redirect uninstall to an unrelated directory', (context) => {
  const { temp, stage, layout, pub, pin, makeStage } = fixture();
  makeStage(stage, 'v1');
  installSignedCore({ stageDir: stage, publicKeyPath: pub, trustedSpkiPin: pin, layout });
  writeFileSync(join(layout.state, 'state-canary.txt'), 'STATE_CANARY');
  const foreign = join(temp, 'unrelated-parent');
  mkdirSync(join(foreign, 'folder'), { recursive: true });
  mkdirSync(join(foreign, 'core'));
  writeFileSync(join(foreign, 'core', 'foreign-canary.txt'), 'FOREIGN_CANARY');
  const alias = join(layout.root, 'alias');
  try {
    symlinkSync(join(foreign, 'folder'), alias, process.platform === 'win32' ? 'junction' : 'dir');
  } catch {
    context.diagnostic('Host cannot create directory link: lexical rejection still tested');
  }
  // Do NOT use join()/resolve(): they erase the crafted dot-dot before fs sees it.
  const coreAlias = `${layout.root}${sep}alias${sep}..${sep}core`;
  const bad = { ...layout, core: coreAlias };
  assert.throws(() => uninstallCore({ layout: bad }), /SHUN_PORTABLE_LIFECYCLE_REFUSED/);
  assert.throws(() => installSignedCore({
    stageDir: stage, publicKeyPath: pub, trustedSpkiPin: pin, layout: bad,
  }), /SHUN_PORTABLE_LIFECYCLE_REFUSED/);
  assert.equal(readFileSync(join(layout.core, 'node.exe'), 'utf8'), 'fixture-v1');
  assert.equal(readFileSync(join(layout.state, 'state-canary.txt'), 'utf8'), 'STATE_CANARY');
  assert.equal(
    readFileSync(join(foreign, 'core', 'foreign-canary.txt'), 'utf8'),
    'FOREIGN_CANARY',
  );
});
