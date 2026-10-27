// CLI entry: run the local control surface on loopback.
//   node src/main.ts            → http://127.0.0.1:7788
// Env:
//   SHUN_CONTROL_PORT           — port (default 7788)
//   SHUN_CONTROL_UI_DIR         — static UI directory (default ../control-ui/public)
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cloudInterpreterFromEnvironment } from './cloud-interpret.ts';
import { DemoShunBackend } from './demo/backend.ts';
import { RealStorageControlBackend } from './real-storage/backend.ts';
import { createControlServer } from './server.ts';

const here = dirname(fileURLToPath(import.meta.url));
const port = Number.parseInt(process.env.SHUN_CONTROL_PORT ?? '7788', 10);
const uiDir = process.env.SHUN_CONTROL_UI_DIR ?? resolve(here, '../../control-ui/public');

// A production mode is an explicit operator decision, never HTTP input.
const mode = process.env.SHUN_CONTROL_MODE ?? 'demo';
if (mode !== 'demo' && mode !== 'real-storage') {
  throw new Error('Unknown SHUN_CONTROL_MODE: refusing to start');
}
const backend =
  mode === 'real-storage'
    ? await RealStorageControlBackend.create({
        workspace: requiredEnv('SHUN_REAL_STORAGE_ROOT'),
        protectedAssets: JSON.parse(requiredEnv('SHUN_REAL_STORAGE_PROTECTED')) as string[],
        databaseFile: requiredEnv('SHUN_REAL_STORAGE_DATABASE'),
        registryRevisionFile: requiredEnv('SHUN_REGISTRY_CURRENTNESS_FILE'),
        registryPublicKeyFile: requiredEnv('SHUN_REGISTRY_PUBLIC_KEY_FILE'),
        registryPublicKeySha256: requiredEnv('SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256'),
        evidenceDir: requiredEnv('SHUN_REAL_STORAGE_EVIDENCE_DIR'),
        issuanceSecret: requiredEnv('SHUN_CONTROLLER_ISSUANCE_SECRET'),
        integritySecret: requiredEnv('SHUN_GRANT_INTEGRITY_SECRET'),
      })
    : new DemoShunBackend();

// Remote mode is a separate opt-in trusted-host feature. Demo Goal tasks
// remain visibly simulated; a cloud interpretation is labeled as an untrusted
// remote proposal and can never be used as an ActionController execution grant.
const cloud = cloudInterpreterFromEnvironment();
const handle = createControlServer({ backend, uiDir, port, cloud });
const bound = await handle.start();
console.log(
  `Shun control surface (${mode === 'demo' ? 'T08 DEMO ONLY' : 'REAL bounded C-003'}) on http://127.0.0.1:${bound}`,
);
console.log('Local only: the surface refuses non-loopback binds and non-loopback Host headers.');

function requiredEnv(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing trusted local configuration ${key}; refusing real mode`);
  return value;
}
