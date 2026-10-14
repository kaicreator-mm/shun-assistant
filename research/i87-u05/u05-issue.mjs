// Operator-side issuance step: run the repo's trusted issuer script against a
// sandbox. Must be invoked within 60s before any server boot / effect approval
// (the issued currentness envelope carries a 60s lifetime by design).
import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { capture, ev, readJson, WORKTREE } from './u05-lib.mjs';

const sandbox = process.argv[2];
if (!sandbox) throw new Error('usage: node u05-issue.mjs <sandboxRoot>');

async function main() {
  const env = await readJson(path.join(sandbox, 'env.json'));
  const issuerEnv = {
    ...process.env,
    SHUN_ISSUER_WORKSPACE: env.SHUN_REAL_STORAGE_ROOT,
    SHUN_REGISTRY_CURRENTNESS_FILE: env.SHUN_REGISTRY_CURRENTNESS_FILE,
    SHUN_REGISTRY_PUBLIC_KEY_FILE: env.SHUN_REGISTRY_PUBLIC_KEY_FILE,
    SHUN_ISSUER_PRIVATE_KEY_FILE: path.join(sandbox, 'keys', 'issuer-private-key.pem'),
    // The receiving ControlBackend runs unelevated. This host account is a
    // member of Administrators but the process token is UAC-filtered (no
    // S-1-16-12288 high-integrity SID, IsInRole(Administrator)=false), so the
    // backend's own token observation classifies FILTERED_ADMIN and the
    // host-facts drift gate requires the pin to match exactly. Allow override
    // via argv for other host shapes.
    SHUN_ISSUER_TARGET_PRIVILEGE_MODE: process.argv[3] || 'FILTERED_ADMIN',
  };
  const res = await capture(
    process.execPath,
    ['--experimental-transform-types', path.join(WORKTREE, 'apps', 'control-api', 'scripts', 'issue-registry-currentness.ts')],
    { env: issuerEnv, timeoutMs: 60_000 },
  );
  const ok = res.code === 0 && /ISSUER_OK/.test(res.stdout);
  await ev('issue.currentness', ok ? 'OK' : 'FAIL', {
    sandbox,
    code: res.code,
    stdout: res.stdout.trim().slice(0, 800),
    stderr: res.stderr.trim().slice(0, 800),
  });
  if (!ok) {
    console.error(JSON.stringify({ ok: false, code: res.code, stderr: res.stderr }));
    process.exit(1);
  }
  let envelope;
  try {
    envelope = JSON.parse(await readFile(env.SHUN_REGISTRY_CURRENTNESS_FILE, 'utf8'));
  } catch {}
  console.log(
    JSON.stringify(
      {
        ok: true,
        revision: envelope?.currentRevision,
        expiresAt: envelope?.expiresAt,
        workspace: envelope?.workspace,
      },
      null,
      2,
    ),
  );
}

main().catch(async (err) => {
  await ev('issue.currentness', 'FAIL', { error: String(err), sandbox });
  console.error(err);
  process.exit(1);
});
