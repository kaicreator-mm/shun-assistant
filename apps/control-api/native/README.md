# native/ — T08 C02 Windows private IPC trusted consent broker (windows-rs)

Shun-owned private IPC consent broker per v0.2 T08 C02 (#110): the broker
process owns BOTH the desktop confirmation dialog and the protected named
pipe. The public Control API / browser can only REQUEST that a native prompt
be shown — it can never mint, forge or substitute an approval. Windows FFI
goes exclusively through Rust `windows-rs` (`koffi` / `node-win32-api` /
localhost-HTTP self-approval are rejected platform baselines; T04 replaced
the last koffi usage in #162).

| crate | artifact | role |
|---|---|---|
| `broker/` (bin `shun-consent-broker`) | `broker/shun-consent-broker.exe` (committed) | pipe server + DACL, per-connection OS-token admission, projection digest pinning, native MessageBox confirmation, single-use nonce/assertion ledger, HMAC proof under a per-process key. **Zero network I/O by construction** |
| `host/` (`shun-consent-host`) | `host/shun_consent_host.node` (committed) | napi addon: unguessable pipe name (BCryptGenRandom), broker spawn with piped stderr, server-image verification BEFORE the first frame, frame-JSON conversation, dialog automation instrument (test-only), OS-token inspection |

TS surface: `index.ts` (fail-closed loader + `PrivateConsentBrokerSession`,
never a JS pipe fallback) and `artifacts.ts` (pinned artifact SHA-256; the
exe is re-hashed at spawn and the addon at load — a tampered binary refuses
with a typed code, it is never run).

## Security posture (enforced in Rust, not in JS)

- **Pipe admission**: explicit DACL (only the broker's own user SID + logon
  SID; `PIPE_REJECT_REMOTE_CLIENTS`), then per-connection comparison of the
  CONNECTING client's token facts (user SID / logon SID / session id) against
  the broker's own token — OS-token only, never a pid or client JSON.
- **Server authentication (client side)**: the host verifies the pipe SERVER's
  image path (`GetNamedPipeServerProcessId` → `OpenProcess` →
  `QueryFullProcessImageNameW`) equals the pinned, SHA-verified broker exe
  before sending the first frame; the pipe name carries 128 bits of CSPRNG
  entropy so a squatter cannot guess it.
- **Exactness**: the request's `projectionJson` must be the frozen T01
  `buildDeepSeekGoalDisclosure` shape with pinned literals
  (deepseek / deepseek-flash / the chat-completions destination / GOAL_TEXT
  only); its recomputed BCrypt SHA-256 must equal
  `scope.approvedProjectionSha256` **before any dialog is shown**.
- **One trusted gesture**: a real `#32770` MessageBox (bilingual, default
  NO) shown only when the broker's current thread desktop IS the session
  input desktop. Non-interactive contexts (service station, hidden desktop)
  refuse; an unattended box auto-closes (WM_CLOSE) and denies; the dialog
  thread is joined only after a confirmed answer so an orphaned box cannot
  wedge the pipe loop.
- **Single use, restart-dead**: approvals carry a fresh nonce and an
  HMAC-SHA256 proof (BCrypt) over the consent-bound fields under a
  per-process random key; `verify` consumes the assertion atomically
  (second use → `ASSERTION_CONSUMED`); a restarted broker has a new key and
  an empty ledger, so every outstanding proof dies (`PROOF_INVALID`).
- **Redaction**: broker stderr is structured `BRD …` lines with task id +
  digest prefix only — never the goal text, nonce, MAC or any credential.

## Build (Windows x64, Build Host; committed artifacts)

Same toolchain as T04 (`packages/recipe-runtime/native/README.md`):
rustc/cargo `stable-x86_64-pc-windows-gnu`, msys2 ucrt64 `gendef`/`dlltool`
import library for node.exe v24.21.0 at
`/c/xDev/runtimes/libnode-import/v24.21.0/libnode.dll`, Node 24 (`.node-version`).

```bash
cd apps/control-api/native
export CARGO_TARGET_DIR=<repo-root>/.target CARGO_INCREMENTAL=0
export LIBNODE_PATH=/c/xDev/runtimes/libnode-import/v24.21.0
rustup run stable-x86_64-pc-windows-gnu cargo build --release --locked
cp "$CARGO_TARGET_DIR/release/shun-consent-broker.exe" broker/shun-consent-broker.exe
cp "$CARGO_TARGET_DIR/release/shun_consent_host.dll"   host/shun_consent_host.node
# then pin the new digests in artifacts.ts (verifyArtifacts refuses on drift)
sha256sum broker/shun-consent-broker.exe host/shun_consent_host.node
```

## Real-run evidence (Windows interactive Desktop, Node 24.21.0, Standard User token)

Produced by `test/private-consent-host.test.ts` (vitest, real Win32 events —
no test doubles claim OS proof):

- real `#32770` dialog found + Allow clicked → `APPROVED`, minted approval
  passes `CloudConsentApprovalSchema` strictly and
  `validateCloudConsent` with the broker-backed verifier → ok;
- second consume → `ASSERTION_CONSUMED`, `checkNonce` → false;
- broker kill (exit code 1) then a fresh broker: old proof `PROOF_INVALID`,
  nonce unused=false (restart = zero egress from stale proofs);
- real Deny click → `DENIED` (exit 0 on clean shutdown);
- unattended dialog → `DENIED_TIMEOUT` (fail-closed default);
- digest mismatch → `REFUSED_DIGEST_MISMATCH`, no dialog ever shown;
- digest-CONSISTENT projection with an attacker destination →
  `REFUSED_PROJECTION_INVALID`, no dialog;
- broker spawned on a pre-created hidden desktop (`winsta0\…`, desktop-name
  mismatch against the input desktop) → `REFUSED_NONINTERACTIVE`, no dialog;
- usage error exit code 2; clean shutdown exit code 0.

## Known evidence boundaries (documented, not claimed)

- The interactive-dialog evidence uses an automation instrument that clicks
  the REAL OS dialog's Yes/No button (BM_CLICK on the button control of the
  genuine `#32770` window owned by the broker pid). It automates input to a
  real dialog; a physical human click was not separately recorded in this
  lane and remains part of the final T08 Windows qualification run.
- Foreign-principal refusal is enforced by the DACL + per-connection token
  comparison; a live second-logon/second-session negative (two real foreign
  principals) needs a second interactive session, which a single-user test
  host cannot provide. The same-principal positive and the token-identity
  equality logic are proven live above; the enforcement code path for a
  mismatching token is the same comparison the evidence exercises.
