# R04 — Per-user LocalAppData Guided trust (L2 decision note)

- **Owner decision (2026-11-09, Issue #404):** 采用每用户 LocalAppData 信任自举方案；安装或首次运行可以要求管理员权限。This supersedes the provisional ProgramData preference (#273 comment 6729943340). Single Builder pack: PR #405 (head `4d5545e0aabe9ff8fc7a256fe92746c57d38e3ac`, manifest blob `5f74ce856a6adc3ba4531735163f7cd2ae1f6f37`); source branch `JIT_only_task/v0.3.0-r04-localappdata-guided-bootstrap-g1` on WIP base `wip/v0.3.0-r02-owner-repairs` @ `0764c8ff10914684a9d748e3dbbf9d3172ef72b0`.

## Decision

The Guided provenance trust root moves from the machine-scoped
`C:\ProgramData\Shun\authority\guided-provenance` (privileged-owner-only DACL
policy) to the **per-interactive-user** Windows profile:

| Piece | Location (per user) |
| --- | --- |
| Trust tree (anchor + receipts) | `%LOCALAPPDATA%\Shun\authority\guided-provenance` |
| Public SPKI pin (sibling) | `%LOCALAPPDATA%\Shun\authority\guided-provenance-trust-pin.json` |
| Issuer private key (distinct secret dir) | `%LOCALAPPDATA%\Shun\secrets\guided-issuer\issuer-private.pem` |

The base is resolved from the OS-provided session value
(`resolveWindowsLocalAppDataBase`): absolute, non-root, canonical (no
reparse/alias), inside no machine-scope root, and equal to
`USERPROFILE\AppData\Local` (or the OS Known Folder value verbatim when
USERPROFILE is absent). No HTTP/model/DB/CLI input can select the trust path.

## Security model changes (deliberate, owner-approved)

- **Removed:** the privileged-owner-only ProgramData DACL requirement
  (Administrators/SYSTEM ownership of every trust object and ancestor) that
  made a legitimate per-user bootstrap impossible.
- **Kept:** ownership checks (owner ∈ {interactive user SID, SYSTEM,
  Administrators}), no foreign-SID write/DELETE/WRITE_DAC/WRITE_OWNER ACE on
  the tree or its ancestor chain (up to the LocalAppData boundary), runtime
  read preservation, canonical/no-reparse path rules, and the external
  Ed25519 receipt semantics (canonical DB path binding, schema digest, SPKI
  pin) — runtime remains verify-only.
- **Residual risk (recorded per #404):** same-interactive-SID malicious
  processes and other-local-user malicious processes are OUTSIDE the frozen
  v0.3 attack model. Per-user profile ACLs (user/SYSTEM/Administrators) are
  the enforcement boundary; this is consciously weaker than the retired
  privileged-only ProgramData DACL and is accepted by the Owner decision.

## Bootstrap (first run) — `apps/control-api/scripts/bootstrap-guided-localappdata.ts`

One consented local action, separate from ordinary runtime and reachable
from no browser/LLM/HTTP surface:

1. **Identity guard (read-only):** resolves the process user SID; an
   ELEVATED token belonging to a DIFFERENT account than the interactive
   console session user (credential/UAC over-the-shoulder) is refused
   (`GUIDED_BOOTSTRAP_WRONG_ACCOUNT_ELEVATION`), and an elevated token with
   NO resolvable console target is refused too
   (`GUIDED_BOOTSTRAP_ELEVATED_TARGET_UNVERIFIABLE` — unverifiable is not
   same-account; whole-version RQ repair of review #5830194105
   P2-IDENTITY-UNKNOWN), so authority never lands in an unproven account's
   profile. Unelevated same-user runs — the normal path, including a remote
   RDP target user — need no UAC at all; PROVEN same-account elevation is
   accepted.
2. **Explicit consent:** without `--consent` the tool only prints the plan
   (identity, per-user paths, current state) and exits non-zero.
3. **Provisioning:** generates the per-user Ed25519 key (the user never
   manufactures keys or pastes pins/digests), stores the private key in the
   distinct per-user secret directory, provisions anchor + receipt through
   the issuer module and publishes the sibling pin. The frozen schema digest
   is derived internally from an ephemeral scratch DB.
4. **Idempotence:** a complete verifying setup is a byte-stable NO-OP —
   never rotated, never re-signed. A second Guided store under the same
   verified anchor is ordinary consented provisioning (no re-keying).
   Structural partials (missing anchor/pin) need an explicit `--repair`
   that completes ONLY missing pieces while every present piece verifies;
   present-but-INVALID material is refused outright (no overwrite, no
   re-sign) and surfaced for an operator reset decision. When the missing
   piece is the anchor itself, the pieces that stayed present were only
   structurally classifiable at plan time — the repair re-verifies them
   against the anchor restored from the secret and refuses
   (`GUIDED_BOOTSTRAP_REPAIR_INCONSISTENT`) instead of reporting
   `REPAIR_COMPLETED` over material the runtime would reject
   (whole-version RQ repair of review #5830194105 P2-REPAIR-INTEGRITY).
5. **No secrets in output:** only identifiers, paths and fingerprints are
   ever printed.

## Known limitation — concurrent first-run (deferred, review #5830194105 P2-CONCURRENT-BOOTSTRAP)

Two SIMULTANEOUS first runs of the consented bootstrap CLI are not
serialized by a cross-process lock: the per-file atomic
(temporary-then-rename) writes do not give the whole key→anchor→receipt→pin
sequence exclusive ownership. An accidental double invocation can interleave
and leave a partial or mismatched set; the runtime then fails closed exactly
as designed and the state is resolved by `--repair` (or an operator reset
for mismatched material). The first-run flow is a single manual consented
command, so this is an availability edge, not an authority bypass. A bounded
exclusive bootstrap guard plus a two-process negative test is required
BEFORE any unattended first-run automation is introduced; do not add a new
trust ledger for it.

## Runtime wiring

`createProductionGuidedService` resolves the per-user trust root + pin +
owner SID + ancestor chain from the current session; a never-provisioned
pin is the truthful first-run refusal `GUIDED_TRUST_SETUP_REQUIRED` (with
the one-time bootstrap command in the operator console record) — never a
DEMO fallback, never a fabricated PASS. Ordinary Guided usage needs no
elevation once a valid bootstrap exists; `main.ts` gates unchanged
otherwise.

Legacy ProgramData provisioning is NOT auto-imported and NOT a fallback.
