# @shun/executor-windows

P0 local Windows execution backend (L2 §8.2) and the one-shot privileged
elevated helper (§8.2.1/§9.3) for Shun v0.1. Implements the frozen contracts
seams `EnvironmentBackend` and `ExecutionBackend` — and nothing around them:
authorization stays with the Action Controller, semantic verification with the
Verifier.

## Surfaces

| Surface | Seam | What runs where |
| --- | --- | --- |
| `LocalWindowsBackend` | `EnvironmentBackend` (§8.1) | in-process, non-elevated, NONE/USER actions |
| `PrivilegedWindowsExecutionBackend` | `ExecutionBackend` (§9.1/§9.3) | one-shot elevated helper per action, via UAC |

## Invariants (frozen by L2 §8.2.1 / §4.6.1 / §9.4)

- **Typed allowlist only.** The op enum in `src/ops.ts` is the entire thing
  the privileged boundary can do. Unknown op = structural refusal. No shell
  exists anywhere: process spawning is `spawn()` argv arrays with
  `shell: false`; shell metacharacters are DATA and cross the boundary
  byte-exact; NTFS-illegal path characters fail closed at validation.
- **Envelope, never command text.** The `AuthorizedAction` envelope crosses
  the privilege boundary as a strict-schema JSON file; no LLM prompt, no
  provider object, no helper path parameter exists in the surface (strict
  schemas refuse smuggled keys).
- **Independent privileged-side re-verification.** The helper re-establishes
  everything itself before any side effect: envelope schema → own-bundle pin
  self-check → I/O containment within the pinned workspace root → currentness
  from the trusted authority store (missing/corrupt ⇒ UNRESOLVABLE ⇒ refused)
  → grant authenticity (HMAC over the contracts canonical form) → grant
  currentness/expiry → plan-hash re-derivation → exact action↔plan identity →
  declared scope (fs realpath + reparse-point checks, registry segment
  containment) → privilege consistency. All of it is the SAME
  `@shun/contracts` code the launcher uses — one canonicalization
  implementation on both sides (the U-06 demo deliberately duplicated it;
  production does not).
- **Pinned helper identity.** The helper is one esbuild bundle
  (`pnpm build:helper` → `dist/executor-helper.mjs`). Its content hash and
  revision live in the authority store (`helper-pin.json`) alongside the
  pinned relay script hash and the workspace-root anchor. The launcher
  verifies the pin before spawning; the helper re-verifies its own hash
  inside the elevated boundary; any mismatch is a structured refusal.
  The pin binds the LOCAL build: the bundle embeds build paths, so a fresh
  checkout on the same host re-pins via the authority (an explicit authority
  event), and per-machine rebuilds are byte-identical (verified). Changing
  the bundle (or the baked authority-store location) is the same class of
  event: rebuild + re-pin.
- **Fail-closed receipts.** Every validation failure produces a structured
  `REFUSED` receipt before any side effect. Unexpected exceptions still
  produce a receipt. A genuine secure-desktop UAC refusal yields
  `UAC_DECLINED` with an provably empty journal (the helper writes nothing
  until its trusted anchors are established).
- **Recovery from journal + post-state only (§9.4).** The phase journal
  (JSONL, torn-append tolerant) plus independent launcher-side verification
  (`rerunVerifyStep`, `reconcileExpectedState`) are the ONLY classification
  inputs. Interruptions inside a step's `[EXEC_START, EXEC_DONE)` window
  resolve only through the action's declared `expectedState`, else stay
  honestly `MAY_HAVE_EXECUTED_UNCERTAIN` — reconcile-first, never blind retry.
- **Cooperative cancellation + helper-side deadlines.** A non-elevated parent
  cannot force-kill the elevated child, so the helper enforces its own
  deadline and polls the cancel sentinel between phases and inside long
  steps; launcher-side tree-kill remains last resort for non-elevated
  children only.

## Trusted substrate (L3 latitude, reference implementation)

One directory (default `<USERPROFILE>\.shun\authority`; baked into the helper
bundle at build time — NEVER taken from argv/env, which an attacker-run
launcher controls):

```
current-authority.json   CurrentAuthorityState (CURRENT | UNRESOLVABLE)
grant-hmac.key           base64 HMAC key (authority-held)
helper-pin.json          pinned helper/relay identity + revision + workspaceRoot
grants/<grantId>.json    issued AuthorizationGrant records (with integrity)
plans/<planHash>.json    ActionPlan records (trusted plan source)
```

The issuer side (AuthorizationAuthority, T02) writes these records; this
package only reads them, fail-closed. On a single-user host the store is
protected by user-profile ACLs; the threat model this closes is a coerced or
compromised launcher (tampered plans, forged/self-declared grants, scope
escape, helper substitution), not the local user themself.

## Layout

```
src/ops.ts               typed op registry + path/key legality
src/action-surface.ts    AuthorizedAction → typed step mapping
src/interpreter.ts       the ONE typed-op executor (shared by both surfaces)
src/fs-safety.ts         realpath containment + reparse-point rejection
src/scope-preflight.ts   grant-scope containment before any effect
src/journal.ts           phase journal (write + tolerant replay)
src/recovery.ts          §9.4 classification from journal + post-state
src/poststate.ts         launcher-side independent verification / reconcile
src/envelope.ts          the boundary envelope (schema + file I/O)
src/trusted-store.ts     authority store readers/writers + HMAC + pin
src/helper-pinning.ts    pinned identity verification
src/backend.ts           LocalWindowsBackend (unprivileged, in-process)
src/privileged-backend.ts launcher: pin check → envelope → relay → classify
src/helper/executor-helper.ts the one-shot elevated helper entry
src/relay/elevate-relay.ps1   pinned single-shot RunAs relay (non-elevated)
src/facts.ts             EnvironmentFacts observation
scripts/build-helper.ts  esbuild bundle + authority-dir define
test/                    95 unit/integration tests (no UAC required)
test/evidence/           real Windows/UAC evidence runs (gated, see below)
evidence/                committed evidence artifacts (E1–E5)
```

## Commands

```bash
pnpm lint / typecheck / test     # always safe (no elevation)
pnpm build:helper                # bundle + print the pin hash
pnpm test:evidence               # real UAC runs — pops secure-desktop prompts
```

Evidence runs are gated behind `SHUN_EXECUTOR_EVIDENCE=1` and require a human
at the console (secure-desktop consent is not automatable by Windows design —
U-06 demonstrated this). See `test/evidence/` and `evidence/` for the
recorded runs and `summary.json` per case.
