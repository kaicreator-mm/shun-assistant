# Shun v0.2 — Generated Script & Recipe Product Contract (DRAFT)

> **L1 product contract proposal**, not L2 design or an executable permission grant. Applies only to v0.2 planning (#80/PR #81). Frozen v0.1 ActionController / ShunStore / Windows privileged-executor constraints remain authoritative until reviewed successor changes.

## A. Why this is a first-class product object

The core v0.2 ROI hypothesis is that users repeat routines (“check what fills disk”, “organize invoices”, “batch resize today's photos”). The **first request** may need LLM understanding and a structured script proposal; the **second** should normally reuse an already verified bounded plan without paying to regenerate code. A Recipe is **not** a general shell command. It is a versioned, inspectable, parameterized operation with an independent verifier and audit trail.

```text
Intent → GoalContract → (exact trusted Recipe reuse OR real LLM proposal)
  → ScriptProposal + effect declaration + ParameterSchema
  → preflight/counterexample checks → scratch isolated dry run → visible preview
  → ActionController plan/hash/scope/currentness and R2 decision
  → typed mediated execution (or proven isolated script runtime)
  → independent semantic outcome verifier + durable receipt
  → proposed Recipe candidate → (user approve when required) → reusable recipe
  → repeat goal + new parameters → currentness/scope/plan-hash recheck → replay
```

## B. Execution classifications and language gates

| Route | v0.2 support | Direct host access | Counterexamples |
| --- | --- | --- | --- |
| `JS_RECIPE` pinned Node/JS | **P0 execution only through mediator or proven isolated host** | Restricted tool API to query observed facts and propose typed effects. No arbitrary `fs` writes, `child_process`, socket/network, require/import native addons. JavaScript source inspection available. | `require('child_process')`, `node:sqlite` native/pseudo filesystem, symlink escape, inherited handles, environment variable/secrets, dynamic `eval` |
| `PS_DIAGNOSTIC` Windows PowerShell | **P0 approved, read-only diagnostic functions/allowlist** | Structured JSON return from audited Windows host functions/cmdlets, not unrestricted model-authored `.ps1`. General PowerShell only with independent OS application-control confinement. | `Invoke-Expression`, `Start-Process`, `Invoke-WebRequest`, `Get-Credential`, `Get-Content` outside scope, COM, network, registry writes, encoded command |
| `PYTHON_RECIPE` | **P1 v0.2, source preview/import** | Direct execution requires pinned Windows embedded Python and proven isolation with package allowlist, exact version, no arbitrary pip installs | `os.system`, `subprocess`, file writes, `ctypes`, native extensions, alternate import hooks |
| `CMD_LEGACY` | **Compatibility-read/import-only P0** | Convert known safe `cmd` steps to approved typed operations or mark `BLOCKED`. No generated `.bat` autonomous execution. | ampersands, pipes, redirection, `for /f`, expansion, inherited environment |
| `TYPED_ACTION_GRAPH` | **P0 preferred for mutations** | Calls Shun's allowlisted execution backend only, with effect-level grant checks. It can be output from a model or a script but is never privileged on its own. | unknown operation, raw shell string, unbounded roots, dynamic target substitution, missing independent post-state check |

PowerShell `ExecutionPolicy` and a manually set ConstrainedLanguage flag are not an OS security boundary. Effective managed application-control policy (App Control/WDAC) or an equivalent demonstrated host restriction must be tested before relaxing `PS_DIAGNOSTIC` into raw generated code. Windows Sandbox does not run on Windows Home; the P0 cross-edition path therefore must use mediated typed APIs without assuming optional Sandbox. Node `--permission` is useful defense in depth but documented non-security-boundary/escape limitations require a real OS boundary to promise raw untrusted JS confinement. `vm`, AST linting and model self-critique alone cannot prove script safety.

## C. Minimal immutable identities / Recipe record fields

Product-level required information (L2 may rename fields while preserving semantics):

- `recipeId`, `recipeRevision`, `lifecycle`: `PROPOSED → PREFLIGHTED → VERIFIED_CANDIDATE → ENABLED` / `BLOCKED` / `STALE` / `REVOKED`.
- `intentSignature`: canonical capability id + normalized goal class + accepted object kinds; descriptive natural language is supplementary, **not authority**.
- `parameterSchema`: exact typed inputs (workspaceRoot, include patterns, bounds, output destination), defaults, constraints and conditions under which a new value requires reapproval.
- `language`, `runtimeRevision`, `scriptDigest`, `sourceOrigin` (LLM id/model/config/hash of proposal vs manually verified), and whether action graph or source is present.
- `actionGraphDigest`, declared effect types/risk, allowed read/write roots, network scope, forbidden protected paths; `lastVerifiedOn` including Windows revision/arch/runtime+provider hashes, plan/authority/policy revision and valid observation time.
- `verifierId`, `verifierRevision`, independent semantic checks and precommitted expected-output properties (counts/hash/identity/safe candidate classification).
- `approvalRequirement`, `userPromotedAt` (when consent required), provenance, last successful verified run, failed run history pointer.
- `executionCount`, `reuseCount`, last seen cost/latency model calls; counters cannot confer authority.

No raw API keys, browser cookies, unrelated file text, entire prompt/completion transcript, password/credential/environment dump or durable user data content in reusable Recipe by default. Keep sensitive inputs in per-run ephemeral typed parameter channels.

## D. Reuse decisions (deterministic, observable)

1. `EXACT_REUSE`: all script digest, runtime identity, authorized capability, verifier, scope/profile, policy currentness and parameter schema match. Recompute action-plan hash for this **execution**. No LLM call needed.
2. `REBIND_AND_RECHECK`: a permitted parameter changed but recipe identity remains. Regenerate bounded effect manifest, re-run preflight and authorization; R2 requests **fresh** user preview/approval for actual targets. No unbounded “approve forever”.
3. `REVALIDATE`: model/provider/runtime/Windows/host facts drift, source changed, verifier changed, time/freshness expired or reusable evidence insufficient. Do not attempt a destructive action before positive revalidation.
   - **Lazy Provider dependency:** A previously verified Recipe may reference a permitted optional Provider not currently installed. This is NOT `EXACT_REUSE` until its catalog identity and pinned artifact/version/runtime hash are present and current. Shun may propose an explicitly approved on-demand acquisition, then revalidate the Recipe and recompute a new action grant; offline/missing/tampered/revoked Provider → `BLOCK`, not arbitrary fallback or a model-generated installer. Cached verified Provider reuse needs no LLM call.
4. `REGENERATE`: genuinely new intent or approved capability change; call LLM, produce **new** script revision and new validation history.
5. `BLOCK`: untrusted script, denied network/elevation, unknown operation, scope escape, expired/revoked grant, ambiguous goal, unsupported runtime or failed oracle. Reject unchanged repeated invalid attempts.

**Match order**: explicit user-chosen Recipe ID and typed parameters → deterministic registered intent aliases → optional semantic candidate retrieval, **not automatic action authorization**. For semantic matches, display choices or ask clarification before selecting a Recipe; similarity score does not equal permission or prove goal equivalence.

Once first run is semantically verified, **automatically suggest saving**; allow default auto-save as a *disabled candidate* without executable permission. Only approved/eligible Recipes become ENABLED. Low-risk exact R0 replays may run with approved persistent local read permission; R1 requires bounded grants and output collision checks; R2 each run needs accurate target-specific approval unless a product-reviewed durable JIT policy explicitly authorizes that exact bounded class. Escalation and unknown system changes always fail closed.

## E. Usage accounting / outcome measurement

A user should see: script language, “created by LLM” vs “reused existing Recipe”, saved LLM calls and latency, actual file count/size, changed paths, verification successes/failures, last successful use, drift and reapproval flags. Cost/latency must be measured, not claimed.

Replay success example: same user's goal “整理下载目录中今年的发票并按月份归类” selects enabled Recipe, supplies current selected root and year, runs preview, obtains consent for file moves, executes; **LLM calls 0** on exact deterministic replay, sources preserved under verified move semantics, all output paths can be traced to signed action receipts. New external root or unplanned extensions are `BLOCK`/`REVALIDATE`, not accepted by fuzzy intent matching.

## F. Independent negative acceptance

Minimum independent host tests:
- Generated JS cannot escape OS/mediator boundaries through Node builtin aliases, `eval`, child process, addon, alternate filesystem APIs or symlink/junction paths; if OS isolation is unavailable, **generated JS runs only as non-executing proposal or mediated action graph**.
- Generated PowerShell never performs host write/network/admin by invoking an obfuscated or indirect cmdlet; model-suggested `ExecutionPolicy Bypass` is never authorization.
- Malicious output from a compromised LLM or a crafted filename/document cannot override scopes/capability registry, read private credentials or cause external upload under LOCAL_ONLY.
- Exactly same valid Recipe replay after a restart uses zero LLM calls, succeeds with independent oracle; revoked grants, script hash tamper, wrong runtime version or changed workspace block the effect.
- Crash between approval/effect and effect/receipt is journaled and reconciled rather than blindly replayed.
- Non-Windows and Windows Home lacking optional security features disclose unsupported isolation explicitly; no blanket Windows Sandbox claim.
- Additional interpreter is never installed on a user's machine without trusted manifest and user-controlled install decision.

## G. Release implication

A saved script is **NOT** a security authorization token. Proven `VERIFIED_CANDIDATE` evidence is NOT proof for arbitrary future inputs. Each parameter binding still creates a new checked plan/execution. The product can truthfully promise *reduced repeated LLM calls and bounded replay*, **not** arbitrary generated PowerShell/Python command execution without an isolation posture. The v0.2 Product Freeze should choose credible host-security profiles and list known unsupported modes rather than pushing raw-script risks into “P2 debt”.

## H. Optimization recipes and on-demand Provider dependencies (2026-10-14)

- A Windows optimization Recipe contains a **scoped goal and typed reversible effects** (e.g. `storage.inspect`, existing bounded `storage.cleanup`, `startup.user_entry.inspect`, approved limited `startup.user_entry.disable/restore`) rather than a general command named `optimize-windows`. Only admit a mutation with actual supported host mechanism, saved original configuration, comparison evidence and a restore method. Critical system/security services and unverified startup entries remain read-only recommendations.
- Each run records **baseline facts, exactly changed state and restore receipt** separately from estimated performance effects. Decrease in resource use/boot delay is not asserted without comparable measured conditions and appropriate observation time; a future post-reboot measurement may remain pending.
- `providerDependencies` records logical capability, exact approved catalog/provider binding identity/version or verified compatibility range, optional native ABI/architecture and the observed artifact identity. Startup download is not a hidden Recipe side effect: user must approve required new software acquisition separately, task execution remains independently authorized, and a cached provider never exempts effect validation.
- Core-only/offline startup and native Windows optimization must remain functional when optional `sharp`, `fd`, `ripgrep`, PDF/archive tools or locally hosted model runtimes are not installed. Remote LLM requests remain separately opt-in and cannot silently download optional providers.
