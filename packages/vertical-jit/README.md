# @shun/vertical-jit — Loop B trusted JIT software lifecycle (T06)

Reference implementation of C-002 `software.jit_capability_lifecycle`
(`docs/product/capability-contracts-v0.1.md`) over the frozen T00 contracts:

```
C-002 → trusted acquisition candidate → local Windows binding → acquire →
task execute + verify → lifecycle-state persistence → R2 remove plan/preview
→ approval or pre-existing durable JIT policy → remove/reconcile →
protected/user-asset verification
```

## Layout

- `src/orchestrator.ts` — `runJitLifecycle` (production input) and
  `runJitBenchmarkLifecycle` (hidden-canary envelope, L2 §4.2). Every side
  effect flows `ActionPlan → grant → AuthorizedAction → privileged backend`;
  outputs are validated against `JitLifecycleOutputSchema` before emission.
- `src/local-authority.ts` — local authorization substrate: real HMAC-SHA256
  grant integrity, trusted plan ledger, current-state mutation seams for the
  fail-closed negatives (stale policy, revocation, unresolvable currentness).
- `src/local-backend.ts` — privileged backend base (L2 §9.3/§9.4): boundary
  re-validation via contracts `validateGrantPresentation`, phase journal
  (`RECEIVED → VALIDATED → EXEC_START → EXEC_DONE → RECEIPT_WRITTEN`),
  torn-append-tolerant replay and journal-only recovery classification.
- `src/residue.ts` — five-class residue classification with fail-closed
  dispositions (`USER_CREATED_UNKNOWN`/`PROTECTED` are never auto-deleted) and
  the strict provider-owned-file mode used by the benchmark envelope.
- `src/adapters/winget.ts` — real winget acquisition (official-source
  allowlist, exact version, Installer SHA256 provenance, typed argv,
  `--disable-interactivity`) and the privileged winget backend (idempotent
  already-installed/already-absent handling, elevation refusal →
  `UAC_DECLINED`/`NOT_STARTED`).
- `src/adapters/cli-backend.ts` — real CLI task backend (I1 interface class).
- `src/mocks.ts` — in-memory harness (filesystem, registry, store, approval,
  acquisition catalog) for the port-level test suite.

## Tests

```
pnpm --filter @shun/vertical-jit test
```

Covers: retain/remove happy paths, provenance fail-closed gate (approval is
never consulted), grant negatives (stale/revoked/forged/unresolvable),
declined elevation (`NOT_STARTED`), interrupted removal (journal
`MAY_HAVE_EXECUTED_UNCERTAIN` → reconcile-first retry of the SAME actionId),
residue classification matrix, torn journal replay, benchmark envelope vs
production input, and winget adapter behavior against scripted process output.

## B-038 real-host evidence (LOCAL_WINDOWS_BUILD_HOST)

```
node scripts/b038-evidence.ts evidence/b038-<run-id>
```

Runs the lifecycle against the real winget official source with disposable
portable packages (`jqlang.jq`, `BurntSushi.ripgrep.MSVC`) and records outputs,
privileged journals and a `summary.md` under `evidence/`. The committed
`evidence/b038-run-20261010/` contains the run from this branch (host:
Windows 10.0.26300 x64, FILTERED_ADMIN): 7 PASS / 1 SKIPPED — the
declined-elevation negative cannot be produced on a UAC never-notify host
(the machine-scope install is silently granted); the attempt artifacts are
kept and the `UAC_DECLINED`/`NOT_STARTED` semantics stay covered by the
port-level test suite.

The script cleans up after itself: every acquired package is removed by a
gated removal before the run exits.

## Scope notes (honest limits of this reference proof)

- Residue discovery observes the provider's declared install layout only
  (WinGet package dir, cache, config roots). WinGet-managed link shims are
  removed by winget itself and are not part of the residue report.
- In non-strict (production) mode, everything inside a declared provider
  install root is treated as `PROGRAM_OWNED`; the strict provider-owned-file
  mode is exercised through the benchmark envelope and canaries.
- The authorization substrate is an in-memory ledger with real HMAC
  integrity; durable ShunStore persistence of grants is T02/T03 scope.
