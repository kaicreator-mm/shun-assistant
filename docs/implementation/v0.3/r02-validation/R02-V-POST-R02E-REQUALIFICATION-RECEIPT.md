# R02-V post-R02-E targeted Windows requalification receipt (generation 2)

**Pack**: `shun-v030-r02-v-post-r02e-requalification-g2` — manifest blob `c1bc844e7ea45e9efb325abc91f63248c766d905` (PR #376, exact pack HEAD `3ccfbfdfb89b6332789ae930325cb33384e35f1e`, base `wip/v0.3.0-r02-owner-repairs`). **Claim**: generation-2 `DISPATCH_CLAIMED`, [#270 comment 6680740704], profile `LOCAL_BUILDER` / `LOCAL_WINDOWS`. Generation-1 Claim #6547910006 is terminal/historical and is not reused or reattributed. This is a factual execution record, not a release certificate and not an R03 PASS.

**Integrated source baseline**: `47ecf345c4b96befd20db5c6d5673bbeaf027e49`, tree `8aff803fc2f80e9b683be3d5e8abea747c6677ea` (R02-E #375 squash merge; parent `39e4f85f3fa01d9f4b20ba73adcf79cbc42707f5`). Live readback at Claim time confirmed the WIP branch head equaled this exact SHA (no drift since pack CI).

**Environment**: Microsoft Windows 11 专业版 (10.0.26300 x64, win32), real native Node **v24.21.0** and **v26.13.0** (both fnm-managed on this host), worktree `i270g2-lbuilder`, source branch `JIT_only_task/v0.3.0-r02-v-post-r02e-requalification-g2` created from the exact baseline (not from the pack PR branch). Zero paid requests, zero physical Windows effects, no UAC, no Provider install, no persistent OS mutation: every spawned process ran in a cloud-sanitized environment (`SHUN_CLOUD_ENABLED=0`; `DEEPSEEK_API_KEY` and all `SHUN_CLOUD_*` authority variables stripped), and all fixture writes stayed inside OS temp roots.

## Why only J07/J08 (the exact R02-E integration delta)

`git diff --stat 39e4f85..47ecf345` is exactly nine paths — none of them touches any J01–J06/J09 production path:

```text
apps/control-api/package.json                                  (dev: "tsx src/main.ts", pinned tsx 4.23.15)
apps/control-api/scripts/issue-guided-provenance.ts            (operator trust issuer — NEW)
apps/control-api/src/main.ts                                   (production Guided trust injection)
apps/control-api/src/real-storage/guided-provenance-issuance.ts (external trust authority — NEW)
apps/control-api/src/v03/composition-guided-provenance.ts      (production Guided composition — NEW)
apps/control-api/test/guided-provenance-issuance.test.ts
pnpm-lock.yaml
tests/integration/v03/r02-e-production/production-startup.test.ts
tests/integration/v03/r02-e-production/startup-runner.test.ts
```

The default production entrypoint/Node runner (J07) and the trusted Guided authority injection (J08) are precisely what changed; the gateway composition (`composition-production.ts`), Kernel, cloud transport, Provider chain, UI strings and Shadow store are byte-identical between the generation-1 evidence baseline `65b656fbf065acd28cb9bdaad494c024eff6f002` and this integrated tree along those paths.

## Journey files (all inside the #270 protected write set)

| File | Gates | What is real |
|---|---|---|
| `tests/integration/v03/r02-v-journeys/j07-startup-requalification.test.ts` | none (netstat assertions win32-only) | The EXACT shipping operator command `pnpm --filter @shun/control-api dev` boots the real import graph through the pinned `tsx@4.23.15` runner with no TypeScript syntax error and never reintroduces the Node-26-removed `--experimental-transform-types`; the real loopback surface serves the actual `apps/control-ui/public` UI (200), refuses a hostile non-loopback Host header (403 `LOCAL_ONLY_VIOLATION`), and reports the absent Guided/gateway truthfully (503 `V03_GUIDED_UNAVAILABLE` / 503 `V03_GATEWAY_UNAVAILABLE`); native `netstat` proves the listener is bound to `127.0.0.1` only; deterministic shutdown + port refusal. Windows-only leg: with every non-trust production input valid (real registry issuance by the shipping `issue-registry-currentness.ts` script over an ephemeral Ed25519 authority), a missing operator trust pin refuses the boot BEFORE any listener exists — nonzero exit, `KEY_NOT_PROVISIONED` + `GUIDED_TRUST_` coded refusal, no REAL banner, no DEMO fallback, no Guided database file created. |
| `tests/integration/v03/r02-v-journeys/j08-guided-trust-requalification.test.ts` | none | The EXACT integrated production trust composition (`createProductionGuidedService`) over real SQLite + real loopback HTTP: operator-pinned Case file (SHA-256 pinned) stages through `provisionGuidedCaseFromHostFile`; hostile HTTP relays (`authorityClaimed:true`, approving ANSWER tuple) are refused 422 pre-consume; navigation (BACK) records `RECORDED` with `humanGrantIssued:false, effectSent:false` without consuming; terminal REFUSE consumes exactly once (200 `RECORDED`, then 409 `STALE` on replay); full service restart over the SAME database re-verifies pin/anchor/exact-database-receipt/ACL, preserves consumption and history, replays stay 409 `GUIDED_STEP_NOT_CURRENT`, a replayed Host observation refuses `GUIDED_SEED_REPLAY`, and a genuinely new observation stages the next step; a swapped/untrusted trust anchor under the same pin refuses boot with `GUIDED_TRUST_PUBLIC_KEY_PIN_MISMATCH` and creates no database; a receipt bound to one database path never authorizes another (`GUIDED_PROVENANCE_RECEIPT_MISSING_OR_UNTRUSTED`). |

**Trust provenance for J08 positives — TEST_FIXTURE, not real operator provisioning**: the positive path uses the VITEST-gated ephemeral test-only Ed25519 issuer (`testOnlyAllowTemporaryKey`, refused outside a test runner) under isolated temp trust/database paths with injected ACL snapshots, mirroring the R02-E production composition fixtures. Console record from both runs: `{"platform":"win32","trustMode":"TEST_FIXTURE_EPHEMERAL_ISSUER","productionTrustPathPositive":"UNKNOWN"}`.

## Command / exit-code record (both native Windows Node versions)

```text
# Biome preflight on the exact new files (root biome.json)              EXIT=0 (0 problems)
node scripts/v03-ci/typecheck-r02.mjs                                   EXIT=0 (PASS 7 — r02-v-journeys included)
node --experimental-transform-types --check <each new file>             EXIT=0 (parse)

# — Node v24.21.0 (PATH-preempted fnm dir; logged node -v first) —
vitest run --config tests/integration/v03/r02-v-journeys/vitest.config.ts j07-… j08-…   EXIT=0 (9 passed / 9)
vitest run --config tests/integration/v03/r02-v-journeys/vitest.config.ts (full, CI gate shape) EXIT=0 (30 passed / 38 skipped — paid/physical legs stay gated off)
vitest run --config tests/integration/v03/r02-e-production/vitest.config.ts (R02-E regression incl. Windows trust-gate + G11 runner suites) EXIT=0 (41 passed / 41)

# — Node v26.13.0 (same three phases) —
vitest run … (j07-… j08-…)                                              EXIT=0 (9 passed / 9)
vitest run … (full r02-v-journeys)                                      EXIT=0 (30 passed / 38 skipped)
vitest run … (r02-e-production)                                         EXIT=0 (41 passed / 41)
```

Loopback-only network evidence (native netstat, one LISTENING row per boot, both versions):

```text
Node v24.21.0: TCP    127.0.0.1:56911        0.0.0.0:0              LISTENING       27784
Node v26.13.0: TCP    127.0.0.1:55619        0.0.0.0:0              LISTENING       10012
```

## Selected BUILD identity / Host authority mode (truthful scope statement)

No production BUILD was ACTIVATED in this targeted requalification: the J07 surface is the truthful demo-mode production entrypoint boot, and the J07 Windows trust-gate leg proves the real-storage boot refuses before activation without operator trust — so the production BUILD activation path (matrix checklist item 3) remains exactly as pending as before this generation; nothing regressed and nothing new was claimed. The Host authority mode qualified here is the integrated external verify-only Guided provenance authority: fixed-sibling pin file + signed anchor + exact per-database receipt + ACL/ancestor policy (TEST_FIXTURE material for positives; the REAL fixed `C:\ProgramData\Shun\authority\guided-provenance` path was exercised only as the fail-closed absent-trust negative, never written).

## Evidence reuse ruling for J01–J06/J09

REUSED (retained from [#270 comment 6554881727] at `65b656f…` and existing R02-INT/R03B/R03C exact-SHA receipts): the nine-path delta touches none of their production source paths (diff above), their journeys/vitest behavior is exercised green on the integrated tree in the same run (full r02-v-journeys 30 passed / 38 skipped on both Node versions), and the host/OS/Node-24 environment equals generation-1's. NOT RERUN, per the standing instruction: paid J03, physical J02/J05, UAC, Provider installation — their authorization scope, ceilings and receipts remain binding and unchanged.

## UNKNOWN / limitations (never marked PASS)

1. **Positive production-path J08 = UNKNOWN**: provisioning genuine operator trust at the fixed ProgramData authority directory requires an already-elevated operator token (the issuer CLI hard-refuses otherwise and never self-triggers UAC) and writes persistent OS state — both out of scope for this zero-paid/zero-physical pack. The positive J08 evidence here is TEST_FIXTURE-labeled at the exact integrated composition level; the production trust gate itself is positively proven only in its fail-closed direction.
2. Production BUILD activation with real operator trust (matrix checklist items 2–3) remains pending exactly as before; this generation adds no claim there.
3. Woodpecker push/PR pipelines for the delivered SHA are recorded in the builder self-check on [#270]; CI badges alone are not treated as Windows qualification — the native runs above are the qualification evidence.

## Non-waivers

No merge to WIP/version/main, no tag, no release, no deploy. No product-source, API, SDK, Host-authority or UI mutation: this delivery adds exactly the two journey files above plus this receipt and the matrix currentness note — all inside the #270 protected write set. The independent Exact-SHA review is the Web Controller's; UNKNOWN is nowhere claimed as PASS.

[#259]: https://github.com/kaicreator-mm/shun-assistant/issues/259
[#270 comment 6554881727]: https://github.com/kaicreator-mm/shun-assistant/issues/270#issuecomment-6554881727
[#270 comment 6680740704]: https://github.com/kaicreator-mm/shun-assistant/issues/270#issuecomment-6680740704
