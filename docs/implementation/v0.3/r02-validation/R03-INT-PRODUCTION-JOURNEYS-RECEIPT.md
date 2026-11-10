# R03-INT production journey integration receipt — F01/F02/Q01 repair

**Authority**: `OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE` + write-set addenda R1 (`trusted-build.ts`) and R2 (`assemble-trusted-build.mjs`), all on [#259]. Base SHA `65b656fbf065acd28cb9d965586c024eff6f002` (R03 review subject). This is a factual execution record, not an R03 PASS and not a release approval.

**What changed**: J02 (Windows effect), J05 (Provider first use) and J09 (meta feedback) now traverse the **selected public v0.10.3 DomainApp** in the shipping composition — one Kernel, no second dispatcher/sender:

- New trusted production Business/Capability Domain Packages (`packages/domain-app/src/activation/modules/business-windows|capability-windows-effect|business-provider|capability-provider|business-meta|capability-meta.mjs`); the windows pair is promoted from the kernel-validated T11 fixtures.
- New trusted Host install seams (`packages/domain-host/src/windows/effect-host-binding.ts`, `provider/provider-host-binding.ts`, `meta/meta-host-binding.ts`) installed by the production composition **through the same staged consumer module instance the sealed capability imports** (the openai-host seam pattern), each over REAL ports: FilePlan/FileGrant/FileCurrentness sources + HMAC grant-presentation validation + real `LocalWindowsBackend`; real `CuratedProviderVerifier→Stager→Activator` + `BoundedSpawnProcess`; real durable `HostMetaShadowStore`.
- Production composition (`composition-journeys.ts` + `composition-production.ts`): multi-route manifest admission (goal-interpret mandatory; journey intents each fail-closed on its binding config), reference-authenticated journey submits with the same truthful receipt classification; `server.ts` adds `/api/v03/effect/submit`, `/api/v03/effect/probe`, `/api/v03/provider/first-use`, `/api/v03/meta/feedback` (503 when unbound); `main.ts` wires `SHUN_V03_WINDOWS_EFFECT_*`, `SHUN_V03_PROVIDER_CONFIG`, `SHUN_V03_META_DATABASE`(+optional pinned case provisioning).
- `trusted-build.ts`/`assemble-trusted-build.mjs`: exactly-one kernel/standard unchanged; ≥1 business/capacity allowed (≤10 total) — the public SDK already collects multiples.

## Command / exit-code record (Windows Node v24.21.0, worktree r02-repairs-zc)

```text
vitest ... r02-v-journeys j02-production (SHUN_R02V_PHYSICAL=1)   EXIT=0 (7/7)
vitest ... r02-v-journeys j05-production (SHUN_R02V_PHYSICAL=1)   EXIT=0 (4/4)
vitest ... r02-v-journeys journeys-composite (SHUN_R02V_PHYSICAL=1) EXIT=0 (1/1)
vitest ... r02-v-journeys j09-production (ungated, CI-safe)      EXIT=0 (5/5)
```

## J02 — production chain (R03-F01 acceptance)

`j02-production-chain.test.ts`: HTTP submit (Host-issued reference pair) → selected K-minted Effect Permit (asserted in the durable k-docs store) → trusted Host binding: real plan/grant records → OS currentness → real grant-presentation validation → **real scoped `windows.fs.write`** in the operator-owned fixture workspace → journal `COMPLETED_VERIFIED` → HTTP 200 COMPLETED with the exact canary bytes on disk. Negatives, all zero filesystem effect: permitless probe intent (K gate), unknown plan hash, EXPIRED grant, forged reference pair (pre-send). Fail-closed boot: journey routes without the trusted windows binding refuse activation.

## J05 — production chain (R03-F02 acceptance)

`j05-production-chain.test.ts`: HTTP first-use → K permit → real staged **ripgrep 14.1.1** execution (`VERSION_PROBE` + FILE_SEARCH canary, merged into one terminal receipt) through the production `shun-provider-host` binding over the operator-pinned curator roots/cache root. Negative: wrong task identity refuses with zero execution; fail-closed boot without the binding.

## J09 — production chain (R03-F02 acceptance)

`j09-production-chain.test.ts` (runs on CI too): genuine guided decision on the real `HostGuidedService` SQLite store → trusted composition records the receipt digest + explicit opt-in → HTTP feedback → K permit → REAL durable `HostMetaShadowStore` candidate (`FUTURE_BUILD_SHADOW`, `active:false`), read back through a fresh store instance (restart durability). Negatives: unknown Case refuses with nothing persisted; forged reference pair refuses pre-send; fail-closed boot. **No promote API exists anywhere; future-BUILD promotion stays an explicit operator decision.**

## Composite proof

`journeys-composite.test.ts` (separate vitest file for clean module globals): ONE selected DomainApp carrying goal + windows + provider + meta route families, each backed by its real binding, with one REAL scoped effect submit through the same reference-authenticated surface.

## Q01 — docs synchronized

- `docs/guide/v0.3/README.en.md` / `README.zh-CN.md`: status now states the exact-SHA CI-verified subset (real B-040, loopback HTTP truth, paid J03 budget-exhausted, R03-INT journey routes) and explicitly withholds release approval; "not yet runtime-qualified" wording replaced by the precise verified-subset statement.
- `j03-live-cloud.test.ts` header: ceiling 8 (amendment R1) and 1024-token budget synced; do-not-rerun note added.

## Non-waivers

No paid DeepSeek call was made by this repair (J03 evidence untouched beyond the header comment). No merge, no tag/release, no `main`/`version/v0.2.0` change. UNKNOWN is never PASS. Independent R03 reassessment (separate ChatGPT session) still required.

[#259]: https://github.com/kaicreator-mm/shun-assistant/issues/259
