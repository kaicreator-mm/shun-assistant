# R02 repair index — Issue #259 findings × disposition

Branch `wip/v0.3.0-r02-owner-repairs` (PR #272, DRAFT). This index maps every
F/Q finding to its bounded implementation, tests and remaining gaps. It is a
repair index, **not** an independent R03 review, release qualification or
merge consent.

## Admission state (materialized 2026-11-01, before any source write)

- Native GitHub `blocked_by` edges (9/9) written and read back:
  #269 ← #262/#263/#264/#265; #270 ← #269/#266/#267/#268; #271 ← #270.
- Execution Packs: `.agent/execution/R02-*/MANIFEST.yaml` (10 lanes) at the
  execution-pack commit `710b2dc0090e4bcee32c9b992175e22353525d9e`.
- Accepted CAS Claims: `DISPATCH_CLAIMED` events on #262–#271 (10/10) by
  `zcode:shun-v030-r02-repairs-20261101` under Owner approval #260.
- Pre-Claim WIP on this branch (before `710b2dc`) remains UNQUALIFIED WIP
  and is never attributed to those Claims.

## Finding disposition

| Finding | Lane | Implementation now present | Verification | Remaining gap |
|---|---|---|---|---|
| F01 production route | E #269 | `main.ts` production mode: real operator-pinned manifest → `composeTrustedRuntimeBuild` → installed public v0.10.3 SDK (`buildV10App`/`activateV10App` from the consumer layout, explicit exports-map resolution) → durable SQLite K docs → shipping gateway; boot fails closed without every trusted input | `r02-e-production` 7/7; V suite real HTTP 200/422/503 | J02 physical effect leg OWNER_DEFERRED |
| F02 Guided backend | B #263 + E | `HostGuidedService` (SQLite, atomic single-consumption, restart fence) + `/api/v03/guided/state|decision` routes wired in `server.ts`; default Case Host-pinned | `r02-b-guided`, V suite J08 | multi-step preview→R2 journeys remain data-path only until J02 authorized |
| F03 same BUILD activates | A #262 | Real K/S bytes (v0.10.3 tag, SHA-pinned) + Shun B/C Domain Packages activate through the SAME operator manifest via the REAL public SDK; fake-facade/placeholder/tamper refusals | `r02-a-build` 8/8 over installed consumer | none within zero-effect scope |
| F04 receipt truth | C1 #264 + E | Gateway COMPLETED/ADMITTED/KERNEL_REFUSED/UNKNOWN separation + production seam LLM-status truth layer (trusted refused → refused; unresolved → unknown; never fake success) | `r02-c1-gateway`, `r02-e-production`, V suite HTTP statuses | none |
| F05 issuer isolation | C2 #265 | Public `@shun/domain-computer|domain-host|domain-app` exports locked to single root entry; Host-only durable issuer + SQLite replay fence; restart negatives | `r02-c2-provenance` | cross-process currentness e2e stays in suite scope |
| F06 J01–J09 evidence | V #270 | Executed zero-paid/zero-physical subset on real Windows Node 24 with receipts | `R02-VALIDATION-RECEIPT.md` | J02/J03/J05 OWNER_DEFERRED; J09 UNKNOWN |
| Q01 label hygiene | done pre-R02 | #229–#241 CLOSED + state:done | — | none |
| Q02/Q05 docs | D1 #266 | Bilingual operator/provider guides + README | docs review | installer/packaging physical validation deferred |
| Q03 CI gate | D2 #267 | Woodpecker repo activated (id 35); local-backend Node 24 pipeline: lint+typecheck+all nested suites+fail-closed verifier | `WOODPECKER-CI-RECEIPT.md` | — |
| Q04 ABI mirror drift | A #262 | Legacy placeholder BUILD no longer used by production activation (manifest-driven trusted bytes) | `r02-a-build` | historical T09 composition kept as declaration-only artifact |
| Q06 B-040 encoding | D3 #268 | PowerShell UTF-8 collector + CN regression; real zh-CN caption captured in J01 | V suite J01 receipt | historical V01 JSON untouched |

## Explicitly not done (no authorization)

Paid DeepSeek calls, physical Windows effects, real device actions,
`main`/`version/v0.2.0` mutation, release/Tag, independent R03 review,
closing Issue #259.
