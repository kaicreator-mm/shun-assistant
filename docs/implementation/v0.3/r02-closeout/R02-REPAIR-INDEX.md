# R02 repair index — Issue #259 findings × final disposition

**As of 2026-11-06.** This is the R02 closeout index and R03 readiness handoff. It is not an independent R03 PASS, a final version integration, or a release certificate.

## Exact candidate and branch state

| Item | Exact current state |
|---|---|
| WIP candidate | \`wip/v0.3.0-r02-owner-repairs\` @ \`47ecf345c4b96befd20db5c6d5673bbeaf027e49\` |
| WIP tree | \`8aff803fc2f80e9b683be3d5e8abea747c6677ea\` |
| WIP integration PR | #272, open/unmerged; head is the current WIP ref |
| Version ref | \`version/v0.3.0\` @ \`91420edca44009aa2c984c876104b40814a7c265\` |
| Version tree | \`ea1557a1159c1f1eec458c297acaf491ce5157b8\` |
| Final version merge | **NOT CREATED**; PR #272 has not been merged |
| Frozen R02 Task Pack | \`docs/planning/v0.3/R02-REPAIR-TASK-PACKS-R1.json\` blob \`93247874e37d492b49f241d294017fd2fa6cb431\` |
| ADS revision | \`2c395c55569fe2edf3f4135f12d3d069e526d0b7\` |

The current WIP candidate contains the integrated R02-A/B/C1/C2/D1/D2/D3/E work and the previously integrated R03-INT/R03B/R03C work. The version branch remains at its planning/freeze base. Do not describe the WIP SHA as a final version SHA.

## R02 task closure and dependency state

- **9/10 R02 Task Issues are CLOSED:** #262–#270.
- **#271 R02-R is the sole remaining R02 Task**, now admitted under generation-2 Claim #6683774019 after #270 closed.
- Native dependency chain is satisfied: #271's only \`blocked_by\` entry is #270, whose state is CLOSED. No open native blocker remains.
- The previous #271 generation-1 Claim (#6547910751) is terminal at #6549001838 and is not reused.
- The generation-2 closeout pack is PR #378, exact HEAD \`d04c384244fd2ece0773f9cdd74247f773ccb700\`, tree \`706b489f9e72f2e31cb3f2a2357a9d59e17a792f\`, one manifest path directly parented to the WIP base. Pack CI: Woodpecker Push #518 / PR #519 and Actions contracts #42209871640 / executor-windows #42209871579 all SUCCESS.

## Finding disposition — F01–F06 and Q01–Q06

| Finding | Task | Delivery / integration record | Review and exact verification | Residual |
|---|---|---|---|---|
| F01 production route | #269 R02-E | Source PR #375, source HEAD \`228d2de0b40c0d983bd96683e5a5766e28559ee0\`; squash-integrated to WIP as \`47ecf345c4b96befd20db5c6d5673bbeaf027e49\` | PR #374 review #5795788381 PASS; Push #499 SUCCESS; original PR event #500 was clone-only network failure (qualification NOT_RUN); one same-SHA retry #501 completed clone + full qualification SUCCESS; Actions contracts #42176394537 and executor-windows #42176394504 SUCCESS | J07/J08 positive selected-production trust/BUILD path remains UNKNOWN; see below |
| F02 Guided backend | #263 R02-B + #269 | Source PR #346 HEAD \`7a4566ec1e42836a7a4d2ba43a032f23e3f45972\`; WIP integration PR #347 merge SHA \`39e4f85f3fa01d9f4b20ba73adcf79cbc42707f5\` | Independent R2 #6639449322 PASS; source Woodpecker #361/#363 SUCCESS; WIP integration #366/#367 SUCCESS | Service/provider layer is complete; production trust injection belongs to #269 and is integrated |
| F03 same-BUILD activation | #262 R02-A | Claimed WIP delivery checkpoint \`41cbefe5b2fd20bd88bf079e8293512cd7a218b2\`; integrated and reviewed in WIP snapshot \`faaaec8f842fb85d8cf38a5bd04b505a4181e39c\` | Independent review #6625679600 PASS; WIP Push #306 / PR #307 SUCCESS; Actions contracts/executor-windows SUCCESS; real installed public v0.10.3 SDK consumer test 8/8 | No version merge implied |
| F04 Gateway outcome truth | #264 R02-C1 | Direct claimed WIP source commits; final task checkpoint \`41cbefe5b2fd20bd88bf079e8293512cd7a218b2\`; integrated WIP review snapshot \`faaaec8f842fb85d8cf38a5bd04b505a4181e39c\` | Independent review #6625680784 PASS; WIP Push #306 / PR #307 SUCCESS; Actions contracts/executor-windows SUCCESS | No blind retry; COMPLETED/ADMITTED/REFUSED/UNKNOWN remain distinct |
| F05 Host-only provenance | #265 R02-C2 | Direct claimed WIP source commits; final task checkpoint \`41cbefe5b2fd20bd88bf079e8293512cd7a218b2\`; integrated WIP review snapshot \`faaaec8f842fb85d8cf38a5bd04b505a4181e39c\` | Independent review #6625682038 PASS; WIP Push #306 / PR #307 SUCCESS; Actions contracts/executor-windows SUCCESS | Public issuer boundary and durable replay fence delivered |
| F06 real user journeys | #270 R02-V | Evidence PR #377, final HEAD \`1f7d5c7fce4a1b2dfa9ad1cebcac68b317449fa1\`, tree \`2074afcdaa035c480601182c6999b46d1123b851\`, base \`47ecf345c4b96befd20db5c6d5673bbeaf027e49\`; intentionally unmerged per its pack | Final independent R2 PASS #6683020538, P0=0/P1=0/P2=0 open; Push #513 / PR #514 and Actions contracts #42204356849 / executor-windows #42204364512 SUCCESS | J07/J08 overall positive production-path status UNKNOWN; evidence is accurately scoped |
| Q01 historical task labels | Pre-R02 | Issues #229–#241 normalized CLOSED + \`state:done\` | Existing task closeouts retained | None |
| Q02/Q05 operator and Provider documentation | #266 R02-D1 | Source PR #337 HEAD \`dd1f8fc1f6b09ba88c75326d3f1f328111c8820c\`; WIP squash merge SHA \`caaffdbc8d0fbf7eb127f6da53c6a581c2d0651a\` | Source Push #333 / PR #334 SUCCESS; WIP Push #339 / PR #340 SUCCESS; independent closeout #6629133968 | Physical installer/packaging validation is not part of this bounded documentation task |
| Q03 nested CI gate | #267 R02-D2 | Direct claimed WIP commits; task terminal SHA \`41cbefe5b2fd20bd88bf079e8293512cd7a218b2\`; integrated WIP review snapshot \`faaaec8f842fb85d8cf38a5bd04b505a4181e39c\` | Independent review #6625682990 PASS; WIP Push #306 / PR #307 SUCCESS; Actions contracts/executor-windows SUCCESS | Persistent syntax-only preflight follow-up #296 is separate from the frozen D2 acceptance |
| Q04 ABI mirror drift | #262 R02-A | Same BUILD/activation delivery as F03; current WIP contains the public SDK consumer and export-lock result | #6625679600 PASS; #306/#307 and Actions SUCCESS | Historical placeholder BUILD is not a production positive |
| Q06 B-040 UTF-8 | #268 R02-D3 | Direct claimed WIP commits; task terminal SHA \`41cbefe5b2fd20bd88bf079e8293512cd7a218b2\`; integrated WIP review snapshot \`faaaec8f842fb85d8cf38a5bd04b505a4181e39c\` | Independent review #6625684049 PASS; #306/#307 and Actions SUCCESS; real zh-CN Windows J01 caption evidence retained | No physical side effect beyond the previously authorized read-only capture |

“Direct claimed WIP source commits” is intentional: the original bounded R02-A/C1/C2/D2/D3 delivery was committed on the WIP line under its accepted Claims; no separate source PR is asserted where the task record does not identify one. PR #272 is the aggregate WIP-to-version snapshot, not an individual source PR and remains unmerged.

## J01–J09 final evidence reconciliation

The original real journey evidence at #270 comment #6554881727 remains authoritative for the executed J01–J06/J09 journeys. Owner authorization for J02/J03/J05/J09 is recorded at #259 comment #6554453456. No paid or physical journey was repeated merely to refresh this report.

| Journey | Current disposition | Evidence / limitation |
|---|---|---|
| J01 | **PROVEN** | Real Windows 11 zh-CN read-only B-040 caption; \`localOnly=true\`, no external disclosure |
| J02 | **PROVEN** | Bounded operator-owned temp-root write, separate R2 grant, independent poststate verification and journal; no new physical run in G2 |
| J03 | **PROVEN** | Exactly two authorized real DeepSeek CN/EN completions; amended budget use 7/8; no rerun |
| J04 | **PROVEN** | K-fenced recipe replay; no blind resend |
| J05 | **PROVEN** | Real signed ripgrep 14.1.1 first-use, offline reuse/restart verification and zero-residue cleanup; no new install in G2 |
| J06 | **PROVEN** | Durable K document CAS/restart and truthful UNKNOWN semantics |
| J07 | **UNKNOWN overall** | G2 proves the exact shipping runner/demo loopback smoke, static UI asset HTTP response, hostile Host refusal, truthful 503s, loopback-only binding and real-storage missing-trust no-listener refusal on Node 24.21.0/26.13.0. Positive selected-production-BUILD startup was not activated. |
| J08 | **UNKNOWN overall** | G2 proves TEST_FIXTURE-only trust semantics over real SQLite/HTTP, restart/replay/refusal and anchor/database-binding negatives. The positive fixed-ProgramData production trust path was not executed; the harness uses a DemoShunBackend. |
| J09 | **PROVEN** | Real durable Host Shadow candidate persistence, provenance digest, restart and non-promoting behavior; no current-build mutation |

J07/J08 are not promoted to PASS from demo, static-asset or TEST_FIXTURE evidence. The final G2 verifier corrected the matrix and receipt claims; see #270 comment #6683020538 and PR #377. PR #377 remains OPEN/UNMERGED because its own generation-2 pack sets \`merge_authorized: false\` and explicitly forbids WIP/version merge.

## R02-R readiness handoff

- **R02 outcome closure:** #262–#270 CLOSED; #271 is the current closeout task.
- **WIP review candidate:** \`47ecf345c4b96befd20db5c6d5673bbeaf027e49\` / tree \`8aff803fc2f80e9b683be3d5e8abea747c6677ea\`, exact integrated WIP CI Push #499 and same-SHA PR retry #501 SUCCESS, Actions contracts/executor-windows SUCCESS.
- **Version branch:** still \`91420edca44009aa2c984c876104b40814a7c265\`; no final version merge SHA exists. PR #272 remains open/unmerged.
- **R03 review readiness:** **READY_FOR_INDEPENDENT_R03_REVIEW on the exact WIP candidate**, with this index, PR #377 evidence and all J07/J08 UNKNOWNs visible. This is a handoff only, not an R03 PASS.
- **Release readiness:** **BLOCKED**. No version/v0.3.0 merge, final version SHA, R03 approval, tag, release or deployment is authorized or implied.
- Issue #259 remains OPEN.