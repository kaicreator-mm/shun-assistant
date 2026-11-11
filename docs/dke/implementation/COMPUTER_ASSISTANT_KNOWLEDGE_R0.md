# Shun Assistant Computer Assistant Domain Knowledge — R0

**Output:** `SHUN_ASSISTANT_DKE_COMPUTER_ASSISTANT_KNOWLEDGE_R0`  
**Status:** `AUTHOR_CANDIDATE_NOT_INDEPENDENTLY_QUALIFIED`  
**Master issue:** [#411](https://github.com/kaicreator-mm/shun-assistant/issues/411)  
**Prior bounded pilot:** [PR #412](https://github.com/kaicreator-mm/shun-assistant/pull/412)  
**Knowledge record:** [COMPUTER_ASSISTANT_KNOWLEDGE_R0.json](./COMPUTER_ASSISTANT_KNOWLEDGE_R0.json)

## 1. Objective and authority boundary

This DKE candidate solidifies the knowledge needed by a Windows-first computer assistant: computer objects, capabilities, provider/environment compatibility, risk and permission semantics, execution lifecycle, verification/recovery, and the boundary between AOT knowledge and live runtime facts.

It is a knowledge model, not an implementation plan disguised as a capability list.

The exact Product authority remains the v0.3.0 Product/L1 freeze:

- Product reviewed source commit: `4c2f8e84b6e6f3f5b526e52d01356159f2dce0e7`
- Product blob: `f062b7f2c3dc3bf4aeeb7594ab5c2bc75b34d0ab`
- L1 parity blob: `4c703c3f0c283f4d3918babef8f87f56869698e5`
- Freeze checkpoint blob: `0f8a67c2f06364d58a842502d3dee11bfeeedba4`
- Current observed implementation snapshot: `version/v0.3.0@1224fea4097799467e2c0c454885e680f1f28248`

The frozen Product describes a goal-first assistant that resolves bounded registered capabilities, presents scope/cost/risk, obtains required approval, performs a permitted action and verifies the observable outcome. It explicitly excludes arbitrary LLM-generated scripts, autonomous general desktop operation, unknown Provider marketplaces and unrelated PC-management expansion. The same freeze checkpoint records IMPLEMENTATION_AUTHORIZED=NO, SOURCE_SCAFFOLD=NOT_AUTHORIZED, L2_FREEZE=NO, TASK_DAG_FREEZE=NO and RELEASE_READY=NO; therefore the inspected code branch is source evidence, not Product implementation authorization or release qualification.

The user's current request authorizes this **knowledge-engineering scope** to study common disk, software and hardware management knowledge. It does not silently amend the frozen Product or make those future capabilities available in Shun. A Product amendment is required before admitting new feature scope.

The method reference is DKE v0.0.1 R2, which is still an Owner-review-pending candidate, not a frozen standard. This R0 therefore remains an author candidate.

## 2. What Shun already has — and what it does not establish

The source-first inventory shows that Shun is not devoid of real computer operations. It has several bounded capabilities. The gap is that these do not yet amount to a complete computer-management assistant.

| Domain | Current source-backed capability | Boundary / gap |
|---|---|---|
| System inventory | Read-only CPU count, memory, fixed system-volume capacity/free space and uptime | Not full hardware inventory, disk topology or provider-backed storage-health diagnosis |
| System diagnosis | Bounded process/startup counts, top-memory observations, limited HKLM installed-software sample, low-disk/low-memory advisory | Single-snapshot diagnosis; no root-cause or guaranteed-speedup claim; no service inventory/dependency model or process/service control |
| Storage | Scoped storage observation, growth attribution, fail-closed classification, preview, approval, bounded cleanup, journaling and protected-asset verification | Not disk initialization, partition create/resize/delete, volume formatting, disk online/offline or provider-backed health management |
| Files | Pure preview for search, duplicate report, copy, move and rename; authorized handle-anchored duplicate observation | Preview is not execution authority; no unrestricted file manager is established by these surfaces |
| Software | Bounded HKLM installed-software observation and curated trusted-provider JIT acquisition/use/verification/removal library | Not a complete app catalog or general consumer install/update/repair/uninstall manager; Domain Computer T08 Provider JIT is proposal-only/T11-wiring-only |
| Hardware / drivers | Microsoft documents PnP enumeration, device enable/disable and driver-store operations | No general Shun PnP/device/driver capability, OEM compatibility contract or rollback implementation is admitted |
| Network | Domain concepts identified for future knowledge coverage | No Shun network-management capability is qualified by this source set |
| Domain Computer orchestration | Typed goal/capability selection, selected-folder read-only observation, B-040 support-context minimization, one-step Guided Journey, Recipe proposals, Provider JIT proposals and opt-in Meta Shadow candidates | These are bounded adapters/proposals, not proof of complete UI/Host composition or real OS effects; no adapter itself grants authority |

Important distinctions:

- Low disk space is an observation; it is not permission to delete data.
- Storage cleanup is not partition management.
- An installed-software sample is not a complete software inventory.
- Curated Provider JIT lifecycle is not a general-purpose package manager.
- A PnP command documented by Microsoft is not automatically a Shun capability.
- A preview, plan, approval label or model answer is not proof that an effect occurred.

## 3. Proposed recursive Element model

The selected author candidate is a hybrid recursive model: one root, cohesive child Elements and explicit global-semantic Elements.

```text
ComputerAssistantDomain (ROOT)
├── Goal & Capability Resolution
├── System Observation & Diagnosis
├── Storage (disk / partition / volume / filesystem / cleanup)
├── File & User Asset Management
├── Software Lifecycle
├── Hardware / PnP Device / Driver Stewardship
├── Process & Service Management
├── Network & Connectivity
├── Execution Environment & Provider Binding
├── Task Lifecycle / Effect / Recovery
└── AOT Knowledge Boundary

Global Semantic Elements
├── Source Provenance & Currentness
├── Authority / Permission / Risk
├── Outcome Verification & Recovery
├── Privacy & Disclosure
└── Source / Policy / Host Invalidation
```

This is not one Element per command or per Function. A child is split further only when it has an independently coherent semantic owner, boundary, CQ set and verification oracle. Semantic relations may cross child Elements; the parent/child ownership hierarchy itself must remain acyclic. The Root requires a dedicated cross-Element closure CQ; no Child or Global Semantic Element can independently establish Root SAP.



### 3.1 Separate hierarchy and semantic relation graphs

The ownership hierarchy is a separate 16-edge graph: 11 Child Elements and 5 Global Semantic Elements belong to `CA-ROOT`. These edges are recorded under `decomposition.hierarchyEdges`, not mixed into the cross-Element semantic `relations` array. The semantic relation graph contains 14 source-scoped assertions. Each Element now carries explicit `relationRefs`, `globalInvariantRefs` and `cqRefs`; each of the 13 Global Invariants lists its exact `appliesTo` Elements and CQ coverage. This is a structural closure map, not a semantic PASS.

## 4. AOT knowledge: what should be compiled

AOT is useful for stable domain knowledge that would otherwise be repeatedly rediscovered by an LLM. Candidate content includes:

- Computer object ontology: disk, partition, volume, filesystem, file, process, service, software package, hardware device, driver, network adapter, IP, route and DNS.
- Stable Windows semantics and command behavior, pinned to official source revisions and supported OS ranges.
- Capability descriptions, preconditions, postconditions, known refusal cases and unsupported combinations.
- Diagnostic decision trees and the evidence required before attributing a cause.
- Risk classifications, protected-asset precedence, permission boundaries and non-entailment rules.
- Provider provenance, package identity, install-manifest and residue semantics.
- Verification, interruption, reconciliation and recovery patterns.
- Common workflows/Recipes only after Product, SAP and DIS/ECP gates qualify them.

AOT must **not** compile:

- Current disk topology, device instances, driver versions, installed software, process/service state or network state.
- Current ACLs, user/session identity, UAC outcome, privilege tokens, approvals, permits or Host authorization.
- User files, personal paths, document contents, credentials, API keys, Wi-Fi secrets or other private state.
- Live provider signatures/revocation state, source reachability or execution receipts.

The simple rule is: **compile how to understand and safely reason about a computer; observe what this computer is like now; authorize each real effect at runtime.** Source/platform/provider/policy/host changes must invalidate exactly the affected knowledge and consumers; unrelated siblings must remain current.

DKE defines the knowledge and SAP obligations. DIS must separately decide Functionization, ECP, dependency/Target binding and actual AOT Package production. No Package is created by this PR.

## 5. Global semantic invariants

1. Observation is not authorization.
2. LLM output is an untrusted proposal, never a permission or grant.
3. Destructive or privileged effects require exact target identity, current scope, explicit approval and trusted Host authorization.
4. Unknown or user-created files are retained; size or location alone never proves disposability.
5. Disk initialization/partition/format operations are blocked when target identity, existing-data state or backup state is unknown.
6. Software and driver acquisition require exact package identity and trusted source/provenance.
7. Device mutation requires exact device-instance identity and runtime privilege checks; driver changes additionally require compatibility, rollback and post-change verification evidence.
8. Success requires independent observable post-state verification. An exit code, UI label or model claim is insufficient.
9. An ambiguous/interrupted effect remains UNKNOWN and must be reconciled before retry.
10. Local-only support context is not automatically sent to an LLM, Meta, network or external issue reporting.
11. AOT contains stable, source-pinned knowledge, never live host state or authority.
12. Source, OS, provider, policy or host changes invalidate affected knowledge and consumers.

## 6. Competency Questions and SAP

The repaired machine-readable dossier contains 20 CQs spanning goal resolution, provider/environment binding, system diagnosis, storage cleanup and health, disk topology, software lifecycle, residue preservation, hardware/driver management, process/service boundaries, network diagnosis, AOT/runtime separation, recovery, privacy, Root cross-Element closure, source-currentness invalidation and external-document non-entailment.

Current status is deliberately conservative:

- K1: 70 internal source records (37 code, 28 test definitions, 3 Product authority/evidence plus 2 related DKE/method context records) and 13 Microsoft Learn external locators pinned by the author; exact original Code/Test Blobs are checked against the immutable source tree.
- K2: claims and relations are an author candidate.
- K3: 17 Root/Child/Global-Semantic Elements, 14 semantic relations, 13 global invariants and 20 CQs are an author candidate; all 17 Elements now have explicit structured SAP profiles. Each obligation has a stable ID, source/relation/invariant/CQ references, positive/negative/UNKNOWN cases, oracle classes and a NOT_RUN state.
- K4: independent review has **not** run.
- Native Windows tests were **not** executed in this DKE turn; test source files are not execution receipts.
- A mechanical author check confirms unique IDs, resolved source/Element references, acyclic hierarchy, 17/17 SAP obligation coverage, maturity labels and external-source applicability fields. This is not a semantic or independent review.
- SAP is **not qualified**: 17/17 profiles and their individual obligation contracts are present, but every Element/Root remains unqualified: all obligations are NOT_RUN/NOT_QUALIFIED pending fresh review of the repaired SHA, applicable native/domain oracles and Owner acceptance.
- DIS handoff is **blocked**.
- No runtime implementation or AOT Package was created.

Hardware/driver, provider-dependent storage health, network and broader disk-management semantics still require stronger domain oracles, Product admission and real Windows evidence. Microsoft Learn sources establish only documented Windows operations and their applicability, not Shun implementation or authorization. The PnPDevice PowerShell pages are rendered under the Windows Server 2025 documentation view and do not provide an explicit Windows 10/11 client applicability matrix; client support remains UNKNOWN until verified.

## 7. Owner decisions and platform applicability

No Product Owner decision is required to repair this documentation-only DKE candidate. An explicit Product amendment is required before partition/format, general software management, PnP/device/driver mutation, process/service mutation, network administration, WSL, remote, sandbox or cloud execution becomes a supported Shun feature. Hardware/driver semantics require an OEM or hardware-domain oracle; storage-health semantics require a Windows Storage Management Provider/storage specialist; network semantics require a network-domain oracle.

Current execution scope remains local Windows-first. Linux/macOS are future knowledge targets only; WSL, remote administration, sandbox and cloud execution are not current Product targets. External Microsoft Learn pages are mutable link-only locators observed on 2026-11-11; the dossier records their documented OS/version applicability or an explicit UNKNOWN boundary, and they must be rechecked before runtime use.



### Windows client servicing is separate from command compatibility

As observed on 2026-11-11, Microsoft's supported-client table records Windows 10 Home/Pro 22H2 (build 19045) as end-of-updates on 2025-10-14; Windows 11 Home/Pro 24H2 (build 26100) ended updates on 2026-10-13; Windows 11 Home/Pro 25H2 (build 26200) and 26H2 (build 26300) remain within their published servicing windows. WinGet's Windows 10 1809+ statement is a client compatibility minimum, not a servicing-support guarantee. Every runtime binding must check exact edition, release, build, architecture and servicing/ESU status. This remains Microsoft platform knowledge only and does not admit any Shun feature.

## 8. Next gates

1. Fresh independent Source-First review of the exact PR HEAD. The Reviewer must read frozen Product and original Code/Test sources before this dossier, freeze an independent Stage-0, then compare claims, relations, Element boundaries, negative cases and AOT/runtime separation.
2. Repair only verified P0/P1/P2 findings; re-review the final exact SHA. Builder self-review is not independent PASS.
3. Execute native Windows tests only where real Windows filesystem, package-manager, device-manager or Host behavior is material. Record the actual command, environment and exit code; skipped tests are not PASS.
4. Obtain explicit Product amendment before treating partition/format, general software management, hardware/device/driver management or network administration as supported Shun features.
5. After SAP and Product admission, open a separate DIS task to functionize selected Elements and qualify ECP/AOT Package consumption.

## 9. External source locators

Official Microsoft Learn sources used as external knowledge locators (link-only; licensing and domain-owner adoption have not been independently qualified in this DKE):

- [Disk Management overview](https://learn.microsoft.com/en-us/windows-server/storage/disk-management/overview-of-disk-management)
- [Initialize new disks](https://learn.microsoft.com/en-us/windows-server/storage/disk-management/initialize-new-disks) — initialization is intended for a new disk with no existing data; the process erases data and requires elevated membership.
- [Windows Storage PowerShell module](https://learn.microsoft.com/en-us/powershell/module/storage/?view=windowsserver2025-ps) — the current locator is a Windows Server 2025 PowerShell view; verify module/cmdlet/provider availability on the exact target client.
- [Get-PhysicalDisk](https://learn.microsoft.com/en-us/powershell/module/storage/get-physicaldisk?view=windowsserver2025-ps) — `HealthStatus` is provider-dependent telemetry, not a universal SMART oracle.
- [WinGet overview](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
- [WinGet list](https://learn.microsoft.com/en-us/windows/package-manager/winget/list)
- [WinGet upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade)
- [WinGet uninstall](https://learn.microsoft.com/en-us/windows/package-manager/winget/uninstall)
- [Get-PnpDevice](https://learn.microsoft.com/en-us/powershell/module/pnpdevice/get-pnpdevice?view=windowsserver2025-ps)
- [Enable-PnpDevice](https://learn.microsoft.com/en-us/powershell/module/pnpdevice/enable-pnpdevice?view=windowsserver2025-ps)
- [Disable-PnpDevice](https://learn.microsoft.com/en-us/powershell/module/pnpdevice/disable-pnpdevice?view=windowsserver2025-ps)
- [pnputil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pnputil)
- [Supported versions of Windows client](https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client) — exact edition/release/build and end-of-updates dates; tool/API compatibility is not OS servicing support.


## 10. Repair reconciliation (R0 review repair)

- Added module-level Domain Computer and B-040 support-context source/test Blob pins; explicitly distinguished observation/proposal adapters from real effects and authority.
- Added missing Storage classification/scope/observation/verification sources and tests, and JIT curated-provider/provenance/lifecycle tests.
- Added explicit maturity labels to all Claims and Elements; clarified that WSL, remote, sandbox and cloud execution are not current Product targets.
- Added OS/version applicability or explicit UNKNOWN applicability to each Microsoft Learn locator.
- Completed structural SAP obligations for all 17 Elements, added Root closure, source-currentness, storage-health and external-document non-entailment CQs, and moved the cross-domain protected-asset invariant to Global Authority.
- These are documentation repairs only. No Product, runtime code, permission, implementation authorization, native test execution or SAP qualification is claimed.


## 11. Fresh Source-First Review + documentation repair reconciliation (2026-11-11)

OUTPUT_LABEL=`SHUN_ASSISTANT_DKE_R0_POST_REPAIR_FRESH_EXACT_SHA_REVIEW`

- Stage-0 was rebuilt from the frozen Product Freeze/PRD/L1 and original `version/v0.3.0@1224fea4097799467e2c0c454885e680f1f28248` Code/Test sources before reading the final JSON/Markdown. All 37 Code and 28 Test Blob pins matched the immutable source tree exactly (65/65, zero mismatch).
- **P1 hierarchy/semantic graph separation:** the old `CA-REL-001 HAS_SEMANTIC_CHILD` was a hierarchy edge and only represented Root→Goal while the ownership hierarchy contained 16 edges. It was removed from semantic relations; all 16 ownership edges are now recorded separately. A source-grounded FileAsset→GlobalAuthority semantic relation was added, preserving 14 semantic relations.
- **P1 global-invariant closure:** each of 13 invariants now declares exact `appliesTo` Elements and CQ refs; each of 17 Elements carries relation/invariant/CQ cross-references. Root references all 13 global invariants.
- **P1 SAP sufficiency:** all 17 SAP profiles now contain stable per-obligation IDs, source/relation/invariant/CQ refs, positive/negative/UNKNOWN cases, oracle classes and NOT_RUN/NOT_QUALIFIED states. Added CQ-019 for FileAsset, which previously had no dedicated CQ. Added CQ-020 for Windows client servicing currentness. This repairs contract structure, not SAP qualification.
- **P2 stale K1 count:** corrected to 70 internal records, 13 external locators and 65 exact Code/Test Blob pins.
- **P2 OS servicing:** added the Microsoft supported Windows client versions locator and separated command/API compatibility from servicing lifecycle. Exact target host version remains required.

P0=0; P1=3 found/3 repaired; P2=2 found/2 repaired. All CQs remain OPEN or CONDITIONAL and NOT_RUN; Root and all SAP profiles remain NOT_QUALIFIED. Native Windows execution remains NOT_RUN. No Product, runtime code, permission, AOT Package, merge or release was changed or authorized. A fresh independent reviewer must review the post-repair exact SHA; this repairer's structural checks are not an independent PASS.
