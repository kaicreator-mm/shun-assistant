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

The frozen Product describes a goal-first assistant that resolves bounded registered capabilities, presents scope/cost/risk, obtains required approval, performs a permitted action and verifies the observable outcome. It explicitly excludes arbitrary LLM-generated scripts, autonomous general desktop operation, unknown Provider marketplaces and unrelated PC-management expansion.

The user's current request authorizes this **knowledge-engineering scope** to study common disk, software and hardware management knowledge. It does not silently amend the frozen Product or make those future capabilities available in Shun. A Product amendment is required before admitting new feature scope.

The method reference is DKE v0.0.1 R2, which is still an Owner-review-pending candidate, not a frozen standard. This R0 therefore remains an author candidate.

## 2. What Shun already has — and what it does not establish

The source-first inventory shows that Shun is not devoid of real computer operations. It has several bounded capabilities. The gap is that these do not yet amount to a complete computer-management assistant.

| Domain | Current source-backed capability | Boundary / gap |
|---|---|---|
| System inventory | Read-only CPU count, memory, fixed system-volume capacity/free space and uptime | Not full hardware inventory, disk topology or storage-health management |
| System diagnosis | Bounded process/startup counts, top-memory observations, limited installed-software sample, low-disk/low-memory advisory | Single-snapshot diagnosis; no root-cause or guaranteed-speedup claim; no process/service control |
| Storage | Scoped storage observation, growth attribution, fail-closed classification, preview, approval, bounded cleanup, journaling and protected-asset verification | Not disk initialization, partition create/resize/delete, volume formatting or disk online/offline management |
| Files | Pure preview for search, duplicate report, copy, move and rename; authorized handle-anchored duplicate observation | Preview is not execution authority; no unrestricted file manager is established by these surfaces |
| Software | Bounded installed-software observation and curated trusted-provider JIT acquisition/use/verification/removal | Not a complete app catalog or general consumer install/update/repair/uninstall manager |
| Hardware / drivers | Windows documentation establishes PnP and driver-store concepts | No general Shun PnP/device/driver capability was found in the reviewed public domain-computer surface |
| Network | Domain concepts identified for future knowledge coverage | No Shun network-management capability is qualified by this source set |

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

This is not one Element per command or per Function. A child is split further only when it has an independently coherent semantic owner, boundary, CQ set and verification oracle. Semantic relations may cross child Elements; the parent/child ownership hierarchy itself must remain acyclic.

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

The simple rule is: **compile how to understand and safely reason about a computer; observe what this computer is like now; authorize each real effect at runtime.**

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

The machine-readable dossier contains 14 CQs spanning goal resolution, provider/environment binding, system diagnosis, storage cleanup, disk topology, software lifecycle, residue preservation, hardware/driver management, process/service boundaries, network diagnosis, AOT/runtime separation, recovery, privacy and platform claims.

Current status is deliberately conservative:

- K1: source inventory pinned by the author.
- K2: claims and relations are an author candidate.
- K3: recursive Element blueprint and CQs are an author candidate.
- K4: independent review has **not** run.
- Native Windows tests were **not** executed in this DKE turn; test source files are not execution receipts.
- SAP is **not qualified**.
- DIS handoff is **blocked**.
- No runtime implementation or AOT Package was created.

Hardware/driver and broader disk-management semantics still require stronger domain oracles, Product admission and real Windows evidence. Microsoft Learn sources establish the existence and administrative/destructive nature of relevant Windows operations, not Shun implementation or authorization.

## 7. Next gates

1. Fresh independent Source-First review of the exact PR HEAD. The Reviewer must read frozen Product and original Code/Test sources before this dossier, freeze an independent Stage-0, then compare claims, relations, Element boundaries, negative cases and AOT/runtime separation.
2. Repair only verified P0/P1/P2 findings; re-review the final exact SHA. Builder self-review is not independent PASS.
3. Execute native Windows tests only where real Windows filesystem, package-manager, device-manager or Host behavior is material. Record the actual command, environment and exit code; skipped tests are not PASS.
4. Obtain explicit Product amendment before treating partition/format, general software management, hardware/device/driver management or network administration as supported Shun features.
5. After SAP and Product admission, open a separate DIS task to functionize selected Elements and qualify ECP/AOT Package consumption.

## 8. External source locators

Official Microsoft Learn sources used as external knowledge locators (link-only; licensing and domain-owner adoption have not been independently qualified in this DKE):

- [Disk Management overview](https://learn.microsoft.com/en-us/windows-server/storage/disk-management/overview-of-disk-management)
- [Initialize new disks](https://learn.microsoft.com/en-us/windows-server/storage/disk-management/initialize-new-disks) — initialization is intended for a new disk with no existing data; the process erases data and requires elevated membership.
- [Windows Storage PowerShell module](https://learn.microsoft.com/en-us/powershell/module/storage)
- [WinGet overview](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
- [WinGet list](https://learn.microsoft.com/en-us/windows/package-manager/winget/list)
- [WinGet upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade)
- [WinGet uninstall](https://learn.microsoft.com/en-us/windows/package-manager/winget/uninstall)
- [Get-PnpDevice](https://learn.microsoft.com/en-us/powershell/module/pnpdevice/get-pnpdevice?view=windowsserver2025-ps)
- [Enable-PnpDevice](https://learn.microsoft.com/en-us/powershell/module/pnpdevice/enable-pnpdevice?view=windowsserver2025-ps)
- [Disable-PnpDevice](https://learn.microsoft.com/en-us/powershell/module/pnpdevice/disable-pnpdevice)
- [pnputil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pnputil)
