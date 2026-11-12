# Shun DKE R14 — current source-aligned 75-SAP admission intake

Main: [shun-assistant #411](https://github.com/kaicreator-mm/shun-assistant/issues/411). Cross-project: DIE #8 and #9.

**Current authoritative candidates** (not formal qualifications):
- [R13 exact-source 75-SAP Owner/Oracle packet](./OWNER_ORACLE_75_SAP_ADJUDICATION_R13.json), Blob `dc7a851e9b542809b5876940cb56fc7a79bbbed9`.
- [R14 project Owner-delegated scope ledger](./PROJECT_OWNER_DELEGATED_SCOPE_DECISIONS_R14.json), Blob `a6a1cb178b01fe3ee7fa0ec04d8250fd26b071eb`.
- Original DKE knowledge `COMPUTER_ASSISTANT_KNOWLEDGE_R0.json` Blob `da8425d82f3725c10bce92d206bbb8adfd6e7169`, maintained in source PR #414 at `d6df57422b8a329e8fcfbad1146c86740978db70`.
- Downstream #415 demand matrix/verifier pinned to that exact knowledge Blob and commit, with native integration negative checks. No Product/L1/Windows Host/source identity change outside the knowledge dossier.

**P2-SEM-R12-01 correction:** `CA-NETWORK` still has no Source-backed domain Claim and CQ-CA-010 remains unqualified. Three SAP obligations now cite **only** original Product policy boundary sources (freeze/PRD/L1); former disk/WinGet/PnP/storage implementer and external links are not network expertise. Direct `EXT-PHYSICAL-DISK` impact on SAP rows changes **58 → 55**, removing three false direct network dependencies. Shared Global/Root dependency effects remain independent and must be adjudicated; do not infer all transitive edges are unaffected.

**P2 R12-416 label correction:** Research decision execution-label output is now issued *inside* the exact pinned candidate wrapper, never from an arbitrary caller-supplied object. UNKNOWN emits no-rule-execution. Existing R11 7+4 research tests must run on the new full CI SHA.

**Machine gate:** `tests/integration/dke-network-sap-source-scope.test.mjs`, `dke-demand-source-repin-r13.test.mjs`, `dke-sap-source-ledger-r14.test.mjs` are part of the actual existing Node workspace integration suite. These provide structural/exact-source regression evidence only; they do **not** establish the trustworthiness of 24 mutable publisher URLs or a semantic Oracle.

Formal standings intentionally unchanged: original Source Owner/qualified domain Oracle 0, independent K5/SAP qualified 0/75, Global 0/19, DIE #8 B5 signed 0/70; Product CA-JOB-16 NOT_ADMITTED, production DIS/ECP/AOT 0, true CA-JOB-02 Windows→Function→user-verified closure 0. External licenses, original publisher bytes/build applicability and live Host witnesses must be obtained separately. Nothing authorizes effectful Windows mutations, merge or release.
