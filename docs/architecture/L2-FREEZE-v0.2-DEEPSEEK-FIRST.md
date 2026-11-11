# Shun Assistant v0.2 — L2 Architecture Freeze (DeepSeek-first)

> **L2_FREEZE=PASS** — explicit controller architecture terminal, **not** a claim that v0.2 production code, real API privacy controls, Windows host matrix, Task DAG or Release have passed. No changes to the reviewed L2/DAG candidate blobs are permitted under this record. 2026-10-14.

## 1. Exact normative authority

| Pin | Immutable identity |
| --- | --- |
| Repository / target | `kaicreator-mm/shun-assistant` / `version/v0.2.0` |
| Historical Product PRD | `docs/product/PRD-v0.2.md` blob `68cf2fcec919dedd9ce61339b81f60855404fb12` |
| Effective Product scoped re-freeze | `docs/product/PRODUCT-REFREEZE-v0.2-DEEPSEEK-FIRST.md` blob `46d35708688663943868b556c0b8b298f609488a`; PR #96, #92 independent Product PASS |
| Reviewed L2 source PR | #100 at source HEAD `c33357bef6b22cb13ccd8692c05cd64f4c8cf635` |
| Reviewed source Git tree | `8ae5c4e1b8be97af3e837b9b9a6b6a4f7103cd65` |
| Integration HEAD / tree | `37cecc0cd2300d7e380981892c819241cc3f74f4` / `8ae5c4e1b8be97af3e837b9b9a6b6a4f7103cd65` |
| **Normative frozen L2 architecture candidate** | `docs/architecture/L2-v0.2-CANDIDATE.md` blob `f23a6c44374ab49d84e608693d7793d294c88258` |
| **Normative frozen L2 contract decisions** | `docs/architecture/L2-v0.2-CONTRACT-DECISIONS.md` blob `c286e48441089ddafd9b6aecaae86ad667a5ba8b` |
| Reviewed DAG draft, not yet frozen | `docs/planning/task-dag-v0.2-DRAFT.md` blob `31574f9767a4e8a8a5f413f02064d52de079f601` |
| Independent review | [#98](https://github.com/kaicreator-mm/shun-assistant/issues/98) R1 `NEEDS_REVISION P1=2 P2=2`, R2 independent terminal comments `6169712832` and `6169982622`: `PASS P0=0 P1=0 P2=0`, R1 findings all CLOSED, `L2_FREEZE_ELIGIBLE=YES`; source SHA, tree, 3 blobs pinned |

This is the **separate L2 freeze authority record after reviewed exact-source R2 PASS**. The reviewed source bytes are normative for this version's architecture, despite their historical `CANDIDATE` filenames and internal `L2_FREEZE=NO` pre-freeze status strings. **Interpret those strings as the documents' captured prior review state**; this terminal controls their frozen status, without rewriting reviewed blobs or moving review SHA. Changed architecture requires new successor + review, never silent edits.

## 2. Frozen architectural choices / P0 guardrails

- **Real DeepSeek API P0**, `deepseek-flash` with `https://api.deepseek.com` in a trusted backend only; locally installed model/Ollama `T02` deferred and unshipped. True `LOCAL_HOST_ATTESTED` remains unavailable. Existing deterministic native features work without model calls.
- **Consent authority:** `GoalRequest.policyContext.privacyPolicy` is user/client intent, **never approval**. A Shun-owned interactive broker uses a session-authenticated private channel, nonce, principal/session/task, visible disclosure projection SHA and provider/model/destination binding; public localhost HTTP cannot self-issue consent. Threat assumptions exclude compromised broker/OS session; no false cryptographic physical-presence guarantee.
- **Transactional cost/disclosure:** durable atomic `maxCalls` and worst-case cost reservation against registry/currentness/revocation; exact serialized outbound disclosure projection verified at send, at most one send for `maxCalls=1` under concurrency, no blind retry/refund of `UNKNOWN_COST/MAY_HAVE_SENT`.
- **No-call negatives:** LOCAL_ONLY, offline, forbidden/unconfirmed disclosure, stale policy/registry, unsupported destination, exhausted cost, missing backend key, forged broker/client consent, payload drift all refuse before HTTP. Never send key to generated scripts/optional Provider/child env; no raw content by default.
- **Proposal only:** model outputs have zero execution authority. Deterministic Resolver, ActionController, R2 approval/effect currentness, independent verification/recovery and immutable exact Recipe revision remain mandatory. Recipe replay makes zero LLM calls.
- **Safe public surface:** replace v0.1 hardcoded `localOnly:true` with truthful per-task remote posture; sanitize both thrown and nonthrow `Outcome.detail`, `ControlError`, rejected proposals, persisted receipts, snapshots and UI.
- **Providers/Windows:** pinned signed curated JIT Provider; local fixed-disk SQLite WAL authoritative state, native Windows diagnostics and scoped file effects, ordinary Standard User Windows Home/Pro, portable packaging. #85/#86/#87 pilot evidence is limited and never a product Release PASS.

## 3. Exact bounded review closure

- #98 R1 P1-01 (forged local consent) **CLOSED at contract** by §2.5; P1-02 (atomic spend & payload digest) **CLOSED at contract** by §2.6.
- #98 R1 P2-01 (all error surfaces) **CLOSED at contract** by §2.7; P2-02 (obsolete optional LOCAL pilot gate) **CLOSED at contract**.
- Fresh R2 separately confirmed 11 draft tasks, 26 DAG edges, zero cycles/unknown IDs, distinct write owners; does **not** itself execute Task DAG Freeze.
- Authenticated private broker, atomic transaction, concurrent refusal, real API CN+EN positive and zero-call negatives, native/packaging/release acceptance are **T00/T01/T08/T10/T11 future tests**, not evidence already executed.

## 4. Terminal and handoff

```ini
PRODUCT_SCOPED_RE_FREEZE=PASS_PR96
L2_INDEPENDENT_EXACT_SHA_REVIEW=#98_R2_PASS_P0_0_P1_0_P2_0
L2_ARCHITECTURE_FREEZE=PASS
FROZEN_L2_SOURCE_HEAD=c33357bef6b22cb13ccd8692c05cd64f4c8cf635
FROZEN_L2_SOURCE_TREE=8ae5c4e1b8be97af3e837b9b9a6b6a4f7103cd65
FROZEN_L2_CANDIDATE_BLOB=f23a6c44374ab49d84e608693d7793d294c88258
FROZEN_L2_CONTRACT_BLOB=c286e48441089ddafd9b6aecaae86ad667a5ba8b
REVIEWED_DAG_DRAFT_BLOB=31574f9767a4e8a8a5f413f02064d52de079f601
TASK_DAG_FREEZE=NO
IMPLEMENTATION_P0=0_OF_11
RELEASE_QUALIFICATION=NO
```

**Next:** separate explicit 11-node Task DAG Freeze and GitHub Issue materialization after this authority record merges and required checks pass. Each implementation PR follows one concern/one write owner and independent review where security-sensitive. A PR CI PASS never equals Release PASS.
