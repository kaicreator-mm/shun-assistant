# Shun Assistant v0.2 — Product scope change: DeepSeek Flash API first

> **PRODUCT_CHANGE_CANDIDATE / THAW_REQUESTED / NOT_YET_RE-FROZEN.** Product Owner directly instructed on 2026-10-14 that v0.2 should use existing DeepSeek API credentials and Flash model rather than require Ollama/local model installations across end-user devices. This is a **material P0 priority/acceptance change** to frozen `docs/product/PRD-v0.2.md`; do NOT rewrite the historical reviewed PRD blob `68cf2fcec919dedd9ce61339b81f60855404fb12` or claim #84 reviewed this successor. Fresh risk-based independent Product review and an explicit revised Product Freeze terminal are required before treating this candidate as authoritative.

## 1. Replacement decisions (scoped supersession on acceptance)

| Existing frozen v0.2 PRD | Product Owner's revised v0.2 requirement |
| --- | --- |
| §1 pillar 1: real LOCAL **and** remote LLM both P0 | **P0 remote-first:** real DeepSeek API Flash is the default configured LLM implementation; LOCAL becomes **optional, out of P0 release gates** |
| §3: user-provisioned Ollama/llama.cpp with attested identity, Windows no-egress and real inference P0 | Preserve the existing fail-closed LOCAL refusal until independently attested, but **do not install local models, demand AppContainer/model IPC acceptance, or block v0.2 L2/Task DAG/Release for unavailable optional LOCAL** |
| §7 journey 1: remote and genuine local inference both required | **One genuine live DeepSeek Flash API call** is the P0 LLM proof, with typed structured proposal, CN/EN goals, user-consented minimal disclosure, redaction and no-send negatives. A real model response is not a trusted executable action. |
| §7 journey 7 & 10: LOCAL Home/Pro trust / offline local model | Core startup and native diagnostics work without network/LLM; cloud model is visibly **UNAVAILABLE_OFFLINE** when offline. Home/Pro shipping matrix still covers portable launch, cleanup, safe file operations, JIT and user state; it no longer requires a live LOCAL model. |
| §8: minimum local bundled model considerations | No local model weights/runtime packaging or GPU/VRAM bench in v0.2 P0. Reuse the narrow #85 AppContainer results as optional future evidence only; don't rerun or discard them. |

## 2. P0 remote model contract

- **Provider:** DeepSeek API at `https://api.deepseek.com` over verified TLS via the existing OpenAI-compatible LLM adapter. **Default model identifier:** `deepseek-flash` (currently DeepSeek-V4.1-Flash). Do not default to obsolete `deepseek-chat` or assume `deepseek-v4-flash` names are stable; explicitly record the runtime model ID/revision returned by the service. Official reference: https://api-docs.deepseek.com/zh-cn/ .
- **Secrets:** Read `DEEPSEEK_API_KEY` from the current **Shun process environment** first, **without printing or persisting its value**; if absent, allow a separately consented OS-protected credential entry. `OPENAI_API_KEY` is **not silently reused** for DeepSeek. Only the trusted local control/backend reads the key; never send it to a model, scripts, UI logs, telemetry, stored Recipe, file manifest or subprocess environment. No key material in CI evidence. If the key is absent, show explicit `CREDENTIAL_MISSING` and preserve deterministic offline capability.
- **Data transfer:** Existing env key is **configuration, not consent** to upload host files, process lists, private filenames or arbitrary prompt text. Confirm one opt-in before real outbound model call with purpose/data summary, default minimal typed disclosure. `LOCAL_ONLY`, `offline=true`, `externalDisclosure=FORBIDDEN`, no/expired consent, stale registry/currentness, prohibited fields or exhausted budget cause **zero API invocations**. No automatic privacy-mode fallback.
- **API behavior:** Bounded timeout/retries, per-task token + currency cost ceilings, cancellation; validate response against frozen `GoalProposal` shape, deterministic Resolver/ActionController revalidation and independent effect verification. Reject hallucinated capabilities, scripts that ask to run arbitrary commands, policy/source drift and model error with typed evidence. Reuse cached approved Recipe exactly when identity/currentness permits and make **zero LLM calls** on second exact replay.
- **UI:** Mark provider `DeepSeek (cloud/API)`, model `deepseek-flash`, `REMOTE_USER_OPT_IN`, sent-data summary and call/cost estimates; distinguish `MODEL_OFFLINE`, `CREDENTIAL_MISSING`, `CONSENT_REQUIRED`, `BUDGET_EXHAUSTED`, `REMOTE_ERROR`, `VERIFIED` vs `PROPOSAL`. No claim of local/offline inference.
- **Local LLM:** optional future design, no P0 implementation task or mandatory Windows host model deployment. Keep the #85 bounded AppContainer research and v0.1 LOCAL fail-closed behavior; only enable LOCAL mode in a separately reviewed opt-in implementation once true model process+egress provenance is measured.

## 3. Release gate changes

P0 needs: (a) one **real DeepSeek `deepseek-flash` API request** with allowed CN/EN typed goals; (b) key not disclosed, no-call with forbidden privacy/currentness, budget/cost receipt, mocked provider failure and prompt-injection negatives; (c) no fabricated real effect; (d) native/Recipe/JIT/UI/portable/closure safety and zero-model recipe replay. Real credentials are already configured **on the user's local Windows Build Host**, per owner, but Web/GitHub **cannot inspect that env**: do not claim a genuine successful call until execution evidence arrives. Manual scripted P0 acceptance on the real host is needed only at the relevant integration/release stages, **not a separate exploratory L2 demo**.

No waiver of security: no remote calls on LOCAL_ONLY/offline, no silent upload of private data, no untrusted model authority, no arbitrary command execution, no unverified Provider downloads. No background model installation, hardware availability dependence or API key copying to CI.

## 4. Process and exact authority

```ini
OLD_PRODUCT_FREEZE=FROZEN_AT_79f47be5ff08a54588790e8abdacffd8697ac4d8
OLD_PRD_BLOB=68cf2fcec919dedd9ce61339b81f60855404fb12
OWNER_CHANGE_AUTHORIZATION=USER_2026-10-14_REMOTE_DEEPSEEK_FLASH_FIRST
DELTA_STATUS=REVIEW_CANDIDATE
PRODUCT_REVIEW_SUCCESSOR=PENDING
REVISED_PRODUCT_FREEZE=PENDING
L2_FREEZE=NO
IMPLEMENTATION_DAG_FREEZE=NO
```

After new independent Product review and explicit revised Product authority terminal, this **scoped successor** overrides the old PRD only for LLM strategy/model/P0 local acceptance; all other reviewed v0.2 PRD guarantees (Recipe, Provider JIT, safe Windows optimization, UI, portable, tests) remain mandatory unchanged. Update #85 disposition to `RESEARCH_ACCEPTED_OPTIONAL_LOCAL_DEFERRED` and close as **de-scoped/not P0**, not U01 technical PASS. Update L2 and Task DAG to remove T02 as P0 execution dependency, and avoid duplicate terminal review loops. The default remote LLM path and its consent/privacy review are still **required** for P0.
