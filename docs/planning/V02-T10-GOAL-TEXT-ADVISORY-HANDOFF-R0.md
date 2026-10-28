# v0.2 T10 GOAL_TEXT → human-selected local C003 — design alignment R0

> **REVIEW CANDIDATE; NOT AN EFFECTIVE IMPLEMENTATION CHANGE.**
> Issue [#221](https://github.com/kaicreator-mm/shun-assistant/issues/221), parent [#212](https://github.com/kaicreator-mm/shun-assistant/issues/212) / T10 [#112](https://github.com/kaicreator-mm/shun-assistant/issues/112).
> Source anchor: `version/v0.2.0@7d6b6d3826b1b0a68afc4357b996b4a97364b6a0`.
> Independent ADS v4.18 #1241 architecture R1, owner approval and a separate exact write-set grant are prerequisites to implementation. Main HOLD, T11 release BLOCK.

## A. Why an API/UI hookup alone cannot work

| Existing accepted source | Exact current behavior | Consequence |
| --- | --- | --- |
| `packages/llm-remote/src/deepseek-transport.ts` | Signed disclosure categories `GOAL_TEXT` only; Chat Completions user message contains *only* `goalText`, no structured JSON contract/prompt | Model is not supplied task ID, selected object(s), local policy or constraints |
| `apps/control-api/src/cloud-interpret.ts` | Human private Win32 consent for exact GOAL_TEXT; local `cloud-UUID` generated in Host; response is `UNTRUSTED_REMOTE_PROPOSAL` raw text | A real response can be useful prose; it cannot attest Host-private task ID or workspace |
| `apps/control-api/src/cloud-proposal-admission.ts` (#213) | Requires strict model-authored `GoalProposalSchema` with exact original taskId, objects, privacy/environment/constraints, and objective before READY | Genuine GOAL_TEXT-only path has insufficient information to produce this shape; fixtures do not prove live reachability |
| `apps/control-api/src/cloud-local-adoption.ts` (#220) | Requires #213 `TYPED_PROPOSAL_ONLY` and exact canonical English *cache-only cleanup* human objective; never accepts inspection-only and constraints | CN/EN freeform suggestions cannot be pushed directly into fixed local C003 by relabeling them |
| `apps/control-api/src/server.ts` + `apps/control-ui/public/app.js` | `/api/cloud/interpret` previews/requests only goalText, renders raw text via textContent, no local selection | Missing positive user-choice→real planHash Controller→verified poststate, not just missing tests |

These restrictions preserve privacy and authority. Do **not** solve by asking the model to guess Host-private fields or by promoting an untrusted response to a signed GoalProposal.

## B. Proposed minimal v0.2 decision (architecture R1/owner to approve)

Continue one private OS-approved DeepSeek call with the **existing GOAL_TEXT-only** signed disclosure. Treat its content as *advisory-only*, with a separate redacted receipt of the Host-verified cloud attempt. There is no model-issued operation or capability authority. A subsequent **independent, explicit human choice** of the *fixed supported* local C003 action is a **new local user intent**, not an interpretation silently inferred from model prose. The UI must clearly distinguish inspection-only advice from optional bounded cache cleanup, and obtain a separate user choice with exact supported scope shown.

The trusted Host, not model/HTTP request, chooses the known `REAL` ControlBackend, exact selected workspace, allowed C003 scope, private/local policy, and fixed new task ID. Any original `RETAIN`, read-only, verification, or inconsistent policy constraints prohibit an automatic upgrade; a different operation needs its own deliberate human intent and explicit policy review rather than truncating those terms. A short-lived, one-use, session-bound correlation between the actual private-consented cloud attempt and displayed local choice is **NOT** an authorization grant.

After creating a local task, use only existing `/api/tasks/:id/preview`, `/api/approvals/:id`, `/api/approvals/:id/decision` with exact `planHash`, `ActionController.authorizePlan/authorizeEffect`, and independently verified poststate. User may decline either cloud disclosure, local candidate, or final plan. No auto-approve, no raw model shell/program, no new issuer/grant engine, no blind model retry under `UNKNOWN_COST`.

**Security/UX decisions to independently verify before code:** Which current Host session/authenticated user gesture actually binds the offer to the same human who saw the preview? Loopback Origin+JSON CSRF checks and a bearer candidate ID alone are NOT proof of an OS-user gesture. Do not expose `CloudTypedProposalAdmission` or a self-reported cloud receipt as an HTTP input. Choose the smallest supported existing UI/host API shape; reject absent session evidence rather than inventing authority.

## C. Options not adopted by this candidate

1. Do **not** expand model disclosure to taskId, workspace paths, policies, constraints or a hidden schema prompt in v0.2 without Product/L2/privacy and C02 consent change review. That would change outbound bytes, exact digest and signed approval scope.
2. Do **not** wire a `GoalProposalSchema` expecting Host-private values to a GOAL_TEXT-only transport, then mark it as a real successful positive.
3. Do **not** run `storage bounded cleanup` merely because the initial user requested `inspect storage`, or because the model wrote `clean`; #220 P1 explicitly closed this unsafe escalation.

Accepted #213 and #220 remain intact in the version branch. Decide whether they should be used as optional strictly typed/internal lanes, or a separate minimal advisory→user-choice seam is needed. Avoid a larger PlannerPort rewrite or a new workflow/journal abstraction.

## D. Reviewable real acceptance path

1. One private Windows broker approval per exact GOAL_TEXT disclosure; no additional charged calls on local candidate selection. CN and EN physical calls must independently pass with actual provider and consent; prior CN HTTP 503 is still BLOCK, EN NOT_RUN. Use merged passive redacted-response diagnostics before changing T01 transport.
2. Actual remote response may be **ordinary prose**; this should display as advisory without JSON parsing side effect. Malicious text, missing/nonterminal HTTP response, forged local source, no OS Allow, or changed policy produces no candidate/submit.
3. Explicit second user selection of fixed local scope: a read-only original or `RETAIN` constraint does not silently become cleanup; wrong choice, expired/session-mismatched/consumed candidate or policy rotation yields zero newly submitted tasks.
4. Existing plan preview + **third distinct approval of exact planHash** is required before any effect. Decline, plan hash drift, source/currentness mutation and repeated decision must yield zero unauthorized effects.
5. Windows real fixed-disk poststate + durable journal/receipts must independently verify task outcome. No claim that a test double is physical evidence; reuse existing T09 Recipe 14/14 and RealStorage negative suite instead of repeating it.
6. Run focused full T10 tests, security leak scans, dual CI and independent exact-SHA RQ; preserve separate Home physical and trusted release origin T11 hard gates, `main=HOLD`.

## E. Next exclusive writes, not yet authorized

Architecture reviewer should name the minimal Host/API/UI source owner and paths after deciding the advisory input binding. Possible existing entrypoints:
`apps/control-api/src/main.ts`, `apps/control-api/src/server.ts`, `apps/control-ui/public/app.js`, matching Control API tests and markup, and a *separate* small host-owned correlation helper **only if necessary**. T10 retains exclusive `tests/integration/v02/**`. #213/#220 source must not be edited casually under an unrelated task claim.

**R1 output:** P0/P1/P2, PASS/BLOCK, `T10_ADVISORY_HANDOFF_DESIGN_READY`, whether frozen Product/L2 allows the advisory interpretation, whether explicit owner approval is needed, exact proposed write-set and actual Host gesture/currentness proof needed. Docs-only PASS is not production, integration or release PASS.
