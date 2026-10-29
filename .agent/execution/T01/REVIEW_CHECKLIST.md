# T01 Independent Review Checklist

- [ ] PR HEAD, base and candidate tree are exact; base is 1165a70a9271f570cbb313210f20aa013db72f86 unless a new authorized pack is generated.
- [ ] Only packages/domain-host/src/windows/**, packages/domain-host/src/state/**, tests/integration/v03/t01-host/** changed.
- [ ] K-issued Permit and real Shun ActionController.authorizeEffect/currentness bind the same effect.
- [ ] The ActionController check is immediately before the Host effect boundary.
- [ ] ShunStore business data remains durable; apply(effectId) is transactionally idempotent.
- [ ] K is the sole effect dispatcher for the migrated Case; old WorkflowEffectJournal is not a second active dispatcher.
- [ ] Fake/stale Permit, stale path/grant, mismatch, duplicate dispatcher and uncertain replay all reject with zero effect.
- [ ] No physical Windows side effect was performed or falsely claimed; task-owned real effect validation is honestly NOT_RUN/BLOCKED.
- [ ] T00/T11-owned package manifests, tsconfigs, exports and lockfile are untouched.
- [ ] Focused tests, typecheck, lint, exact-HEAD CI and independent review all bind to the same SHA.
- [ ] Task Learning closeout declares NONE_MATERIAL or durable material evidence references.
- [ ] No main/v0.2 merge; version-only eligibility is not release qualification.
