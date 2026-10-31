/**
 * v0.3 T11 — the controlled public entry of @shun/domain-computer.
 *
 * Zero-dependency like the package manifest (t00 keeps enforcing that): the
 * merged task lanes are re-exported as-is, no side effects run at import
 * time and no internal implementation detail leaves the package.
 *
 *   - semantic/goal-semantic (T03): issuance-style Host observation evidence
 *     and the goal semantic selection adapter.
 *   - guided (T05): the approved step-template catalog and guided journey
 *     step/outcome adapters.
 *   - feedback (T06): the meta-feedback shadow candidate adapter.
 *   - provider (T08): the curated provider JIT business adapter.
 *   - recipes (T07): the domain recipe replay adapter.
 *   - computer (T02): folder observation and support context adapters.
 *   - cloud (T04): the neutral `dh.llm.generate/1` request builder.
 *   - contracts (T00): the selected-C adapter seam and LLM contract types.
 */
export * from './cloud/goal-request.ts';
export * from './computer/folder-observation.ts';
export * from './computer/support-context.ts';
export * from './contracts/index.ts';
export * from './feedback/meta-feedback.ts';
export * from './guided/guided-contract.ts';
export * from './guided/guided-journey.ts';
export * from './provider/provider-jit.ts';
export * from './recipes/recipe-replay.ts';
export * from './semantic/goal-semantic.ts';
