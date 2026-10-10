// @shun/resolver — T01 goal/capability/provider resolution for Shun v0.1.
//
// Authority: docs/architecture/L2-v0.1.md §6 (Planner boundary), §7 (Provider
// Registry / Resolver), §13 (failure ownership), C-000
// (docs/product/capability-contracts-v0.1.md) and the frozen Product resolver
// v0.1 rules (docs/product/provider-resolver-v0.1.md). Resolution is read-only
// and deterministic: hard gates precede ranking, risk is never a score
// component, ambiguity and failure are typed, and planner output is untrusted
// proposal data only.
export * from './feasibility.ts';
export * from './gates.ts';
export * from './matchers.ts';
export * from './normalize.ts';
export * from './planner-seam.ts';
export * from './ranking.ts';
export * from './registry.ts';
export * from './resolve.ts';
export * from './revision.ts';
