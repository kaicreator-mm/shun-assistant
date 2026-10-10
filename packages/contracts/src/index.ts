// @shun/contracts — T00 frozen runtime contracts for Shun v0.1.
//
// Authority: docs/product/capability-contracts-v0.1.md (C-000..C-003) and
// docs/architecture/L2-v0.1.md (§4 core contracts, §4.6.1 authorization,
// §4.7 receipts, §5.2/§6/§8 ports). Contracts are authoritative and no
// arbitrary execution is implemented here: this package contains schemas,
// types, pure validation/canonicalization, typed ports and contract tests.

export * from './authorization.ts';
export * from './capabilities/c000.ts';
export * from './capabilities/c001.ts';
export * from './capabilities/c002.ts';
export * from './capabilities/c003.ts';
export * from './capability.ts';
export * from './environment.ts';
export * from './goal.ts';
export * from './plan.ts';
export * from './ports.ts';
export * from './provider.ts';
export * from './receipts.ts';
export * from './registry.ts';
export * from './taxonomy.ts';
export * from './version.ts';
