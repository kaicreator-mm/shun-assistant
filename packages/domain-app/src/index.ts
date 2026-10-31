/**
 * v0.3 T11 — the controlled public entry of @shun/domain-app.
 *
 * Zero-dependency like the package manifest (t00 keeps enforcing that): only
 * the merged task adapters are re-exported, no side effects run at import
 * time and no internal implementation detail leaves the package.
 *
 *   - build/composition (T09): the plain-data BUILD composition adapter for
 *     the real public DomainHarness `buildV10App` SDK (this package itself
 *     never imports the SDK).
 *   - api/gateway (T09): the single trusted Control API Host gateway in
 *     front of any injected `domainApp.send` facade.
 */
export * from './api/gateway.ts';
export * from './build/composition.ts';
