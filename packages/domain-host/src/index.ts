/**
 * v0.3 T11 — the controlled public entry of @shun/domain-host.
 *
 * Zero-dependency like the package manifest (t00 keeps enforcing that): the
 * merged Host adapter seams are re-exported as-is, no side effects run at
 * import time and no internal implementation detail leaves the package.
 *
 *   - cloud/openai-host (T04): the frozen TrustedCloudInterpreterPort
 *     contract, the durable ShunStore-backed request journal seam and the
 *     trusted cloud Host binding over the ONE existing sender.
 *   - windows/effect-host (T01): the K→C Windows effect Host adapter.
 *   - state/shun-store-state (T01): the ShunStore business-state adapter for
 *     K-mediated writes (never a second journal or dispatcher).
 *   - provider/trusted-provider-host (T08): the signed curated provider
 *     Host verification adapter.
 */
export * from './cloud/openai-host.ts';
export * from './provider/trusted-provider-host.ts';
export * from './state/shun-store-state.ts';
export * from './windows/effect-host.ts';
