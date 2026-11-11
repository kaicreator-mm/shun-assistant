/**
 * v0.3 T11 — the controlled public entry of @shun/domain-app.
 *
 * Zero-dependency like the package manifest (t00 keeps enforcing that): only
 * the merged task adapters are re-exported, no side effects run at import
 * time and no internal implementation detail leaves the package.
 *
 *   - api/gateway (T09): the single trusted Control API Host gateway in
 *     front of any injected `domainApp.send` facade.
 *
 * The legacy T09 structural BUILD preview composer (build/composition.ts) is
 * deliberately NOT re-exported here: it is an internal, test-preview-only
 * helper that mirrors the old v0.10.2-rc.0 BUILD contract and carries
 * placeholder K/S module bytes. Production uses composeTrustedRuntimeBuild
 * plus the real public DomainHarness v0.10.3 buildV10App/activateV10App
 * chain (R02-A/t12 facade proof); exporting the preview composer from this
 * root would create a second, unsupported apparent production entry path.
 *
 * The trusted-cloud-interpreter port pins, by contrast, are part of the
 * public Control API surface (V01 anchoring) and stay exported — selectively,
 * so the preview composer itself never becomes a public Package ABI entry.
 */
export * from './api/gateway.ts';
export {
  V03_EXTERNAL_IMPORT_BINDINGS,
  V03_TRUSTED_CLOUD_INTERPRETER_PORT,
} from './build/composition.ts';
