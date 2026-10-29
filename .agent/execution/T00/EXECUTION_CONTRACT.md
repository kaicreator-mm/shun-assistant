# T00 Execution Contract

## Authority and identity

- Repository: `kaicreator-mm/shun-assistant`
- Integration target: `version/v0.3.0`
- Exact base: `936548fef7fa9252049c0caa29656d293a585472`
- Frozen Task Pack blob: `8aef87cac27297cc32e4e79e0141658a712484fb`
- Frozen DAG blob: `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4`
- DAG freeze record blob: `b47e02f59704ed1699c651b89fd8f26291312ff0`
- Effective ADS: `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`
- DomainHarness source tag: `v0.10.3@061376f4a023070f215f9feffad5c24d96d503cb`, tree `099cdc831aef63befd62aaede7e7a853d1be468f`.

## Claim before execution

This pack is planning/execution metadata only. It is not a Claim. The Local Builder must re-read Issue #228, all native blocked_by links, the live integration SHA, the effective ADS pin, Task Pack identity, branch identity, and active dispatch facts immediately before claiming. Publish the current canonical `ads:github` / `ai-dev/event-v2` `DISPATCH_CLAIMED` with self-declared operator identity only after the existing single-writer admission predicates pass. No accepted current Claim means no source write, package install, or implementation execution.

The designated local invocation is the sole admission writer for protected key `kaicreator-mm/shun-assistant#228:builder:__default__`. Do not start the same dispatch in another agent/session. A duplicate or stale claim must stop without source mutation. This dispatch uses admission generation 1; the worker must verify the live generation and current dispatch record rather than trusting this text.

## Exact source write set

Only these eight path patterns are permitted:
1. `packages/domain-computer/package.json`
2. `packages/domain-computer/tsconfig.json`
3. `packages/domain-computer/src/contracts/**`
4. `packages/domain-host/package.json`
5. `packages/domain-host/tsconfig.json`
6. `packages/domain-app/package.json`
7. `packages/domain-app/tsconfig.json`
8. `tests/integration/v03/t00-scaffold/**`

The three package manifests must have zero dependencies, zero devDependencies, and no scripts. Do not modify `pnpm-lock.yaml`; it is owned by T11. Before commit require `git diff --exit-code -- pnpm-lock.yaml`. Do not add package entrypoints such as `src/index.ts`; shared/public integration wiring belongs to T11. Do not write to sibling task directories.

## SDK source and package rules

Build and pack the four public DomainHarness v0.10.3 Git-source workspaces from the exact immutable tag/tree listed above:
- `@kaicreator/domain-harness-contracts`
- `@kaicreator/domain-harness-microkernel`
- `@kaicreator/domain-harness-host-node`
- `@kaicreator/domain-harness-build`

Use the pinned Git source and the source repository's lockfile. Do not resolve or claim an npm-published `0.10.3` release; it is not the qualified source. Record the actual tarball SHA256 values and the exact tag/tree in committed evidence under `tests/integration/v03/t00-scaffold/**`. Use an isolated Node >=24 consumer and local `file:` tarballs; prohibit registry fallback with offline mode or an equivalent verified no-network mechanism.

Do not import private SDK packages or deep paths. Do not install or import `@kaicreator/domain-harness-host-node/llm/openai`: the frozen L2 prohibits a second physical sender. Because the SDK manifest exports that subpath, the negative oracle must prove Shun does not install/reference/use it, not falsely assert that the SDK package itself rejects an exported path. The BUILD tooling is a separate build-time dependency and must not become an App runtime sender.

## Implementation behavior

Keep `packages/domain-computer/src/contracts/**` to non-effectful, typed contract/DTO scaffolding grounded in actual public exports and frozen L2. Do not implement Windows effects, providers, LLM transport, approval flows, journal mutations, or UI; those belong to downstream frozen Tasks. No API key use, paid model request, credential access, or real Windows side effect.

## Completion

Produce the exact allowed eight-path diff, actual Node 24 environment/tool versions, actual exit codes, tarball SHA256 receipts, positive/negative test results, no-lockfile-drift evidence, and a PR targeting `version/v0.3.0`. Keep the PR open for required independent exact-HEAD Review and CI. Do not merge, close Task #228, or dispatch downstream Tasks.
