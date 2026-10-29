# T00 Implementation Map

## Baseline-owned structure

The current root workspace already includes `packages/*`, `apps/*`, and `tests/integration`; do not edit root workspace configuration. Root package requires Node >=24 and pins pnpm 10.34.5. The current `tsconfig.base.json` uses strict TypeScript, ESNext modules and bundler resolution. `.node-version` is `24.21.0`.

## Exact source ownership

| Allowed path | T00 deliverable | Boundary |
|---|---|---|
| `packages/domain-computer/package.json` | private local package manifest | zero deps/devDeps/scripts |
| `packages/domain-computer/tsconfig.json` | strict package typecheck config | extends existing root config; no root config changes |
| `packages/domain-computer/src/contracts/**` | non-effectful typed DTO/contracts only | derive types from real public v0.10.3 exports and frozen L2; no provider/Host/Kernel effects |
| `packages/domain-host/package.json` | private local package manifest | zero deps/devDeps/scripts |
| `packages/domain-host/tsconfig.json` | strict scaffold typecheck config | no implementation entrypoint or sibling source |
| `packages/domain-app/package.json` | private local package manifest | zero deps/devDeps/scripts |
| `packages/domain-app/tsconfig.json` | strict scaffold typecheck config | no implementation entrypoint or sibling source |
| `tests/integration/v03/t00-scaffold/**` | pinned tarball receipts, source identity, scoped smoke and negative tests | tests are explicitly run; root top-level test discovery does not include this nested path |

## Public SDK source

Use only these public workspaces from DomainHarness tag `v0.10.3` commit `061376f4a023070f215f9feffad5c24d96d503cb`, tree `099cdc831aef63befd62aaede7e7a853d1be468f`:
- `@kaicreator/domain-harness-contracts` — public `.`
- `@kaicreator/domain-harness-microkernel` — public `.` and `./host-seam`
- `@kaicreator/domain-harness-host-node` — public root `.`; the `./llm/openai` subpath is forbidden for this project
- `@kaicreator/domain-harness-build` — public `.`, build-time only

The first three source package versions currently read as `0.10.2-rc.0` at the qualified v0.10.3 Git tag; this is expected source-tag evidence and must not be rewritten to pretend an npm `0.10.3` release exists. The BUILD workspace has a transitive dependency on contracts; microkernel depends on contracts; host-node depends on contracts and microkernel. The isolated consumer must resolve these via local tarballs with registry fallback disabled.

## Forbidden integration changes

No `src/index.ts` public entrypoints, no provider selection implementation, no Host authorization implementation, no Kernel wiring, no Case gateway, no LLM sender, no UI, no root package/workspace/lockfile edits. Those are owned by later frozen Tasks. No files under `packages/domain-computer/src/provider/**`, `packages/domain-host/src/provider/**`, or any sibling Task path.

## Expected PR

One T00 concern PR from `JIT_only_task/v0.3.0-t00` to `version/v0.3.0`, with exactly the allowed source path set. Keep the Execution Pack branch separate; do not merge or cherry-pick `.agent/execution/T00/**` into the source PR.
