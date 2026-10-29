# T00 Independent Review Checklist

Reviewer is a distinct logical operator/session from the Builder. Review is required and binds to the exact PR HEAD SHA. No merge is authorized by this pack.

## Identity and scope
- [ ] Current base remains `version/v0.3.0@936548fef7fa9252049c0caa29656d293a585472`, or a currentness/staleness decision is recorded.
- [ ] Effective ADS pin is exactly `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`.
- [ ] Frozen Task Pack, DAG and Freeze record blobs match the manifest.
- [ ] Valid current `DISPATCH_CLAIMED` exists with actual builder operator attribution and no incompatible active claim.
- [ ] Source diff contains only the eight allowed paths; no sibling Task, root workspace, root config or lockfile edits.
- [ ] Three package manifests have zero dependencies/devDependencies and no scripts.

## SDK provenance and packaging
- [ ] Exact DomainHarness Git tag resolves to the pinned commit and tree.
- [ ] Only the four public workspace tarballs are produced; SHA256 receipts match the actual tarball bytes.
- [ ] Clean Node >=24 consumer installs from local tarballs with registry fallback disabled.
- [ ] Public imports resolve from the recorded local tarballs.
- [ ] No private SDK import, no npm-published v0.10.3 assumption, no prohibited `host-node/llm/openai` use.
- [ ] BUILD tooling remains separate from App runtime.
- [ ] No package install hook triggers unapproved network or effects.

## Validation and evidence
- [ ] Scoped T00 tests were actually run; actual EXIT and test counts are recorded.
- [ ] Typecheck and Biome ran on exact PR HEAD and only the relevant scope.
- [ ] `pnpm-lock.yaml` is unchanged and verified by a real zero exit.
- [ ] Negative tests cover missing/tampered provenance, private import boundary and prohibited Provider path.
- [ ] CI checks are tied to exact PR HEAD; no historical PASS is promoted to this SHA.
- [ ] P0/P1/P2 findings and PASS/BLOCK are recorded against exact HEAD.
- [ ] Local/Windows evidence is labelled by actual environment; no simulated Host or unrun test is described as PASS.

## Decision
- [ ] Required independent Review: PASS/BLOCK with exact SHA.
- [ ] Version-only merge eligibility: YES/NO.
- [ ] No merge, Task closure or downstream dispatch until the owning authority separately admits each next step.
