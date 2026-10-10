# @shun/vertical-image — T05 Loop A reference vertical

C-001 `image.batch_process` business adapter, precommitted SSIM oracle and
semantic verifier. Scope authority: Issue #16, frozen Product
(`docs/product/capability-contracts-v0.1.md` C-001), frozen L2
(`docs/architecture/L2-v0.1.md`) and the Task DAG (`docs/planning/task-dag-v0.1.md` T05).

## Scope boundary

This package owns **only** the vertical concerns of C-001:

- typed C-001 input handling (`ImageBatchProcessInputSchema` from `@shun/contracts`),
- one real image Provider adapter (sharp as an I0 library provider),
- deterministic binding ranking over **pre-screened** candidates,
- the precommitted quality oracle (20 samples by ascending source SHA-256,
  lossless PNG reference resize, per-sample SSIM ≥ 0.95),
- the semantic verifier (count conservation, output decodability, long-edge
  bound, capture-date preservation, SSIM oracle, source preservation),
- safe fallbacks: missing provider, infeasible binding, output collision,
  corrupt input (`DECODE_FAILED`), format mismatch (`UNSUPPORTED_INPUT`),
  metadata loss, output self-check failure.

Goal parsing, trust screening, grant/authorization and the shared
Provider×Environment resolver belong to T01/T02/T04/T08; they hand this
vertical already-trusted candidate bindings. Ranking here
(`rank-pol-t05-v0.1`: interface class I0>I1>I2, bindingId tiebreak) is
deterministic and policy-free — it never evaluates trust.

## API sketch

```ts
import { runImageBatchProcess, makeSharpImageProvider } from '@shun/vertical-image';

const result = await runImageBatchProcess(rawC001Input, {
  facts: environmentFacts,            // observed machine facts
  providers: [makeSharpImageProvider()],
  // preferredBindingId?, candidates?, oracleWorkDir?, metric?
});
// result.ok  -> { output: ImageBatchProcessOutput (schema-valid), diagnostics }
// !result.ok -> { failure: { code: NO_TRUSTED_PROVIDER | NO_FEASIBLE_BINDING | POLICY_BLOCKED, ... } }
```

Schema violations of the C-001 input throw `ShunContractError` before any
side effect. Every output record is either `WRITTEN` (with `outputPath`) or
`REJECTED` (with a frozen `rejectionCode`); outputs are created with
`O_EXCL`-semantics so an existing file can never be overwritten, and a failed
write is removed again. Original inputs are re-hashed after the run and the
verifier reports `sources-unchanged`.

## Verification independence

The verifier re-reads every output and sample from disk through
`src/inspect.ts` and replays the oracle committed *before* execution
(`src/oracle.ts`); the executor cannot see or tune it afterwards. Decode uses
the platform decoder (sharp) on **buffers only** — letting libvips open paths
itself leaves Windows file handles open that block later writes/deletes.
SSIM is `ssim.js` pinned to the standard configuration (original SSIM,
11×11 Gaussian window σ=1.5, K1 0.01, K2 0.03, no downsampling, full
resolution). If the metric cannot be produced the `ssim-oracle` check is
`NOT_RUN` and the receipt degrades to `INCOMPLETE` — never a PASS-equivalent.

## B-037 evidence

`pnpm b037` (Node ≥ 24, Windows) generates the 200-image corpus
deterministically (seed 20261010, soft photographic-style scenes), runs the
full reference journey (shrink to long edge 1600, threshold 0.95) plus the
missing-Provider / corrupt-input / unsupported-declared fallbacks, and writes
`evidence/b037/b037-results.json`. The corpus itself is not committed — its
SHA-256 fingerprint in the evidence file makes any run reproducible.

## Validation & CI note

Mandatory local validation for this task ran as
`biome check` + `tsc --noEmit` + `vitest run` (51 tests) + `pnpm b037` on a
clean checkout of the exact evidence SHA (see the issue terminal and
`evidence/b037/`). No repository CI is configured yet (T00 shipped none and
CI files are outside this task's exclusive write set
`packages/vertical-image/**`); per the Task DAG this is recorded as a
CI waiver with alternate local clean-checkout validation, not as a PASS claim.
