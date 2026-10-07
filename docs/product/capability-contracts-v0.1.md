# Shun v0.1 — Minimum Capability Contracts

Status: **Product/L1 candidate contract surface for the first executable MVP proof.**

These are minimum Product contracts. L2 may choose implementation types, libraries, persistence formats, or process boundaries, but it must not change the user-observable semantics below without returning to Product/L1 review.

## C-000 — Shared Goal / Resolution Contract

### Input

- `goal`: user desired outcome in natural language or structured form.
- `objects`: zero or more referenced files, directories, devices, applications, or system states.
- `constraints`: required format, privacy, offline/online policy, resource/time limits, licensing preferences, retain/remove policy, and other user constraints.
- `policy_context`: organization/user safety policy and allowed execution environments.
- `verification_intent`: explicit user success conditions when supplied.

### Preconditions

- referenced objects are resolvable or the resolver can report which object is missing;
- policy context is available before any side-effecting execution;
- Provider Registry currentness can be checked sufficiently to avoid silently using stale trust/version state.

### Output

A structured resolution record containing:

- resolved `capability_id`;
- normalized outcome constraints;
- candidate Providers and their environment requirements;
- feasible Provider × Environment bindings;
- hard-gate dispositions for each binding;
- selected binding plus reasons;
- risk class;
- execution-plan class;
- semantic verification plan;
- privacy/disclosure plan;
- failure/fallback disposition when no binding is feasible.

### Side effects

Resolution itself is read-only. Provider acquisition, configuration, or execution is a separate step and must carry its own risk gate.

### Failure taxonomy

- `GOAL_AMBIGUOUS`
- `OBJECT_UNRESOLVED`
- `CAPABILITY_UNRESOLVED`
- `NO_TRUSTED_PROVIDER`
- `NO_FEASIBLE_BINDING`
- `POLICY_BLOCKED`
- `VERIFICATION_UNSPECIFIABLE`
- `REGISTRY_CURRENTNESS_INSUFFICIENT`

### Supported interface classes

Resolution may inspect I0–I2 structured metadata. It must not require I3/I4 UI operation merely to determine a Provider when equivalent structured metadata exists.

---

## C-001 — `image.batch_process` (Loop A reference)

### User outcome

Transform a set of local images according to explicit dimension/format/metadata constraints and return a verified output set without requiring the user to learn an image-editing application.

### Input schema

- input file set: JPG/PNG for the reference benchmark;
- operation: resize with `max_long_edge_px`;
- metadata policy: preserve capture date when present;
- output directory must differ from the input fixture directory;
- quality policy: `NO_OBVIOUS_DEGRADATION_V1`.

### Constraints / preconditions

- inputs must decode successfully or be individually reported as rejected;
- original inputs are read-only;
- output naming collisions must be detected before write;
- no cloud upload is allowed for the reference journey.

### Expected output

- one output or explicit rejection record per input;
- output manifest mapping input → output;
- selected Provider × Environment binding and ranking evidence;
- verification record.

### Side effects

Creates new output files only. It must not overwrite or delete source files in the reference journey.

### Semantic verification

All of the following are required:

1. output count + explicit rejects = input count;
2. every output decodes;
3. longest edge ≤ requested bound;
4. capture date is preserved when present;
5. **quality oracle is precommitted before execution**:
   - choose 20 samples deterministically by ascending SHA-256 of source bytes (or all files if <20);
   - generate a lossless reference resize at the requested dimensions;
   - compare decoded Provider output against that reference;
   - SSIM must be ≥ 0.95 for every sampled image;
   - if the required metric cannot be produced, the run cannot receive PASS-equivalent status.

### Failure taxonomy

- `UNSUPPORTED_INPUT`
- `DECODE_FAILED`
- `OUTPUT_COLLISION`
- `METADATA_LOST`
- `QUALITY_ORACLE_FAILED`
- `OUTPUT_VERIFY_FAILED`
- shared resolution failures from C-000.

### Supported interface classes

I0 library/API, I1 structured CLI, I2 file interface are preferred. I3/I4 are fallback only and are not acceptable for the reference benchmark when an I0–I2 Provider is available.

---

## C-002 — `software.jit_capability_lifecycle` (Loop B reference)

### User outcome

Obtain one missing machine-friendly capability from a trusted source, use it for a bounded task, verify the task, record lifecycle state, and safely retain or remove the Provider according to a declared policy.

### Input schema

- resolved capability requirement;
- Provider constraints: trusted provenance, license/policy, supported local Windows environment for P0;
- declared lifecycle policy: `RETAIN` or `JIT_REMOVE_AFTER_VERIFIED_USE`;
- target task fixture;
- pre-existing user-asset fixture placed where residue classification could discover it.

### Preconditions

- clean disposable Windows fixture or equivalent rollback-capable test host;
- acquisition provenance can be verified;
- exact Provider version can be recorded;
- lifecycle policy is declared **before** acquisition/use.

### Expected output

- selected trusted Provider × local-environment binding;
- provenance record: official source, version, hash/signature where available, license/policy disposition;
- task result + semantic verification;
- lifecycle-state record;
- final retained/removed state;
- residue classification report.

### R2 side-effect gate

Any uninstall/removal or residue deletion is R2 and MUST expose an observable gate in this order:

1. **plan** — exact uninstall mechanism and candidate filesystem/configuration changes;
2. **preview** — classify every candidate residue as program-owned, cache, configuration, user-created/unknown, or protected;
3. **checkpoint / recovery disposition** — record exact Provider version/source so reinstall is possible; back up any configuration selected for removal when restoration is required; never include user-created/unknown/protected data in automatic deletion;
4. **approval condition** — explicit user approval **or** a pre-existing durable policy that specifically authorizes removal of verified JIT Providers after successful task completion and forbids deletion of user-created/unknown/protected data;
5. execute the bounded removal;
6. **verify** final Provider state, protected/user asset integrity, and residue disposition.

User confirmation alone cannot override failed/unknown provenance.

### Failure taxonomy

- `PROVENANCE_UNKNOWN`
- `ACQUISITION_FAILED`
- `INSTALL_FAILED`
- `TASK_FAILED`
- `TASK_VERIFY_FAILED`
- `R2_GATE_MISSING`
- `RESIDUE_UNKNOWN`
- `USER_ASSET_AT_RISK`
- `REMOVE_FAILED`
- `POST_REMOVE_VERIFY_FAILED`
- shared resolution failures from C-000.

### Supported interface classes

I0–I2 are preferred. Acquisition and lifecycle operations must be observable and scriptable enough to produce provenance and before/after verification evidence.

---

## C-003 — `system.storage.diagnose_bounded_action` (Loop C reference)

### User outcome

Explain a known disk-space growth problem, identify the responsible source with evidence, preview one bounded safe cleanup, execute only when authorized, and verify reclaimed space without damaging protected/user data.

### Input schema

- target local volume;
- synthetic or reproducible growth fixture;
- protected user-asset fixture;
- policy defining what categories are eligible for bounded cleanup.

### Preconditions

- observation can run read-only before cleanup;
- protected asset baseline hash exists;
- growth injector/source is known to the benchmark harness but hidden from the resolver/diagnoser;
- cleanup eligibility policy is available.

### Expected output

- evidence-backed attribution of growth;
- classification of target data;
- bounded cleanup plan/preview;
- required approval/policy disposition;
- execution evidence;
- reclaimed-space measurement;
- protected asset integrity verification.

### Side effects / safety gate

Observation is R0. Cleanup is R2 and requires plan → preview → approval/durable policy → bounded action → verify.

Deletion by size alone is forbidden.

Only data classified as disposable by the applicable policy may be removed automatically. Unknown or user-created data is fail-closed.

### Semantic verification

- injected growth source correctly identified;
- only policy-eligible disposable data removed;
- protected asset hash unchanged;
- reclaimed bytes measured and attributable to the bounded action;
- if the cache/source recreates data during verification, the result records both gross reclaimed bytes and current post-action state rather than falsely claiming permanent recovery.

### Failure taxonomy

- `GROWTH_NOT_ATTRIBUTED`
- `DATA_CLASSIFICATION_UNKNOWN`
- `R2_GATE_MISSING`
- `PROTECTED_ASSET_TOUCHED`
- `RECLAIM_NOT_VERIFIED`
- `ACTION_NOT_BOUNDED`
- shared resolution failures from C-000.

### Supported interface classes

I0 OS APIs, I1 structured CLI/PowerShell, and I2 filesystem metadata are preferred. UI is not required for the reference journey.

---

## Contract change rule

A change that materially alters any reference capability's input, side-effect boundary, failure semantics, or success oracle is a Product/L1 contract change and requires affected Product review currentness to be re-established.
