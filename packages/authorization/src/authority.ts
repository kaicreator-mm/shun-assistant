// AuthorizationAuthority — the trusted issuer (L2 §4.6.1).
//
// The authority applies the integrity envelope itself (callers can never
// supply one), binds every grant to the CURRENT authority/policy state at
// issuance time, and persists a durable record before the grant is returned.
// Issuance fails closed: no grant is ever issued under unresolvable
// currentness, a non-ACTIVE policy, or a request classified under a stale
// policy revision.
//
// Authority events (rotate authority, adopt policy, revoke policy, revoke
// grant) are deliberate recorded state transitions. They are what turns
// previously authentic grants stale or revoked — currentness is always
// re-established by the privileged boundary before any side effect.
import { randomUUID } from 'node:crypto';
import {
  type AuthorizationGrant,
  AuthorizationGrantSchema,
  type AuthorizationPort,
  type ContractErrorCode,
  type CurrentAuthorityState,
  type GrantIntegrityVerifier,
  type GrantIssueRequest,
  GrantIssueRequestSchema,
  IsoDateTimeSchema,
  ShunContractError,
} from '@shun/contracts';
import { z } from 'zod';
import {
  createHmacGrantVerifier,
  type GrantIntegritySecret,
  signGrantIntegrity,
} from './integrity.ts';
import {
  type IssuanceProof,
  parseIssuanceProof,
  verifyIssuanceProofMac,
} from './issuance-proof.ts';
import {
  type AuthorityRecord,
  AuthorityRecordSchema,
  type PolicySnapshotRecord,
  PolicySnapshotRecordSchema,
  type PolicyStateStore,
  resolveCurrentAuthorityState,
} from './policy.ts';

/** Default bounded grant validity. */
export const DEFAULT_GRANT_TTL_MS = 15 * 60 * 1000;

/**
 * R2 (P1-B): bounded retry budget for compare-and-save mutations of BOTH
 * durable slots (policy snapshot and authority record). Every attempt
 * re-reads the fresh record and re-applies the mutation; if a concurrent
 * writer wins every generation the mutation refuses typed instead of
 * silently clobbering (fail-closed).
 */
const POLICY_MUTATION_CAS_ATTEMPTS = 4;

/** Durable, integrity-protected grant record (L2 §4.6.1: grants live in ShunStore). */
export const StoredGrantRecordSchema = z.strictObject({
  grantId: z.string().min(1),
  grant: AuthorizationGrantSchema,
  storedAt: IsoDateTimeSchema,
});
export type StoredGrantRecord = z.infer<typeof StoredGrantRecordSchema>;

/**
 * Durable grant-record seam. Like PolicyStateStore, reads return unknown so
 * corrupt records can never re-enter the trust domain; the workflow/store
 * package provides the ShunStore adapter, tests an in-memory one.
 *
 * R2 (P1-A): `hasAnyGrant` is the evidence seam that distinguishes a VIRGIN
 * store (never any policy — nothing to resurrect) from an initialized-but-
 * unmarked one (grant records exist, so a policy once existed): grants are
 * only ever written by issuance under an ACTIVE policy, so any grant record
 * proves prior policy existence.
 */
export interface GrantRecordStore {
  put(record: StoredGrantRecord): Promise<void>;
  get(grantId: string): Promise<unknown>;
  /** R2 (P1-A): true when at least one grant record is durably stored. */
  hasAnyGrant(): Promise<boolean>;
}

export interface PolicyBootstrapSnapshot {
  policySnapshotRevision: string;
  rules: PolicySnapshotRecord['rules'];
  riskGuards?: PolicySnapshotRecord['riskGuards'];
}

export interface PolicyBootstrapAuthorizationInput {
  readonly proof: unknown;
  readonly authorityRecord: AuthorityRecord;
  readonly snapshot: PolicyBootstrapSnapshot;
}

export interface AuthorizationAuthorityConfig {
  state: PolicyStateStore;
  grants: GrantRecordStore;
  /** HMAC secret of the reference substrate; lives in trusted local configuration. */
  integritySecret: GrantIntegritySecret;
  /**
   * HMAC secret of the controller-issuance proof channel (P1-04); shared only
   * with the trusted Action Controller through trusted local configuration.
   * Issuance without a proof minted under this secret is refused.
   */
  issuanceSecret: GrantIntegritySecret;
  /**
   * Optional trusted ceremony gate for FIRST policy provisioning only.
   * Absence means bootstrap is disabled. A production implementation must
   * validate/consume a proof rooted outside ordinary policy state (T04's
   * protected one-shot writer is the intended composition); a caller-visible
   * "state is empty" observation is never sufficient authority.
   */
  bootstrapAuthorizer?: (
    input: PolicyBootstrapAuthorizationInput,
  ) => boolean | Promise<boolean>;
  /** ISO 8601 UTC clock; injected so issuance stays deterministic in tests. */
  clock: () => string;
  grantTtlMs?: number;
  newGrantId?: () => string;
}

function issueFailure(code: ContractErrorCode, detail: string): never {
  throw new ShunContractError(code, detail);
}

/**
 * The trusted issuance authority. Implements the frozen `AuthorizationPort`
 * seam (issue / currentAuthority) plus the authority events that move the
 * current authority/policy state.
 */
export class AuthorizationAuthority implements AuthorizationPort {
  readonly #config: AuthorizationAuthorityConfig;
  readonly #grantTtlMs: number;
  readonly #newGrantId: () => string;
  /**
   * R1 (P1-B): single-writer chain for every authority EVENT that moves the
   * durable policy/authority state. Each event's read-modify-write runs
   * inside this serialized tail, so two events on this instance can never
   * interleave their load→compute→save windows (the reviewer's parked
   * revocation could previously roll a concurrent adoption back).
   *
   * R2 (P1-B): the tail serializes THIS instance's events; cross-instance and
   * cross-process ordering is enforced by the store's MANDATORY
   * compare-and-save primitives, which every mutation uses — a store without
   * them is rejected at construction.
   */
  #mutationTail: Promise<unknown> = Promise.resolve();

  constructor(config: AuthorizationAuthorityConfig) {
    if (config.integritySecret.length === 0) {
      throw new TypeError('AuthorizationAuthority requires a non-empty integritySecret');
    }
    if (config.issuanceSecret.length === 0) {
      throw new TypeError('AuthorizationAuthority requires a non-empty issuanceSecret');
    }
    // R2 (P1-B): the shared-durable atomicity primitives are mandatory. A
    // store that cannot provide them previously degraded to unconditional
    // saves (the optional-CAS fallback) — a second Authority instance could
    // drive a policy/authority rollback straight through that hole. Refuse
    // the unsafe implementation instead of degrading.
    const store = config.state as Partial<PolicyStateStore>;
    if (typeof store.compareAndSavePolicySnapshot !== 'function') {
      throw new TypeError(
        'AuthorizationAuthority requires a PolicyStateStore with a mandatory compareAndSavePolicySnapshot primitive — a store without shared-durable atomic compare-and-save is an unsafe implementation and is refused',
      );
    }
    if (typeof store.compareAndSaveAuthorityRecord !== 'function') {
      throw new TypeError(
        'AuthorizationAuthority requires a PolicyStateStore with a mandatory compareAndSaveAuthorityRecord primitive — authority-record mutations (initialization marker, rotation) must be atomic against concurrent instances',
      );
    }
    if (typeof store.consumeIssuanceNonce !== 'function') {
      throw new TypeError(
        'AuthorizationAuthority requires a PolicyStateStore with a mandatory consumeIssuanceNonce primitive — issuance-proof consumption must be shared durable state, not an instance-local ledger',
      );
    }
    this.#config = config;
    this.#grantTtlMs = config.grantTtlMs ?? DEFAULT_GRANT_TTL_MS;
    this.#newGrantId = config.newGrantId ?? (() => randomUUID());
  }

  /**
   * R2 (P1-C): single-use proof consumption is SHARED DURABLE STATE. The
   * instance-local ledger was reset by every reconstructed issuer — a second
   * Authority over the same state (or an issuer restart) replayed an already
   * consumed proof inside its validity window and minted an unrevoked grant.
   * Consumption now runs through the store's mandatory atomic
   * `consumeIssuanceNonce`, so every instance (and, once the durable adapter
   * persists the ledger, every restart) sees the same one-shot record.
   */
  async #consumeIssuanceNonce(nonce: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    return this.#config.state.consumeIssuanceNonce(nonce, expiresAtMs, nowMs);
  }

  /**
   * R1 (P1-B): serialize an authority EVENT (policy/authority mutation) on
   * this instance's single-writer tail. Each event's full read-modify-write
   * runs inside the serialized section, so two events can never interleave
   * their load→compute→save windows. Events must never call each other
   * directly (they would wait on their own tail); they compose only through
   * private, lock-free loaders.
   */
  #serializeEvent<T>(event: () => Promise<T>): Promise<T> {
    const run = this.#mutationTail.then(event, event);
    this.#mutationTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * R2 (P1-B): save a computed policy mutation ONLY while the store still
   * holds exactly the record (or absence) this event last read. The
   * compare-and-save primitive is mandatory (validated at construction); a
   * lost race returns false and the caller re-reads and retries (bounded) —
   * there is no unconditional-save fallback.
   */
  async #savePolicyMutation(next: PolicySnapshotRecord, expectedPrior: unknown): Promise<boolean> {
    return this.#config.state.compareAndSavePolicySnapshot(next, expectedPrior);
  }

  /**
   * R2 (P1-B): save an authority-record mutation (initialization marker,
   * rotation) ONLY while the stored record still equals `expectedPrior`.
   * The R1 plain save let a parked unmarked-A1 marker write overwrite an
   * intervening A2 rotation from another instance — currentness rolled back.
   */
  async #saveAuthorityRecordMutation(
    next: AuthorityRecord,
    expectedPrior: unknown,
  ): Promise<boolean> {
    return this.#config.state.compareAndSaveAuthorityRecord(next, expectedPrior);
  }

  /**
   * R1 (P1-A), R2 (P1-B): persist the durable initialization marker BEFORE
   * the snapshot it guards, as a compare-and-save against the record just
   * read. Ordering is deliberate: a crash between marker and snapshot bricks
   * adoption (fail-closed, operator-visible), while the reverse order would
   * leave a window in which storage loss looks like a virgin store and
   * adoption resurrects revoked grants. A lost race re-reads the FRESH record
   * (the marker carries forward there — a concurrent rotation is preserved,
   * never overwritten) and retries bounded. Returns the record the marker is
   * effective on — the caller binds its snapshot to THAT record, never to a
   * pre-race read.
   */
  async #ensureInitializationMarker(authorityRecord: AuthorityRecord): Promise<AuthorityRecord> {
    let current = authorityRecord;
    for (let attempt = 1; ; attempt++) {
      if (current.policyInitialized === true) return current;
      const marked: AuthorityRecord = {
        ...current,
        policyInitialized: true,
        updatedAt: requireInstant(this.#config.clock),
      };
      if (await this.#saveAuthorityRecordMutation(marked, current)) return marked;
      if (attempt >= POLICY_MUTATION_CAS_ATTEMPTS) {
        throw new ShunContractError(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          `authority record moved concurrently on every initialization-marker attempt; refusing after ${POLICY_MUTATION_CAS_ATTEMPTS} bounded retries (fail-closed)`,
        );
      }
      current = await this.#loadAuthorityOrThrow();
    }
  }

  /**
   * Raw current policy record for a mutation: typed refusal when missing or
   * unreadable — an event never acts blindly on absent state.
   */
  async #rawPolicyRecordOrThrow(): Promise<unknown> {
    let raw: unknown;
    try {
      raw = await this.#config.state.loadCurrentPolicy();
    } catch (error) {
      throw new ShunContractError(
        'GRANT_CURRENTNESS_UNRESOLVABLE',
        `current policy record missing or corrupt; cannot apply authority event (${(error as Error).message})`,
      );
    }
    if (raw === null || raw === undefined) {
      throw new ShunContractError(
        'GRANT_CURRENTNESS_UNRESOLVABLE',
        'current policy record missing or corrupt; cannot apply authority event',
      );
    }
    return raw;
  }

  #parsePolicyRecordOrThrow(raw: unknown): PolicySnapshotRecord {
    const parsed = PolicySnapshotRecordSchema.safeParse(raw);
    if (!parsed.success) {
      throw new ShunContractError(
        'GRANT_CURRENTNESS_UNRESOLVABLE',
        'current policy record missing or corrupt; cannot apply authority event',
      );
    }
    return parsed.data;
  }

  /** The trusted verifier backed by this authority's substrate (injected into the privilege boundary). */
  get integrityVerifier(): GrantIntegrityVerifier {
    return createHmacGrantVerifier(this.#config.integritySecret);
  }

  /**
   * Issue one grant. Fails closed on: a missing/invalid controller issuance
   * proof, unresolvable currentness, non-ACTIVE policy, a request classified
   * under a stale policy revision, a malformed request, missing approval
   * reference for explicit-approval grants, or an unreadable validation clock.
   * The envelope is applied here from trusted configuration — a
   * caller-supplied envelope cannot exist on this path.
   *
   * P1-04: the port is protected. `proof` must be an issuance proof minted by
   * the Action Controller for THIS exact request under the shared trusted
   * secret (a second optional parameter keeps the class assignable to the
   * frozen `AuthorizationPort` seam). Direct issuance with no plan intake, no
   * durable-policy rule and no approval evidence is refused with a structured
   * error.
   *
   * R1 (P1-C): the proof is a single-use, expiring capability. A valid proof
   * is parsed, MAC-verified, checked against its validity window and then
   * CONSUMED synchronously — a second presentation of the same (request,
   * proof) pair refuses even though the bytes still MAC-verify, so an
   * observed pair can never re-mint a grant that escapes an earlier grant's
   * revocation. The controller mints a fresh nonce per approval, so every
   * legitimate issuance consumes its own proof.
   */
  async issue(request: GrantIssueRequest, proof?: IssuanceProof): Promise<AuthorizationGrant> {
    const current = await this.currentAuthority();
    if (current.kind === 'UNRESOLVABLE') {
      issueFailure('GRANT_CURRENTNESS_UNRESOLVABLE', `refusing issuance: ${current.reason}`);
    }
    if (current.policyStatus === 'REVOKED') {
      issueFailure('GRANT_POLICY_REVOKED', 'refusing issuance: current policy revision is revoked');
    }
    if (current.policyStatus === 'SUPERSEDED') {
      issueFailure(
        'GRANT_POLICY_STALE',
        'refusing issuance: current policy revision is superseded',
      );
    }
    const parsed = GrantIssueRequestSchema.safeParse(request);
    if (!parsed.success) {
      issueFailure('SCHEMA_VIOLATION', 'grant issue request is not a valid GrantIssueRequest');
    }
    const req = parsed.data;
    const nowParsed = IsoDateTimeSchema.safeParse(this.#config.clock());
    if (!nowParsed.success) {
      issueFailure('GRANT_MALFORMED', 'authority clock returned a non-ISO 8601 UTC instant');
    }
    const issuedAt = nowParsed.data;
    const nowMs = Date.parse(issuedAt);
    const claims = parseIssuanceProof(proof);
    if (claims === undefined || !verifyIssuanceProofMac(this.#config.issuanceSecret, req, claims)) {
      issueFailure(
        'GRANT_NOT_AUTHENTIC',
        'issuance refused: caller presented no valid controller issuance proof; grants are issued only through the Action Controller',
      );
    }
    if (Date.parse(claims.expiresAt) < nowMs) {
      issueFailure(
        'GRANT_NOT_AUTHENTIC',
        'issuance refused: the controller issuance proof expired before presentation; obtain a fresh proof from the Action Controller',
      );
    }
    if (!(await this.#consumeIssuanceNonce(claims.nonce, Date.parse(claims.expiresAt), nowMs))) {
      issueFailure(
        'GRANT_NOT_AUTHENTIC',
        'issuance refused: the controller issuance proof was already consumed; controller approval is strictly single-use',
      );
    }
    if (req.policySnapshotRevision !== current.policySnapshotRevision) {
      issueFailure(
        'GRANT_POLICY_STALE',
        `request classified under policy ${req.policySnapshotRevision} but current policy is ${current.policySnapshotRevision}; reclassify under current policy`,
      );
    }
    if (req.authorizationKind === 'EXPLICIT_APPROVAL' && !req.approvalRef) {
      issueFailure(
        'GRANT_APPROVAL_REF_MISSING',
        'explicit-approval grants require the durable approval record reference',
      );
    }
    const expiresAt = new Date(nowMs + this.#grantTtlMs).toISOString();
    const grant: AuthorizationGrant = {
      grantId: this.#newGrantId(),
      issuer: { authorityId: current.authorityId, authorityRevision: current.authorityRevision },
      taskId: req.taskId,
      planHash: req.planHash,
      policySnapshotRevision: current.policySnapshotRevision,
      actionScope: req.actionScope,
      issuedAt,
      expiresAt,
      ...(req.approvalRef ? { approvalRef: req.approvalRef } : {}),
      integrity: { scheme: 'HMAC_SHA256', value: '' },
    };
    grant.integrity = signGrantIntegrity(this.#config.integritySecret, grant);
    await this.#config.grants.put({ grantId: grant.grantId, grant, storedAt: issuedAt });
    return grant;
  }

  /** Current authority/policy state; UNRESOLVABLE on any missing/corrupt/incoherent record. */
  async currentAuthority(): Promise<CurrentAuthorityState> {
    return resolveCurrentAuthorityState(this.#config.state);
  }

  /** Durable grant record, or undefined when absent. Corrupt records surface as a schema error. */
  async storedGrant(grantId: string): Promise<StoredGrantRecord | undefined> {
    const raw = await this.#config.grants.get(grantId);
    if (raw === null || raw === undefined) return undefined;
    return StoredGrantRecordSchema.parse(raw);
  }

  /**
   * Authority event: rotate the authority revision (A1 → A2). Until a policy is adopted under the new revision, currentness is deliberately UNRESOLVABLE.
   *
   * R1 (P1-A): the rewritten record carries the initialization marker forward
   * (a rotation never un-initializes lineage), and the event runs serialized
   * against the other authority events.
   *
   * R2 (P1-D): authority revisions are NON-REUSABLE. Rotating back to a used
   * revision re-coheres the policy still bound to it and re-currents its
   * stale grants without any race (A1→A2→A1 resurrected A1/P1 grants). The
   * revision is checked against the durable lineage (current + every prior
   * revision) and refused with GRANT_AUTHORITY_STALE; each rotation carries
   * the lineage forward.
   *
   * R2 (P1-B): the record write is a compare-and-save against the record just
   * read — a concurrent rotation from another instance wins the CAS, this
   * event re-reads the fresh record, re-checks reuse against ITS lineage and
   * re-applies (bounded), so a parked rotation can never overwrite an
   * intervening one and no revision is ever dropped from the lineage.
   */
  async rotateAuthority(next: { authorityRevision: string }): Promise<void> {
    await this.#serializeEvent(async () => {
      // Authority events are deliberate mutations of a readable domain: refuse
      // to act blindly on an unreadable/corrupt state.
      let currentRecord = await this.#loadAuthorityOrThrow();
      await this.#parsePolicyRecordOrThrow(await this.#rawPolicyRecordOrThrow());
      for (let attempt = 1; ; attempt++) {
        // Re-check non-reuse against the FRESH lineage on every attempt: a
        // lost CAS race reveals a moved record whose lineage may already use
        // the requested revision.
        const usedRevisions = new Set([
          ...(currentRecord.priorAuthorityRevisions ?? []),
          currentRecord.authorityRevision,
        ]);
        if (usedRevisions.has(next.authorityRevision)) {
          issueFailure(
            'GRANT_AUTHORITY_STALE',
            `authority revision ${next.authorityRevision} was already used; authority revisions are non-reusable — rotating back would re-current the grants bound to it (rotate to a fresh revision instead)`,
          );
        }
        const record: AuthorityRecord = {
          ...currentRecord,
          authorityRevision: next.authorityRevision,
          priorAuthorityRevisions: [
            ...(currentRecord.priorAuthorityRevisions ?? []),
            currentRecord.authorityRevision,
          ],
          updatedAt: requireInstant(this.#config.clock),
        };
        if (await this.#saveAuthorityRecordMutation(record, currentRecord)) return;
        if (attempt >= POLICY_MUTATION_CAS_ATTEMPTS) {
          issueFailure(
            'GRANT_CURRENTNESS_UNRESOLVABLE',
            `authority record moved concurrently on every rotation attempt; refusing after ${POLICY_MUTATION_CAS_ATTEMPTS} bounded retries (fail-closed)`,
          );
        }
        currentRecord = await this.#loadAuthorityOrThrow();
        await this.#parsePolicyRecordOrThrow(await this.#rawPolicyRecordOrThrow());
      }
    });
  }

  /**
   * Authority event: adopt a new ACTIVE policy revision. The snapshot binds to
   * the CURRENT AUTHORITY RECORD — not to a coherence-checked state — because
   * adoption is exactly the act that restores coherence after a rotation
   * (rotation alone leaves currentness deliberately UNRESOLVABLE).
   *
   * P1-02: policy revisions are globally non-reusable. Re-adopting a revision
   * — the currently active one or any superseded one — would reset its
   * revocation list and re-activate every grant still bound to it (revoked
   * grants resurrect); adoption is therefore refused for every revision in
   * the durable lineage. Each adoption carries the predecessor's revision
   * history and revocations forward, so revocation stays durable across
   * successor revisions. A corrupt predecessor refuses fail-closed.
   *
   * R1 (P1-A): a MISSING predecessor is first-ever bootstrap ONLY while the
   * authority record does not prove an earlier adoption. The first successful
   * adoption persists a durable `policyInitialized` marker in the authority
   * record — outside the policy slot it guards — BEFORE the snapshot write;
   * once marked, adoption over a missing policy record refuses fail-closed
   * (that state is storage loss, and sealing over it would resurrect revoked
   * grants and reset lineage).
   *
   * R3 (P1-A): absence is never bootstrap authority. Legacy revoked state
   * with zero grants is observationally identical to a truly virgin policy
   * slot, so ordinary adoption always refuses a missing predecessor. Initial
   * policy creation uses bootstrapPolicy() with a separately trusted ceremony.
   *
   * R1 (P1-B): the whole event runs on the single-writer tail, and the
   * snapshot write is a compare-and-save against the exact record this event
   * read; on a lost race the event re-reads and re-validates (revision
   * non-reuse included) against the fresh record, refusing typed after
   * bounded retries instead of clobbering a concurrent writer.
   */
  /**
   * Establish the FIRST policy only through an explicit trusted provisioning
   * ceremony. Ordinary adoptPolicy() never bootstraps from absence.
   *
   * The authorizer is injected at trusted composition and must validate a
   * one-shot proof protected independently from the mutable policy slot. This
   * method still re-checks authority/policy/grant state after an async
   * authorization decision and commits through the same CAS primitives, so a
   * race cannot turn a stale ceremony into a policy overwrite.
   */
  async bootstrapPolicy(snapshot: PolicyBootstrapSnapshot, proof: unknown): Promise<void> {
    await this.#serializeEvent(async () => {
      const authorizer = this.#config.bootstrapAuthorizer;
      if (!authorizer) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          'initial policy bootstrap is disabled: no trusted bootstrap authorizer is configured',
        );
      }

      const authorityBefore = await this.#loadAuthorityOrThrow();
      let rawPrior: unknown;
      try {
        rawPrior = await this.#config.state.loadCurrentPolicy();
      } catch (error) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          `current policy read failed during bootstrap: ${(error as Error).message}`,
        );
      }
      if (rawPrior !== null && rawPrior !== undefined) {
        issueFailure(
          'GRANT_POLICY_STALE',
          'initial policy bootstrap refused: a policy record already exists; use adoptPolicy for a successor revision',
        );
      }
      if (authorityBefore.policyInitialized === true || (await this.#config.grants.hasAnyGrant())) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          'initial policy bootstrap refused: durable state proves this authority was already initialized',
        );
      }

      let authorized = false;
      try {
        authorized = await authorizer({
          proof,
          authorityRecord: authorityBefore,
          snapshot,
        });
      } catch (error) {
        issueFailure(
          'GRANT_NOT_AUTHENTIC',
          `trusted bootstrap authorizer rejected the ceremony: ${(error as Error).message}`,
        );
      }
      if (!authorized) {
        issueFailure(
          'GRANT_NOT_AUTHENTIC',
          'trusted bootstrap authorizer rejected the initial policy ceremony',
        );
      }

      // The authorizer may perform I/O. Re-read EVERY durable premise after
      // it returns so a concurrent rotate/bootstrap/grant cannot be hidden by
      // the earlier snapshot.
      const authorityNow = await this.#loadAuthorityOrThrow();
      if (
        authorityNow.authorityId !== authorityBefore.authorityId ||
        authorityNow.authorityRevision !== authorityBefore.authorityRevision ||
        authorityNow.policyInitialized === true
      ) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          'authority state moved while the bootstrap ceremony was being authorized; obtain a fresh trusted ceremony',
        );
      }
      try {
        rawPrior = await this.#config.state.loadCurrentPolicy();
      } catch (error) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          `current policy re-read failed during bootstrap: ${(error as Error).message}`,
        );
      }
      if (rawPrior !== null && rawPrior !== undefined) {
        issueFailure(
          'GRANT_POLICY_STALE',
          'a policy appeared while the bootstrap ceremony was being authorized; bootstrap is no longer applicable',
        );
      }
      if (await this.#config.grants.hasAnyGrant()) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          'grant history appeared while the bootstrap ceremony was being authorized; refusing fail-closed',
        );
      }

      const markedAuthority = await this.#ensureInitializationMarker(authorityNow);
      if (
        markedAuthority.authorityId !== authorityBefore.authorityId ||
        markedAuthority.authorityRevision !== authorityBefore.authorityRevision
      ) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          'authority revision moved before initial policy persistence; refusing stale bootstrap',
        );
      }
      const initial: PolicySnapshotRecord = {
        policySnapshotRevision: snapshot.policySnapshotRevision,
        status: 'ACTIVE',
        authorityId: markedAuthority.authorityId,
        authorityRevision: markedAuthority.authorityRevision,
        revokedGrantIds: [],
        priorRevisions: [],
        rules: snapshot.rules,
        riskGuards: snapshot.riskGuards ?? [],
        updatedAt: requireInstant(this.#config.clock),
      };
      if (!(await this.#savePolicyMutation(initial, rawPrior))) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          `initial policy slot moved before commit of ${snapshot.policySnapshotRevision}; refusing instead of overwriting concurrent state`,
        );
      }
    });
  }

  async adoptPolicy(snapshot: PolicyBootstrapSnapshot): Promise<void> {
    await this.#serializeEvent(async () => {
      let rawPrior: unknown;
      try {
        rawPrior = await this.#config.state.loadCurrentPolicy();
      } catch (error) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          `current policy read failed: ${(error as Error).message}`,
        );
      }
      if (rawPrior === null || rawPrior === undefined) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          `current policy record is missing; ordinary adoption can never infer a virgin authority from absence (refusing ${snapshot.policySnapshotRevision}). Use an explicit trusted bootstrap ceremony for first provisioning, or restore the lost lineage`,
        );
      }

      for (let attempt = 1; ; attempt++) {
        if (rawPrior === null || rawPrior === undefined) {
          issueFailure(
            'GRANT_CURRENTNESS_UNRESOLVABLE',
            `current policy record disappeared during adoption of ${snapshot.policySnapshotRevision}; refusing fail-closed`,
          );
        }
        const authorityNow = await this.#ensureInitializationMarker(
          await this.#loadAuthorityOrThrow(),
        );
        const parsedPrior = PolicySnapshotRecordSchema.safeParse(rawPrior);
        if (!parsedPrior.success) {
          issueFailure(
            'GRANT_CURRENTNESS_UNRESOLVABLE',
            'current policy record is corrupt; refusing to adopt a new revision over unreadable state',
          );
        }
        const prior = parsedPrior.data;
        const usedRevisions = new Set([
          ...(prior.priorRevisions ?? []),
          prior.policySnapshotRevision,
        ]);
        if (usedRevisions.has(snapshot.policySnapshotRevision)) {
          issueFailure(
            'GRANT_POLICY_STALE',
            `policy revision ${snapshot.policySnapshotRevision} was already used; policy revisions are non-reusable — adopt a fresh revision (revocations and staleness stay durable)`,
          );
        }
        const snapshotRecord: PolicySnapshotRecord = {
          policySnapshotRevision: snapshot.policySnapshotRevision,
          status: 'ACTIVE',
          authorityId: authorityNow.authorityId,
          authorityRevision: authorityNow.authorityRevision,
          revokedGrantIds: [...prior.revokedGrantIds],
          priorRevisions: [...(prior.priorRevisions ?? []), prior.policySnapshotRevision],
          rules: snapshot.rules,
          riskGuards: snapshot.riskGuards ?? [],
          updatedAt: requireInstant(this.#config.clock),
        };
        if (await this.#savePolicyMutation(snapshotRecord, rawPrior)) return;
        if (attempt >= POLICY_MUTATION_CAS_ATTEMPTS) {
          issueFailure(
            'GRANT_CURRENTNESS_UNRESOLVABLE',
            `policy record moved concurrently on every adoption attempt; refusing to adopt ${snapshot.policySnapshotRevision} after ${POLICY_MUTATION_CAS_ATTEMPTS} bounded retries (fail-closed)`,
          );
        }
        try {
          rawPrior = await this.#config.state.loadCurrentPolicy();
        } catch (error) {
          issueFailure(
            'GRANT_CURRENTNESS_UNRESOLVABLE',
            `current policy read failed: ${(error as Error).message}`,
          );
        }
      }
    });
  }

  /**
   * Authority event: revoke the CURRENT policy revision in place. All grants bound to it become policy-revoked.
   * R1 (P1-B): serialized with the other events; the in-place status flip is
   * a compare-and-save against the exact record just read — a concurrent move
   * re-reads and re-flips the fresh record, or refuses typed after bounded
   * retries (a stale write may never resurrect a superseded status).
   */
  async revokePolicy(): Promise<void> {
    await this.#serializeEvent(async () => {
      let raw = await this.#rawPolicyRecordOrThrow();
      for (let attempt = 1; ; attempt++) {
        const record = this.#parsePolicyRecordOrThrow(raw);
        const next: PolicySnapshotRecord = {
          ...record,
          status: 'REVOKED',
          updatedAt: requireInstant(this.#config.clock),
        };
        if (await this.#savePolicyMutation(next, raw)) return;
        if (attempt >= POLICY_MUTATION_CAS_ATTEMPTS) {
          issueFailure(
            'GRANT_CURRENTNESS_UNRESOLVABLE',
            `policy record moved concurrently on every revocation attempt; refusing after ${POLICY_MUTATION_CAS_ATTEMPTS} bounded retries (fail-closed)`,
          );
        }
        raw = await this.#rawPolicyRecordOrThrow();
      }
    });
  }

  /**
   * Authority event: revoke one grant on the CURRENT policy's revocation list.
   * R1 (P1-B): serialized with the other events; the list append is a
   * compare-and-save against the exact record just read. A concurrent move
   * (e.g. another process adopting a successor) re-reads and re-applies the
   * revocation to the FRESH current record — the pre-fix last-write-wins
   * could roll the whole revision back, re-currenting unrevoked grants — and
   * an unwinnable race refuses typed after bounded retries.
   */
  async revokeGrant(grantId: string): Promise<void> {
    await this.#serializeEvent(async () => {
      let raw = await this.#rawPolicyRecordOrThrow();
      for (let attempt = 1; ; attempt++) {
        const record = this.#parsePolicyRecordOrThrow(raw);
        const next: PolicySnapshotRecord = record.revokedGrantIds.includes(grantId)
          ? { ...record, updatedAt: requireInstant(this.#config.clock) }
          : {
              ...record,
              revokedGrantIds: [...record.revokedGrantIds, grantId],
              updatedAt: requireInstant(this.#config.clock),
            };
        if (await this.#savePolicyMutation(next, raw)) return;
        if (attempt >= POLICY_MUTATION_CAS_ATTEMPTS) {
          issueFailure(
            'GRANT_CURRENTNESS_UNRESOLVABLE',
            `policy record moved concurrently on every revocation attempt for grant ${grantId}; refusing after ${POLICY_MUTATION_CAS_ATTEMPTS} bounded retries (fail-closed)`,
          );
        }
        raw = await this.#rawPolicyRecordOrThrow();
      }
    });
  }

  async #loadAuthorityOrThrow(): Promise<AuthorityRecord> {
    const parsed = AuthorityRecordSchema.safeParse(await this.#config.state.loadAuthorityRecord());
    if (!parsed.success) {
      throw new ShunContractError(
        'GRANT_CURRENTNESS_UNRESOLVABLE',
        'authority record missing or corrupt; cannot apply authority event',
      );
    }
    return parsed.data;
  }
}

function requireInstant(clock: () => string): string {
  const parsed = IsoDateTimeSchema.safeParse(clock());
  if (!parsed.success)
    throw new ShunContractError(
      'GRANT_MALFORMED',
      'authority clock returned a non-ISO 8601 UTC instant',
    );
  return parsed.data;
}
