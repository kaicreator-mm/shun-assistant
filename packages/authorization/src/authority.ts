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
 * R1 (P1-B): bounded retry budget for compare-and-save policy mutations.
 * Every attempt re-reads the fresh record and re-applies the mutation; if a
 * concurrent writer wins every generation the mutation refuses typed instead
 * of silently clobbering (fail-closed).
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
 */
export interface GrantRecordStore {
  put(record: StoredGrantRecord): Promise<void>;
  get(grantId: string): Promise<unknown>;
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
   */
  #mutationTail: Promise<unknown> = Promise.resolve();
  /**
   * R1 (P1-C): consumed issuance-proof nonces (nonce → expiry epoch ms).
   * Check-and-consume is SYNCHRONOUS, so the event loop can never interleave
   * two presentations of the same proof between the check and the set.
   */
  readonly #consumedIssuanceNonces = new Map<string, number>();

  constructor(config: AuthorizationAuthorityConfig) {
    if (config.integritySecret.length === 0) {
      throw new TypeError('AuthorizationAuthority requires a non-empty integritySecret');
    }
    if (config.issuanceSecret.length === 0) {
      throw new TypeError('AuthorizationAuthority requires a non-empty issuanceSecret');
    }
    this.#config = config;
    this.#grantTtlMs = config.grantTtlMs ?? DEFAULT_GRANT_TTL_MS;
    this.#newGrantId = config.newGrantId ?? (() => randomUUID());
  }

  /**
   * R1 (P1-C): single-use proof consumption. Synchronous check-and-set — no
   * await sits between the membership check and the insert, so two concurrent
   * presentations of the same proof cannot both pass. Expired nonces are
   * pruned opportunistically so the registry stays bounded by the live proof
   * window.
   */
  #consumeIssuanceNonce(nonce: string, expiresAtMs: number, nowMs: number): boolean {
    if (this.#consumedIssuanceNonces.size > 0) {
      for (const [seen, expiry] of this.#consumedIssuanceNonces) {
        if (expiry < nowMs) this.#consumedIssuanceNonces.delete(seen);
      }
    }
    if (this.#consumedIssuanceNonces.has(nonce)) return false;
    this.#consumedIssuanceNonces.set(nonce, expiresAtMs);
    return true;
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
   * R1 (P1-B): save a computed policy mutation only while the store still
   * holds exactly the record (or absence) this event last read. With a
   * CAS-capable store a lost race returns false and the caller re-reads and
   * retries (bounded); without one the write is a plain save — the instance
   * lock is then the only serialization, and cross-process atomicity remains
   * a store-adapter obligation.
   */
  async #savePolicyMutation(next: PolicySnapshotRecord, expectedPrior: unknown): Promise<boolean> {
    const store = this.#config.state;
    if (typeof store.compareAndSavePolicySnapshot === 'function') {
      return store.compareAndSavePolicySnapshot.call(store, next, expectedPrior);
    }
    await store.savePolicySnapshot(next);
    return true;
  }

  /**
   * R1 (P1-A): persist the durable initialization marker BEFORE the snapshot
   * it guards. Ordering is deliberate: a crash between marker and snapshot
   * bricks adoption (fail-closed, operator-visible), while the reverse order
   * would leave a window in which storage loss looks like a virgin store and
   * adoption resurrects revoked grants.
   */
  async #ensureInitializationMarker(authorityRecord: AuthorityRecord): Promise<void> {
    if (authorityRecord.policyInitialized === true) return;
    await this.#config.state.saveAuthorityRecord({
      ...authorityRecord,
      policyInitialized: true,
      updatedAt: requireInstant(this.#config.clock),
    });
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
    if (!this.#consumeIssuanceNonce(claims.nonce, Date.parse(claims.expiresAt), nowMs)) {
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
   * R1 (P1-A): the rewritten record carries the initialization marker forward
   * (a rotation never un-initializes lineage), and the event runs serialized
   * against the other authority events.
   */
  async rotateAuthority(next: { authorityRevision: string }): Promise<void> {
    await this.#serializeEvent(async () => {
      // Authority events are deliberate mutations of a readable domain: refuse
      // to act blindly on an unreadable/corrupt state.
      const currentRecord = await this.#loadAuthorityOrThrow();
      await this.#parsePolicyRecordOrThrow(await this.#rawPolicyRecordOrThrow());
      const record: AuthorityRecord = {
        ...currentRecord,
        authorityRevision: next.authorityRevision,
        updatedAt: requireInstant(this.#config.clock),
      };
      await this.#config.state.saveAuthorityRecord(record);
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
   * R1 (P1-B): the whole event runs on the single-writer tail, and the
   * snapshot write is a compare-and-save against the exact record this event
   * read; on a lost race the event re-reads and re-validates (revision
   * non-reuse included) against the fresh record, refusing typed after
   * bounded retries instead of clobbering a concurrent writer.
   */
  async adoptPolicy(snapshot: {
    policySnapshotRevision: string;
    rules: PolicySnapshotRecord['rules'];
    riskGuards?: PolicySnapshotRecord['riskGuards'];
  }): Promise<void> {
    await this.#serializeEvent(async () => {
      const authorityRecord = await this.#loadAuthorityOrThrow();
      let rawPrior: unknown;
      try {
        rawPrior = await this.#config.state.loadCurrentPolicy();
      } catch (error) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          `current policy read failed: ${(error as Error).message}`,
        );
      }
      const missingPrior = rawPrior === null || rawPrior === undefined;
      if (missingPrior && authorityRecord.policyInitialized === true) {
        issueFailure(
          'GRANT_CURRENTNESS_UNRESOLVABLE',
          `authority record proves an earlier policy adoption, but the current policy record is missing; this is durable-state loss, never a first bootstrap — adopt only after the lineage is restored (refusing ${snapshot.policySnapshotRevision}, fail-closed)`,
        );
      }
      // Marker precedes the snapshot write (see #ensureInitializationMarker).
      await this.#ensureInitializationMarker(authorityRecord);

      for (let attempt = 1; ; attempt++) {
        // Re-evaluate absence on EVERY attempt: a lost CAS race may reveal a
        // predecessor that appeared (a concurrent bootstrap — the successor
        // path then re-validates revision non-reuse against it) or one that
        // vanished mid-adoption (never sealable over in an initialized
        // authority). Only the initial read of a not-yet-initialized store
        // may ever bootstrap.
        const priorMissingNow = rawPrior === null || rawPrior === undefined;
        if (priorMissingNow && !(attempt === 1 && missingPrior)) {
          issueFailure(
            'GRANT_CURRENTNESS_UNRESOLVABLE',
            `current policy record is missing during adoption of ${snapshot.policySnapshotRevision}; an absent predecessor can only ever bootstrap a virgin store — refusing fail-closed`,
          );
        }
        let prior: PolicySnapshotRecord | undefined;
        if (!priorMissingNow) {
          const parsedPrior = PolicySnapshotRecordSchema.safeParse(rawPrior);
          if (!parsedPrior.success) {
            issueFailure(
              'GRANT_CURRENTNESS_UNRESOLVABLE',
              'current policy record is corrupt; refusing to adopt a new revision over unreadable state',
            );
          }
          prior = parsedPrior.data;
        }
        const usedRevisions = new Set([
          ...(prior?.priorRevisions ?? []),
          ...(prior ? [prior.policySnapshotRevision] : []),
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
          authorityId: authorityRecord.authorityId,
          authorityRevision: authorityRecord.authorityRevision,
          revokedGrantIds: prior ? [...prior.revokedGrantIds] : [],
          priorRevisions: prior
            ? [...(prior.priorRevisions ?? []), prior.policySnapshotRevision]
            : [],
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
