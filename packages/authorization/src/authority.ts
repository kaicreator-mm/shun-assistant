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
import { type IssuanceProof, verifyIssuanceProof } from './issuance-proof.ts';
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
    if (!verifyIssuanceProof(this.#config.issuanceSecret, req, proof)) {
      issueFailure(
        'GRANT_NOT_AUTHENTIC',
        'issuance refused: caller presented no valid controller issuance proof; grants are issued only through the Action Controller',
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
    const nowParsed = IsoDateTimeSchema.safeParse(this.#config.clock());
    if (!nowParsed.success) {
      issueFailure('GRANT_MALFORMED', 'authority clock returned a non-ISO 8601 UTC instant');
    }
    const issuedAt = nowParsed.data;
    const expiresAt = new Date(Date.parse(issuedAt) + this.#grantTtlMs).toISOString();
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

  /** Authority event: rotate the authority revision (A1 → A2). Until a policy is adopted under the new revision, currentness is deliberately UNRESOLVABLE. */
  async rotateAuthority(next: { authorityRevision: string }): Promise<void> {
    // Authority events are deliberate mutations of a readable domain: refuse
    // to act blindly on an unreadable/corrupt state.
    const currentRecord = await this.#loadAuthorityOrThrow();
    await this.#loadPolicyOrThrow();
    const record: AuthorityRecord = {
      authorityId: currentRecord.authorityId,
      authorityRevision: next.authorityRevision,
      updatedAt: requireInstant(this.#config.clock),
    };
    await this.#config.state.saveAuthorityRecord(record);
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
   * successor revisions. A corrupt predecessor refuses fail-closed; an absent
   * one is the first-ever bootstrap adoption.
   */
  async adoptPolicy(snapshot: {
    policySnapshotRevision: string;
    rules: PolicySnapshotRecord['rules'];
    riskGuards?: PolicySnapshotRecord['riskGuards'];
  }): Promise<void> {
    const authorityRecord = await this.#loadAuthorityOrThrow();
    const rawPrior = await this.#config.state.loadCurrentPolicy();
    let prior: PolicySnapshotRecord | undefined;
    if (rawPrior !== null && rawPrior !== undefined) {
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
      priorRevisions: prior ? [...(prior.priorRevisions ?? []), prior.policySnapshotRevision] : [],
      rules: snapshot.rules,
      riskGuards: snapshot.riskGuards ?? [],
      updatedAt: requireInstant(this.#config.clock),
    };
    await this.#config.state.savePolicySnapshot(snapshotRecord);
  }

  /** Authority event: revoke the CURRENT policy revision in place. All grants bound to it become policy-revoked. */
  async revokePolicy(): Promise<void> {
    const record = await this.#loadPolicyOrThrow();
    await this.#config.state.savePolicySnapshot({
      ...record,
      status: 'REVOKED',
      updatedAt: requireInstant(this.#config.clock),
    });
  }

  /** Authority event: revoke one grant on the CURRENT policy's revocation list. */
  async revokeGrant(grantId: string): Promise<void> {
    const record = await this.#loadPolicyOrThrow();
    if (!record.revokedGrantIds.includes(grantId)) {
      record.revokedGrantIds = [...record.revokedGrantIds, grantId];
    }
    record.updatedAt = requireInstant(this.#config.clock);
    await this.#config.state.savePolicySnapshot(record);
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

  async #loadPolicyOrThrow(): Promise<PolicySnapshotRecord> {
    const parsed = PolicySnapshotRecordSchema.safeParse(
      await this.#config.state.loadCurrentPolicy(),
    );
    if (!parsed.success) {
      throw new ShunContractError(
        'GRANT_CURRENTNESS_UNRESOLVABLE',
        'current policy record missing or corrupt; cannot apply authority event',
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
