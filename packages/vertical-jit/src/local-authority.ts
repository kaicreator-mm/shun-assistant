// Local authorization substrate used by the vertical's test harness and the
// B-038 evidence run (L2 §4.6.1).
//
// This is a REAL implementation of the grant mechanics, not a stub of them:
// grants carry a genuine HMAC-SHA256 integrity envelope over the canonical
// grant form, `issue` refuses plans that are not in the trusted ledger, and
// the privileged boundary re-validates presentations against the CURRENT
// authority/policy state via the contracts' validateGrantPresentation. What
// is deliberately small is the substrate scope: an in-memory ledger/revocation
// list standing in for the durable ShunStore records a full deployment uses.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  type ActionPlan,
  type AuthorizationGrant,
  type CurrentAuthorityState,
  canonicalJson,
  type GrantIntegrityVerifier,
  type GrantIssueRequest,
  type GrantValidationInput,
  ShunContractError,
  validateGrantPresentation,
} from '@shun/contracts';
import type { PlanLedgerPort } from './ports.ts';

export class MemoryPlanLedger implements PlanLedgerPort {
  readonly #plans = new Map<string, ActionPlan>();

  async register(plan: ActionPlan): Promise<void> {
    this.#plans.set(plan.planHash, plan);
  }

  async byHash(planHash: string): Promise<ActionPlan | undefined> {
    return this.#plans.get(planHash);
  }

  get size(): number {
    return this.#plans.size;
  }
}

export interface LocalAuthorityOptions {
  readonly authorityId?: string;
  readonly authorityRevision?: string;
  readonly policySnapshotRevision?: string;
  readonly ledger?: PlanLedgerPort;
  readonly now?: () => string;
  readonly grantTtlMs?: number;
  /** Stable key for reproducible evidence; random when omitted. */
  readonly hmacKey?: string;
}

export class LocalAuthority {
  readonly ledger: PlanLedgerPort;
  readonly verifier: GrantIntegrityVerifier;
  readonly #now: () => string;
  readonly #ttlMs: number;
  readonly #key: Buffer;
  #current: CurrentAuthorityState;
  #counter = 0;

  constructor(options: LocalAuthorityOptions = {}) {
    this.ledger = options.ledger ?? new MemoryPlanLedger();
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#ttlMs = options.grantTtlMs ?? 15 * 60_000;
    this.#key = Buffer.from(options.hmacKey ?? randomBytes(32).toString('hex'), 'utf8');
    this.#current = {
      kind: 'CURRENT',
      authorityId: options.authorityId ?? 'shun.local-authority',
      authorityRevision: options.authorityRevision ?? 'auth-r1',
      policySnapshotRevision: options.policySnapshotRevision ?? 'pol-snap-r1',
      policyStatus: 'ACTIVE',
      revokedGrantIds: [],
    };
    this.verifier = (grant, envelope) => this.#verify(grant, envelope);
  }

  #sign(grant: Omit<AuthorizationGrant, 'integrity'>): string {
    return createHmac('sha256', this.#key).update(canonicalJson(grant), 'utf8').digest('hex');
  }

  #verify(grant: AuthorizationGrant, envelope: AuthorizationGrant['integrity']): boolean {
    if (envelope.scheme !== 'HMAC_SHA256') return false;
    const { integrity: _omitted, ...rest } = grant;
    const expected = this.#sign(rest);
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(envelope.value, 'utf8');
    return a.length === b.length && timingSafeEqual(a, b);
  }

  async issue(request: GrantIssueRequest): Promise<AuthorizationGrant> {
    // The authority only signs plans it can see in the trusted ledger.
    const plan = await this.ledger.byHash(request.planHash);
    if (!plan) {
      throw new ShunContractError(
        'GRANT_PLAN_MISMATCH',
        `plan ${request.planHash} is not registered in the trusted ledger — refusing to issue a grant`,
      );
    }
    if (request.authorizationKind === 'EXPLICIT_APPROVAL' && !request.approvalRef) {
      throw new ShunContractError(
        'GRANT_APPROVAL_REF_MISSING',
        'explicit-approval grants require the durable approval record reference',
      );
    }
    if (this.#current.kind !== 'CURRENT') {
      throw new ShunContractError(
        'GRANT_CURRENTNESS_UNRESOLVABLE',
        'authority cannot issue grants while its currentness record is unresolvable',
      );
    }
    this.#counter += 1;
    const issuedAt = this.#now();
    const expiresAt = new Date(Date.parse(issuedAt) + this.#ttlMs).toISOString();
    const base = {
      grantId: `grant-${this.#counter.toString().padStart(4, '0')}`,
      issuer: {
        authorityId: this.#current.authorityId,
        authorityRevision: this.#current.authorityRevision,
      },
      taskId: request.taskId,
      planHash: request.planHash,
      policySnapshotRevision: request.policySnapshotRevision,
      actionScope: request.actionScope,
      issuedAt,
      expiresAt,
      ...(request.approvalRef ? { approvalRef: request.approvalRef } : {}),
    };
    const grant: AuthorizationGrant = {
      ...base,
      integrity: { scheme: 'HMAC_SHA256', value: this.#sign(base) },
    };
    return grant;
  }

  async currentAuthority(): Promise<CurrentAuthorityState> {
    return this.#current;
  }

  /** The exact input the privileged boundary consumes (verifier included). */
  validationInput(
    presented: GrantValidationInput['grant'],
    plan: ActionPlan,
    action: GrantValidationInput['action'],
    now: string,
  ): Omit<GrantValidationInput, 'now'> & { now: string } {
    return {
      grant: presented,
      plan,
      action,
      currentAuthority: this.#current,
      now,
      verifyIntegrity: this.verifier,
    };
  }

  // ---- negative seams (used by fail-closed tests and evidence runs) ----

  /** A new policy revision supersedes grants issued under the old snapshot. */
  supersedePolicy(revision: string): void {
    if (this.#current.kind !== 'CURRENT') throw new Error('currentness is unresolvable');
    this.#current = { ...this.#current, policySnapshotRevision: revision, policyStatus: 'ACTIVE' };
  }

  revokePolicy(): void {
    if (this.#current.kind !== 'CURRENT') throw new Error('currentness is unresolvable');
    this.#current = { ...this.#current, policyStatus: 'REVOKED' };
  }

  rotateAuthority(revision: string): void {
    if (this.#current.kind !== 'CURRENT') throw new Error('currentness is unresolvable');
    this.#current = { ...this.#current, authorityRevision: revision };
  }

  revokeGrant(grantId: string): void {
    if (this.#current.kind !== 'CURRENT') throw new Error('currentness is unresolvable');
    this.#current = {
      ...this.#current,
      revokedGrantIds: [...this.#current.revokedGrantIds, grantId],
    };
  }

  corruptCurrentness(reason: string): void {
    this.#current = { kind: 'UNRESOLVABLE', reason };
  }

  /** Full independent boundary check against the CURRENT substrate state. */
  validatePresentation(
    input: Omit<GrantValidationInput, 'currentAuthority' | 'verifyIntegrity' | 'now'> & {
      now: string;
    },
  ): ReturnType<typeof validateGrantPresentation> {
    return validateGrantPresentation({
      ...input,
      currentAuthority: this.#current,
      verifyIntegrity: this.verifier,
    });
  }
}
