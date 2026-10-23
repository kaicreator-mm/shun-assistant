// T04 private mediation: reserve BEFORE an authorized R0 search effect,
// and fail closed on every ambiguous/replayed/invalid receipt. It is never
// a grant issuer, native search implementation or semantic PASS oracle.
// The caller MUST compose this only behind the independent SQLite grant gate.
import { createHash } from 'node:crypto';
import {
  type AuthorizedAction,
  AuthorizedActionSchema,
  canonicalJson,
  ExecutionReceiptSchema,
} from '@shun/contracts';

export type R0SearchJournalPort = Readonly<{
  reserve: (action: AuthorizedAction) => { ok: boolean };
  recordObservation: (
    action: AuthorizedAction,
    state: 'OBSERVED_NOT_SEMANTICALLY_VERIFIED' | 'UNCERTAIN',
    receiptSha256: string,
  ) => boolean;
}>;

export type JournaledR0SearchConfig = Readonly<{
  journal: R0SearchJournalPort;
  /** The trusted host's handle-anchored OS search, never the model/Recipe. */
  effect: (action: AuthorizedAction) => Promise<unknown>;
}>;

const ERROR = 'R0_JOURNALED_SEARCH_UNCERTAIN';
const UNKNOWN_DIGEST = createHash('sha256').update(ERROR).digest('hex');

export class JournaledR0SearchCapability {
  private readonly journal: R0SearchJournalPort;
  private readonly effect: JournaledR0SearchConfig['effect'];

  constructor(options: JournaledR0SearchConfig) {
    if (
      !options?.journal ||
      typeof options.journal.reserve !== 'function' ||
      typeof options.journal.recordObservation !== 'function' ||
      typeof options.effect !== 'function'
    )
      throw new Error('R0_JOURNALED_SEARCH_CONFIG_REFUSED');
    this.journal = options.journal;
    this.effect = options.effect;
  }

  async execute(raw: AuthorizedAction): Promise<unknown> {
    try {
      const parsed = AuthorizedActionSchema.safeParse(raw);
      if (!parsed.success) throw new Error(ERROR);
      const action = parsed.data;
      if (
        action.action.op !== 'file.search' ||
        action.action.sideEffectClass !== 'R0' ||
        action.action.requiredPrivilege !== 'USER' ||
        action.action.filesystemScope?.read.length !== 1 ||
        action.action.filesystemScope.write.length !== 0 ||
        action.action.networkScope !== undefined ||
        action.action.registryScope !== undefined ||
        (action.action.secretRefs?.length ?? 0) !== 0
      )
        throw new Error(ERROR);

      // The *real* journal implementation must durably COMMIT STARTED before
      // this returns. A duplicate or ambiguous previous STARTED never replays.
      const reserved = this.journal.reserve(action);
      if (!reserved?.ok) throw new Error(ERROR);

      let output: unknown;
      try {
        output = await this.effect(action);
      } catch {
        // Even if this write fails, the prior STARTED remains an UNKNOWN
        // that cannot be auto-replayed. Never issue a second OS call.
        this.tryRecord(action, 'UNCERTAIN', UNKNOWN_DIGEST);
        throw new Error(ERROR);
      }

      const receipt = ExecutionReceiptSchema.safeParse(output);
      if (
        !receipt.success ||
        receipt.data.actionId !== action.actionId ||
        receipt.data.terminal !== 'SUCCEEDED' ||
        receipt.data.sideEffectEvidence.sideEffectClass !== 'R0' ||
        // L2 9.4: positive observation requires independent post-state proof.
        // NOT_STARTED / FAILED_BEFORE_EFFECT contradict terminal=SUCCEEDED.
        // MAY_HAVE_EXECUTED_UNCERTAIN must remain UNKNOWN, not OBSERVED.
        receipt.data.sideEffectEvidence.postStateVerified !== true ||
        receipt.data.sideEffectEvidence.recoveryClassification !== 'COMPLETED_VERIFIED'
      ) {
        this.tryRecord(action, 'UNCERTAIN', UNKNOWN_DIGEST);
        throw new Error(ERROR);
      }
      // COMPLETED_VERIFIED is privileged *effect post-state* evidence, not
      // the task's separate semantic oracle. No task PASS is minted here.
      // Store only a digest, not file names or user content.
      const digest = createHash('sha256').update(canonicalJson(receipt.data)).digest('hex');
      if (!this.journal.recordObservation(action, 'OBSERVED_NOT_SEMANTICALLY_VERIFIED', digest))
        throw new Error(ERROR);
      return receipt.data;
    } catch {
      // Neither the OS search port nor journal errors may leak local paths.
      throw new Error(ERROR);
    }
  }

  private tryRecord(action: AuthorizedAction, state: 'UNCERTAIN', digest: string): void {
    try {
      this.journal.recordObservation(action, state, digest);
    } catch {
      // STARTED remains the conservative durable decision.
    }
  }
}
