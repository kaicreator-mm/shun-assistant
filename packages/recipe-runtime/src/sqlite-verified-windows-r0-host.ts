// T04 fixed, private Windows R0 Host composition. No Recipe, model, UI or
// plugin may supply or replace the native effect or independent state oracle.
// This is a separate, explicit upgraded Host; conservative R0 remains the
// fallback for callers not admitted to this trust boundary.
import type { AuthorizedAction, ExecutionReceipt } from '@shun/contracts';
import {
  createSqliteAuthorizedRecipeEffectHost,
  type SqliteAuthorizedRecipeEffectHostOptions,
} from './index.ts';
import {
  type R0TaskSemanticVerdict,
  verifyR0SearchTaskSemantics,
} from './r0-task-semantic-verifier.ts';
import { SqliteR0EffectJournal } from './sqlite-r0-effect-journal.ts';
import {
  executeTrustedWindowsR0Search,
  type R0SearchEffectEvidence,
} from './trusted-windows-r0-effect.ts';

export type FixedVerifiedWindowsHostOptions = Omit<
  SqliteAuthorizedRecipeEffectHostOptions,
  'executeScopedSearch'
>;
type Observed = Readonly<{
  action: AuthorizedAction;
  receipt: ExecutionReceipt;
  evidence: R0SearchEffectEvidence;
}>;

const REFUSED: R0TaskSemanticVerdict = {
  ok: false,
  taskSemantic: 'UNCERTAIN',
  code: 'SEMANTIC_EVIDENCE_INCOMPLETE',
};

/**
 * The caller owns a real local ShunStore and ActionController. This factory
 * whitelists every option and ALWAYS installs the native+independent-Oracle
 * implementation. An extra JS executeScopedSearch property is ignored.
 *
 * Positive task semantics are not inferred from a successful effect: only
 * verifyTaskSemantics(), which independently re-reads the durable journal,
 * committed phase digest and actual bounded filesystem, can emit PASS.
 * Task evidence is single-use and in-memory: process crash loses the
 * capability to assert semantic PASS (fail closed, never replay).
 */
export function createSqliteVerifiedWindowsR0RecipeEffectHost(
  options: FixedVerifiedWindowsHostOptions,
) {
  try {
    const journal = new SqliteR0EffectJournal(options.store);
    const observed = new Map<string, Observed>();
    const host = createSqliteAuthorizedRecipeEffectHost({
      store: options.store,
      controller: options.controller,
      currentness: options.currentness,
      loadExpectedPlan: options.loadExpectedPlan,
      loadPlanByHash: options.loadPlanByHash,
      executeScopedSearch: async (action) => {
        // Bounded evidence memory; exhaustion degrades to journal UNCERTAIN.
        if (observed.size >= 128 || observed.has(action.taskId))
          throw new Error('R0_NATIVE_EFFECT_UNCERTAIN');
        let evidence: R0SearchEffectEvidence | null = null;
        const receipt = await executeTrustedWindowsR0Search(action, {
          phaseJournal: journal,
          evidenceSink: (value) => {
            evidence = value;
          },
        });
        if (receipt.terminal === 'SUCCEEDED' && evidence !== null) {
          observed.set(action.taskId, { action, receipt, evidence });
        }
        return receipt;
      },
    });
    return {
      readService: host.readService,
      runner: host.runner,
      verifyTaskSemantics: (taskId: string): R0TaskSemanticVerdict => {
        if (!taskId || typeof taskId !== 'string') return REFUSED;
        const saved = observed.get(taskId);
        if (!saved) return REFUSED;
        observed.delete(taskId);
        return verifyR0SearchTaskSemantics({ ...saved, journal });
      },
    };
  } catch {
    throw new Error('R0_VERIFIED_WINDOWS_HOST_BOOTSTRAP_REFUSED');
  }
}
