import { describe, expect, it } from 'vitest';
import {
  AMBIGUITY_DISPOSITIONS,
  AUTHORIZATION_KINDS,
  EXECUTION_TERMINALS,
  IMAGE_BATCH_FAILURES,
  INTERFACE_CLASSES,
  JIT_LIFECYCLE_FAILURES,
  RECIPE_CURRENTNESS,
  RECIPE_LIFECYCLE_STATES,
  RECOVERY_CLASSIFICATIONS,
  RESOLUTION_FAILURES,
  RISK_CLASSES,
  ShunContractError,
  STORAGE_DIAGNOSE_FAILURES,
  TASK_STATES,
  VERIFICATION_STATUSES,
} from '../src/taxonomy.ts';

describe('frozen taxonomy sets are exactly the documented codes', () => {
  it('ambiguity dispositions (L2 §4.1)', () => {
    expect([...AMBIGUITY_DISPOSITIONS]).toEqual([
      'READY',
      'NEEDS_CLARIFICATION',
      'UNRESOLVED_OBJECT',
      'UNRESOLVED_CAPABILITY',
      'VERIFICATION_UNSPECIFIABLE',
      'POLICY_BLOCKED',
    ]);
  });

  it('shared resolution failures (Product C-000)', () => {
    expect([...RESOLUTION_FAILURES]).toEqual([
      'GOAL_AMBIGUOUS',
      'OBJECT_UNRESOLVED',
      'CAPABILITY_UNRESOLVED',
      'NO_TRUSTED_PROVIDER',
      'NO_FEASIBLE_BINDING',
      'POLICY_BLOCKED',
      'VERIFICATION_UNSPECIFIABLE',
      'REGISTRY_CURRENTNESS_INSUFFICIENT',
    ]);
  });

  it('image.batch_process failures (Product C-001)', () => {
    expect([...IMAGE_BATCH_FAILURES]).toEqual([
      'UNSUPPORTED_INPUT',
      'DECODE_FAILED',
      'OUTPUT_COLLISION',
      'METADATA_LOST',
      'QUALITY_ORACLE_FAILED',
      'OUTPUT_VERIFY_FAILED',
    ]);
  });

  it('software.jit_capability_lifecycle failures (Product C-002)', () => {
    expect([...JIT_LIFECYCLE_FAILURES]).toEqual([
      'PROVENANCE_UNKNOWN',
      'ACQUISITION_FAILED',
      'INSTALL_FAILED',
      'TASK_FAILED',
      'TASK_VERIFY_FAILED',
      'R2_GATE_MISSING',
      'RESIDUE_UNKNOWN',
      'USER_ASSET_AT_RISK',
      'REMOVE_FAILED',
      'POST_REMOVE_VERIFY_FAILED',
    ]);
  });

  it('system.storage.diagnose_bounded_action failures (Product C-003)', () => {
    expect([...STORAGE_DIAGNOSE_FAILURES]).toEqual([
      'GROWTH_NOT_ATTRIBUTED',
      'DATA_CLASSIFICATION_UNKNOWN',
      'R2_GATE_MISSING',
      'PROTECTED_ASSET_TOUCHED',
      'RECLAIM_NOT_VERIFIED',
      'ACTION_NOT_BOUNDED',
    ]);
  });

  it('risk classes (L2 §9.2)', () => {
    expect([...RISK_CLASSES]).toEqual(['R0', 'R1', 'R2', 'R3']);
  });

  it('interface classes (Product contracts)', () => {
    expect([...INTERFACE_CLASSES]).toEqual(['I0', 'I1', 'I2', 'I3', 'I4']);
  });

  it('recovery classifications (L2 §9.4)', () => {
    expect([...RECOVERY_CLASSIFICATIONS]).toEqual([
      'NOT_STARTED',
      'FAILED_BEFORE_EFFECT',
      'MAY_HAVE_EXECUTED_UNCERTAIN',
      'COMPLETED_VERIFIED',
    ]);
  });

  it('task workflow states (L2 §5.1)', () => {
    expect([...TASK_STATES]).toEqual([
      'RECEIVED',
      'INTERPRETING',
      'CLARIFICATION',
      'RESOLVING',
      'PLANNED',
      'AWAITING_AUTHORIZATION',
      'EXECUTING',
      'VERIFYING',
      'LIFECYCLE_RECONCILIATION',
      'SUCCEEDED',
      'FAILED',
      'CANCELLED',
      'NEEDS_INTERVENTION',
    ]);
  });

  it('execution terminals (L2 §4.7, §8.2.1)', () => {
    expect([...EXECUTION_TERMINALS]).toEqual([
      'SUCCEEDED',
      'FAILED',
      'REFUSED',
      'CANCELLED',
      'TIMED_OUT',
      'UAC_DECLINED',
      'UNCERTAIN',
    ]);
  });

  it('verification statuses (L2 §4.7)', () => {
    expect([...VERIFICATION_STATUSES]).toEqual(['PASS', 'FAIL', 'INCOMPLETE']);
  });

  it('authorization kinds (L2 §4.6)', () => {
    expect([...AUTHORIZATION_KINDS]).toEqual(['AUTOMATIC', 'EXPLICIT_APPROVAL', 'DURABLE_POLICY']);
  });

  it('recipe currentness and lifecycle (L2 §6.9)', () => {
    expect([...RECIPE_CURRENTNESS]).toEqual(['CURRENT', 'STALE', 'INAPPLICABLE', 'UNKNOWN']);
    expect([...RECIPE_LIFECYCLE_STATES]).toEqual(['CANDIDATE', 'ACTIVE', 'QUARANTINED', 'RETIRED']);
  });
});

describe('ShunContractError', () => {
  it('carries its typed code', () => {
    const error = new ShunContractError('GRANT_EXPIRED', 'expired');
    expect(error.code).toBe('GRANT_EXPIRED');
    expect(error.name).toBe('ShunContractError');
    expect(error).toBeInstanceOf(Error);
  });
});
