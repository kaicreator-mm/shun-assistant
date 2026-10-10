// Semantic verifier for the JIT task step (L2 §4.7).
//
// The oracle is precommitted in the verification plan BEFORE execution
// (expectedVersion — the exact acquired provider version). Execution success
// without this verification passing can never become Task PASS.
import {
  ExecutionReceiptSchema,
  type VerificationInput,
  type VerificationReceipt,
  type VerifierPort,
} from '@shun/contracts';

export class PatternVerifier implements VerifierPort {
  async verify(input: VerificationInput): Promise<VerificationReceipt> {
    const receipt = ExecutionReceiptSchema.parse(input.executionReceipt);
    const expected = input.oracleInputs?.expectedVersion;
    const actual = input.oracleInputs?.actualStdout;
    const check = input.verificationPlan.checks[0];
    const checkId = check?.checkId ?? 'provider-task-observable';

    if (receipt.terminal !== 'SUCCEEDED') {
      return this.#receipt(input, checkId, 'FAIL', `execution terminal was ${receipt.terminal}`);
    }
    if (typeof expected !== 'string' || expected.length === 0) {
      return this.#receipt(input, checkId, 'INCOMPLETE', 'oracle has no expectedVersion');
    }
    if (typeof actual !== 'string' || actual.length === 0) {
      return this.#receipt(input, checkId, 'INCOMPLETE', 'no captured task output');
    }
    const passed = actual.includes(expected);
    return this.#receipt(
      input,
      checkId,
      passed ? 'PASS' : 'FAIL',
      passed
        ? `task output names the exact acquired version ${expected}`
        : `task output does not name the acquired version ${expected}`,
    );
  }

  #receipt(
    input: VerificationInput,
    checkId: string,
    status: VerificationReceipt['status'],
    detail: string,
  ): VerificationReceipt {
    const stdoutRef = ExecutionReceiptSchema.parse(input.executionReceipt).stdoutRef;
    return {
      taskId: input.taskId,
      verifierId: input.verificationPlan.verifierId,
      verifierRevision: input.verificationPlan.verifierRevision,
      status,
      checks: [{ checkId, status: status === 'PASS' ? 'PASS' : 'FAIL', detail }],
      oracleInputs: { ...input.oracleInputs },
      evidenceRefs: [...(stdoutRef ? [stdoutRef] : [])],
    };
  }
}
