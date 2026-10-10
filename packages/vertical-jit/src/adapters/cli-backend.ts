// Real CLI task backend for the Loop B vertical: executes the acquired
// provider's command-line interface with typed argv (I1 interface class,
// L2 §8.1 EnvironmentBackend seam). Task output lands on disk as evidence;
// the receipt references the files, never inlines them.

import { join } from 'node:path';
import {
  type AuthorizedAction,
  type EnvironmentBackend,
  type EnvironmentFacts,
  type EnvironmentRequirements,
  ExecutionReceiptSchema,
  type Feasibility,
  type PreparedEnvironment,
  type ProviderCapabilityBinding,
  type ProviderEnvironmentBinding,
} from '@shun/contracts';
import type { FilesystemPort, ProcessPort } from '../ports.ts';

export interface CliTaskBackendDeps {
  readonly process: ProcessPort;
  readonly fs: FilesystemPort;
  readonly facts: EnvironmentFacts;
  readonly clock: () => string;
  readonly taskOutputDir: string;
  readonly timeoutMs?: number;
}

export class CliTaskBackend implements EnvironmentBackend {
  readonly #deps: CliTaskBackendDeps;

  constructor(deps: CliTaskBackendDeps) {
    this.#deps = deps;
  }

  async observe(): Promise<EnvironmentFacts> {
    return this.#deps.facts;
  }

  async canPrepare(requirements: EnvironmentRequirements): Promise<Feasibility> {
    const facts = this.#deps.facts;
    const rejectionReasons: Feasibility['rejectionReasons'] = [];
    if (requirements.backendKind !== facts.backendKind) {
      rejectionReasons.push('BACKEND_KIND_INELIGIBLE');
    }
    if (requirements.os && !facts.os.toLowerCase().startsWith(requirements.os.toLowerCase())) {
      rejectionReasons.push('PLATFORM_UNSUPPORTED');
    }
    if (requirements.guiSessionRequired && !facts.guiSession) {
      rejectionReasons.push('GUI_SESSION_UNAVAILABLE');
    }
    if (requirements.networkAccess === 'FORBIDDEN' && facts.networkPolicy === 'OPEN') {
      rejectionReasons.push('NETWORK_POLICY_FORBIDDEN');
    }
    return { feasible: rejectionReasons.length === 0, rejectionReasons };
  }

  async prepare(
    _binding: ProviderEnvironmentBinding | ProviderCapabilityBinding,
  ): Promise<PreparedEnvironment> {
    return {
      preparedEnvironmentId: `prepared-${this.#deps.facts.environmentId}`,
      environmentId: this.#deps.facts.environmentId,
    };
  }

  async execute(action: AuthorizedAction) {
    const parameters = action.action.parameters as { executable?: unknown; argv?: unknown };
    const executable = typeof parameters.executable === 'string' ? parameters.executable : '';
    const argv = Array.isArray(parameters.argv)
      ? parameters.argv.filter((entry): entry is string => typeof entry === 'string')
      : [];
    const startedAt = this.#deps.clock();
    if (!executable) {
      return this.#failedReceipt(action, startedAt);
    }
    const result = await this.#deps.process.run({
      argv: [executable, ...argv],
      timeoutMs: this.#deps.timeoutMs ?? 5 * 60_000,
    });
    const stdoutPath = join(this.#deps.taskOutputDir, 'stdout.txt');
    const stderrPath = join(this.#deps.taskOutputDir, 'stderr.txt');
    await this.#deps.fs.writeText(stdoutPath, result.stdout);
    await this.#deps.fs.writeText(stderrPath, result.stderr);
    const ok = result.exitCode === 0 && !result.timedOut;
    return ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: this.#deps.facts.environmentId,
      providerId: 'cli-task',
      providerVersion: 'task-execution',
      startedAt,
      finishedAt: this.#deps.clock(),
      terminal: ok ? 'SUCCEEDED' : 'FAILED',
      exitCode: result.exitCode,
      outputRefs: [stdoutPath, stderrPath],
      stdoutRef: stdoutPath,
      sideEffectEvidence: {
        sideEffectClass: action.action.sideEffectClass,
        recoveryClassification: 'COMPLETED_VERIFIED',
        postStateVerified: await this.#deps.fs.exists(stdoutPath),
      },
    });
  }

  #failedReceipt(action: AuthorizedAction, startedAt: string) {
    return ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: this.#deps.facts.environmentId,
      providerId: 'cli-task',
      providerVersion: 'task-execution',
      startedAt,
      finishedAt: this.#deps.clock(),
      terminal: 'FAILED',
      outputRefs: [],
      sideEffectEvidence: {
        sideEffectClass: action.action.sideEffectClass,
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        postStateVerified: true,
      },
    });
  }

  async cancel(_actionId: string): Promise<void> {
    /* the process port has no live handle exposure; timeouts bound the task */
  }

  async cleanup(_prepared: PreparedEnvironment): Promise<void> {
    /* task outputs are evidence — cleanup is deliberately not automatic */
  }
}
