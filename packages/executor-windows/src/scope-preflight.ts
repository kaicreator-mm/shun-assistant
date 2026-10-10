// Scope preflight: grant-scope containment for EVERY declared path/key,
// checked in the validation phase — before any side effect — by BOTH the
// in-process backend and the privileged helper. Execution re-checks at touch
// time (TOCTOU bound); this pass guarantees a scope escape is a structured
// REFUSED receipt, never a mid-run FAILED with partial effects.
import { pathWithin } from '@shun/contracts';
import { resolveWithinScope } from './fs-safety.ts';
import type { InterpreterScope } from './interpreter.ts';
import type { ExecutorStep } from './ops.ts';

/** Returns a refusal reason when a declared target escapes the grant scope, or undefined when all targets are contained. */
export function preflightScope(step: ExecutorStep, scope: InterpreterScope): string | undefined {
  switch (step.op) {
    case 'windows.fs.write':
    case 'windows.fs.delete':
    case 'windows.fs.verify': {
      const prefixes = scope.filesystem
        ? [...scope.filesystem.read, ...scope.filesystem.write]
        : [];
      const within = resolveWithinScope(step.args.path, prefixes);
      return within.ok ? undefined : within.reason;
    }
    case 'windows.registry.createKey':
    case 'windows.registry.setValue':
    case 'windows.registry.deleteKey':
    case 'windows.registry.verify': {
      const prefixes = scope.registry?.write ?? [];
      if (prefixes.length === 0)
        return 'grant declares no registry scope but the action touches the registry';
      return prefixes.some((p) => pathWithin(step.args.key, p))
        ? undefined
        : `registry key outside declared scope: ${step.args.key}`;
    }
    case 'windows.proc.exec': {
      // The program is plan-pinned (hash-bound) infrastructure; existence is
      // checked at execution. It is not grant-scope bound by frozen contracts.
      return undefined;
    }
    case 'windows.proc.contextCheck':
      return undefined;
  }
}
