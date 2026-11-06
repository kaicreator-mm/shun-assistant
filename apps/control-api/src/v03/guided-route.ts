/**
 * Host-backed Guided State / Decision HTTP seam. The trusted composition
 * creates the port; untrusted HTTP can only read state or relay an answer.
 * No route can mint a grant, consent, Kernel Permit or effect command.
 */
import type {
  GuidedDecisionReceipt,
  HostGuidedService,
} from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import type { ComputerFolderObservationResult } from '../../../../packages/domain-computer/src/computer/folder-observation.ts';
import type { FolderSelectionResult } from './folder-selection-host.ts';
import type { V03FolderSelectionRoutePort } from './folder-selection-route.ts';

export type V03GuidedPort = Pick<HostGuidedService, 'state' | 'decide'>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export interface V03GuidedRoute {
  state(): ReturnType<V03GuidedPort['state']>;
  decide(raw: unknown): GuidedDecisionReceipt;
  selectRoot(): Promise<FolderSelectionResult>;
  folderObservation(): Promise<ComputerFolderObservationResult>;
  httpStatus(result: GuidedDecisionReceipt): number;
}

export function createV03GuidedRoute(
  port: V03GuidedPort,
  folderSelection?: V03FolderSelectionRoutePort,
): V03GuidedRoute {
  if (!port || typeof port.state !== 'function' || typeof port.decide !== 'function') {
    throw new TypeError('V03_GUIDED_HOST_UNAVAILABLE');
  }
  const state = port.state.bind(port);
  const decide = port.decide.bind(port);
  return Object.freeze({
    state,
    decide(raw: unknown) {
      const step = state().currentStep;
      if (
        step?.templateRef.artifactId === 'shun.guided.select-root' &&
        isRecord(raw) && raw.decision === 'ANSWER' &&
        isRecord(raw.outcome) && raw.outcome.event === 'USER_SUBMIT'
      ) {
        if (!folderSelection) return { status: 'REFUSED', code: 'FOLDER_SELECTION_UNAVAILABLE' };
        const validation = folderSelection.validateSelectionAnswer(raw, step);
        if (validation) return validation;
        const receipt = decide(raw);
        if (receipt.status === 'RECORDED') {
          return folderSelection.afterSelectionRecorded(raw, step, receipt);
        }
        return receipt;
      }
      return decide(raw);
    },
    async selectRoot() {
      if (!folderSelection) return { status: 'REFUSED', code: 'FOLDER_SELECTION_UNAVAILABLE' };
      return folderSelection.selectRoot();
    },
    async folderObservation() {
      if (!folderSelection) return { ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' };
      return folderSelection.observeCurrentSelectedFolder();
    },
    httpStatus(result: GuidedDecisionReceipt) {
      switch (result.status) {
        case 'RECORDED':
          return 200;
        case 'STALE':
          return 409;
        case 'REFUSED':
          return 422;
        case 'UNKNOWN':
          return 503;
      }
    },
  });
}
