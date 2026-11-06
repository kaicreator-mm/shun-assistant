/** Host-only R04 folder selection adapter for the Guided HTTP route. */
import type { ComputerFolderObservationResult } from '../../../../packages/domain-computer/src/computer/folder-observation.ts';
import type { GuidedDecisionReceipt } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import type { FolderSelectionHostPort, FolderSelectionResult } from './folder-selection-host.ts';

export type V03FolderSelectionStep = Readonly<{
  stepId: string;
  taskId: string;
  journeyId: string;
  caseRef: unknown;
  templateRef: Readonly<{ digest: string; artifactId: string }>;
}>;

export interface V03FolderSelectionRoutePort {
  selectRoot(): Promise<FolderSelectionResult>;
  validateSelectionAnswer(raw: unknown, step: V03FolderSelectionStep): GuidedDecisionReceipt | null;
  afterSelectionRecorded(
    raw: unknown,
    step: V03FolderSelectionStep,
    receipt: GuidedDecisionReceipt,
  ): GuidedDecisionReceipt;
  observeCurrentSelectedFolder(): Promise<ComputerFolderObservationResult>;
}

export function createV03FolderSelectionRoute(
  host: FolderSelectionHostPort,
): V03FolderSelectionRoutePort {
  if (
    !host ||
    typeof host.selectRoot !== 'function' ||
    typeof host.validateSelectionAnswer !== 'function' ||
    typeof host.afterSelectionRecorded !== 'function' ||
    typeof host.observeCurrentSelectedFolder !== 'function'
  )
    throw new TypeError('V03_FOLDER_SELECTION_HOST_UNAVAILABLE');
  return Object.freeze({
    selectRoot: host.selectRoot.bind(host),
    validateSelectionAnswer: host.validateSelectionAnswer.bind(host),
    afterSelectionRecorded: host.afterSelectionRecorded.bind(host),
    observeCurrentSelectedFolder: host.observeCurrentSelectedFolder.bind(host),
  });
}
