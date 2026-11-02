/**
 * The R04 UI's safe, pure Windows observation projection.
 *
 * Only allowlisted aggregate fields from the existing trusted read-only Host
 * contracts reach the visual surface. Never enumerate a raw report/DTO into
 * HTML, because future Host fields may carry local paths or other secrets.
 */
const PROVENANCE = 'node:os+node:fs:statfs';

/** @param {number} total @param {number} free */
function bytesValid(total, free) {
  return Number.isSafeInteger(total) && total > 0 &&
    Number.isSafeInteger(free) && free >= 0 && free <= total;
}

/** @param {any} value */
function inventoryValid(value) {
  return value && typeof value === 'object' &&
    value.schema === 'shun.system-inventory.v02' &&
    value.platform === 'win32' && value.provenance === PROVENANCE &&
    value.localOnly === true && Array.isArray(value.externalDisclosures) &&
    value.externalDisclosures.length === 0 &&
    Number.isSafeInteger(value.cpuLogicalCount) &&
    value.cpuLogicalCount >= 1 && value.cpuLogicalCount <= 4096 &&
    bytesValid(value.memoryTotalBytes, value.memoryFreeBytes) &&
    bytesValid(value.diskTotalBytes, value.diskFreeBytes);
}

/** Format an observed byte count for ordinary users, not as a causal claim. */
/** @param {number} bytes */
export function formatGib(bytes) {
  if (!Number.isSafeInteger(bytes) || bytes < 0) return null;
  return (bytes / 1073741824).toFixed(1) + ' GiB';
}

/** @param {any} evidence */
function metrics(evidence) {
  return [
    { key: 'cpu', value: String(evidence.cpuLogicalCount) },
    { key: 'memory', value: formatGib(evidence.memoryFreeBytes) + ' / ' +
      formatGib(evidence.memoryTotalBytes) },
    { key: 'storage', value: formatGib(evidence.diskFreeBytes) + ' / ' +
      formatGib(evidence.diskTotalBytes) },
  ];
}

/** @param {string} code @returns {{status:'REFUSED',code:string}} */
function invalid(code) { return { status: 'REFUSED', code }; }

/**
 * @param {string} kind
 * @param {any} value Raw actual loopback API body (validated before projection).
 * @returns {{status: 'OBSERVED', metrics: {key:string,value:string}[],
 *   signals: string[], counts: {key:string,value:string}[] } |
 *   {status: 'REFUSED',code:string}}
 */
export function projectLocalObservation(kind, value) {
  if (kind !== 'inventory' && kind !== 'diagnosis') return invalid('MODE_UNSUPPORTED');
  if (!value || typeof value !== 'object' || value.ok !== true ||
      value.source !== 'LIVE_WINDOWS_LOCAL_READONLY') return invalid('SOURCE_UNVERIFIED');

  if (kind === 'inventory') {
    if (!value.localOnly || !Array.isArray(value.externalDisclosures) ||
        value.externalDisclosures.length !== 0 ||
        !inventoryValid(value.snapshot)) return invalid('INVENTORY_INVALID');
    return { status: 'OBSERVED', metrics: metrics(value.snapshot), signals: [], counts: [] };
  }

  const report = value.report;
  if (!report || typeof report !== 'object' ||
      report.schema !== 'shun.windows-diagnostic-report.v02' ||
      report.status !== 'OBSERVED_ONLY' || report.localOnly !== true ||
      !Array.isArray(report.externalDisclosures) ||
      report.externalDisclosures.length !== 0 ||
      value.cloudCalls !== 0 || value.recipeExecuted !== false ||
      report.limitation !== 'SINGLE_SNAPSHOT_NO_ROOT_CAUSE_OR_SPEEDUP_CLAIM' ||
      !report.evidence || typeof report.evidence !== 'object' ||
      report.evidence.inventoryProvenance !== PROVENANCE ||
      report.evidence.runtimeProvenance !== 'fixed-readonly-powershell' ||
      !inventoryValid({
        ...report.evidence, schema:'shun.system-inventory.v02', platform:'win32',
        provenance:report.evidence.inventoryProvenance,
        localOnly:true, externalDisclosures:[]
      }) ||
      !Number.isSafeInteger(report.evidence.processCount) ||
      report.evidence.processCount < 0 ||
      !Number.isSafeInteger(report.evidence.startupEntryCount) ||
      report.evidence.startupEntryCount < 0 ||
      !Array.isArray(report.signals) ||
      report.signals.some(x => !['LOW_DISK_SPACE', 'LOW_FREE_MEMORY'].includes(x))) {
    return invalid('DIAGNOSIS_INVALID');
  }
  return {
    status: 'OBSERVED',
    metrics: metrics(report.evidence),
    signals: [...new Set(report.signals)],
    counts: [
      { key:'processes', value:String(report.evidence.processCount) },
      { key:'startup', value:String(report.evidence.startupEntryCount) },
    ]
  };
}

/** Validate saved, immutable built-in Recipe status without exposing its SHA. */
/** @param {any} value */
export function projectRoutineState(value) {
  if (!value || typeof value !== 'object' || value.ok !== true ||
      value.recipeId !== 'shun.builtin.system-inventory.readonly.v02' ||
      value.executionAuthorized !== false || value.modelCalls !== 0 ||
      typeof value.saved !== 'boolean') return invalid('ROUTINE_STATUS_UNVERIFIED');
  if (value.saved && (value.state !== 'PERSISTED_CANDIDATE_ONLY' ||
      typeof value.revisionSha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(value.revisionSha256))) return invalid('ROUTINE_REVISION_INVALID');
  if (!value.saved && (value.state !== 'NOT_SAVED' ||
      value.revisionSha256 !== null)) return invalid('ROUTINE_STATE_INVALID');
  return { status: 'OBSERVED', saved: value.saved };
}

/**
 * True read-only Recipe execution is a separate Host-controlled path.
 * Unlike /api/system/inventory it has no "source" field. Check the complete
 * immutable Recipe receipt before showing a verified local observation.
 * @param {any} value
 */
export function projectRoutineExecution(value) {
  if (!value || typeof value !== 'object' || value.ok !== true ||
      value.status !== 'VERIFIED_READONLY_OBSERVATION' ||
      value.recipeExecuted !== true || value.modelCalls !== 0 ||
      !Array.isArray(value.externalDisclosures) ||
      value.externalDisclosures.length !== 0 ||
      value.recipeId !== 'shun.builtin.system-inventory.readonly.v02' ||
      typeof value.revisionSha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(value.revisionSha256) ||
      typeof value.planHash !== 'string' ||
      !/^[a-f0-9]{64}$/.test(value.planHash) ||
      !inventoryValid(value.snapshot)) return invalid('ROUTINE_EXECUTION_UNVERIFIED');
  return { status: 'OBSERVED', metrics: metrics(value.snapshot),
    signals: [], counts: [] };
}

/**
 * Exact disclosure preview is local-only: no consent, grant or cloud send.
 * Keep the original projectionJson bytes unchanged in the UI.
 * @param {any} value
 */
export function projectDisclosurePreview(value) {
  if (!value || typeof value !== 'object' || value.ok !== true ||
      value.status !== 'LOCAL_PREVIEW_ONLY' ||
      value.consentIssued !== false || value.cloudSendAllowed !== false ||
      value.privateBrokerReady !== false ||
      typeof value.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.sha256) ||
      typeof value.projectionJson !== 'string' ||
      value.projectionJson.length === 0 || value.projectionJson.length > 16384) {
    return invalid('DISCLOSURE_PREVIEW_UNVERIFIED');
  }
  return {status:'OBSERVED', projectionJson:value.projectionJson};
}
