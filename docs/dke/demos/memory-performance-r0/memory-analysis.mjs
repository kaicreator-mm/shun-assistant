const MISSING_METRICS = Object.freeze([
  'SYSTEM_COMMIT_BYTES',
  'SYSTEM_COMMIT_LIMIT',
  'PROCESS_PRIVATE_USAGE_BYTES',
  'PROCESS_PRIVATE_WORKING_SET_BYTES',
  'PAGEFILE_USAGE_AND_CAPACITY',
  'PAGES_INPUT_OUTPUT_RATE',
  'KERNEL_PAGED_NONPAGED_POOL',
  'COMPRESSED_MEMORY',
  'STABLE_PROCESS_INSTANCE_IDENTITY',
  'COMPARABLE_WORKLOAD_IDENTITY',
  'USER_RESPONSE_OR_THROUGHPUT_METRIC',
]);

function unknown(code, analyzedAt = new Date().toISOString()) {
  return {
    schema: 'shun.demo.memory-performance-report.v0',
    outcome: 'UNKNOWN',
    observedAt: 'UNKNOWN',
    sampledAt: 'UNKNOWN',
    analyzedAt,
    code,
    diagnosis: { status: 'UNKNOWN', rootCause: 'UNKNOWN' },
    optimizationPlan: { status: 'NOT_PRODUCED', effectsAuthorized: false, executed: false },
    verification: { status: 'UNKNOWN', speedupClaim: 'NONE' },
    privacy: { localOnly: true, externalDisclosures: [], processNamesRedacted: true },
  };
}

function validBytes(total, available) {
  return Number.isSafeInteger(total) && Number.isSafeInteger(available) &&
    total > 0 && available >= 0 && available <= total;
}

/**
 * Pure DIS-candidate assessment. It consumes the existing v0.3 read-only
 * collectors and never invokes a process/service/cache/pagefile effect.
 */
export function analyzeMemoryObservation(diagnosticResult, processResult, options = {}) {
  // A caller-provided observedAt/sampledAt is not a trusted Host sampling receipt.
  const analyzedAt = new Date().toISOString();
  const includeLocalProcessNames = options.includeLocalProcessNames === true;
  if (!diagnosticResult?.ok || !processResult?.ok) {
    const code = !diagnosticResult?.ok
      ? (diagnosticResult?.code ?? 'SYSTEM_OBSERVATION_UNAVAILABLE')
      : (processResult?.code ?? 'PROCESS_OBSERVATION_UNAVAILABLE');
    return unknown(code, analyzedAt);
  }
  const report = diagnosticResult.report;
  const facts = processResult.facts;
  if (
    report?.schema !== 'shun.windows-diagnostic-report.v02' ||
    report.status !== 'OBSERVED_ONLY' ||
    report.localOnly !== true ||
    !Array.isArray(report.externalDisclosures) ||
    report.externalDisclosures.length !== 0 ||
    facts?.schema !== 'shun.windows-top-memory.v02' ||
    facts.status !== 'OBSERVED_ONLY' ||
    facts.localOnly !== true ||
    !Array.isArray(facts.externalDisclosures) ||
    facts.externalDisclosures.length !== 0 ||
    facts.metric !== 'RESIDENT_MEMORY_BYTES_AT_SNAPSHOT' ||
    facts.interpretation !== 'MEMORY_ONLY_NO_CPU_OR_ROOT_CAUSE_INFERENCE' ||
    facts.provenance !== 'fixed-readonly-powershell' ||
    !Array.isArray(report.signals) ||
    !report.signals.every((x) => x === 'LOW_DISK_SPACE' || x === 'LOW_FREE_MEMORY') ||
    !Number.isSafeInteger(report.evidence?.processCount) || report.evidence.processCount < 0 ||
    !Number.isSafeInteger(report.evidence?.startupEntryCount) || report.evidence.startupEntryCount < 0 ||
    !validBytes(report.evidence?.memoryTotalBytes, report.evidence?.memoryFreeBytes) ||
    !Array.isArray(facts.top) ||
    facts.top.length < 1 ||
    facts.top.length > 8
  ) return unknown('INVALID_OR_INCOMPLETE_MEMORY_EVIDENCE', analyzedAt);

  let previous = Number.MAX_SAFE_INTEGER;
  const topResidentProcesses = [];
  for (let i = 0; i < facts.top.length; i += 1) {
    const entry = facts.top[i];
    if (
      !entry || typeof entry.name !== 'string' ||
      entry.name.length < 1 || entry.name.length > 64 ||
      !/^[\p{L}\p{N}_. ()-]+$/u.test(entry.name) ||
      !Number.isSafeInteger(entry.residentBytes) ||
      entry.residentBytes < 0 || entry.residentBytes > previous
    ) return unknown('INVALID_PROCESS_MEMORY_FACT', analyzedAt);
    previous = entry.residentBytes;
    const row = { rank: i + 1, localAlias: `PROCESS_${String(i + 1).padStart(2, '0')}`, residentWorkingSetBytes: entry.residentBytes };
    if (includeLocalProcessNames) row.localName = entry.name;
    topResidentProcesses.push(row);
  }

  const lowFreeSignal = report.signals.includes('LOW_FREE_MEMORY');
  return {
    schema: 'shun.demo.memory-performance-report.v0',
    outcome: 'OBSERVED_ONLY',
    observedAt: 'UNKNOWN',
    sampledAt: 'UNKNOWN',
    analyzedAt,
    source: {
      systemDiagnosisSchema: report.schema,
      processObservationSchema: facts.schema,
      processMetric: facts.metric,
      processInterpretation: facts.interpretation,
      aotRuleIds: [],
      aotRuleConsumption: 'NOT_APPLIED_BY_THIS_DEMO',
    },
    evidence: {
      memory: {
        totalBytes: report.evidence.memoryTotalBytes,
        freeMemoryObservedBytes: report.evidence.memoryFreeBytes,
        freeMemoryObservedRatio: report.evidence.memoryFreeBytes / report.evidence.memoryTotalBytes,
        meaning: 'Raw existing Node os.freemem field (memoryFreeBytes), not a separately measured Windows Available MBytes or complete pressure diagnosis.',
      },
      topResidentProcesses,
      processCount: report.evidence.processCount,
      startupEntryCount: report.evidence.startupEntryCount,
      signalSource: 'LEGACY_SINGLE_SNAPSHOT_DIAGNOSTIC',
    },
    diagnosis: {
      status: lowFreeSignal ? 'LOW_FREE_MEMORY_LEGACY_HEURISTIC' : 'NO_LEGACY_LOW_FREE_MEMORY_SIGNAL',
      confidence: 'SINGLE_SNAPSHOT_LIMITED',
      rootCause: 'UNKNOWN',
      leakStatus: 'NOT_ASSESSED_NO_TIME_SERIES_OR_STABLE_PROCESS_IDENTITY',
      explanation: lowFreeSignal
        ? 'The existing diagnostic threshold emitted LOW_FREE_MEMORY. This is a prompt for further investigation, not a confirmed root cause or proof of slow performance.'
        : 'No legacy LOW_FREE_MEMORY signal was emitted in this snapshot. This does not prove that the workload has no memory pressure.',
      missingMetrics: [...MISSING_METRICS],
    },
    optimizationPlan: {
      status: 'ADVISORY_ONLY',
      effectsAuthorized: false,
      executed: false,
      steps: lowFreeSignal
        ? [
            { id: 'REVIEW_CURRENT_WORKLOAD', effect: 'NONE', rationale: 'Establish which user workload is active before attributing memory use.' },
            { id: 'COLLECT_COMMIT_AND_PAGING_METRICS', effect: 'NONE', rationale: 'Current collector lacks commit, pagefile and paging-rate evidence.' },
            { id: 'REVIEW_TOP_RESIDENT_PROCESSES', effect: 'NONE', rationale: 'Ranking is Working Set only; do not terminate a process from this evidence.' },
            { id: 'CONSIDER_HARDWARE_CAPACITY_ONLY_AFTER_COMPATIBILITY_REVIEW', effect: 'NONE', rationale: 'A RAM upgrade requires sustained workload evidence and exact hardware compatibility.' },
          ]
        : [
            { id: 'NO_AUTOMATIC_OPTIMIZATION_FROM_SINGLE_SNAPSHOT', effect: 'NONE', rationale: 'No actionable memory optimization is justified by this observation alone.' },
            { id: 'COLLECT_WORKLOAD_EVIDENCE_IF_SLOWNESS_PERSISTS', effect: 'NONE', rationale: 'Compare memory, CPU, storage and user-visible latency under a known workload.' },
          ],
      prohibitedActions: ['PROCESS_TERMINATION','SERVICE_MUTATION','STARTUP_MUTATION','CACHE_OR_STANDBY_CLEAR','WORKING_SET_TRIM','PAGEFILE_CHANGE','REGISTRY_TUNING','HARDWARE_MUTATION'],
    },
    verification: {
      status: 'NOT_APPLICABLE_NO_SHUN_EFFECT_EXECUTED',
      speedupClaim: 'NONE',
      improvementComparison: 'UNKNOWN_UNTIL_TRUSTED_COMPARABLE_WORKLOAD_AND_USER_OUTCOME_METRIC',
    },
    privacy: {
      localOnly: true,
      externalDisclosures: [],
      processNamesRedacted: !includeLocalProcessNames,
      commandLinesCollected: false,
      processIdsCollected: false,
      userNamesCollected: false,
      pathsCollected: false,
    },
    limitations: [
      'WorkingSet64 is resident Working Set, not Private Bytes or system Commit.',
      'Top-eight process names are not stable process-instance identity.',
      'A single snapshot cannot establish a leak, root cause or speedup.',
      'The existing 10-percent low-free-memory threshold is a legacy heuristic, not a universal policy.',
      'This demo does not mutate the host and is not a production Shun capability.',
    ],
  };
}

/**
 * Comparison deliberately requires an explicit trusted comparator receipt.
 * A memory-only delta never qualifies as a user-visible performance improvement.
 */
/**
 * No trusted same-host/same-workload comparator issuer exists in this R0 demo.
 * An object shaped like a receipt is caller data, not proof of Host provenance.
 * Only DIS/Host integration may introduce a verified comparator port later.
 */
export function compareMemoryPerformance(_before, _after, _untrustedComparatorReceipt) {
  return {
    outcome: 'UNKNOWN',
    reason: 'INDEPENDENT_TRUSTED_WORKLOAD_COMPARATOR_NOT_IMPLEMENTED',
    speedupClaim: 'NONE',
  };
}
