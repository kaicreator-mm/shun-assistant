#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { analyzeMemoryObservation } from './memory-analysis.mjs';
import { validateMemoryAotCandidate } from './memory-aot-integrity.mjs';
import { consumePinnedResearchAot, researchAotConsumptionLabel } from './memory-aot-research-consumer-r9.mjs';

const args = process.argv.slice(2);
const includeLocalProcessNames = args.includes('--show-local-process-names');
if (args.some((x) => x !== '--show-local-process-names')) {
  process.stderr.write('Usage: node run-windows-memory-demo.mjs [--show-local-process-names]\n');
  process.exitCode = 2;
} else if (process.platform !== 'win32') {
  process.stdout.write(JSON.stringify({
    schema: 'shun.demo.memory-performance-runtime.v0',
    outcome: 'UNKNOWN',
    code: 'WINDOWS_REQUIRED',
    effectsAuthorized: false,
    externalDisclosures: [],
  }, null, 2) + '\n');
  process.exitCode = 2;
} else {
  try {
    const aotRaw = await readFile(new URL('./AOT_MEMORY_KNOWLEDGE_CANDIDATE_R0.json', import.meta.url), 'utf8');
    const aotIntegrity = validateMemoryAotCandidate(aotRaw);
    if (!aotIntegrity.ok) throw new Error(aotIntegrity.code);
    const aot = JSON.parse(aotRaw);
    const contract = JSON.parse(await readFile(new URL('./DIS_FUNCTION_CONTRACT_R0.json', import.meta.url), 'utf8'));
    if (aot.status !== 'DEMO_ONLY_CANDIDATE_NOT_QUALIFIED' || aot.productionConsumable !== false ||
        contract.status !== 'DIS_CONTRACT_CANDIDATE_NOT_QUALIFIED') {
      throw new Error('DEMO_ARTIFACT_STATUS_MISMATCH');
    }
    const { collectWindowsReadonlyDiagnosis, collectWindowsTopMemoryProcesses } =
      await import('../../../../packages/vertical-system/src/index.ts');
    const diagnostic = collectWindowsReadonlyDiagnosis();
    const topMemory = collectWindowsTopMemoryProcesses();
    const report = analyzeMemoryObservation(diagnostic, topMemory, { includeLocalProcessNames });
    const researchDecisionEvaluation = consumePinnedResearchAot(aotRaw, report);
    if (report.outcome === 'OBSERVED_ONLY' && researchDecisionEvaluation.outcome !== 'ADVISORY_ONLY') {
      throw new Error('RESEARCH_AOT_DECISION_CONSUMPTION_FAILED');
    }
    process.stdout.write(JSON.stringify({
      schema: 'shun.demo.memory-performance-runtime.v0',
      demoOnly: true,
      productFeature: false,
      aotPackage: {
        packageId: aot.packageId, packageVersion: aot.packageVersion,
        status: aot.status, activation: aot.activation,
        sourceGitBlob: aotIntegrity.gitBlob,
        integrity: aotIntegrity.integrity,
        sourceRulesApplied: [],
        researchDecisionRuleIdsMatched: researchDecisionEvaluation.matchedDecisionRuleIds,
        consumption: researchAotConsumptionLabel(researchDecisionEvaluation),
      },
      disPipeline: contract.pipeline.pipelineId,
      researchAotDecisionEvaluation: researchDecisionEvaluation,
      runtime: { platform: process.platform, arch: process.arch, nodeVersion: process.version, sourceCommit: '1224fea4097799467e2c0c454885e680f1f28248' },
      report,
      effectsAuthorized: false,
      externalDisclosures: [],
    }, null, 2) + '\n');
    if (report.outcome !== 'OBSERVED_ONLY') process.exitCode = 2;
  } catch {
    process.stdout.write(JSON.stringify({
      schema: 'shun.demo.memory-performance-runtime.v0',
      outcome: 'UNKNOWN',
      code: 'RUNTIME_ADAPTER_OR_DEMO_ARTIFACT_UNAVAILABLE',
      effectsAuthorized: false,
      externalDisclosures: [],
    }, null, 2) + '\n');
    process.exitCode = 2;
  }
}
