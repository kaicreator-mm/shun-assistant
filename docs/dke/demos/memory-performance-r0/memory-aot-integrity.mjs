// Candidate AOT source integrity only. This is not SAP qualification or
// evidence that semantic rules were actually executed by this demo.
import {createHash} from 'node:crypto';

export const REVIEWED_AOT_GIT_BLOB = 'ccbb6b4d2f97e62cbecdade81405a73148ec29fb';

function gitBlob(raw) {
  const bytes = Buffer.from(raw, 'utf8');
  return createHash('sha1').update(Buffer.from('blob '+bytes.length+'\0')).update(bytes).digest('hex');
}

export function validateMemoryAotCandidate(raw) {
  if (typeof raw !== 'string' || gitBlob(raw) !== REVIEWED_AOT_GIT_BLOB)
    return {ok:false, code:'AOT_SOURCE_BLOB_MISMATCH'};
  let value;
  try { value = JSON.parse(raw); } catch {
    return {ok:false, code:'AOT_INVALID_JSON'};
  }
  const rules = value.sourceRules;
  const decisions = value.decisionRules;
  const expectedIds = Array.from({length:8},(_,i)=>'MEM-AOT-'+String(i+1).padStart(3,'0'));
  if (value.status !== 'DEMO_ONLY_CANDIDATE_NOT_QUALIFIED' ||
      value.productionConsumable !== false ||
      value.activation !== 'RESEARCH_DEMO_HARNESS_ONLY' ||
      !Array.isArray(rules) || rules.length !== 8 ||
      !Array.isArray(decisions) || decisions.length !== 6 ||
      expectedIds.some((id,i)=>rules[i]?.id!==id ||
        typeof rules[i]?.rule!=='string' || !rules[i].rule.trim() ||
        !Array.isArray(rules[i].sourceRefs) || !rules[i].sourceRefs.length)) {
    return {ok:false, code:'AOT_CONTRACT_MISMATCH'};
  }
  return {ok:true, gitBlob:REVIEWED_AOT_GIT_BLOB,
    integrity:'EXACT_CANDIDATE_BYTES_PINNED',
    semanticsConsumed:false, appliedRuleIds:[]};
}
