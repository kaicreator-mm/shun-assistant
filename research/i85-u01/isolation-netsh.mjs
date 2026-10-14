// i85-U01 step 4a — Windows Firewall enforcement probe (mechanism
// exploration, NOT a U01 PASS). As a non-admin, attempt to add a uniquely
// named outbound block rule, expect ACCESS_DENIED, then prove the rule does
// NOT exist (no cleanup needed). All output recorded to events + _tmp.
import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { EVIDENCE_DIR, ensureDirs, logEvent, logNote, runCmd } from './lib/runner.mjs';

await ensureDirs();
const ruleName = `SHUN-U01-PROBE-${randomBytes(6).toString('hex')}`;
const evidence = { ruleName, mechanism: 'netsh advfirewall outbound block rule (non-admin attempt)' };

const add = await runCmd(
  'S4A-netsh-add-rule',
  'netsh',
  ['advfirewall', 'firewall', 'add', 'rule',
    `name=${ruleName}`,
    'dir=out',
    'action=block',
    'remoteip=192.0.2.0/24',
    'profile=any',
    'description=Shun i85-U01 non-admin enforcement probe (must be denied)'],
  { fullToTmp: 's4a-netsh-add.txt' },
);
evidence.addRule = { rc: add.rc, output: add.text.trim() };

const show = await runCmd(
  'S4A-netsh-show-rule',
  'netsh',
  ['advfirewall', 'firewall', 'show', 'rule', `name=${ruleName}`],
  { fullToTmp: 's4a-netsh-show.txt' },
);
evidence.showRule = { rc: show.rc, output: show.text.trim() };
evidence.ruleCreated = !/no rules match/i.test(show.text) && show.rc === 0;
evidence.verdict = add.rc !== 0 && !evidence.ruleCreated
  ? 'ENFORCEMENT_DENY_CONFIRMED: non-admin cannot add firewall rules; no rule leaked; no cleanup required'
  : add.rc === 0
    ? 'UNEXPECTED_RULE_CREATED — MUST clean up (investigate before any further claim)'
    : 'INCONCLUSIVE';
await logNote('S4A-verdict', { verdict: evidence.verdict, addRc: add.rc, ruleCreated: evidence.ruleCreated });

const outPath = resolve(EVIDENCE_DIR, 'isolation-netsh.json');
await writeFile(outPath, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
await logEvent('S4A-evidence-written', { cmd: `write ${outPath}`, rc: 0, stdout: outPath });
console.log(JSON.stringify(evidence, null, 2));
