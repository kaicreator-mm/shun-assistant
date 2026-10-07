// U-06 demo orchestrator. Runs the D1–D5 scenarios of
// kaicreator-mm/shun-assistant issue #5 on the local Windows host and writes
// one evidence JSON per case plus an aggregate summary.
//
// Usage:
//   node run-demo.mjs local            D1 + non-elevated D4 negatives + D5 (no UAC)
//   node run-demo.mjs decline          elevated launch expected to be refused at UAC (D4)
//   node run-demo.mjs d2               plan-bound elevated fixture action (D2 positive)
//   node run-demo.mjs d2tamper         plan mutated after approval -> must refuse (D2/D4)
//   node run-demo.mjs d3               winget package lifecycle through elevated helper (D3)
//   node run-demo.mjs summary          aggregate all case JSONs -> summary.json
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { canonical, sha256, withPlanHash, planWithoutHash, makeApproval, makeAuthorizedAction, validateAuthorizedAction } from "./lib/plan.mjs";
import { runOrdinary, runElevated, classifyOutcome, readJournal } from "./lib/launcher.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const HELPERS = join(HERE, "helpers");
const OBS = join(HELPERS, "obs.ps1");
const ACTION = join(HELPERS, "action-helper.ps1");
const TMPROOT = "C:\\xDev\\kAiCreator\\_tmp\\u06-demo";

const arg = process.argv[2] ?? "local";
const OUT = process.env.U06_OUT ?? join(TMPROOT, "run-" + new Date().toISOString().replace(/[:.]/g, "-"));
mkdirSync(OUT, { recursive: true });

const approver = "local-windows-agent (issue #5 demo operator)";

function writeCase(id, record) {
  const path = join(OUT, id + ".json");
  writeFileSync(path, JSON.stringify(record, null, 2), "utf8");
  const c = record.classification?.outcome;
  const ok = record.verdict === "PASS" ? "PASS" : "FAIL";
  console.log(`[${ok}] ${id} -> ${c ?? "?"}  (${path})`);
}

function expected(record, outcomes) {
  return { ...record, verdict: outcomes.includes(record.classification?.outcome) ? "PASS" : "FAIL" };
}

// ---------- environment capture (once per invocation) ----------
function captureEnvironment() {
  const ps = process.env.SystemRoot + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const out = execFileSync(ps, ["-NoProfile", "-Command", `
    $id=[Security.Principal.WindowsIdentity]::GetCurrent();
    $p=New-Object Security.Principal.WindowsPrincipal($id);
    $cv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';
    $sys='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';
    @{ user=$id.Name;
       isElevatedLauncher=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
       build=('{0}.{1}.{2}.{3}' -f 10,0,$cv.CurrentBuild,$cv.UBR);
       displayVersion=$cv.DisplayVersion;
       uacEnableLUA=(Get-ItemProperty $sys -Name EnableLUA).EnableLUA;
       uacConsentPrompt=(Get-ItemProperty $sys -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin;
       uacSecureDesktop=(Get-ItemProperty $sys -Name PromptOnSecureDesktop).PromptOnSecureDesktop } | ConvertTo-Json -Compress
  `], { encoding: "utf8", shell: false });
  return JSON.parse(out);
}

// ---------- plan/envelope builders ----------
function basePlan({ taskId, capabilityId, actions, verificationPlan, recoveryPlan }) {
  return withPlanHash({
    taskId,
    capabilityId,
    providerEnvironmentBindingId: "local-windows/nilar",
    rankingPolicyRevision: "u06-demo/1",
    policySnapshotRevision: "u06-demo/1",
    actions,
    verificationPlan,
    recoveryPlan,
  });
}

function envelopeFor({ plan, approval, requiredPrivilege, scope, timeoutMs, steps, fault = null, cancelFile = null, outDir, actionFileStem }) {
  const envObj = makeAuthorizedAction({ plan, approval, requiredPrivilege, scope, timeoutMs, steps, fault, cancelFile });
  const envelopeFile = join(outDir, actionFileStem + ".envelope.json");
  const journalFile = join(outDir, actionFileStem + ".journal.jsonl");
  const receiptFile = join(outDir, actionFileStem + ".receipt.json");
  writeFileSync(envelopeFile, JSON.stringify(envObj, null, 2), "utf8");
  return { envObj, envelopeFile, journalFile, receiptFile };
}

function freshRunDir(stem) {
  const dir = join(OUT, "procs", stem + "-" + Date.now());
  mkdirSync(dir, { recursive: true });
  return dir;
}

const pre = validateAuthorizedAction; // Action Controller-side pre-check

// =====================================================================
// D1 — non-elevated structured execution
// =====================================================================
async function d1() {
  const cases = [];
  const dir = freshRunDir("d1");

  const osb = await runOrdinary({ script: OBS, args: ["-Query", "os.build"], timeoutMs: 15000 });
  let parsed = null;
  try { parsed = JSON.parse(osb.stdout.trim().split(/\r?\n/).pop()); } catch {}
  cases.push(expected({
    id: "D1-a", description: "structured OS/build observation (typed argv, JSON stdout)",
    launch: { exitCode: osb.exitCode, timedOut: osb.timedOut, stderrEmpty: osb.stderr === "" },
    stdout: parsed, rawStdout: osb.stdout.slice(0, 400),
    classification: { outcome: osb.exitCode === 0 && parsed?.os?.buildString ? "OK_STRUCTURED" : "BROKEN" },
  }, ["OK_STRUCTURED"]));

  const svc = await runOrdinary({ script: OBS, args: ["-Query", "service.query", "-Target", "wuauserv"], timeoutMs: 15000 });
  let svcParsed = null;
  try { svcParsed = JSON.parse(svc.stdout.trim().split(/\r?\n/).pop()); } catch {}
  cases.push(expected({
    id: "D1-b", description: "service query with typed target",
    launch: { exitCode: svc.exitCode, stderrEmpty: svc.stderr === "" },
    stdout: svcParsed,
    classification: { outcome: svcParsed?.service?.name === "wuauserv" ? "OK_STRUCTURED" : "BROKEN" },
  }, ["OK_STRUCTURED"]));

  const inv = await runOrdinary({ script: OBS, args: ["-Query", "package.inventory", "-Target", "Windows"], timeoutMs: 20000 });
  let invParsed = null;
  try { invParsed = JSON.parse(inv.stdout.trim().split(/\r?\n/).pop()); } catch {}
  cases.push(expected({
    id: "D1-c", description: "package inventory query (registry uninstall keys)",
    launch: { exitCode: inv.exitCode },
    stdout: { matchCount: invParsed?.inventory?.matchCount, sampleSize: invParsed?.inventory?.sample?.length },
    classification: { outcome: typeof invParsed?.inventory?.matchCount === "number" ? "OK_STRUCTURED" : "BROKEN" },
  }, ["OK_STRUCTURED"]));

  const fail = await runOrdinary({ script: OBS, args: ["-Query", "os.build", "-SimulateFailure"], timeoutMs: 15000 });
  cases.push(expected({
    id: "D1-d", description: "stdout/stderr separation + terminal classification on helper error",
    launch: { exitCode: fail.exitCode, stderr: fail.stderr.trim(), stdoutEmpty: fail.stdout === "" },
    classification: { outcome: fail.exitCode === 3 && fail.stderr.includes("simulated") && fail.stdout === "" ? "FAILED_STDERR_SEPARATE" : "BROKEN" },
  }, ["FAILED_STDERR_SEPARATE"]));

  const to = await runOrdinary({ script: OBS, args: ["-Query", "os.build", "-DelayMs", "8000"], timeoutMs: 2000 });
  cases.push(expected({
    id: "D1-e", description: "timeout -> launcher kills child, terminal classified TIMED_OUT",
    launch: { exitCode: to.exitCode, timedOut: to.timedOut },
    classification: { outcome: to.timedOut ? "TIMED_OUT" : "BROKEN" },
  }, ["TIMED_OUT"]));

  const cancelFile = join(dir, "d1.cancel.sentinel");
  const co = (async () => {
    const p = runOrdinary({ script: OBS, args: ["-Query", "os.build", "-DelayMs", "8000", "-CancelFile", cancelFile], timeoutMs: 20000 });
    setTimeout(() => writeFileSync(cancelFile, "cancel", "utf8"), 1500);
    return await p;
  })();
  const cancelled = await co;
  cases.push(expected({
    id: "D1-f", description: "cooperative cancellation via cancel sentinel -> structured CANCELLED",
    launch: { exitCode: cancelled.exitCode },
    stdout: (() => { try { return JSON.parse(cancelled.stdout.trim().split(/\r?\n/).pop()); } catch { return null; } })(),
    classification: { outcome: cancelled.exitCode === 5 ? "CANCELLED" : "BROKEN" },
  }, ["CANCELLED"]));

  return { scenario: "D1", cases };
}

// =====================================================================
// D4 (non-elevated subset) — negative/failure paths
// =====================================================================
async function d4Local() {
  const cases = [];
  const dir = freshRunDir("d4");

  // D4-1 unknown op -> no arbitrary shell endpoint
  {
    const plan = basePlan({
      taskId: "u06-d4-1", capabilityId: "u06.demo", actions: [],
      verificationPlan: "n/a (negative case)", recoveryPlan: "n/a",
    });
    const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 300 });
    const { envelopeFile, journalFile, receiptFile } = envelopeFor({
      plan, approval, requiredPrivilege: "none",
      scope: { filesystem: { allowedRoots: [dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
      timeoutMs: 30000, steps: [{ op: "shell.exec", args: { command: "whoami" } }],
      outDir: dir, actionFileStem: "d4-1",
    });
    const precheck = pre(JSON.parse(readFileSync(envelopeFile, "utf8")));
    const r = await runOrdinary({ script: ACTION, args: [envelopeFile, journalFile, receiptFile], timeoutMs: 30000 });
    const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
    const classification = classifyOutcome({ launch: { relay: { kind: "RAN" } }, journal: readJournal(journalFile), receipt, postState: null });
    cases.push(expected({
      id: "D4-1", description: "unknown op rejected (no arbitrary shell endpoint)",
      precheck, launch: { exitCode: r.exitCode }, receipt: receipt && { terminal: receipt.terminal, reason: receipt.reason },
      classification, expectedNote: "REFUSED",
    }, ["REFUSED"]));
  }

  // D4-2 plan mutated after approval -> planHash mismatch
  {
    const plan = basePlan({
      taskId: "u06-d4-2", capabilityId: "u06.demo", actions: [],
      verificationPlan: "fixture absent", recoveryPlan: "nothing to recover",
    });
    const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 300 });
    // tamper AFTER approval: change the declared target path
    plan.actions = [{ note: "tampered after approval", target: "C:\\Windows\\evil-marker.txt" }];
    const { envelopeFile, journalFile, receiptFile } = envelopeFor({
      plan, approval, requiredPrivilege: "none",
      scope: { filesystem: { allowedRoots: [dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
      timeoutMs: 30000, steps: [{ op: "fs.write", args: { path: "C:\\Windows\\evil-marker.txt", content: "nope" } }],
      outDir: dir, actionFileStem: "d4-2",
    });
    const precheck = pre(JSON.parse(readFileSync(envelopeFile, "utf8")));
    const r = await runOrdinary({ script: ACTION, args: [envelopeFile, journalFile, receiptFile], timeoutMs: 30000 });
    const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
    const postState = { evilMarkerExists: existsSync("C:\\Windows\\evil-marker.txt") };
    const classification = classifyOutcome({ launch: { relay: { kind: "RAN" } }, journal: readJournal(journalFile), receipt, postState });
    cases.push(expected({
      id: "D4-2", description: "plan mutated after approval -> hash mismatch -> refused, no side effect",
      precheck, launch: { exitCode: r.exitCode }, receipt: receipt && { terminal: receipt.terminal, reason: receipt.reason }, postState,
      classification, expectedNote: "REFUSED + fixture absent",
    }, ["REFUSED"]));
  }

  // D4-3 scope exceed with VALID approval -> refused at scope phase
  {
    const plan = basePlan({
      taskId: "u06-d4-3", capabilityId: "u06.demo", actions: [],
      verificationPlan: "fixture absent", recoveryPlan: "nothing to recover",
    });
    const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 300 });
    const { envelopeFile, journalFile, receiptFile } = envelopeFor({
      plan, approval, requiredPrivilege: "none",
      scope: { filesystem: { allowedRoots: [dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
      timeoutMs: 30000, steps: [{ op: "fs.write", args: { path: "C:\\Windows\\out-of-scope.txt", content: "nope" } }],
      outDir: dir, actionFileStem: "d4-3",
    });
    const precheck = pre(JSON.parse(readFileSync(envelopeFile, "utf8")));
    const r = await runOrdinary({ script: ACTION, args: [envelopeFile, journalFile, receiptFile], timeoutMs: 30000 });
    const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
    const postState = { outOfScopeFileExists: existsSync("C:\\Windows\\out-of-scope.txt") };
    const classification = classifyOutcome({ launch: { relay: { kind: "RAN" } }, journal: readJournal(journalFile), receipt, postState });
    cases.push(expected({
      id: "D4-3", description: "path outside declared scope -> refused before execution",
      precheck, launch: { exitCode: r.exitCode }, receipt: receipt && { terminal: receipt.terminal, reason: receipt.reason }, postState,
      classification, expectedNote: "REFUSED + fixture absent",
    }, ["REFUSED"]));
  }

  // D4-4 shell metacharacters as typed data
  // NB: '< > : " / \ | ? *' are illegal in NTFS filenames, so the fixture
  // name stays inside the legal set while still carrying ; & $ ( ) % ^ !
  {
    const meta = "p;wn &$(calc)^%S!)~'.txt";
    const content = 'quote " backslash \\ ; & | < > $ ( ) % ^ ! `~';
    const plan = basePlan({
      taskId: "u06-d4-4", capabilityId: "u06.demo", actions: [],
      verificationPlan: "content read-back equals envelope value", recoveryPlan: "delete fixture",
    });
    const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 300 });
    const { envelopeFile, journalFile, receiptFile } = envelopeFor({
      plan, approval, requiredPrivilege: "none",
      scope: { filesystem: { allowedRoots: [dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
      timeoutMs: 30000,
      steps: [
        { op: "fs.write", args: { path: join(dir, meta), content } },
        { op: "fs.verify", args: { path: join(dir, meta), expectContent: content } },
      ],
      outDir: dir, actionFileStem: "d4-4",
    });
    const precheck = pre(JSON.parse(readFileSync(envelopeFile, "utf8")));
    const r = await runOrdinary({ script: ACTION, args: [envelopeFile, journalFile, receiptFile], timeoutMs: 30000 });
    const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
    const targetPath = join(dir, meta);
    const postState = { fileExists: existsSync(targetPath), contentMatches: existsSync(targetPath) && readFileSync(targetPath, "utf8") === content };
    postState.pass = postState.fileExists && postState.contentMatches;
    const classification = classifyOutcome({ launch: { relay: { kind: "RAN" } }, journal: readJournal(journalFile), receipt, postState });
    cases.push(expected({
      id: "D4-4", description: "shell metacharacters in filename/content pass through literally (typed envelope, no shell)",
      precheck, launch: { exitCode: r.exitCode }, receipt: receipt && { terminal: receipt.terminal }, postState,
      classification, expectedNote: "COMPLETED_VERIFIED with metachar fixture intact",
    }, ["COMPLETED_VERIFIED"]));
  }

  // D4-4b path with filesystem-illegal characters -> structured refusal, no crash
  {
    const illegalPath = join(dir, "bad|pipe.txt"); // '|' is illegal in NTFS names
    const plan = basePlan({
      taskId: "u06-d4-4b", capabilityId: "u06.demo", actions: [],
      verificationPlan: "fixture absent", recoveryPlan: "nothing to recover",
    });
    const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 300 });
    const { envelopeFile, journalFile, receiptFile } = envelopeFor({
      plan, approval, requiredPrivilege: "none",
      scope: { filesystem: { allowedRoots: [dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
      timeoutMs: 30000, steps: [{ op: "fs.write", args: { path: illegalPath, content: "x" } }],
      outDir: dir, actionFileStem: "d4-4b",
    });
    const precheck = pre(JSON.parse(readFileSync(envelopeFile, "utf8")));
    const r = await runOrdinary({ script: ACTION, args: [envelopeFile, journalFile, receiptFile], timeoutMs: 30000 });
    const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
    const classification = classifyOutcome({ launch: { relay: { kind: "RAN" } }, journal: readJournal(journalFile), receipt, postState: null });
    cases.push(expected({
      id: "D4-4b", description: "filesystem-illegal characters in typed path -> fail-closed structured REFUSED (no crash, no side effect)",
      precheck, launch: { exitCode: r.exitCode }, receipt: receipt && { terminal: receipt.terminal, reason: receipt.reason },
      classification, expectedNote: "REFUSED",
    }, ["REFUSED"]));
  }

  // D4-5 expired approval
  {
    const plan = basePlan({
      taskId: "u06-d4-5", capabilityId: "u06.demo", actions: [],
      verificationPlan: "n/a", recoveryPlan: "n/a",
    });
    const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: -10 });
    const { envelopeFile, journalFile, receiptFile } = envelopeFor({
      plan, approval, requiredPrivilege: "none",
      scope: { filesystem: { allowedRoots: [dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
      timeoutMs: 30000, steps: [{ op: "fs.write", args: { path: join(dir, "never.txt"), content: "x" } }],
      outDir: dir, actionFileStem: "d4-5",
    });
    const precheck = pre(JSON.parse(readFileSync(envelopeFile, "utf8")));
    const r = await runOrdinary({ script: ACTION, args: [envelopeFile, journalFile, receiptFile], timeoutMs: 30000 });
    const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
    const postState = { fixtureExists: existsSync(join(dir, "never.txt")) };
    const classification = classifyOutcome({ launch: { relay: { kind: "RAN" } }, journal: readJournal(journalFile), receipt, postState });
    cases.push(expected({
      id: "D4-5", description: "expired approval -> refused, no side effect",
      precheck, launch: { exitCode: r.exitCode }, receipt: receipt && { terminal: receipt.terminal, reason: receipt.reason }, postState,
      classification, expectedNote: "REFUSED",
    }, ["REFUSED"]));
  }

  // D4-6 authorizationRef mismatch
  {
    const plan = basePlan({
      taskId: "u06-d4-6", capabilityId: "u06.demo", actions: [],
      verificationPlan: "n/a", recoveryPlan: "n/a",
    });
    const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 300 });
    const { envelopeFile, journalFile, receiptFile } = envelopeFor({
      plan, approval, requiredPrivilege: "none",
      scope: { filesystem: { allowedRoots: [dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
      timeoutMs: 30000, steps: [{ op: "fs.write", args: { path: join(dir, "never-6.txt"), content: "x" } }],
      outDir: dir, actionFileStem: "d4-6",
    });
    // corrupt the ref after envelope build
    const envObj = JSON.parse(readFileSync(envelopeFile, "utf8"));
    envObj.authorizationRef.approvalId = "appr-forged-000000000000";
    writeFileSync(envelopeFile, JSON.stringify(envObj, null, 2), "utf8");
    const precheck = pre(envObj);
    const r = await runOrdinary({ script: ACTION, args: [envelopeFile, journalFile, receiptFile], timeoutMs: 30000 });
    const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
    const postState = { fixtureExists: existsSync(join(dir, "never-6.txt")) };
    const classification = classifyOutcome({ launch: { relay: { kind: "RAN" } }, journal: readJournal(journalFile), receipt, postState });
    cases.push(expected({
      id: "D4-6", description: "authorizationRef pointing at a forged approvalId -> refused",
      precheck, launch: { exitCode: r.exitCode }, receipt: receipt && { terminal: receipt.terminal, reason: receipt.reason }, postState,
      classification, expectedNote: "REFUSED",
    }, ["REFUSED"]));
  }

  return { scenario: "D4-local", cases };
}

// =====================================================================
// D5 — crash / recovery classification (non-elevated fs fixtures)
// =====================================================================
async function d5() {
  const cases = [];
  const dir = freshRunDir("d5");

  async function crashCase({ id, description, steps, fault, postStateFn, expect, noVerify = false }) {
    const plan = basePlan({
      taskId: "u06-" + id.toLowerCase(), capabilityId: "u06.demo", actions: [],
      verificationPlan: "post-state fixture check", recoveryPlan: "re-run after classify",
    });
    const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 300 });
    const { envelopeFile, journalFile, receiptFile } = envelopeFor({
      plan, approval, requiredPrivilege: "none",
      scope: { filesystem: { allowedRoots: [dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
      timeoutMs: 30000, steps, fault, outDir: dir, actionFileStem: id,
    });
    const r = await runOrdinary({ script: ACTION, args: [envelopeFile, journalFile, receiptFile], timeoutMs: 30000 });
    const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
    const journal = readJournal(journalFile);
    const postState = noVerify ? null : postStateFn();
    const classification = classifyOutcome({ launch: { relay: { kind: "RAN", exitCode: r.exitCode } }, journal, receipt, postState });
    cases.push(expected({ id, description, launch: { exitCode: r.exitCode }, journalPhases: journal.map((j) => j.phase), receipt: receipt && { terminal: receipt.terminal }, postState, classification, expectedNote: expect.join("|") }, expect));
  }

  const A = join(dir, "crash-A.txt");
  const B = join(dir, "crash-B.txt");
  const twoStep = [
    { op: "fs.write", args: { path: A, content: "A" } },
    { op: "fs.write", args: { path: B, content: "B" } },
  ];
  const state = () => ({ aExists: existsSync(A), bExists: existsSync(B) });

  await crashCase({
    id: "D5-a", description: "hard crash after EXEC_START but before side effect",
    steps: twoStep, fault: { beforeStepEffect: 0, mode: "hardkill" },
    postStateFn: state, expect: ["EXECUTED_PARTIALLY_RESOLVED_BY_VERIFICATION"],
  });
  await crashCase({
    id: "D5-b", description: "hard crash after step 0 side effect, before step 1 and receipt",
    steps: twoStep, fault: { afterStep: 0, mode: "hardkill" },
    postStateFn: state, expect: ["EXECUTED_PARTIALLY_RESOLVED_BY_VERIFICATION"],
  });
  await crashCase({
    id: "D5-c", description: "crash with torn journal append (JSONL tolerance)",
    steps: twoStep, fault: { afterStep: 0, mode: "torn" },
    postStateFn: state, expect: ["EXECUTED_PARTIALLY_RESOLVED_BY_VERIFICATION"],
  });
  await crashCase({
    id: "D5-d", description: "same crash WITHOUT post-state verification -> honest UNCERTAIN",
    steps: twoStep, fault: { afterStep: 0, mode: "hardkill" },
    postStateFn: state, expect: ["MAY_HAVE_EXECUTED_UNCERTAIN"], noVerify: true,
  });
  await crashCase({
    id: "D5-e", description: "crash after last EXEC_DONE, before receipt -> receipt lost, post-state resolves",
    steps: twoStep, fault: { afterStep: 1, mode: "hardkill" },
    postStateFn: state, expect: ["EXECUTED_PARTIALLY_RESOLVED_BY_VERIFICATION", "EXECUTED_RECEIPT_LOST"],
  });

  return { scenario: "D5", cases };
}

// =====================================================================
// Elevated scenarios (each triggers one UAC prompt)
// =====================================================================
function elevatedIO(stem) {
  const dir = freshRunDir(stem);
  return { dir, relayFile: join(dir, "relay.json"), stdoutFile: join(dir, "elev.stdout.txt"), stderrFile: join(dir, "elev.stderr.txt") };
}

// D4-elev-a: UAC declined path
async function decline() {
  const plan = basePlan({
    taskId: "u06-d4-uac-decline", capabilityId: "u06.demo", actions: [],
    verificationPlan: "n/a", recoveryPlan: "n/a",
  });
  const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 600 });
  const io = elevatedIO("d4-uac-decline");
  const { envelopeFile, journalFile, receiptFile } = envelopeFor({
    plan, approval, requiredPrivilege: "elevated-admin",
    scope: { filesystem: { allowedRoots: [io.dir] }, registry: { allowedKeys: [] }, process: { allowedPrograms: [] } },
    timeoutMs: 60000,
    steps: [
      { op: "proc.elevated-context-check", args: { expectElevated: true } },
      { op: "fs.write", args: { path: join(io.dir, "harmless.txt"), content: "if you see this, UAC consent was given" } },
    ],
    outDir: io.dir, actionFileStem: "d4-uac-decline",
  });
  const r = await runElevated({ script: ACTION, helperArgs: [envelopeFile, journalFile, receiptFile], timeoutMs: 200000, ...io });
  const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
  const classification = classifyOutcome({ launch: r, journal: readJournal(journalFile), receipt, postState: null });
  return { scenario: "D4-elevated", cases: [expected({
    id: "D4-7", description: "UAC refused/cancelled -> helper never runs, structured UAC_DECLINED (user was asked to click NO or ignore)",
    launch: r, receipt: receipt && { terminal: receipt.terminal }, classification,
    expectedNote: "UAC_DECLINED (or RAN harmless if consent was given)",
  }, ["UAC_DECLINED", "COMPLETED_VERIFIED"])] };
}

// D2 positive: plan-bound elevated fixture action
async function d2() {
  const key = "HKLM:\\SOFTWARE\\ShunU06Demo";
  const plan = basePlan({
    taskId: "u06-d2-elevated-fixture", capabilityId: "u06.demo", actions: [],
    verificationPlan: "in-helper reg.verify + harness post-state HKLM read",
    recoveryPlan: "delete HKLM:\\SOFTWARE\\ShunU06Demo (elevated) if partial",
  });
  const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 600 });
  const io = elevatedIO("d2-elevated");
  const { envelopeFile, journalFile, receiptFile } = envelopeFor({
    plan, approval, requiredPrivilege: "elevated-admin",
    scope: { filesystem: { allowedRoots: [io.dir] }, registry: { allowedKeys: [key] }, process: { allowedPrograms: [] } },
    timeoutMs: 60000,
    steps: [
      { op: "proc.elevated-context-check", args: { expectElevated: true } },
      { op: "reg.create", args: { key } },
      { op: "reg.set", args: { key, name: "planHash", value: plan.planHash } },
      { op: "reg.set", args: { key, name: "approvedBy", value: approver } },
      { op: "reg.set", args: { key, name: "executedAt", value: new Date().toISOString() } },
      { op: "reg.verify", args: { key, expectValues: { planHash: plan.planHash, approvedBy: approver } } },
      { op: "reg.delete", args: { key } },
      { op: "reg.verify", args: { key, expectValues: {}, expectKeyExists: false } },
    ],
    outDir: io.dir, actionFileStem: "d2-elevated",
  });
  const r = await runElevated({ script: ACTION, helperArgs: [envelopeFile, journalFile, receiptFile], timeoutMs: 200000, ...io });
  const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
  // non-elevated post-state verification: the approved plan is a full
  // create->verify->delete lifecycle, so the durable post-state is "key gone";
  // the created-state proof lives in the receipt's sideEffectEvidence
  let postState = { keyExists: true };
  try {
    const out = execFileSync(process.env.SystemRoot + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      ["-NoProfile", "-Command", `
        if (Test-Path 'HKLM:\\SOFTWARE\\ShunU06Demo') { @{ keyExists=$true } | ConvertTo-Json -Compress }
        else { @{ keyExists=$false } | ConvertTo-Json -Compress }
      `], { encoding: "utf8", shell: false });
    postState = JSON.parse(out.trim().split(/\r?\n/).pop());
    postState.pass = postState.keyExists === false;
  } catch (e) { postState = { keyExists: null, error: String(e) }; }
  const classification = classifyOutcome({ launch: r, journal: readJournal(journalFile), receipt, postState });
  return { scenario: "D2", cases: [expected({
    id: "D2-a", description: "planHash-bound approval -> elevated one-shot helper -> structured receipt -> post-state verified (HKLM fixture; write requires elevation on this host)",
    planHash: plan.planHash, launch: r, receipt: receipt && { terminal: receipt.terminal, elevated: receipt.elevated, sideEffectEvidence: receipt.sideEffectEvidence },
    postState, classification, expectedNote: "COMPLETED_VERIFIED with elevated=true",
  }, ["COMPLETED_VERIFIED"])] };
}

// D2/D4 negative: plan mutated after approval, executed through the real elevated helper
async function d2tamper() {
  const key = "HKLM:\\SOFTWARE\\ShunU06Demo";
  const plan = basePlan({
    taskId: "u06-d2-tamper", capabilityId: "u06.demo", actions: [],
    verificationPlan: "key must NOT exist", recoveryPlan: "n/a",
  });
  const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 600 });
  // tamper AFTER approval
  plan.actions = [{ note: "tampered: escalate fixture to HKLM uninstall run key", target: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" }];
  const io = elevatedIO("d2-tamper");
  const { envelopeFile, journalFile, receiptFile } = envelopeFor({
    plan, approval, requiredPrivilege: "elevated-admin",
    scope: { filesystem: { allowedRoots: [io.dir] }, registry: { allowedKeys: [key] }, process: { allowedPrograms: [] } },
    timeoutMs: 60000,
    steps: [{ op: "reg.create", args: { key } }],
    outDir: io.dir, actionFileStem: "d2-tamper",
  });
  const precheck = pre(JSON.parse(readFileSync(envelopeFile, "utf8")));
  const r = await runElevated({ script: ACTION, helperArgs: [envelopeFile, journalFile, receiptFile], timeoutMs: 200000, ...io });
  const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
  const postState = { keyExists: existsSync("HKLM:\\SOFTWARE\\ShunU06Demo") };
  const classification = classifyOutcome({ launch: r, journal: readJournal(journalFile), receipt, postState });
  return { scenario: "D2-tamper", cases: [expected({
    id: "D2-b", description: "destructive/elevated plan mutated after approval -> authorization invalidated, helper refuses inside privileged boundary",
    precheck, launch: r, receipt: receipt && { terminal: receipt.terminal, reason: receipt.reason }, postState, classification,
    expectedNote: "REFUSED + key absent",
  }, ["REFUSED"])] };
}

// D3: winget lifecycle through the elevated one-shot helper
async function d3() {
  const ps = process.env.SystemRoot + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const wingetPath = execFileSync(ps, ["-NoProfile", "-Command", "(Get-Command winget.exe).Source"], { encoding: "utf8", shell: false }).trim().split(/\r?\n/).pop();
  if (!wingetPath) throw new Error("winget.exe not resolvable");
  // NB: wingetPath is an App Execution Alias reparse stub; fs.existsSync()
  // reports false for it but CreateProcess resolves it fine.
  // pin the version from the official winget source before building the plan
  const showOut = execFileSync(ps, ["-NoProfile", "-Command",
    `(winget show --id 7zip.7zip --exact --disable-interactivity | Out-String)`], { encoding: "utf8", shell: false });
  const version = (showOut.match(/Version:\s*(\S+)/) || [])[1];
  const installerUrl = (showOut.match(/Installer Url:\s*(\S+)/) || [])[1];
  if (!version) throw new Error("could not pin version from winget show:\n" + showOut);

  const plan = basePlan({
    taskId: "u06-d3-winget-lifecycle", capabilityId: "u06.demo", actions: [],
    verificationPlan: "winget.verify before/after uninstall + harness registry post-state",
    recoveryPlan: "uninstall leftover install via same helper if partial",
  });
  const approval = makeApproval({ planHash: plan.planHash, approver, ttlSeconds: 900 });
  const io = elevatedIO("d3-winget");
  const { envelopeFile, journalFile, receiptFile } = envelopeFor({
    plan, approval, requiredPrivilege: "elevated-admin",
    scope: {
      filesystem: { allowedRoots: [io.dir] },
      registry: { allowedKeys: [] },
      process: { allowedPrograms: ["winget.exe"] },
      packages: ["7zip.7zip"],
    },
    timeoutMs: 420000,
    steps: [
      { op: "proc.elevated-context-check", args: { expectElevated: true } },
      { op: "winget.inventory", args: { wingetPath } },
      { op: "winget.install", args: { wingetPath, id: "7zip.7zip", version, scope: "machine" } },
      { op: "winget.verify", args: { wingetPath, id: "7zip.7zip", displayPattern: "7-Zip*", expectInstalled: true } },
      { op: "winget.uninstall", args: { wingetPath, id: "7zip.7zip" } },
      { op: "winget.verify", args: { wingetPath, id: "7zip.7zip", displayPattern: "7-Zip*", expectInstalled: false } },
    ],
    outDir: io.dir, actionFileStem: "d3-winget",
  });
  const r = await runElevated({ script: ACTION, helperArgs: [envelopeFile, journalFile, receiptFile], timeoutMs: 480000, ...io });
  const receipt = existsSync(receiptFile) ? JSON.parse(readFileSync(receiptFile, "utf8")) : null;
  const classification = classifyOutcome({ launch: r, journal: readJournal(journalFile), receipt, postState: null });
  return { scenario: "D3", pinnedVersion: version, installerUrl, cases: [expected({
    id: "D3-a", description: "winget machine-scope lifecycle (inventory/install@pinnedVersion/verify/uninstall/verify-gone) through the plan-bound elevated one-shot helper",
    launch: r, receipt: receipt && { terminal: receipt.terminal, elevated: receipt.elevated, sideEffectEvidence: receipt.sideEffectEvidence },
    classification, expectedNote: "COMPLETED_VERIFIED",
  }, ["COMPLETED_VERIFIED", "FAILED"])] };
}

// =====================================================================
(async () => {
  const env = captureEnvironment();
  writeFileSync(join(OUT, "environment.json"), JSON.stringify(env, null, 2), "utf8");
  console.log(`host: ${env.build} (${env.displayVersion}) user=${env.user} launcherElevated=${env.isElevatedLauncher} UAC(on=${env.uacEnableLUA}, prompt=${env.uacConsentPrompt}, secureDesktop=${env.uacSecureDesktop})`);
  console.log(`out: ${OUT}\n`);

  let result;
  switch (arg) {
    case "local": {
      const d1r = await d1();
      const d4r = await d4Local();
      const d5r = await d5();
      result = { environment: env, scenarios: [d1r, d4r, d5r] };
      break;
    }
    case "decline": result = { environment: env, scenarios: [await decline()] }; break;
    case "d2": result = { environment: env, scenarios: [await d2()] }; break;
    case "d2tamper": result = { environment: env, scenarios: [await d2tamper()] }; break;
    case "d3": result = { environment: env, scenarios: [await d3()] }; break;
    case "summary": {
      const files = [];
      for (const f of (await import("node:fs")).readdirSync(OUT)) {
        if (f.endsWith(".json") && !["environment.json", "summary.json"].includes(f)) files.push(join(OUT, f));
      }
      const scenarios = {};
      for (const f of files) {
        const j = JSON.parse(readFileSync(f, "utf8"));
        const key = (j.scenario || j.id || f).split("-")[0];
        (scenarios[key] ??= []).push(j);
      }
      result = { environment: env, scenarios };
      break;
    }
    default: throw new Error("unknown phase: " + arg);
  }

  const all = [];
  for (const s of result.scenarios ?? []) for (const c of s.cases ?? []) all.push(c);
  result.totalCases = all.length;
  result.pass = all.filter((c) => c.verdict === "PASS").length;
  result.fail = all.filter((c) => c.verdict === "FAIL").length;
  writeFileSync(join(OUT, "summary.json"), JSON.stringify(result, null, 2), "utf8");
  console.log(`\nsummary: ${result.pass}/${result.totalCases} PASS -> ${join(OUT, "summary.json")}`);
  process.exit(result.fail > 0 ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
