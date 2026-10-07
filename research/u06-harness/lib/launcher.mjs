// U-06 demo: process launching + terminal classification.
// No shell is ever involved: spawn() with argv arrays only (shell: false).
// shell:true / cmd.exe / string concatenation are deliberately absent — that
// is part of the D1 evidence ("no shell-string concatenation for typed args").
import { spawn } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";

const POWERSHELL = process.env.SystemRoot + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

function fileToJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
  } catch {
    return null;
  }
}

// Plain (non-elevated) one-shot child. Typed argv array, no shell.
export function runOrdinary({ script, args, timeoutMs = 15000 }) {
  const startedAt = new Date().toISOString();
  return new Promise((resolve) => {
    const child = spawn(POWERSHELL, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, ...args], {
      shell: false,
      windowsHide: true,
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      // tree-kill; no shell involved
      spawn(process.env.SystemRoot + "\\System32\\taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { shell: false });
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({
        launched: true,
        exitCode: code,
        stdout,
        stderr,
        timedOut,
        startedAt,
        finishedAt: new Date().toISOString(),
      });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ launched: false, spawnError: String(err), stdout, stderr, timedOut: false, startedAt, finishedAt: new Date().toISOString() });
    });
  });
}

// Elevated one-shot child via UAC (Start-Process -Verb RunAs).
// A relay launcher PowerShell performs the RunAs and reports back through a
// relay JSON file, because UAC cancellation surfaces as a .NET exception there.
// The elevated child itself writes journal + receipt; stdout is not a
// structured channel across the privilege boundary by design.
export function runElevated({ script, helperArgs, timeoutMs = 150000, relayFile, stdoutFile, stderrFile }) {
  const startedAt = new Date().toISOString();
  const relayArgs = [script, JSON.stringify(helperArgs), relayFile, stdoutFile, stderrFile];
  return new Promise((resolve) => {
    const child = spawn(
      POWERSHELL,
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script.replace(/[^\\/]+$/, "") + "elevate-relay.ps1", ...relayArgs],
      { shell: false, windowsHide: true }
    );
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      spawn(process.env.SystemRoot + "\\System32\\taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { shell: false });
    }, timeoutMs);
    child.on("exit", () => {
      clearTimeout(timer);
      const relay = existsSync(relayFile) ? fileToJson(relayFile) : { kind: "NO_RELAY" };
      resolve({
        launched: true,
        timedOut,
        relay,
        stdout: existsSync(stdoutFile) ? readFileSync(stdoutFile, "utf8") : "",
        stderr: existsSync(stderrFile) ? readFileSync(stderrFile, "utf8") : "",
        startedAt,
        finishedAt: new Date().toISOString(),
      });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ launched: false, spawnError: String(err), timedOut, relay: null, startedAt, finishedAt: new Date().toISOString() });
    });
  });
}

// D5: four-way outcome classification from launcher observation + journal +
// receipt + post-state verification. Side-effect journal phases, in order:
// RECEIVED -> VALIDATED -> APPROVAL_OK -> SCOPE_OK -> EXEC_START (per step)
// -> EXEC_DONE (per step) -> RECEIPT_WRITTEN. The helper writes no side effect
// before EXEC_START of the step performing it.
export function classifyOutcome({ launch, journal, receipt, postState }) {
  const phases = (journal ?? []).map((e) => e.phase);
  const started = phases.includes("RECEIVED");
  const execStarted = phases.some((p) => p === "EXEC_START");
  const execDone = phases.includes("EXEC_DONE");
  const receiptWritten = phases.includes("RECEIPT_WRITTEN") || receipt != null;

  if (launch && launch.relay && launch.relay.kind === "UAC_DECLINED") {
    return { outcome: "UAC_DECLINED", basis: "elevation launch refused/cancelled before helper start", journalPhases: phases };
  }
  // The helper's own terminal classification is authoritative for refusals
  // and structured failures: by construction those happen before any side
  // effect, and the receipt is the privileged side's verdict.
  if (receipt && receipt.terminal !== "OK") {
    return { outcome: receipt.terminal, basis: "helper terminal: " + (receipt.reason ?? ""), postState: postState ?? null, journalPhases: phases };
  }
  if (!started) {
    return { outcome: "NOT_STARTED", basis: "no journal RECEIVED phase — helper never began; no side effect possible", journalPhases: phases };
  }
  if (!execStarted) {
    return { outcome: "FAILED_BEFORE_SIDE_EFFECT", basis: "helper started validation but died before first EXEC_START", journalPhases: phases };
  }
  if (execStarted && !execDone) {
    const resolved = postState
      ? { outcome: "EXECUTED_PARTIALLY_RESOLVED_BY_VERIFICATION", postState }
      : { outcome: "MAY_HAVE_EXECUTED_UNCERTAIN", postState: null };
    return { outcome: resolved.outcome, basis: "crash inside side-effect window (EXEC_START without EXEC_DONE)", ...resolved, journalPhases: phases };
  }
  if (execDone && !receiptWritten) {
    return { outcome: "EXECUTED_RECEIPT_LOST", basis: "EXEC_DONE present but receipt channel lost", postState: postState ?? null, journalPhases: phases };
  }
  if (receipt && receipt.terminal === "OK" && (!postState || postState.pass)) {
    return { outcome: "COMPLETED_VERIFIED", basis: "receipt OK + post-state verification pass", postState: postState ?? null, journalPhases: phases };
  }
  return { outcome: "UNCLASSIFIED", basis: "no rule matched", journalPhases: phases };
}

export function readJournal(path) {
  if (!existsSync(path)) return [];
  const out = [];
  for (const line of readFileSync(path, "utf8").replace(/^\uFEFF/, "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      out.push({ phase: "TORN_LINE", raw: line.slice(0, 80) }); // crash mid-append
    }
  }
  return out;
}
