// i85-U01 step 4b child probe (runs under node.exe, possibly inside an
// AppContainer). Attempts: (1) loopback TCP connect to a live local listener,
// (2) TEST-NET-1 192.0.2.1:9 (non-routable) diagnostic ONLY.
// IMPORTANT: timeout/denial of a non-routable IP is NOT OS no-egress proof.
// A separate positive-control reachable destination, blocked AppContainer
// attempt, and independent OS/network observation are mandatory.
// Writes one JSON result line to the output file given as argv[3] — no
// stdout dependency, because the isolated child's stdio is not inherited.
'use strict';
const net = require('node:net');
const fs = require('node:fs');

const localPort = Number(process.argv[2]);
const outFile = process.argv[3];
if (!Number.isInteger(localPort) || !outFile) {
  process.exit(2);
}

function tryConnect(host, port, timeoutMs) {
  return new Promise((resolveAttempt) => {
    const started = Date.now();
    const socket = net.connect({ host, port });
    let settled = false;
    const finish = (outcome, detail) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch {}
      resolveAttempt({ host, port, outcome, detail, elapsedMs: Date.now() - started });
    };
    socket.setTimeout(timeoutMs, () => finish('TIMEOUT', `no connect within ${timeoutMs}ms`));
    socket.on('connect', () => finish('CONNECTED', 'tcp established'));
    socket.on('error', (e) => finish('ERROR', String(e.code ?? e.message)));
  });
}

(async () => {
  const loopback = await tryConnect('127.0.0.1', localPort, 4000);
  const testnet = await tryConnect('192.0.2.1', 9, 6000);
  fs.writeFileSync(outFile, `${JSON.stringify({ pid: process.pid, loopback, testnet })}\n`);
  process.exit(0);
})().catch((e) => {
  try { fs.writeFileSync(outFile, `${JSON.stringify({ fatal: String(e && e.message ? e.message : e) })}\n`); } catch {}
  process.exit(1);
});
