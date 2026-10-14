// i85-U01 step 4b child probe (runs under node.exe, possibly inside an
// AppContainer). Attempts: (1) loopback TCP connect to a live local listener,
// (2) connection to the explicitly selected reachable controlled sink.
// An independent NON-sandboxed client MUST first connect to the same sink.
// Only OS-enforced denial with token evidence and independent observation
// supports an egress verdict; unreachable destinations are NOT an oracle.
// Writes one JSON line to the fresh output path given as argv[3].
'use strict';
const net = require('node:net');
const fs = require('node:fs');

const localPort = Number(process.argv[2]);
const outFile = process.argv[3];
const controlledHost = process.argv[4];
const controlledPort = Number(process.argv[5]);
if (!(localPort > 0 && localPort <= 65535) || !outFile ||
    !controlledHost || !Number.isInteger(controlledPort) ||
    !(controlledPort > 0 && controlledPort <= 65535)) {
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
  const controlled = await tryConnect(controlledHost, controlledPort, 6000);
  fs.writeFileSync(outFile, `${JSON.stringify({ pid: process.pid, loopback, controlled })}\n`, { flag: 'wx' });
  process.exit(0);
})().catch((e) => {
  try { fs.writeFileSync(outFile, `${JSON.stringify({ fatal: String(e && e.message ? e.message : e) })}\n`, { flag: 'wx' }); } catch {}
  process.exit(1);
});
