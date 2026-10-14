// i85-U01 R2 inference child (runs under node.exe inside an AppContainer
// whose only capability is internetClient, S-1-15-3-1).
//
// Modes:
//   run            — negative probes (live loopback + LAN sinks, expected to
//                    be OS-denied in the sandbox), then read task JSONL from
//                    RESTRICTED stdin until EOF and perform one real
//                    DeepSeek chat-completion inference per task against
//                    https://api.deepseek.com (model deepseek-flash), writing
//                    one JSONL result line per task to RESTRICTED stdout.
//   control-holds  — unsandboxed observer-sensitivity control: TCP connect to
//                    the same three destinations (loopback, LAN, api:443),
//                    each held ~2s so a 100ms poller must catch it. No
//                    inference, no API key use.
//
// The API key is read from the environment only and is NEVER printed; logs
// carry keyEnvPresent booleans only.
'use strict';
const net = require('node:net');
const https = require('node:https');
const crypto = require('node:crypto');

const mode = process.argv[2] || 'run';
const loopPort = Number(process.argv[3]);
const lanHost = process.argv[4];
const lanPort = Number(process.argv[5]);
const API_HOST = 'api.deepseek.com';
if (!(loopPort > 0 && loopPort <= 65535) || !lanHost ||
    !(lanPort > 0 && lanPort <= 65535) || !['run', 'control-holds'].includes(mode)) {
  process.exit(2);
}

function out(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }

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

function connectHold(host, port, holdMs) {
  return new Promise((resolveAttempt) => {
    const started = Date.now();
    const socket = net.connect({ host, port });
    const fail = (e) => { try { socket.destroy(); } catch {}
      resolveAttempt({ host, port, outcome: 'ERROR', detail: String(e.code ?? e.message), elapsedMs: Date.now() - started }); };
    socket.setTimeout(8000, () => fail({ code: 'ETIMEDOUT' }));
    socket.on('error', fail);
    socket.on('connect', () => {
      socket.setTimeout(0);
      setTimeout(() => { try { socket.destroy(); } catch {}
        resolveAttempt({ host, port, outcome: 'CONNECTED', heldMs: holdMs, elapsedMs: Date.now() - started });
      }, holdMs);
    });
  });
}

function normalizeAddr(a) {
  if (typeof a !== 'string') return a;
  return a.startsWith('::ffff:') ? a.slice(7) : a;
}

async function inferOnce(task) {
  const started = Date.now();
  const body = JSON.stringify({
    model: 'deepseek-flash',
    messages: [{ role: 'user', content: task.prompt }],
    max_tokens: Number(task.max_tokens) > 0 ? Number(task.max_tokens) : 64,
  });
  return new Promise((resolveAttempt) => {
    const req = https.request({
      host: API_HOST,
      port: 443,
      path: '/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        Authorization: 'Bearer ' + (process.env.DEEPSEEK_API_KEY || ''),
      },
      timeout: 60000,
    }, (res) => {
      // Capture endpoint identity while the TLS socket is alive; after 'end'
      // the socket is destroyed and exposes neither peer cert nor address.
      const rec = {
        type: 'inference', seq: task.seq, ok: false,
        httpStatus: res.statusCode,
        remoteAddress: normalizeAddr(res.socket && res.socket.remoteAddress),
        elapsedMs: Date.now() - started,
      };
      try {
        const tlsSock = res.socket;
        const cert = (tlsSock && typeof tlsSock.getPeerCertificate === 'function')
          ? tlsSock.getPeerCertificate() : null;
        if (cert && cert.fingerprint256) {
          rec.peerCert = {
            fingerprint256: cert.fingerprint256,
            subjectCN: cert.subject && cert.subject.CN,
            issuerCN: cert.issuer && cert.issuer.CN,
            validTo: cert.valid_to,
          };
        } else {
          rec.peerCert = { fingerprint256: null, note: 'no peer certificate object' };
        }
      } catch (e) { rec.peerCert = { fingerprint256: null, note: String(e.message) }; }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try { parsed = JSON.parse(text); } catch { rec.error = 'non_json_body'; rec.bodyExcerpt = text.slice(0, 160); return resolveAttempt(rec); }
        rec.modelEcho = parsed.model;
        rec.usage = parsed.usage || null;
        const content = parsed && parsed.choices && parsed.choices[0] &&
          parsed.choices[0].message && parsed.choices[0].message.content;
        if (typeof content === 'string' && content.length > 0) {
          rec.ok = true;
          rec.contentLen = content.length;
          rec.contentExcerpt = content.slice(0, 160);
          rec.contentSha256 = crypto.createHash('sha256').update(content, 'utf8').digest('hex').toUpperCase();
        } else {
          rec.error = 'empty_content';
          rec.finishReason = parsed.choices && parsed.choices[0] && parsed.choices[0].finish_reason;
        }
        resolveAttempt(rec);
      });
    });
    req.on('timeout', () => { req.destroy(new Error('request timeout 60s')); });
    req.on('error', (e) => resolveAttempt({
      type: 'inference', seq: task.seq, ok: false,
      error: String(e.code ?? e.message), elapsedMs: Date.now() - started,
    }));
    req.end(body);
  });
}

function readStdinTasks() {
  return new Promise((resolveRead, rejectRead) => {
    const chunks = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('error', (e) => rejectRead(e));
    process.stdin.on('end', () => {
      const tasks = chunks.join('').split(/\r?\n/)
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l));
      resolveRead(tasks);
    });
  });
}

(async () => {
  if (mode === 'control-holds') {
    const results = [];
    results.push(await connectHold('127.0.0.1', loopPort, 2000));
    results.push(await connectHold(lanHost, lanPort, 2000));
    results.push(await connectHold(API_HOST, 443, 2000));
    out({ type: 'control-summary', pid: process.pid, nodeVersion: process.version, results });
    process.exit(results.every((r) => r.outcome === 'CONNECTED') ? 0 : 3);
  }

  // sandbox 'run' mode
  const loopback = await tryConnect('127.0.0.1', loopPort, 4000);
  const lan = await tryConnect(lanHost, lanPort, 6000);
  let tasks = [];
  let stdinError = null;
  try { tasks = await readStdinTasks(); } catch (e) { stdinError = String(e.message); }
  const keyEnvPresent = typeof process.env.DEEPSEEK_API_KEY === 'string' &&
    process.env.DEEPSEEK_API_KEY.length > 0;
  const results = [];
  if (!stdinError && keyEnvPresent) {
    for (const t of tasks) results.push(await inferOnce(t));
  } else if (!keyEnvPresent) {
    for (const t of tasks) results.push({ type: 'inference', seq: t.seq, ok: false, error: 'missing DEEPSEEK_API_KEY env' });
  }
  out({ type: 'summary', pid: process.pid, nodeVersion: process.version, arch: process.arch,
    platform: process.platform, keyEnvPresent, stdinTaskCount: tasks.length, stdinError,
    probes: { loopback, lan }, inferenceCount: results.length,
    allOk: results.length > 0 && results.every((r) => r.ok === true) });
  for (const r of results) out(r);
  process.exit(results.length > 0 && results.every((r) => r.ok === true) ? 0 : 4);
})().catch((e) => {
  process.stdout.write(JSON.stringify({ type: 'fatal', error: String(e && e.message ? e.message : e) }) + '\n');
  process.exit(1);
});
