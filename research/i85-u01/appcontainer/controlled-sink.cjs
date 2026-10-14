// Standalone non-privileged test TCP sink; use ONLY an owned test IP/port.
// Bind a specific interface (never 0.0.0.0). Intended for an independently
// reachable positive-control endpoint, not as a proof of isolation by itself.
'use strict';
const net = require('node:net');
const [host, portText] = process.argv.slice(2);
const port = Number(portText);
if (!host || !net.isIP(host) || !Number.isInteger(port) || port < 1 || port > 65535 ||
    host === '0.0.0.0' || host === '::') {
  console.error('Usage: node controlled-sink.cjs <owned-interface-IP> <1-65535>');
  process.exit(2);
}
let accepted = 0;
const server = net.createServer((socket) => {
  accepted += 1;
  console.log(JSON.stringify({
    event: 'accepted', sequence: accepted, remote: socket.remoteAddress,
    local: socket.localAddress, port: socket.localPort,
    when: new Date().toISOString(),
  }));
  socket.end();
});
server.on('error', (err) => {
  console.error(JSON.stringify({ event: 'listen-error', code: err.code, message: err.message }));
  process.exitCode = 3;
});
server.listen({ host, port, exclusive: true }, () => {
  console.log(JSON.stringify({ event: 'ready', host, port, pid: process.pid, when: new Date().toISOString() }));
});
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}
