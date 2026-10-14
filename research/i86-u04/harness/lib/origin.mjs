// origin.mjs — local origin server that replays real payload bytes with
// request accounting, plus fault modes for the negative matrix.
// Always binds an OS-assigned port (listen(0)) unless a fixed port is given.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * modes:
 *  - 'replay'      : serve file bytes verbatim (cache-replay / concurrent legs)
 *  - 'redirect'    : 302 to a foreign, unapproved host (redirect negative)
 *  - 'truncate'    : serve only the first N bytes (incomplete-download negative)
 */
export function startOrigin({ root, port = 0, mode = 'replay', truncateBytes = 1024, redirectTarget = 'http://foreign.host.invalid/payload.zip' }) {
  const server = createServer(async (req, res) => {
    server.requests += 1;
    server.log.push({ ts: new Date().toISOString(), method: req.method, url: req.url, mode });
    try {
      if (mode === 'redirect') {
        res.writeHead(302, { location: redirectTarget });
        res.end();
        return;
      }
      const path = join(root, decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
      const info = await stat(path).catch(() => null);
      if (!info || !info.isFile()) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
        return;
      }
      const bytes = await readFile(path);
      const payload = mode === 'truncate' ? bytes.subarray(0, Math.min(truncateBytes, bytes.length)) : bytes;
      res.writeHead(200, {
        'content-type': 'application/zip',
        'content-length': String(payload.length),
      });
      res.end(payload);
    } catch (error) {
      res.writeHead(500);
      res.end(String(error).slice(0, 200));
    }
  });
  server.requests = 0;
  server.log = [];
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        port: address.port,
        url: (name) => `http://127.0.0.1:${address.port}/${encodeURIComponent(name)}`,
        close: () => new Promise((res) => server.close(res)),
        get requests() {
          return server.requests;
        },
        log: server.log,
      });
    });
  });
}
