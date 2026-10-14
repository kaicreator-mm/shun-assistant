// downloader.mjs — redirect-pinned HTTPS fetch with host allowlist.
// redirect:'manual' at every hop: the pipeline, never the network stack,
// decides which hosts are acceptable. Every request carries AbortSignal.timeout.
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, rename, rm, stat } from 'node:fs/promises';
import { dirname } from 'node:path';

export class DownloadError extends Error {
  constructor(code, detail) {
    super(`[${code}] ${detail}`);
    this.name = 'DownloadError';
    this.code = code;
  }
}

/**
 * Stream `url` to destPath.part, hashing on the fly, then atomically rename
 * to destPath. Redirect hops are followed manually and every hop host must be
 * in approvedHosts. Returns {sha256, sizeBytes, hops}.
 */
export async function downloadTo(url, destPath, { approvedHosts, maxBytes, timeoutMs = 120_000 }) {
  let current = String(url);
  const hops = [];
  for (let hop = 0; hop < 5; hop += 1) {
    const parsed = new URL(current);
    if (!approvedHosts.includes(parsed.hostname)) {
      throw new DownloadError(
        'REDIRECT_HOST_UNAPPROVED',
        `host "${parsed.hostname}" is not in the approved allowlist [${approvedHosts.join(', ')}] (hop ${hop})`,
      );
    }
    hops.push({ hop, url: current, host: parsed.hostname });
    let response;
    try {
      response = await fetch(current, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      await rm(`${destPath}.part`, { force: true }).catch(() => {});
      throw new DownloadError(
        'ORIGIN_UNREACHABLE',
        `request to ${parsed.hostname} failed/timed out: ${String(error).slice(0, 200)}`,
      );
    }
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) {
        await rm(`${destPath}.part`, { force: true }).catch(() => {});
        throw new DownloadError('ORIGIN_MALFORMED', `redirect ${response.status} without Location at ${current}`);
      }
      await response.body?.cancel().catch(() => {});
      current = new URL(location, current).toString();
      continue;
    }
    if (response.status !== 200) {
      await rm(`${destPath}.part`, { force: true }).catch(() => {});
      throw new DownloadError('ORIGIN_UNREACHABLE', `origin answered ${response.status} for ${current}`);
    }
    const declaredSize = Number(response.headers.get('content-length') ?? '-1');
    const hasher = createHash('sha256');
    await mkdir(dirname(destPath), { recursive: true });
    await rm(`${destPath}.part`, { force: true });
    let received = 0;
    const fileStream = createWriteStream(`${destPath}.part`);
    try {
      const reader = response.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > maxBytes) {
          throw new DownloadError('SIZE_BUDGET_EXCEEDED', `received ${received} bytes > budget ${maxBytes}`);
        }
        hasher.update(value);
        if (!fileStream.write(value)) {
          await new Promise((resolve, reject) => {
            const onError = (cause) => reject(cause);
            fileStream.once('error', onError);
            fileStream.once('drain', () => {
              fileStream.removeListener('error', onError);
              resolve();
            });
          });
        }
      }
      await new Promise((resolve, reject) => fileStream.end(resolve));
    } catch (error) {
      fileStream.destroy();
      await rm(`${destPath}.part`, { force: true }).catch(() => {});
      throw error;
    }
    const finalStat = await stat(`${destPath}.part`);
    const digest = hasher.digest('hex');
    await rename(`${destPath}.part`, destPath);
    return { sha256: digest, sizeBytes: finalStat.size, hops, declaredSize, streamedBytes: received };
  }
  throw new DownloadError('REDIRECT_LOOP', 'more than 5 redirect hops');
}

/** Streamed content hash of any file. */
export function sha256File(path) {
  return new Promise((resolve, reject) => {
    const hasher = createHash('sha256');
    createReadStream(path)
      .on('data', (chunk) => hasher.update(chunk))
      .on('end', () => resolve(hasher.digest('hex')))
      .on('error', reject);
  });
}
