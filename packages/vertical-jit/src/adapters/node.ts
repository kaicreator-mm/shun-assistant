// Real Windows host adapters for the Loop B vertical: read-only filesystem
// observation, shell-free process spawning and a torn-tolerant file journal.

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { JournalEntry, JournalPort } from '../journal.ts';
import type { FilesystemPort, ProcessPort, ProcessResult, ProcessRunSpec } from '../ports.ts';

export class NodeFilesystem implements FilesystemPort {
  async exists(path: string): Promise<boolean> {
    try {
      await stat(path);
      return true;
    } catch {
      return false;
    }
  }

  async isDirectory(path: string): Promise<boolean> {
    try {
      return (await stat(path)).isDirectory();
    } catch {
      return false;
    }
  }

  async listChildren(path: string): Promise<string[]> {
    try {
      return await readdir(path);
    } catch {
      return [];
    }
  }

  async sha256File(path: string): Promise<string> {
    const content = await readFile(path);
    return createHash('sha256').update(content).digest('hex');
  }

  async readText(path: string): Promise<string> {
    return readFile(path, 'utf8');
  }

  async writeText(path: string, contents: string): Promise<void> {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, 'utf8');
  }

  async sizeBytes(path: string): Promise<number> {
    return (await stat(path)).size;
  }
}

export interface SpawnProcessOptions {
  /** Escape hatch for tests; defaults to `winget` resolution via PATH. */
  readonly programPrefix?: readonly string[];
}

/**
 * Spawns the program named by argv[0] with the remaining argv — no shell
 * interpretation at any point (typed argv only, L2 §8.2.1).
 */
export class SpawnProcess implements ProcessPort {
  readonly #prefix: readonly string[];

  constructor(options: SpawnProcessOptions = {}) {
    this.#prefix = options.programPrefix ?? [];
  }

  run(spec: ProcessRunSpec): Promise<ProcessResult> {
    const [program, ...args] = [...this.#prefix, ...spec.argv];
    if (!program) {
      return Promise.resolve({ exitCode: -1, stdout: '', stderr: 'empty argv', timedOut: false });
    }
    return new Promise<ProcessResult>((resolve) => {
      const child = spawn(program, args, {
        cwd: spec.cwd,
        env: spec.env ? { ...process.env, ...spec.env } : process.env,
        windowsHide: true,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const timer =
        spec.timeoutMs !== undefined
          ? setTimeout(() => {
              timedOut = true;
              child.kill();
            }, spec.timeoutMs)
          : undefined;
      child.stdout.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
      });
      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });
      child.on('error', (error) => {
        if (timer) clearTimeout(timer);
        resolve({ exitCode: -1, stdout, stderr: `${stderr}${error.message}`, timedOut });
      });
      child.on('close', (code) => {
        if (timer) clearTimeout(timer);
        resolve({ exitCode: code ?? -1, stdout, stderr, timedOut });
      });
    });
  }
}

/** Append-only JSONL journal with torn-append-tolerant replay (U-06 D5). */
export class FileJournal implements JournalPort {
  readonly #path: string;

  constructor(path: string) {
    this.#path = path;
  }

  async append(entry: JournalEntry): Promise<void> {
    const line = `${JSON.stringify(entry)}\n`;
    const { appendFile, mkdir } = await import('node:fs/promises');
    const { dirname } = await import('node:path');
    await mkdir(dirname(this.#path), { recursive: true });
    await appendFile(this.#path, line, 'utf8');
  }

  async replay(): Promise<JournalEntry[]> {
    let text: string;
    try {
      text = await readFile(this.#path, 'utf8');
    } catch {
      return [];
    }
    const entries: JournalEntry[] = [];
    for (const line of text.split('\n')) {
      if (line.trim().length === 0) continue;
      try {
        entries.push(JSON.parse(line) as JournalEntry);
      } catch {
        // Torn append: isolate the broken line; earlier entries stay intact.
        break;
      }
    }
    return entries;
  }
}
