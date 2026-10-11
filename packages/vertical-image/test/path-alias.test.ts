// Negative control for the T05 safety correction (Issue #38, VI-P1-03): the
// output/input directory precheck must compare final (real) paths, so a
// junction (Windows) or symlink (POSIX) alias between the two cannot defeat
// the lexical "must differ from every input directory" guarantee.
//
// Junctions need no elevation on Windows, so the alias is built with
// `mklink /J` there and with a plain symlink elsewhere — repeatable on both
// BUILD_HOST targets.
import { execFileSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runImageBatchProcess } from '../src/executor.ts';
import { makeSharpImageProvider } from '../src/sharp-engine.ts';
import { fixtureDir, jpegBytes, testFacts } from './helpers.ts';

const dirsToRemove: string[] = [];

afterEach(async () => {
  for (const dir of dirsToRemove.reverse()) {
    await rm(dir, { recursive: true, force: true });
  }
  dirsToRemove.length = 0;
});

async function scratchDir(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), 'shun-alias-'));
  dirsToRemove.push(path);
  return path;
}

/** Directory alias without elevation: junction on Windows, symlink elsewhere. */
function makeDirAlias(linkPath: string, targetPath: string): void {
  if (process.platform === 'win32') {
    execFileSync('cmd.exe', ['/d', '/c', 'mklink', '/J', linkPath, targetPath], {
      stdio: 'pipe',
    });
  } else {
    symlinkSync(targetPath, linkPath);
  }
}

async function sourceDirWithImage(parent: string, seed: number): Promise<string> {
  const srcDir = join(parent, 'src');
  await mkdir(srcDir);
  await writeFile(join(srcDir, 'a.jpg'), await jpegBytes({ width: 600, height: 400, seed }));
  return srcDir;
}

function c001Input(inputFiles: Array<{ path: string; format: 'JPG' }>, outputDirectory: string) {
  return {
    taskId: 'task-alias',
    inputFiles,
    operation: { kind: 'RESIZE' as const, maxLongEdgePx: 300 },
    metadataPolicy: { preserveCaptureDate: true as const },
    outputDirectory,
    qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1' as const, ssimThreshold: 0.95 },
    networkUsage: 'LOCAL_ONLY' as const,
  };
}

const deps = () => ({ facts: testFacts(), providers: [makeSharpImageProvider()] });

describe('output/input directory alias precheck (VI-P1-03)', () => {
  it('blocks an output directory that aliases an input directory', async () => {
    const parent = await scratchDir();
    const srcDir = await sourceDirWithImage(parent, 401);
    const alias = join(parent, 'alias');
    makeDirAlias(alias, srcDir);

    const result = await runImageBatchProcess(
      c001Input([{ path: join(srcDir, 'a.jpg'), format: 'JPG' }], alias),
      deps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('POLICY_BLOCKED');
    }
    // Sources intact, nothing written through the alias.
    expect((await readdir(srcDir)).sort()).toEqual(['a.jpg']);
  });

  it('blocks when an aliased input path resolves onto the output directory', async () => {
    const parent = await scratchDir();
    const srcDir = await sourceDirWithImage(parent, 402);
    const alias = join(parent, 'alias');
    makeDirAlias(alias, srcDir);

    const result = await runImageBatchProcess(
      c001Input([{ path: join(alias, 'a.jpg'), format: 'JPG' }], srcDir),
      deps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('POLICY_BLOCKED');
    }
    expect((await readdir(srcDir)).sort()).toEqual(['a.jpg']);
  });

  it('does not block a genuinely distinct output directory (overblocking guard)', async () => {
    const src = await fixtureDir('shun-alias-src-');
    const out = await fixtureDir('shun-alias-out-');
    dirsToRemove.push(src.path, out.path);
    const a = await src.write('a.jpg', await jpegBytes({ width: 600, height: 400, seed: 403 }));
    const result = await runImageBatchProcess(
      c001Input([{ path: a, format: 'JPG' }], out.path),
      deps(),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.output.records[0]?.status).toBe('WRITTEN');
    }
  });
});
