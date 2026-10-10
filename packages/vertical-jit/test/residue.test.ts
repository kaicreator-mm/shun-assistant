// Residue classification unit tests: the five frozen classes, fail-closed
// dispositions and the strict provider-owned-file mode.
import { describe, expect, it } from 'vitest';
import type { ProviderInstallLayout } from '../src/ports.ts';
import { assertNoProtectedDeletions, classifyResidue, dispositionFor } from '../src/residue.ts';
import { CACHE_DIR, CONFIG_DIR, EXECUTABLE, INSTALL_DIR } from './helpers.ts';

const layout: ProviderInstallLayout = {
  providerId: 'tool.pdftool',
  version: '2.4.1',
  installDirs: [INSTALL_DIR],
  cacheDirs: [CACHE_DIR],
  configDirs: [CONFIG_DIR],
  executables: [EXECUTABLE],
};

describe('residue classification (C-002 preview)', () => {
  it('classifies provider roots, cache and configuration with fail-closed dispositions', () => {
    const candidates = classifyResidue({
      layout,
      observed: [INSTALL_DIR, EXECUTABLE, CACHE_DIR, `${CACHE_DIR}\\thumbs.db`, CONFIG_DIR],
      protectedRoots: [],
    });
    const byPath = new Map(candidates.map((candidate) => [candidate.path, candidate]));
    expect(byPath.get(INSTALL_DIR)).toMatchObject({
      classification: 'PROGRAM_OWNED',
      disposition: 'DELETE',
    });
    expect(byPath.get(EXECUTABLE)).toMatchObject({
      classification: 'PROGRAM_OWNED',
      disposition: 'DELETE',
    });
    expect(byPath.get(CACHE_DIR)).toMatchObject({ classification: 'CACHE', disposition: 'DELETE' });
    expect(byPath.get(`${CACHE_DIR}\\thumbs.db`)).toMatchObject({
      classification: 'CACHE',
      disposition: 'DELETE',
    });
    expect(byPath.get(CONFIG_DIR)).toMatchObject({
      classification: 'CONFIGURATION',
      disposition: 'RETAIN',
    });
  });

  it('classifies unknown-origin paths as USER_CREATED_UNKNOWN with RETAIN', () => {
    const candidates = classifyResidue({
      layout,
      observed: ['C:\\fixtures\\user-assets\\notes.txt'],
      protectedRoots: [],
    });
    expect(candidates[0]).toMatchObject({
      classification: 'USER_CREATED_UNKNOWN',
      disposition: 'RETAIN',
    });
  });

  it('protected roots win over program-owned claims (fail-closed precedence)', () => {
    const candidates = classifyResidue({
      layout,
      observed: [`${INSTALL_DIR}\\documents`],
      protectedRoots: [`${INSTALL_DIR}\\documents`],
    });
    expect(candidates[0]).toMatchObject({ classification: 'PROTECTED', disposition: 'RETAIN' });
  });

  it('strict mode marks unrecorded files inside program dirs as USER_CREATED_UNKNOWN', () => {
    const candidates = classifyResidue({
      layout,
      observed: [EXECUTABLE, `${INSTALL_DIR}\\notes.txt`],
      protectedRoots: [],
      providerOwnedFiles: [EXECUTABLE],
    });
    const byPath = new Map(candidates.map((candidate) => [candidate.path, candidate]));
    expect(byPath.get(EXECUTABLE)).toMatchObject({ classification: 'PROGRAM_OWNED' });
    expect(byPath.get(`${INSTALL_DIR}\\notes.txt`)).toMatchObject({
      classification: 'USER_CREATED_UNKNOWN',
      disposition: 'RETAIN',
    });
  });

  it('pre-existing canaries stay user-created even inside provider roots', () => {
    const canary = `${INSTALL_DIR}\\notes.txt`;
    const candidates = classifyResidue({
      layout,
      observed: [canary, EXECUTABLE],
      protectedRoots: [],
      preExisting: [canary],
    });
    const byPath = new Map(candidates.map((candidate) => [candidate.path, candidate]));
    expect(byPath.get(canary)).toMatchObject({ classification: 'USER_CREATED_UNKNOWN' });
  });

  it('dispositions are total and fail-closed over the frozen classes', () => {
    expect(dispositionFor('PROGRAM_OWNED')).toBe('DELETE');
    expect(dispositionFor('CACHE')).toBe('DELETE');
    expect(dispositionFor('CONFIGURATION')).toBe('RETAIN');
    expect(dispositionFor('USER_CREATED_UNKNOWN')).toBe('RETAIN');
    expect(dispositionFor('PROTECTED')).toBe('RETAIN');
  });

  it('assertNoProtectedDeletions refuses any fail-closed DELETE disposition', () => {
    expect(() =>
      assertNoProtectedDeletions([
        { path: INSTALL_DIR, classification: 'PROTECTED', disposition: 'DELETE' },
      ]),
    ).toThrow(/PROTECTED/);
    expect(() =>
      assertNoProtectedDeletions([
        { path: INSTALL_DIR, classification: 'PROGRAM_OWNED', disposition: 'DELETE' },
        { path: CACHE_DIR, classification: 'CACHE', disposition: 'DELETE' },
      ]),
    ).not.toThrow();
  });
});
