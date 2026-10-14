// oracle.mjs — independent task-result oracle for the ripgrep leg.
// The oracle recomputes the expected match set in plain node (line scan) and
// compares it against the tool output as a multiset. The rg exit code is a
// transport fact and is never trusted.
import { randomInt } from 'node:crypto';

/** Generate a deterministic-content fixture tree; returns {files, linesByFile}. */
export function buildFixtureText(fileCount = 6, linesPerFile = 40) {
  const files = [];
  for (let f = 0; f < fileCount; f += 1) {
    const lines = [];
    for (let i = 0; i < linesPerFile; i += 1) {
      // pattern lines are 'NEEDLE_xxxx' tokens sprinkled among filler text
      if (randomInt(4) === 0) {
        lines.push(`filler ${f}-${i} NEEDLE_${String(randomInt(10000)).padStart(4, '0')} trailing ${i}`);
      } else {
        lines.push(`filler ${f}-${i} nothing-to-see trailing ${i}`);
      }
    }
    files.push({ name: `fixture-${f}.txt`, lines });
  }
  return files;
}

/** Independent expectation: every line containing NEEDLE_\d{4}, with file attribution. */
export function expectedMatches(files) {
  const expected = [];
  for (const file of files) {
    file.lines.forEach((line, index) => {
      if (/NEEDLE_\d{4}/.test(line)) expected.push(`${file.name}:${index + 1}:${line}`);
    });
  }
  return expected.sort();
}

/** Parse rg output lines `name:lineNo:text` into the same canonical shape. */
export function parseRgOutput(stdout) {
  return stdout
    .split(/\r?\n/)
    .filter((line) => line.length > 0)
    .map((line) => {
      const m = /^([^:]+):(\d+):(.*)$/.exec(line);
      if (!m) return null;
      return `${m[1]}:${m[2]}:${m[3]}`;
    })
    .filter(Boolean)
    .sort();
}

export function oracleVerdict(expected, actual) {
  const missing = expected.filter((line) => !actual.includes(line));
  const unexpected = actual.filter((line) => !expected.includes(line));
  return {
    match: missing.length === 0 && unexpected.length === 0,
    expectedCount: expected.length,
    actualCount: actual.length,
    missing: missing.slice(0, 5),
    unexpected: unexpected.slice(0, 5),
  };
}
