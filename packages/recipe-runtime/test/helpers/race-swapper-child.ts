// T04 oracle race-falsifier child: aggressively toggles the scope's ANCESTOR
// directory (<base>/A) between the real directory (<base>/holder renamed in)
// and a junction to the mirror tree, and concurrently swaps the in-tree
// directory <holder>/scope/inner between a recreated real object (new FileId,
// same name and content) and a junction. Walks therefore race against swaps
// at an ancestor position and an in-tree position. Best-effort per step: a
// failed toggle (e.g. sharing violation against an open handle) is skipped
// and the state flags stay the source of truth. Exits leaving the real
// directory in the anchor position when possible.
import {
  existsSync,
  lstatSync,
  mkdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

const [base, durationMs] = process.argv.slice(2);
if (!base || !durationMs) process.exit(11);

const anchor = join(base, 'A');
const holder = join(base, 'holder');
const outside = join(base, 'outside');

type AnchorState = 'real' | 'junction' | 'absent';
let anchorState: AnchorState = 'absent';
let innerIsJunction = false;

// Reconcile with the actual on-disk state first: the parent may have left
// the anchor as a junction, and a state flag that disagrees with the disk
// would make every later toggle a silent no-op.
try {
  if (existsSync(anchor)) {
    anchorState = lstatSync(anchor).isSymbolicLink() ? 'junction' : 'real';
  }
  const innerProbe = join(anchorState === 'real' ? anchor : holder, 'scope', 'inner');
  if (existsSync(innerProbe)) innerIsJunction = lstatSync(innerProbe).isSymbolicLink();
} catch {
  // Fall through with the conservative defaults below.
}

const sleep = (ms: number) => new Promise((resolvePause) => setTimeout(resolvePause, ms));

function liveInner(): string {
  return join(anchorState === 'real' ? anchor : holder, 'scope', 'inner');
}

function step(action: () => void): void {
  try {
    action();
  } catch {
    // A sharing violation against an in-flight walk handle is expected and
    // fine: the toggles are best-effort probes, not a required sequence.
  }
}

function setAnchor(next: AnchorState): void {
  if (anchorState === next) return;
  if (anchorState === 'junction') {
    step(() => rmSync(anchor));
    anchorState = existsSync(anchor) && lstatSync(anchor).isSymbolicLink() ? 'junction' : 'absent';
  } else if (anchorState === 'real') {
    step(() => renameSync(anchor, holder));
    anchorState = existsSync(anchor) ? 'real' : 'absent';
  }
  if (anchorState === 'absent' && next === 'junction') {
    step(() => symlinkSync(outside, anchor, 'junction'));
    anchorState = existsSync(anchor) ? 'junction' : 'absent';
  } else if (anchorState === 'absent' && next === 'real') {
    step(() => renameSync(holder, anchor));
    anchorState = existsSync(anchor) ? 'real' : 'absent';
  }
}

function setInner(next: 'real' | 'junction'): void {
  if (innerIsJunction === (next === 'junction')) return;
  const path = liveInner();
  if (next === 'junction') {
    step(() => {
      rmSync(path, { recursive: true, force: true });
      symlinkSync(outside, path, 'junction');
      innerIsJunction = true;
    });
  } else {
    step(() => {
      rmSync(path, { recursive: true, force: true });
      mkdirSync(path, { recursive: true });
      writeFileSync(join(path, 'b.txt'), 'real-bravo');
      innerIsJunction = false;
    });
  }
}

try {
  const end = Date.now() + Number(durationMs);
  while (Date.now() < end) {
    // Walkable real ancestor with a real in-tree directory.
    setAnchor('real');
    await sleep(1);
    // Same-name in-tree object swap (new FileId, same content) mid-walk.
    setInner('junction');
    await sleep(1);
    setInner('real');
    await sleep(1);
    // Ancestor junction phase: every walk must refuse at the anchor.
    setAnchor('junction');
    await sleep(1);
  }
} finally {
  setInner('real');
  setAnchor('real');
  process.exit(0);
}
