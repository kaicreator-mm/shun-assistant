"""T10 B-039 harness-side pre-delete size evidence.

Runs AFTER fixture-lock verification and synthetic growth injection, but BEFORE
candidate execution. Reads only public capability-inputs.json + visible
workspace metadata; never reads private gold/injection receipt. The output file
lives under private/ because it is oracle-owned evidence, not candidate input.
"""
import argparse
import json
from pathlib import Path

DISPOSABLE_DIR_NAMES = {"cache", "caches", "temp", "tmp", "temporary"}


def safe_under(root: Path, candidate: Path) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    if candidate == root or root not in candidate.parents:
        raise ValueError("path escaped fixture root")
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    public = json.loads((root / "public/capability-inputs.json").read_text(encoding="utf-8"))
    entry = public.get("B-039")
    if not isinstance(entry, dict) or entry.get("capability_id") != "system.storage.diagnose_bounded_action":
        raise ValueError("B039 public input mismatch")
    workspace_rel = entry.get("workspace")
    if not isinstance(workspace_rel, str):
        raise ValueError("B039 workspace missing")
    workspace = safe_under(root, root / workspace_rel)

    sizes = {}
    for child in workspace.iterdir():
        if not child.is_dir() or child.is_symlink():
            continue
        if child.name.lower() not in DISPOSABLE_DIR_NAMES:
            continue
        for file in child.rglob("*"):
            if file.is_symlink() or not file.is_file():
                continue
            actual = safe_under(root, file)
            rel = actual.relative_to(root).as_posix()
            sizes[rel] = actual.stat().st_size

    if not sizes:
        raise ValueError("B039 no visible disposable file sizes to precommit")
    target = root / "private/eligible-sizes.json"
    if target.exists():
        raise ValueError("refusing to overwrite existing eligible-sizes evidence")
    target.write_text(
        json.dumps(sizes, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"eligible_size_evidence": target.as_posix(), "entries": len(sizes)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
