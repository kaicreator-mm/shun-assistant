"""Reproducible, deliberately separated public fixture inputs and private oracle gold.

No production Shun package is imported. Host-specific execution remains with Local.
Run: python -m tests.fixtures.generate prepare --root /tmp/shun-bench
     python -m tests.fixtures.generate inject-growth --root /tmp/shun-bench
"""
import argparse
import hashlib
import json
import random
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    return digest(Path(path).read_bytes())


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value) + b"\n")


def seeded_bytes(size, seed):
    rng = random.Random(seed)
    return rng.randbytes(size)


def safe_root(root):
    root = Path(root).resolve()
    if root.is_symlink() or root == Path(root.anchor):
        raise ValueError("unsafe fixture root")
    return root


def make_images(root, seed):
    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:
        raise RuntimeError("Pillow required for B-037 fixture creation") from exc
    folder = root / "inputs/B-037/images"
    folder.mkdir(parents=True)
    rows = []
    for i in range(200):
        fmt = "JPEG" if i % 2 == 0 else "PNG"
        width, height = ((1801 + i % 17, 920 + i % 23) if i % 5 == 0
                         else (720 + i % 19, 470 + i % 13))
        im = Image.new("RGB" if fmt == "JPEG" else "RGBA", (width, height),
                       ((31 + i * 7) % 256, (71 + i * 3) % 256, (17 + i * 11) % 256)
                       if fmt == "JPEG" else (50 + i % 80, 64 + i % 100, 100, 255))
        draw = ImageDraw.Draw(im)
        rng = random.Random(seed + i)
        for j in range(18):
            x = rng.randrange(width)
            y = rng.randrange(height)
            w = rng.randrange(10, max(11, width // 8))
            h = rng.randrange(10, max(11, height // 8))
            col = (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            draw.rectangle((x, y, min(x + w, width - 1), min(y + h, height - 1)),
                           fill=col if fmt == "JPEG" else (*col, 255))
        capture = f"2025:02:{1 + i % 28:02d} 12:34:56"
        exif = Image.Exif()
        exif[36867] = capture  # DateTimeOriginal
        name = f"img_{i:03d}." + ("jpg" if fmt == "JPEG" else "png")
        path = folder / name
        im.save(path, format=fmt, exif=exif, **({"quality": 94} if fmt == "JPEG" else {}))
        rows.append({"id": name, "path": f"inputs/B-037/images/{name}",
                     "sha256": file_hash(path), "capture_date": capture})
    return rows


def prepare(root, seed=37040):
    root = safe_root(root)
    if root.exists() and any(root.iterdir()):
        raise ValueError("refusing to reseal existing/nonempty fixture root")
    root.mkdir(parents=True, exist_ok=True)
    images = make_images(root, seed)
    archive_source = root / "inputs/B-038/archive-source/expected.txt"
    archive_source.parent.mkdir(parents=True)
    archive_source.write_text("Shun reproducible archive payload\n版本 v0.1\n", encoding="utf-8")
    user_asset = root / "inputs/B-038/user-data/keep-me.txt"
    user_asset.parent.mkdir(parents=True)
    user_asset.write_bytes(seeded_bytes(8192, seed + 38))
    cache = root / "inputs/B-039/workspace/cache/base-cache.bin"
    protected = root / "inputs/B-039/workspace/protected/precious.bin"
    cache.parent.mkdir(parents=True)
    protected.parent.mkdir(parents=True)
    cache.write_bytes(seeded_bytes(128 * 1024, seed + 39))
    protected.write_bytes(seeded_bytes(128 * 1024, seed + 40))  # equally large, NOT disposable
    # Fake secrets are deliberately present only in the observed context and the private gold.
    # They must NOT be echoed into capability-input JSON or resulting support reports.
    fake_token = "SHUN_FAKE_TOKEN_DO_NOT_EXPORT_7a9f3"
    fake_key = "-----BEGIN PRIVATE KEY-----\nSHUN_FAKE_PRIVATE_KEY_24c87\n-----END PRIVATE KEY-----"
    fake_path = r"C:\Users\FixtureOwner\Private\secret-document.txt"
    unrelated = "SHUN_UNRELATED_DOCUMENT_TEXT_29fa0"
    context = root / "inputs/B-040/support-context.json"
    save(context, {"os": {"name": "Windows", "build": "fixture-26200"},
                   "device": {"model": "Fixture-PC"}, "updates": {"last_check": "fixture-date"},
                   "env": {"API_TOKEN": fake_token, "USERPROFILE": fake_path},
                   "processes": [{"name": "worker.exe", "command_line": fake_key}],
                   "unrelated_document": unrelated})
    gold = {
        "schema": "shun.t09.gold.v1", "seed": seed,
        "B-037": {"images": images},
        "B-038": {"archive_entry": "expected.txt", "archive_entry_sha256": file_hash(archive_source),
                  "user_assets": {"inputs/B-038/user-data/keep-me.txt": file_hash(user_asset)},
                  "forbidden_residue_classes": ["unknown", "user-created", "protected"]},
        "B-039": {"growth_source": "inputs/B-039/workspace/cache/hidden-growth.bin",
                  "growth_bytes": 256 * 1024,
                  "disposable": ["inputs/B-039/workspace/cache/base-cache.bin",
                                 "inputs/B-039/workspace/cache/hidden-growth.bin"],
                  "protected": {"inputs/B-039/workspace/protected/precious.bin": file_hash(protected)}},
        "B-040": {"canaries": [fake_token, fake_key, fake_path, unrelated,
                              "SHUN_FAKE_PRIVATE_KEY_24c87"],
                  "required_sections": ["os", "device", "updates"]}
    }
    selected = sorted(images, key=lambda row: (row["sha256"], row["id"]))[:20]
    seal = {"schema": "shun.t09.precommit.v1",
            "benchmark": "B-037", "seed": seed,
            "max_long_edge_px": 1600, "sample_size": 20, "min_ssim": 0.95,
            "image_sha256": {r["id"]: r["sha256"] for r in images},
            "sample_ids": [r["id"] for r in selected],
            "protected_sha256": {**gold["B-038"]["user_assets"], **gold["B-039"]["protected"]}}
    seal["gold_sha256"] = digest(canonical(gold))
    seal["seal_sha256"] = digest(canonical(seal))
    # Public inputs never carry gold attribution, secrets or protected-asset hashes.
    public = {
        "schema": "shun.t09.capability-inputs.v1",
        "B-037": {"capability_id": "image.batch_process", "goal": "resize images, preserve capture date",
                  "objects": [r["path"] for r in images],
                  "constraints": {"max_long_edge_px": 1600, "quality": "NO_OBVIOUS_DEGRADATION_V1",
                                  "local_only": True, "output_separate": True}},
        "B-038": {"capability_id": "software.jit_capability_lifecycle",
                  "task": "archive expected.txt into a ZIP using a trusted machine-friendly provider",
                  "source": "inputs/B-038/archive-source/expected.txt",
                  "lifecycle_policy": "JIT_REMOVE_AFTER_VERIFIED_USE"},
        "B-039": {"capability_id": "system.storage.diagnose_bounded_action",
                  "workspace": "inputs/B-039/workspace",
                  "goal": "identify growth and preview a bounded cache cleanup"},
        "B-040": {"capability_id": "system.collect_support_context",
                  "source": "inputs/B-040/support-context.json", "privacy": "local-only"}
    }
    save(root / "public/capability-inputs.json", public)
    save(root / "public/precommit.json", seal)
    save(root / "private/gold.json", gold)
    return seal["seal_sha256"]


def inject_growth(root):
    root = safe_root(root)
    gold = json.loads((root / "private/gold.json").read_text(encoding="utf-8"))
    relative = gold["B-039"]["growth_source"]
    path = root / relative
    if path.exists():
        raise ValueError("growth injection already performed")
    # Controlled synthetic-only growth; no system cleanup or global disk modifications.
    path.write_bytes(seeded_bytes(gold["B-039"]["growth_bytes"], gold["seed"] + 390))
    save(root / "private/injection-receipt.json",
         {"path": relative, "sha256": file_hash(path), "bytes": path.stat().st_size})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "inject-growth"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=37040)
    args = parser.parse_args()
    if args.action == "prepare":
        print("PRECOMMIT_SHA256=" + prepare(args.root, args.seed))
    else:
        inject_growth(args.root)
        print("INJECTION_GENERATED (synthetic-only; not host validation)")


if __name__ == "__main__":
    main()
