"""T09 fixed-toolchain fixture lock. Run before candidate execution; test-owned only."""
import argparse
import hashlib
import json
import platform
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

LOCK_PATH = Path(__file__).with_name("fixture-lock-v0.1.json")
FIXED_SOURCE_PATHS = {
    "inputs/B-039/workspace/cache/base-cache.bin",
    "inputs/B-040/support-context.json",
    "public/capability-inputs.json",
}
NON_IMAGE_PATHS = {
    "inputs/B-038/archive-source/expected.txt",
    "inputs/B-038/user-data/keep-me.txt",
    "inputs/B-039/workspace/cache/base-cache.bin",
    "inputs/B-039/workspace/protected/precious.bin",
    "inputs/B-040/support-context.json",
    "private/gold.json",
    "public/capability-inputs.json",
    "public/precommit.json",
}


class FixtureLockError(ValueError):
    """Fixed non-sensitive error codes only."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def installed_toolchain():
    packages = {}
    for key, distribution in (("pillow", "Pillow"), ("numpy", "numpy"),
                              ("scikit-image", "scikit-image")):
        try:
            packages[key] = version(distribution)
        except PackageNotFoundError:
            packages[key] = "MISSING"
    return {"python": platform.python_version(), **packages}


def require(ok, code):
    if not ok:
        raise FixtureLockError(code)


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise FixtureLockError("MALFORMED_MANIFEST") from exc


def sha_file(root, rel):
    path = root / rel
    require(path.is_file() and not path.is_symlink(), "SOURCE_MISSING")
    return sha256(path.read_bytes())


def git_blob_sha_text(content):
    """Match Git's text clean filter on autocrlf Windows checkouts, not raw worktree bytes."""
    normalized = content.replace(b"\r\n", b"\n")
    return hashlib.sha1(b"blob " + str(len(normalized)).encode() + b"\0" + normalized).hexdigest()


def generator_blob_sha():
    return git_blob_sha_text(Path(__file__).with_name("generate.py").read_bytes())


def check_fixture_lock(root, record=None, installed=None):
    """Strict pre-execution check. Overrides are exclusively for unit injections."""
    record = read_json(LOCK_PATH) if record is None else record
    require(isinstance(record, dict) and record.get("schema") == "shun.t09.fixture-lock.v1",
            "LOCK_SCHEMA")
    actual = installed_toolchain() if installed is None else installed
    require(actual == record.get("toolchain"), "TOOLCHAIN_MISMATCH")
    require(generator_blob_sha() == record.get("generator_git_blob_sha"), "GENERATOR_DRIFT")
    require(record.get("reproducibility", "").startswith("SAME_TOOLCHAIN_ONLY"), "SCOPE_DRIFT")
    require(record.get("non_image_paths") == sorted(NON_IMAGE_PATHS), "LOCK_FILE_SET")
    root = Path(root).resolve()
    require(root.is_dir(), "MISSING_ROOT")
    entries = list(root.rglob("*"))
    require(not any(p.is_symlink() for p in entries), "SYMLINK")
    files = {p.relative_to(root).as_posix() for p in entries if p.is_file()}

    gold = read_json(root / "private/gold.json")
    seal = read_json(root / "public/precommit.json")
    seed = record.get("seed")
    require(seed == 37040 and gold.get("seed") == seed and seal.get("seed") == seed,
            "SEED_DRIFT")
    require(seal.get("seal_sha256") == record.get("precommit_seal_sha256"),
            "LOCK_SEAL_MISMATCH")
    require(sha256(canonical({k: v for k, v in seal.items() if k != "seal_sha256"})) ==
            record["precommit_seal_sha256"], "PRECOMMIT_TAMPER")
    require(sha256(canonical(gold)) == seal.get("gold_sha256"), "GOLD_TAMPER")

    images = gold["B-037"]["images"]
    require(len(images) == record.get("image_file_count") == 200, "IMAGE_COUNT")
    manifest = {}
    for item in images:
        name, rel, hashed = item["id"], item["path"], item["sha256"]
        require(isinstance(name, str) and name.startswith("img_") and
                name.endswith((".jpg", ".png")) and
                rel == "inputs/B-037/images/" + name and
                isinstance(hashed, str) and len(hashed) == 64 and
                rel not in manifest, "IMAGE_MANIFEST")
        manifest[rel] = hashed
    require(seal.get("image_sha256") ==
            {item["id"]: item["sha256"] for item in images}, "IMAGE_SEAL")
    selected = sorted(images, key=lambda item: (item["sha256"], item["id"]))[:20]
    require(seal.get("sample_ids") == [item["id"] for item in selected] and
            seal.get("sample_size") == 20 and seal.get("min_ssim") == 0.95 and
            seal.get("max_long_edge_px") == 1600, "SAMPLE_SEAL")
    require(files == set(manifest) | NON_IMAGE_PATHS and
            len(files) == record.get("generated_file_count") == 208, "FILE_SET")

    for rel, hashed in manifest.items():
        require(sha_file(root, rel) == hashed, "IMAGE_HASH")
    protected = {**gold["B-038"]["user_assets"], **gold["B-039"]["protected"]}
    require(seal.get("protected_sha256") == protected, "PROTECTED_MANIFEST")
    for rel, hashed in protected.items():
        require(rel in NON_IMAGE_PATHS and sha_file(root, rel) == hashed, "PROTECTED_HASH")
    require(sha_file(root, "inputs/B-038/archive-source/expected.txt") ==
            gold["B-038"]["archive_entry_sha256"], "ARCHIVE_HASH")

    # Fixed input hashes are independent of the mutable fixture root and sealed gold.
    # Derived from the pinned generator; the new expected digests need Local revalidation.
    fixed = record.get("fixed_source_sha256")
    require(isinstance(fixed, dict) and set(fixed) == FIXED_SOURCE_PATHS and
            all(isinstance(digest, str) and len(digest) == 64 and
                all(c in "0123456789abcdef" for c in digest)
                for digest in fixed.values()), "LOCK_FIXED_SOURCE_SET")
    for rel in sorted(FIXED_SOURCE_PATHS):
        require(sha_file(root, rel) == fixed[rel], "FIXED_SOURCE_HASH")

    public_bytes = (root / "public/capability-inputs.json").read_bytes()
    public_text = public_bytes.decode("utf-8")
    require(not any(canary in public_text for canary in gold["B-040"]["canaries"]) and
            "growth_source" not in public_text and "protected_sha256" not in public_text,
            "PRIVATE_GOLD_LEAK")
    require(read_json(root / "public/capability-inputs.json").get("schema") ==
            "shun.t09.capability-inputs.v1", "PUBLIC_SCHEMA")
    return {"fixture_lock_status": "PASS", "scope": "FIXTURE_LOCK_ONLY",
            "real_host_validation": "NOT_RUN", "seed": seed,
            "seal_sha256": record["precommit_seal_sha256"],
            "image_file_count": len(images), "generated_file_count": len(files),
            "toolchain": actual}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["verify"])
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check_fixture_lock(args.root)
    except (FixtureLockError, OSError, ValueError, KeyError, TypeError) as exc:
        code = str(exc) if isinstance(exc, FixtureLockError) else "MALFORMED_FIXTURE"
        print(json.dumps({"fixture_lock_status": "FAIL", "error_code": code,
                          "scope": "FIXTURE_LOCK_ONLY", "real_host_validation": "NOT_RUN"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
