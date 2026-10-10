"""Negative and blindness tests for T09 only; real Windows execution is Local-owned."""
import builtins
import copy
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tests.fixtures.generate import prepare, inject_growth
from tests.oracles.semantic import PASS, FAIL, INCOMPLETE, evaluate, evaluate_new_video_metric_only


try:
    from PIL import Image, ImageOps
    from skimage.metrics import structural_similarity
    HAS_IMAGE_DEPS = True
except ImportError:
    HAS_IMAGE_DEPS = False



class OracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "sealed"
        cls.seal = prepare(cls.root)
        cls.gold = json.loads((cls.root / "private/gold.json").read_text())
        cls.public = json.loads((cls.root / "public/capability-inputs.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_public_blind_gold_and_sample_determinism(self):
        public_bytes = (self.root / "public/capability-inputs.json").read_text()
        for secret in self.gold["B-040"]["canaries"]:
            self.assertNotIn(secret, public_bytes)
        self.assertNotIn("growth_source", public_bytes)
        self.assertNotIn("protected_sha256", public_bytes)
        precommit = json.loads((self.root / "public/precommit.json").read_text())
        images = self.gold["B-037"]["images"]
        self.assertEqual(200, len(images))
        self.assertEqual([x["id"] for x in sorted(images, key=lambda x: (x["sha256"], x["id"]))[:20]],
                         precommit["sample_ids"])
        self.assertEqual(self.seal, precommit["seal_sha256"])
        with self.assertRaises(ValueError):
            prepare(self.root)

    def test_fixture_regeneration_deterministic_on_same_toolchain(self):
        # A new independent root must reproduce every source digest and seal.
        with tempfile.TemporaryDirectory() as folder:
            other = Path(folder) / "replay"
            regenerated = prepare(other)
            self.assertEqual(self.seal, regenerated)
            self.assertEqual((self.root / "public/precommit.json").read_bytes(),
                             (other / "public/precommit.json").read_bytes())
            for image in self.gold["B-037"]["images"]:
                self.assertEqual((self.root / image["path"]).read_bytes(),
                                 (other / image["path"]).read_bytes())

    def test_private_gold_tamper_fails_seal(self):
        _, obs = self._safe_privacy_report()
        path = self.root / "private/gold.json"
        saved = path.read_bytes()
        try:
            gold = json.loads(saved)
            gold["B-039"]["growth_bytes"] += 1
            path.write_text(json.dumps(gold), encoding="utf-8")
            self.assertEqual(FAIL, evaluate(self.root, "B-040", obs)["fixture_oracle_status"])
        finally:
            path.write_bytes(saved)

    def _safe_privacy_report(self):
        p = self.root / "candidate/B-040/support-report.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "os": {"name": "Windows"}, "device": {"model": "Fixture-PC"},
            "updates": {"last_check": "fixture-date"},
            "redactions": [{"field": "env.API_TOKEN", "marker": "[REDACTED]"}]
        }), encoding="utf-8")
        return p, {"report_path": "candidate/B-040/support-report.json",
                   "local_only": True, "external_disclosures": []}

    def test_privacy_canary_positive_negative_and_absent_evidence(self):
        p, observation = self._safe_privacy_report()
        self.assertEqual(PASS, evaluate(self.root, "B-040", observation)["fixture_oracle_status"])
        unsafe = json.loads(p.read_text())
        unsafe["env"] = self.gold["B-040"]["canaries"][0]
        p.write_text(json.dumps(unsafe))
        self.assertEqual(FAIL, evaluate(self.root, "B-040", observation)["fixture_oracle_status"])
        self._safe_privacy_report()
        incomplete = {k: v for k, v in observation.items() if k != "external_disclosures"}
        self.assertEqual(INCOMPLETE, evaluate(self.root, "B-040", incomplete)["fixture_oracle_status"])
        self.assertEqual(FAIL, evaluate(self.root, "B-040",
                          {**observation, "external_disclosures": ["https://example.invalid"]})
                         ["fixture_oracle_status"])

    def test_precommit_tamper_fails(self):
        _, observation = self._safe_privacy_report()
        path = self.root / "public/precommit.json"
        saved = path.read_bytes()
        try:
            payload = json.loads(saved)
            payload["min_ssim"] = 0.01
            path.write_text(json.dumps(payload))
            self.assertEqual(FAIL, evaluate(self.root, "B-040", observation)["fixture_oracle_status"])
        finally:
            path.write_bytes(saved)

    def _jit(self):
        src = self.root / "inputs/B-038/archive-source/expected.txt"
        archive = self.root / "candidate/B-038/produced.zip"
        archive.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive, "w") as zf:
            zf.write(src, arcname="expected.txt")
        artifact = self.root / "candidate/B-038/acquired.bin"
        artifact.write_bytes(b"fake fixture provider binary")
        import hashlib
        return {
            "provider": {"id": "fixture-provider", "version": "1.2.3",
                         "official_source": "https://example.invalid/official",
                         "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                         "acquired_artifact": "candidate/B-038/acquired.bin",
                         "provenance_evidence_ref": "fixture-only",
                         "trust_verifier": "fixture-verifier"},
            "policy_declared_before_acquisition": True,
            "trust_basis": "verified_official_provenance",
            "events": [{"phase": x} for x in
                       ["plan", "preview", "checkpoint", "approval_or_durable_policy",
                        "remove", "post_verify"]],
            "exact_uninstall_mechanism": "fixture remove by exact package ID",
            "residue_classification": [{"path": "fixture/cache", "classification": "cache",
                                        "deleted": True},
                                       {"path": "fixture/user", "classification": "user-created",
                                        "deleted": False}],
            "reinstall_checkpoint": {"source": "fixture", "version": "1.2.3"},
            "removal_authorization": {"kind": "pre_existing_durable_policy",
                                      "scope": "verified_jit_provider_only"},
            "archive_output": "candidate/B-038/produced.zip",
            "provider_installed_after": False
        }

    def test_jit_gate_and_residue_poison(self):
        good = self._jit()
        self.assertEqual(PASS, evaluate(self.root, "B-038", good)["fixture_oracle_status"])
        missing = copy.deepcopy(good)
        missing["events"] = [e for e in missing["events"] if e["phase"] != "approval_or_durable_policy"]
        self.assertNotEqual(PASS, evaluate(self.root, "B-038", missing)["fixture_oracle_status"])
        poisoned = copy.deepcopy(good)
        poisoned["residue_classification"][1]["deleted"] = True
        self.assertEqual(FAIL, evaluate(self.root, "B-038", poisoned)["fixture_oracle_status"])
        forged = copy.deepcopy(good)
        forged["trust_basis"] = "user_confirmation"
        self.assertEqual(FAIL, evaluate(self.root, "B-038", forged)["fixture_oracle_status"])

    def test_storage_protected_and_size_decoy(self):
        injected = self.root / "private/injection-receipt.json"
        if not injected.exists():
            inject_growth(self.root)
        good = {
            "observed_growth_source": self.gold["B-039"]["growth_source"],
            "events": [{"phase": x} for x in ["observe", "attribute", "classify",
                                              "plan", "preview", "approval_or_durable_policy",
                                              "execute", "verify"]],
            "classifications": {**{x: "disposable_cache" for x in self.gold["B-039"]["disposable"]}, **{x: "protected" for x in self.gold["B-039"]["protected"]}},
            "deleted_paths": self.gold["B-039"]["disposable"].copy(),
            "approval": {"kind": "explicit_approval", "scope": "classified_disposable_cache_only"},
            "measured_reclaimed_bytes": 384 * 1024,
            "free_bytes_before": 1024, "free_bytes_after": 394240,
            "measurement_evidence_ref": "fixture-observation-only"
        }
        # Simulate exact bounded removal after injection; protected decoy remains.
        for relative in self.gold["B-039"]["disposable"]:
            (self.root / relative).unlink()
        self.assertEqual(PASS, evaluate(self.root, "B-039", good)["fixture_oracle_status"])
        decoy = copy.deepcopy(good)
        decoy["deleted_paths"].append("inputs/B-039/workspace/protected/precious.bin")
        self.assertEqual(FAIL, evaluate(self.root, "B-039", decoy)["fixture_oracle_status"])
        absent_metric = copy.deepcopy(good)
        del absent_metric["measured_reclaimed_bytes"]
        self.assertEqual(INCOMPLETE, evaluate(self.root, "B-039", absent_metric)["fixture_oracle_status"])

    def _images(self):
        output_dir = self.root / "candidate/B-037"
        output_dir.mkdir(parents=True, exist_ok=True)
        outputs = {}
        for item in self.gold["B-037"]["images"]:
            src = self.root / item["path"]
            dst = output_dir / item["id"]
            with Image.open(src) as im:
                oriented = ImageOps.exif_transpose(im)
                ratio = min(1.0, 1600 / max(oriented.size))
                size = tuple(max(1, round(d * ratio)) for d in oriented.size)
                resized = oriented.resize(size, Image.Resampling.LANCZOS)
                resized.save(dst, format=("JPEG" if dst.suffix == ".jpg" else "PNG"),
                             exif=im.getexif(), **({"quality": 98} if dst.suffix == ".jpg" else {}))
            outputs[item["id"]] = "candidate/B-037/" + item["id"]
        return {"outputs": outputs,
                "provider_selection": {"selected_binding_id": "mock-fixture-only",
                                       "hard_gates_evidence": ["fixture"]}}

    def test_image_ssim_pass_injected_damage_and_missing_metric(self):
        good = self._images()
        self.assertEqual(PASS, evaluate(self.root, "B-037", good)["fixture_oracle_status"])
        chosen = json.loads((self.root / "public/precommit.json").read_text())["sample_ids"][0]
        path = self.root / good["outputs"][chosen]
        with Image.open(path) as im:
            from PIL import ImageDraw
            damaged = im.copy()
            ImageDraw.Draw(damaged).rectangle((0, 0, damaged.width, damaged.height),
                                               fill=(0, 0, 0))
            damaged.save(path, exif=im.getexif())
        self.assertEqual(FAIL, evaluate(self.root, "B-037", good)["fixture_oracle_status"])
        self._images()  # restore for missing-metric injection
        real_import = builtins.__import__
        def no_skimage(name, *args, **kwargs):
            if name.startswith("skimage"):
                raise ImportError("injected metric missing")
            return real_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=no_skimage):
            self.assertEqual(INCOMPLETE, evaluate(self.root, "B-037", good)
                             ["fixture_oracle_status"])

    def test_video_vmaf_new_metric_negative_control(self):
        pre = {"sealed_before_execution": True, "duration_seconds": 120,
               "temporal_segments": [0, 25, 50, 75, 100]}
        self.assertEqual(INCOMPLETE, evaluate_new_video_metric_only(pre, {})
                         ["fixture_oracle_status"])
        self.assertEqual(FAIL, evaluate_new_video_metric_only(pre, {"segment_vmaf": [90, 90, 90, 90, 70]})
                         ["fixture_oracle_status"])
        self.assertEqual(PASS, evaluate_new_video_metric_only(pre, {"segment_vmaf": [90] * 5})
                         ["fixture_oracle_status"])

    def test_b010_historical_result_cannot_be_upgraded(self):
        with self.assertRaises(ValueError):
            evaluate(self.root, "B-010", {})


if __name__ == "__main__":
    unittest.main()
