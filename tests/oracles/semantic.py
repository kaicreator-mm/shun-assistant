"""Independent T09 semantic oracles, deliberately disconnected from Shun runtime schemas.

Output is FIXTURE_ORACLE evidence only; never a real Windows or release claim.
Candidate output is untrusted. Private gold stays local to this process.
"""
import hashlib
import json
import math
import os
import zipfile
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
INCOMPLETE = "INCOMPLETE_SEMANTIC_VERIFICATION"


def _hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def _safe_path(root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("bad path")
    p = Path(relative)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("path traversal")
    resolved = (root / p).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("path escapes fixture root")
    return resolved


def _file_identity(path):
    """Same-file identity via os.stat, independent of any lexical path.

    Returns (st_dev, st_ino) — the volume serial plus NTFS/POSIX file ID that
    every hardlink of a file shares and that os.stat of a symlink reports for
    its target — or None when the filesystem does not expose file IDs
    (st_ino == 0) or the stat fails. st_nlink counts how many directory
    entries share an identity, but a freshly written output also has
    st_nlink == 1, so only an identity *match against a sealed input* proves
    aliasing; the link count alone can neither prove nor exclude it.
    """
    try:
        info = os.stat(path)
    except OSError:
        return None
    if info.st_ino == 0:
        return None
    return info.st_dev, info.st_ino


def _placeholder_text(value):
    """Evidence literals that claim a citation while citing nothing."""
    if not isinstance(value, str):
        return True
    return value.strip().lower() in {
        "", "n/a", "na", "none", "null", "-", "--", "tbd", "todo",
        "unknown", "unmeasured", "not measured", "not_measured", "placeholder",
    }


class Verdict:
    def __init__(self, case):
        self.case = case
        self.checks = []

    def check(self, name, satisfied, missing=False):
        self.checks.append({"check": name, "status": INCOMPLETE if missing else (PASS if satisfied else FAIL)})

    def require(self, name, value):
        missing = value is None
        self.check(name, not missing, missing=missing)
        return not missing

    def result(self):
        statuses = [x["status"] for x in self.checks]
        status = FAIL if FAIL in statuses else INCOMPLETE if INCOMPLETE in statuses else PASS
        if not statuses:
            status = INCOMPLETE
        return {"case_id": self.case, "fixture_oracle_status": status,
                "checks": self.checks, "scope": "FIXTURE_ORACLE_ONLY",
                "real_host_validation": "NOT_RUN"}


def _sealed(root, gold, public, seal, verdict):
    # The recorded seal must be externally checkpointed BEFORE candidate output exists.
    stated = seal.get("seal_sha256")
    computed = hashlib.sha256(_canonical({k: v for k, v in seal.items()
                                          if k != "seal_sha256"})).hexdigest()
    verdict.check("precommit.digest", stated == computed and isinstance(stated, str))
    verdict.check("gold.digest", seal.get("gold_sha256") == hashlib.sha256(_canonical(gold)).hexdigest())
    verdict.check("gold.not_in_public",
                  not any(t in _canonical(public).decode("utf-8")
                          for t in gold["B-040"]["canaries"])
                  and "growth_source" not in _canonical(public).decode("utf-8")
                  and "protected_sha256" not in _canonical(public).decode("utf-8"))
    for relative, expected in seal.get("protected_sha256", {}).items():
        path = _safe_path(root, relative)
        verdict.check("protected.sha256:" + relative,
                      path.is_file() and _hash_file(path) == expected)


def _event_order(verdict, events, required):
    """Fail closed on *every* side effect, not merely a valid later subsequence.

    Each sealed benchmark describes exactly one bounded destructive operation.
    More than one remove/execute therefore requires a different, independently
    precommitted action sequence; a repeated effect cannot inherit one gate.
    Only the test-owned, side-effect-free "audit_note" phase may be extra.
    Unknown phases cannot be assumed harmless, and audit_note must not carry
    unvalidated effect metadata. This oracle does not authenticate host traces.
    """
    if not isinstance(events, list):
        verdict.require("event.sequence", None)
        return
    if not all(isinstance(event, dict)
               and isinstance(event.get("phase"), str)
               and bool(event["phase"]) for event in events):
        verdict.check("event.entries_well_formed", False)
        return
    tags = [event["phase"] for event in events]
    # Closed test-owned audit vocabulary. Unknown side effects such as
    # "delete_user_asset"/"cleanup_execute" must not bypass R2 authorization.
    # The only benign extra event in the sealed fixtures is a bare audit_note;
    # extra metadata can contain an untrusted destructive effect declaration.
    extras = [event for event in events if event["phase"] not in required]
    verdict.check("event.extra_phases_audit_only",
                  all(event == {"phase": "audit_note"} for event in extras))
    unique = True
    for tag in required:
        exactly_once = tags.count(tag) == 1
        verdict.check("event.exactly_once:" + tag, exactly_once)
        unique = unique and exactly_once
    # The sealed fixture permits one destructive operation total. Never treat
    # a different destructive phase as an ignorable audit-only extra event.
    effect = next((tag for tag in required if tag in ("remove", "execute")), None)
    verdict.check("event.destructive_effect_exclusive",
                  [tag for tag in tags if tag in ("remove", "execute")] == [effect])
    if not unique:
        return
    positions = [tags.index(tag) for tag in required]
    verdict.check("event.order", positions == sorted(positions))


def _image_oracle(root, observation, gold, seal, verdict):
    image_gold = gold["B-037"]["images"]
    originals = {r["id"]: r for r in image_gold}
    fixed_order = sorted(image_gold, key=lambda r: (r["sha256"], r["id"]))[:20]
    verdict.check("sample.precommitted",
                  seal.get("sample_ids") == [r["id"] for r in fixed_order]
                  and seal.get("sample_size") == 20 and seal.get("min_ssim") == 0.95
                  and seal.get("max_long_edge_px") == 1600)
    input_identities = set()
    for row in image_gold:
        path = _safe_path(root, row["path"])
        verdict.check("original.sha256:" + row["id"],
                      path.is_file() and _hash_file(path) == row["sha256"]
                      and seal.get("image_sha256", {}).get(row["id"]) == row["sha256"])
        identity = _file_identity(path)
        if identity is not None:
            input_identities.add(identity)
    if not verdict.require("provider.selection", observation.get("provider_selection")):
        return
    selection = observation["provider_selection"]
    if not isinstance(selection, dict):
        verdict.check("provider.selection.object", False)
        return
    # P2: an unstated binding or an empty/malformed hard-gates record must not
    # PASS. Absent evidence stays INCOMPLETE; present-but-empty evidence is a
    # falsified claim and FAILs. The oracle only requires the disposition to be
    # stated; it does not authenticate production Provider trust (T10 owns that).
    binding = selection.get("selected_binding_id")
    if binding is None:
        verdict.require("provider.selected_binding", None)
    else:
        verdict.check("provider.selected_binding.specified",
                      isinstance(binding, str) and binding.strip() != "")
    gates = selection.get("hard_gates_evidence")
    if gates is None:
        verdict.require("provider.hard_gates_evidence", None)
    else:
        verdict.check("provider.hard_gates_evidence.specified",
                      isinstance(gates, list) and len(gates) > 0
                      and all(isinstance(entry, str) and entry.strip() for entry in gates))
    if not verdict.require("output.manifest", observation.get("outputs")):
        return
    outputs = observation["outputs"]
    if not isinstance(outputs, dict):
        verdict.check("output.manifest.type", False)
        return
    verdict.check("output.exact_count", set(outputs) == set(originals))
    try:
        from PIL import Image, ImageOps
        import numpy as np
        from skimage.metrics import structural_similarity
    except ImportError:
        verdict.check("ssim.metric.available", False, missing=True)
        return
    for ident, row in originals.items():
        rel = outputs.get(ident)
        if rel is None:
            verdict.check("output.present:" + ident, False)
            continue
        try:
            path = _safe_path(root, rel)
            # Prevent a candidate from "passing" by pointing output to original.
            if not rel.startswith("candidate/B-037/") or not path.is_file():
                verdict.check("output.separate:" + ident, False)
                continue
            # P1-1: a lexically separate candidate path can still alias the
            # sealed input. A symlink output, or a hardlink sharing any
            # input's file identity, must FAIL independently of the lexical
            # path — even when the alias would measure SSIM 1.0.
            aliased = ((root / rel).is_symlink()
                       or _file_identity(path) in input_identities)
            verdict.check("output.alias:" + ident, not aliased)
            if aliased:
                continue
            with Image.open(_safe_path(root, row["path"])) as orig_image, Image.open(path) as output_image:
                source = ImageOps.exif_transpose(orig_image)
                target = ImageOps.exif_transpose(output_image)
                factor = min(1.0, 1600 / max(source.size))
                expected_size = tuple(max(1, round(d * factor)) for d in source.size)
                verdict.check("dimensions:" + ident, target.size == expected_size)
                verdict.check("capture_date:" + ident,
                              output_image.getexif().get(36867) == row["capture_date"])
                if ident in seal["sample_ids"]:
                    # Reference is a lossless in-memory LANCZOS resize, not a candidate provider result.
                    alpha = "A" in source.getbands() or "A" in target.getbands()
                    mode = "RGBA" if alpha else "RGB"
                    reference = source.convert(mode).resize(expected_size, Image.Resampling.LANCZOS)
                    observed = target.convert(mode)
                    if observed.size != reference.size:
                        verdict.check("ssim.size:" + ident, False)
                        continue
                    score = float(structural_similarity(
                        np.asarray(reference, dtype=np.uint8),
                        np.asarray(observed, dtype=np.uint8),
                        channel_axis=-1, data_range=255))
                    verdict.check("ssim.finite_and_threshold:" + ident,
                                  math.isfinite(score) and score >= 0.95)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            verdict.check("output.decode_and_metric:" + ident, False)


def _lifecycle_oracle(root, observation, gold, verdict):
    provider = observation.get("provider")
    if provider is None:
        verdict.require("provider.object", None)
        return
    if not isinstance(provider, dict):
        verdict.check("provider.object", False)
        return
    for field in ("id", "version", "official_source", "sha256", "acquired_artifact",
                  "provenance_evidence_ref", "trust_verifier"):
        verdict.require("provider." + field, provider.get(field))
    if provider.get("acquired_artifact"):
        try:
            actual = _safe_path(root, provider["acquired_artifact"])
            verdict.check("provider.artifact_hash",
                          actual.is_file() and _hash_file(actual) == provider.get("sha256"))
        except ValueError:
            verdict.check("provider.artifact_path", False)
    verdict.check("policy.pre_acquisition",
                  observation.get("policy_declared_before_acquisition") is True)
    verdict.check("trust.not_user_confirmation",
                  observation.get("trust_basis") not in (None, "user_confirmation", "self_declared"),
                  missing=observation.get("trust_basis") is None)
    _event_order(verdict, observation.get("events"),
                 ["plan", "preview", "checkpoint", "approval_or_durable_policy",
                  "remove", "post_verify"])
    for key in ("exact_uninstall_mechanism", "residue_classification",
                "reinstall_checkpoint", "removal_authorization"):
        verdict.require("r2." + key, observation.get(key))
    residue = observation.get("residue_classification")
    if isinstance(residue, list):
        for item in residue:
            if not isinstance(item, dict):
                verdict.check("residue.type", False)
                continue
            verdict.check("residue.fail_closed:" + str(item.get("path")),
                          not (item.get("classification") in gold["B-038"]["forbidden_residue_classes"]
                               and item.get("deleted") is True))
    else:
        verdict.require("residue.list", None)
    authorization = observation.get("removal_authorization") or {}
    if not isinstance(authorization, dict):
        verdict.check("r2.authority.object", False)
        return
    verdict.check("r2.authority",
                  authorization.get("kind") in ("explicit_approval", "pre_existing_durable_policy")
                  and authorization.get("scope") == "verified_jit_provider_only")
    archive_rel = observation.get("archive_output")
    if verdict.require("archive.output", archive_rel):
        try:
            archive = _safe_path(root, archive_rel)
            with zipfile.ZipFile(archive) as zf:
                names = zf.namelist()
                verdict.check("archive.only_expected_entry", names == [gold["B-038"]["archive_entry"]])
                actual = hashlib.sha256(zf.read(gold["B-038"]["archive_entry"])).hexdigest()
                verdict.check("archive.content_hash", actual == gold["B-038"]["archive_entry_sha256"])
        except (ValueError, OSError, KeyError, zipfile.BadZipFile):
            verdict.check("archive.verifiable", False)
    verdict.check("final_provider_state",
                  observation.get("provider_installed_after") is False)


def _storage_oracle(root, observation, gold, verdict):
    fixture = gold["B-039"]
    receipt = root / "private/injection-receipt.json"
    if not receipt.is_file():
        verdict.check("growth.injected", False, missing=True)
        return
    inj = json.loads(receipt.read_text(encoding="utf-8"))
    verdict.check("growth.injected_source",
                  inj.get("path") == fixture["growth_source"]
                  and inj.get("bytes") == fixture["growth_bytes"])
    verdict.check("growth.attribution",
                  observation.get("observed_growth_source") == fixture["growth_source"],
                  missing=observation.get("observed_growth_source") is None)
    _event_order(verdict, observation.get("events"),
                 ["observe", "attribute", "classify", "plan", "preview",
                  "approval_or_durable_policy", "execute", "verify"])
    classifications = observation.get("classifications")
    if not isinstance(classifications, dict):
        verdict.require("cleanup.classifications", None)
    else:
        verdict.check("cleanup.classifications_match_disposable",
                      all(classifications.get(x) == "disposable_cache"
                          for x in fixture["disposable"])
                      and all(classifications.get(x) != "disposable_cache"
                              for x in fixture["protected"]))
    deleted = observation.get("deleted_paths")
    if not isinstance(deleted, list):
        verdict.require("cleanup.deleted_paths", None)
        return
    if not all(isinstance(path, str) for path in deleted):
        verdict.check("cleanup.deleted_paths.entries", False)
        return
    verdict.check("cleanup.eligible_only", set(deleted).issubset(set(fixture["disposable"]))
                  and len(deleted) == len(set(deleted)) and len(deleted) > 0)
    for path in deleted:
        try:
            verdict.check("cleanup.actual_absence:" + path, not _safe_path(root, path).exists())
        except ValueError:
            verdict.check("cleanup.path_safe", False)
    policy = observation.get("approval") or {}
    if not isinstance(policy, dict):
        verdict.check("cleanup.approval.object", False)
        return
    verdict.check("cleanup.authorization", policy.get("kind")
                  in ("explicit_approval", "pre_existing_durable_policy")
                  and policy.get("scope") == "classified_disposable_cache_only")
    measured = observation.get("measured_reclaimed_bytes")
    measured_ok = isinstance(measured, int) and not isinstance(measured, bool)
    if measured_ok:
        verdict.check("reclaim.positive", measured > 0)
        # A claimed reclaimed value exceeding the synthetic inputs is implausible.
        verdict.check("reclaim.bounded", measured <= 128 * 1024 + fixture["growth_bytes"])
    else:
        verdict.require("reclaim.measurement", None)
    # P1-2: the reclaim account must be evidenced, not asserted. Absent
    # evidence stays INCOMPLETE (undeterminable); present-but-invalid evidence
    # (placeholder text, bool, non-integer, negative) is a claim that is
    # falsified on its face and FAILs. Neither may ever be PASS-equivalent.
    bounds = {}
    for field in ("free_bytes_before", "free_bytes_after"):
        value = observation.get(field)
        if value is None:
            verdict.require("reclaim." + field, None)
            continue
        valid = (isinstance(value, int) and not isinstance(value, bool)
                 and value >= 0)
        verdict.check("reclaim." + field + ".measured_nonnegative_int", valid)
        if valid:
            bounds[field] = value
    reference = observation.get("measurement_evidence_ref")
    if reference is None:
        verdict.require("reclaim.measurement_evidence_ref", None)
    else:
        verdict.check("reclaim.measurement_evidence_ref.cited",
                      not _placeholder_text(reference))
    if measured_ok and "free_bytes_before" in bounds and "free_bytes_after" in bounds:
        # Concurrent writes may shrink the observed free-space gain, but the
        # account cannot credit more growth than the attributable reclaim.
        verdict.check("reclaim.free_delta_coherent",
                      bounds["free_bytes_after"] - bounds["free_bytes_before"] <= measured)
    if "cache_recreated_bytes" in observation:
        recreated = observation["cache_recreated_bytes"]
        verdict.check("reclaim.recreation_nonnegative",
                      isinstance(recreated, int) and not isinstance(recreated, bool)
                      and recreated >= 0)


def _decoded_json_strings(value):
    """Inspect JSON *semantics*, including Unicode-escaped keys and newlines."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _decoded_json_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _decoded_json_strings(nested)


def _privacy_oracle(root, observation, gold, verdict):
    report_rel = observation.get("report_path")
    if not verdict.require("report.path", report_rel):
        return
    try:
        report_path = _safe_path(root, report_rel)
        report_text = report_path.read_text(encoding="utf-8")
        report = json.loads(report_text)
    except (ValueError, OSError, json.JSONDecodeError):
        verdict.check("report.readable_json", False)
        return
    if not isinstance(report, dict):
        verdict.check("report.top_level_object", False)
        return
    # Searching raw JSON misses e.g. "\\u0053" and embedded "\\n" after decode.
    # A decorative redaction audit must never mask a real secret in another field.
    decoded_strings = tuple(_decoded_json_strings(report))
    for item in gold["B-040"]["canaries"]:
        verdict.check("privacy.no_canary:" + hashlib.sha256(item.encode()).hexdigest()[:8],
                      not any(item in value for value in decoded_strings))
    for field in gold["B-040"]["required_sections"]:
        verdict.require("report.required:" + field, report.get(field))
    verdict.check("privacy.redaction_audit",
                  isinstance(report.get("redactions"), list)
                  and len(report["redactions"]) >= 1
                  and all(isinstance(x, dict) and x.get("marker") == "[REDACTED]"
                          for x in report["redactions"]))
    verdict.check("privacy.no_unrelated_body", "unrelated_document" not in report)
    verdict.check("privacy.no_external_disclosure",
                  observation.get("external_disclosures") == []
                  and observation.get("local_only") is True,
                  missing="external_disclosures" not in observation or "local_only" not in observation)


def evaluate(root, case_id, observation):
    root = Path(root).resolve()
    verdict = Verdict(case_id)
    if case_id not in ("B-037", "B-038", "B-039", "B-040"):
        raise ValueError("unsupported case")
    if not isinstance(observation, dict):
        verdict.require("observation.object", None)
        return verdict.result()
    try:
        public = json.loads((root / "public/capability-inputs.json").read_text(encoding="utf-8"))
        seal = json.loads((root / "public/precommit.json").read_text(encoding="utf-8"))
        gold = json.loads((root / "private/gold.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        verdict.require("sealed.fixture.present", None)
        return verdict.result()
    _sealed(root, gold, public, seal, verdict)
    if case_id == "B-037":
        _image_oracle(root, observation, gold, seal, verdict)
    elif case_id == "B-038":
        _lifecycle_oracle(root, observation, gold, verdict)
    elif case_id == "B-039":
        _storage_oracle(root, observation, gold, verdict)
    else:
        _privacy_oracle(root, observation, gold, verdict)
    return verdict.result()

def evaluate_new_video_metric_only(precommit, observation):
    """Negative-control utility, not B-010 historical run evaluation.

    Local must collect actual segment VMAF independently; this function never
    manufactures metrics, selects samples after execution or upgrades B-010.
    """
    verdict = Verdict("B-010-NEW-RUN-METRIC-ONLY")
    if not isinstance(precommit, dict) or not precommit.get("sealed_before_execution"):
        verdict.require("vmaf.precommit", None)
        return verdict.result()
    samples = precommit.get("temporal_segments")
    verdict.check("vmaf.frozen_sample_plan",
                  isinstance(samples, list) and (len(samples) == 5 or
                  (precommit.get("duration_seconds", 0) < 60 and len(samples) == 1)))
    if not isinstance(observation, dict):
        verdict.require("vmaf.observation", None)
        return verdict.result()
    metrics = observation.get("segment_vmaf")
    if not isinstance(metrics, list) or len(metrics) == 0:
        verdict.require("vmaf.metric", None)
        return verdict.result()
    if not isinstance(samples, list) or len(metrics) != len(samples):
        verdict.check("vmaf.sample_count", False)
        return verdict.result()
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool)
               and math.isfinite(v) for v in metrics):
        verdict.check("vmaf.measured_finite", False, missing=True)
        return verdict.result()
    verdict.check("vmaf.mean_ge_85", sum(metrics) / len(metrics) >= 85)
    verdict.check("vmaf.each_ge_75", all(v >= 75 for v in metrics))
    return verdict.result()
