from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qualify_api32_system_framework_gnss_1_1_candidate.py"


def load_qualifier():
    if not SCRIPT.is_file():
        raise AssertionError("GNSS 1.1-only qualifier is missing")
    spec = importlib.util.spec_from_file_location(
        "qualify_api32_system_framework_gnss_1_1_candidate_test", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixtures():
    build = {
        "device_io_performed": False,
        "boot_control": {"output_emitted": False, "sha256": "boot"},
        "output_system": {"path": "/build-a/system", "sha256": "system", "size": 10},
        "output_super": {"path": "/build-a/super", "sha256": "super", "size": 20},
        "framework_manifest": {"output_sha256": "manifest"},
        "system_audit": {"outside_span_byte_identical": True},
        "super_audit": {"outside_span_byte_identical": True},
    }
    qualification = {
        "status": "pass",
        "device_io_performed": False,
        "output_system": {"path": "/verified/system", "sha256": "system", "size": 10},
        "output_super": {"path": "/verified/super", "sha256": "super", "size": 20},
        "framework_manifest": {"output_sha256": "manifest"},
    }
    replay = {
        "classification": "source-derived-correction-restores-aggregation",
        "execution_evidence": {"valid": True},
        "normalized_evidence": {
            "corrected": {
                "access_events": [
                    {
                        "operation": "fetch",
                        "status": 0,
                        "path": "/system/etc/vintf/manifest.xml",
                        "sha256": "manifest",
                        "hash_source": "host-bound-view",
                    }
                ],
                "queries": {
                    "framework_keystore_aidl": True,
                    "framework_suspend_hidl": True,
                    "framework_suspend_transport": "hwbinder",
                    "framework_gnss_1_0": True,
                    "framework_gnss_1_1": True,
                },
            }
        },
    }
    return build, qualification, replay


class Api32SystemFrameworkGnss11QualifierTests(unittest.TestCase):
    def test_qualified_pair_binds_exact_image_to_target_replay(self) -> None:
        qualifier = load_qualifier()
        build_a, qualification, replay = fixtures()
        build_b = {
            **build_a,
            "output_system": {**build_a["output_system"], "path": "/build-b/system"},
            "output_super": {**build_a["output_super"], "path": "/build-b/super"},
        }
        report = qualifier.qualify(build_a, build_b, qualification, qualification, replay)
        self.assertEqual("offline-qualified-not-flashed", report["status"])
        self.assertFalse(report["live_write_gate"])
        self.assertEqual("manifest", report["target_replay_binding"]["manifest_sha256"])

    def test_pair_hash_mismatch_is_rejected(self) -> None:
        qualifier = load_qualifier()
        build_a, qualification, replay = fixtures()
        build_b = {**build_a, "output_super": {"sha256": "different", "size": 20}}
        with self.assertRaisesRegex(ValueError, "deterministic build mismatch"):
            qualifier.qualify(build_a, build_b, qualification, qualification, replay)

    def test_replay_manifest_mismatch_is_rejected(self) -> None:
        qualifier = load_qualifier()
        build, qualification, replay = fixtures()
        replay["normalized_evidence"]["corrected"]["access_events"][0]["sha256"] = "other"
        with self.assertRaisesRegex(ValueError, "target replay manifest binding"):
            qualifier.qualify(build, build, qualification, qualification, replay)


if __name__ == "__main__":
    unittest.main()
