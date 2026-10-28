from __future__ import annotations

import importlib.util
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit_api32_vintf_target_replay.py"


def load_auditor():
    if not SCRIPT.is_file():
        raise AssertionError("target libvintf replay auditor is missing")
    spec = importlib.util.spec_from_file_location(
        "audit_api32_vintf_target_replay", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def result(*, framework="ok", device="ok", keystore=True, suspend=True, gnss=False):
    return {
        "schema": "dby-w09-api32-target-libvintf-replay-v1",
        "framework": {"status": framework, "xml_sha256": "framework"},
        "device": {"status": device, "xml_sha256": "device"},
        "queries": {
            "framework_keystore_aidl": keystore,
            "framework_suspend_hidl": suspend,
            "framework_gnss_1_0": gnss,
            "framework_gnss_1_1": gnss,
            "device_keystore_aidl": False,
            "device_suspend_hidl": False,
        },
        "access_events": [
            {
                "operation": "fetch",
                "path": "/system/etc/vintf/manifest.xml",
                "status": 0,
                "size": 8,
                "sha256": "bound",
                "hash_source": "host-bound-view",
            }
        ],
        "property_events": [{"key": "ro.boot.product.hardware.sku", "value": "DBY-W09"}],
    }


def execution_fixture():
    summary = {
        "harness_tree_sha256": "tree",
        "query_sha256": "query",
        "container": "probe",
        "image": "dby-offline-ubuntu:24.04.5-arm64",
        "architecture": "aarch64",
        "network": "none",
        "rootfs": "read-only",
        "container_exit": 0,
        "linker_list_exit": 0,
        "control_exit": 0,
        "candidate_exit": 2,
        "device_io_performed": False,
    }
    inspect = [
        {
            "Config": {"Image": summary["image"]},
            "State": {"ExitCode": 0},
            "HostConfig": {
                "ReadonlyRootfs": True,
                "NetworkMode": "none",
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
            },
            "Mounts": [
                {"Destination": "/system", "RW": False, "Type": "bind"},
                {"Destination": "/control", "RW": False, "Type": "bind"},
                {"Destination": "/candidate", "RW": False, "Type": "bind"},
                {"Destination": "/run-target-replay.sh", "RW": False, "Type": "bind"},
                {"Destination": "/evidence", "RW": True, "Type": "bind"},
            ],
        }
    ]
    manifest = {
        "tree": {"tree_sha256": "tree"},
        "runtime": {
            "query": {"sha256": "query"},
            "objects": [
                {"path": "/system/bin/linker64"},
                {"path": "/system/lib64/ld-android.so"},
                {"path": "/system/lib64/libvintf.so"},
                {"path": "/system/lib64/libc.so"},
            ],
        },
    }
    linker_list = "\n".join(
        (
            "libvintf.so => /system/lib64/libvintf.so (0x1)",
            "libc.so => /system/lib64/libc.so (0x2)",
        )
    )
    return summary, inspect, manifest, linker_list


class Api32TargetVintfReplayAuditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.auditor = load_auditor()

    def test_invalid_control_stops_before_candidate_interpretation(self) -> None:
        report = self.auditor.classify(result(framework="null"), result())
        self.assertEqual("invalid-control", report["classification"])

    def test_matching_service_queries_with_only_expected_gnss_is_valid_negative(self) -> None:
        control = result(gnss=False)
        candidate = result(gnss=True)
        candidate["framework"]["xml_sha256"] = "framework-with-gnss"
        report = self.auditor.classify(control, candidate)
        self.assertEqual("valid-negative-f15-content-layer", report["classification"])
        self.assertEqual(
            ["framework_gnss_1_0", "framework_gnss_1_1"],
            report["changed_queries"],
        )

    def test_candidate_specific_service_declaration_loss_is_positive(self) -> None:
        report = self.auditor.classify(result(), result(keystore=False, suspend=False))
        self.assertEqual("positive-candidate-service-query-drift", report["classification"])
        self.assertEqual(
            ["framework_keystore_aidl", "framework_suspend_hidl"],
            report["changed_queries"],
        )

    def test_source_derived_correction_restores_aggregation_and_services(self) -> None:
        control = result(gnss=False)
        candidate = result(framework="null", keystore=False, suspend=False, gnss=False)
        corrected = result(gnss=True)
        report = self.auditor.classify_triplet(control, candidate, corrected)
        self.assertEqual(
            "source-derived-correction-restores-aggregation",
            report["classification"],
        )
        self.assertEqual(
            ["framework_gnss_1_0", "framework_gnss_1_1"],
            report["corrected_changed_queries"],
        )

    def test_source_derived_correction_that_stays_null_is_not_a_pass(self) -> None:
        control = result()
        candidate = result(framework="null", keystore=False, suspend=False)
        corrected = result(framework="null", keystore=False, suspend=False)
        report = self.auditor.classify_triplet(control, candidate, corrected)
        self.assertEqual(
            "source-derived-correction-did-not-restore-aggregation",
            report["classification"],
        )

    def test_missing_access_or_property_trace_is_invalid(self) -> None:
        candidate = result()
        candidate["access_events"] = []
        report = self.auditor.classify(result(), candidate)
        self.assertEqual("invalid-incomplete-runtime-trace", report["classification"])

    def test_successful_fetch_without_content_hash_is_invalid(self) -> None:
        candidate = result()
        del candidate["access_events"][0]["sha256"]
        report = self.auditor.classify(result(), candidate)
        self.assertEqual("invalid-incomplete-runtime-trace", report["classification"])

    def test_normalize_result_hashes_raw_xml_and_successful_fetch_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "system/etc/vintf/manifest.xml"
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(b"manifest")
            raw = result()
            raw["framework"] = {"status": "ok", "xml": "<manifest/>"}
            raw["device"] = {"status": "ok", "xml": "<device/>"}
            raw["access_events"][0].pop("sha256")
            raw["access_events"][0].pop("hash_source")

            normalized = self.auditor.normalize_result(raw, root)

            self.assertEqual(
                hashlib.sha256(b"<manifest/>").hexdigest(),
                normalized["framework"]["xml_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(b"<device/>").hexdigest(),
                normalized["device"]["xml_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(b"manifest").hexdigest(),
                normalized["access_events"][0]["sha256"],
            )
            self.assertEqual(
                "host-bound-view",
                normalized["access_events"][0]["hash_source"],
            )

    def test_normalize_result_rejects_fetch_size_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "system/etc/vintf/manifest.xml"
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(b"manifest")
            raw = result()
            raw["access_events"][0].pop("sha256")
            raw["access_events"][0].pop("hash_source")
            raw["access_events"][0]["size"] = 1

            with self.assertRaisesRegex(ValueError, "fetch size drift"):
                self.auditor.normalize_result(raw, root)

    def test_execution_gate_accepts_exact_isolated_target_closure(self) -> None:
        summary, inspect, manifest, linker_list = execution_fixture()
        gate = self.auditor.validate_execution(summary, inspect, linker_list, manifest)
        self.assertTrue(gate["valid"])
        self.assertEqual(
            ["libc.so", "libvintf.so"],
            gate["resolved_libraries"],
        )

    def test_execution_gate_rejects_network_or_library_escape(self) -> None:
        summary, inspect, manifest, linker_list = execution_fixture()
        inspect[0]["HostConfig"]["NetworkMode"] = "default"
        linker_list += "\nlibescape.so => /usr/lib/libescape.so (0x3)"
        gate = self.auditor.validate_execution(summary, inspect, linker_list, manifest)
        self.assertFalse(gate["valid"])
        self.assertIn("network-mode", gate["errors"])
        self.assertIn("resolved-library-set", gate["errors"])

    def test_execution_gate_accepts_optional_corrected_fresh_process(self) -> None:
        summary, inspect, manifest, linker_list = execution_fixture()
        summary["corrected_exit"] = 0
        inspect[0]["Mounts"].append(
            {"Destination": "/corrected", "RW": False, "Type": "bind"}
        )
        gate = self.auditor.validate_execution(summary, inspect, linker_list, manifest)
        self.assertTrue(gate["valid"])


if __name__ == "__main__":
    unittest.main()
