from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_w1_live_gate.py"
LIVE_GATE_MANIFEST = Path(
    os.environ.get(
        "DBY_W1_LIVE_GATE_MANIFEST",
        ROOT / "private-fixtures/w1-live-gate-manifest.json",
    )
)


def load_gate():
    spec = importlib.util.spec_from_file_location("verify_w1_live_gate", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class W1LiveGateTests(unittest.TestCase):
    def test_stage_requires_every_exact_hash(self):
        gate = load_gate()
        good = b"expected"
        manifest = {
            "schema": "test",
            "stages": {
                "prewrite": {
                    "ramdisk": {
                        "size": len(good),
                        "sha256": hashlib.sha256(good).hexdigest(),
                    },
                    "misc": {"size": 4},
                }
            },
            "endpoint_policy": {
                "expected": "edl",
                "recognized": ["edl", "unknown"],
            },
        }
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            ramdisk = directory / "ramdisk.img"
            misc = directory / "misc.img"
            ramdisk.write_bytes(good)
            misc.write_bytes(b"misc")
            report = gate.verify_stage(
                manifest,
                "prewrite",
                {"ramdisk": ramdisk, "misc": misc},
                "unknown",
            )
            self.assertTrue(report["passed"])

            ramdisk.write_bytes(b"tampered")
            report = gate.verify_stage(
                manifest,
                "prewrite",
                {"ramdisk": ramdisk, "misc": misc},
                "unknown",
            )
            self.assertFalse(report["passed"])
            self.assertIn("ramdisk:sha256_mismatch", report["failures"])

    def test_post_attempt_requires_independent_edl_endpoint(self):
        gate = load_gate()
        manifest = {
            "schema": "test",
            "stages": {"post_attempt": {"log": {"size": 3}}},
            "endpoint_policy": {
                "expected": "edl",
                "recognized": ["edl", "fastboot", "unknown"],
            },
        }
        with tempfile.TemporaryDirectory() as directory_text:
            log = Path(directory_text) / "log.img"
            log.write_bytes(b"log")
            report = gate.verify_stage(
                manifest, "post_attempt", {"log": log}, "fastboot"
            )
            self.assertFalse(report["passed"])
            self.assertIn("endpoint:unexpected", report["failures"])

            report = gate.verify_stage(
                manifest, "post_attempt", {"log": log}, "edl"
            )
            self.assertTrue(report["passed"])

    @unittest.skipUnless(
        LIVE_GATE_MANIFEST.is_file(),
        "set DBY_W1_LIVE_GATE_MANIFEST to the private manifest fixture",
    )
    def test_manifest_is_well_formed_and_pins_review6_candidate(self):
        manifest = json.loads(LIVE_GATE_MANIFEST.read_text())
        self.assertEqual("dby-w09-w1-live-gate-v1", manifest["schema"])
        self.assertEqual(
            "15263ce2dddbf52f5580b6e7cf330a2f6f06a330e08a922dfdbd7bb75d4571ec",
            manifest["stages"]["w1_readback"]["ramdisk"]["sha256"],
        )
        self.assertEqual("edl", manifest["endpoint_policy"]["expected"])


if __name__ == "__main__":
    unittest.main()
