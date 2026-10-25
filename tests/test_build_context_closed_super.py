from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_context_closed_super.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("build_context_closed_super", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ContextClosedSuperTests(unittest.TestCase):
    def setUp(self):
        self.builder = load_builder()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.geometry = self.builder.Geometry(
            super_size=64,
            system_offset=8,
            system_extent_size=32,
            system_payload_size=16,
            sector_size=8,
        )
        self.stock = self.root / "stock-super.img"
        self.payload = self.root / "system.ext4"
        self.output = self.root / "candidate-super.img"
        self.manifest = self.root / "manifest.json"
        self.stock_bytes = bytes(range(64))
        self.payload_bytes = b"context-closed!!"
        self.assertEqual(16, len(self.payload_bytes))
        self.stock.write_bytes(self.stock_bytes)
        self.payload.write_bytes(self.payload_bytes)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def build(self):
        return self.builder.build_super(
            self.stock,
            self.payload,
            self.output,
            manifest=self.manifest,
            geometry=self.geometry,
            expected_stock_sha256=self.digest(self.stock_bytes),
            expected_payload_sha256=self.digest(self.payload_bytes),
            copier=self.builder.regular_copy,
        )

    def test_replaces_only_payload_and_zero_tail(self):
        result = self.build()
        expected = (
            self.stock_bytes[:8]
            + self.payload_bytes
            + b"\0" * 16
            + self.stock_bytes[40:]
        )
        self.assertEqual(expected, self.output.read_bytes())
        self.assertEqual(self.digest(expected), result["output_super"]["output_sha256"])
        self.assertEqual("offline-built-not-flashed", result["status"])
        self.assertFalse(result["device_io_performed"])
        self.assertEqual(result, json.loads(self.manifest.read_text()))

    def test_refuses_existing_output_without_changing_it(self):
        self.output.write_bytes(b"keep-me")
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(b"keep-me", self.output.read_bytes())

    def test_hash_mismatch_leaves_no_output(self):
        with self.assertRaisesRegex(ValueError, "stock super SHA-256"):
            self.builder.build_super(
                self.stock,
                self.payload,
                self.output,
                geometry=self.geometry,
                expected_stock_sha256="0" * 64,
                expected_payload_sha256=self.digest(self.payload_bytes),
                copier=self.builder.regular_copy,
            )
        self.assertFalse(self.output.exists())

    def test_refuses_manifest_path_that_aliases_output(self):
        with self.assertRaisesRegex(ValueError, "manifest.*output"):
            self.builder.build_super(
                self.stock,
                self.payload,
                self.output,
                manifest=self.output,
                geometry=self.geometry,
                expected_stock_sha256=self.digest(self.stock_bytes),
                expected_payload_sha256=self.digest(self.payload_bytes),
                copier=self.builder.regular_copy,
            )
        self.assertFalse(self.output.exists())

    def test_recorded_production_geometry_is_sector_exact(self):
        geometry = self.builder.DBY_W09_GEOMETRY
        self.assertEqual(7_692_353_536, geometry.super_size)
        self.assertEqual(2_097_152, geometry.system_offset)
        self.assertEqual(3_581_935_616, geometry.system_extent_size)
        self.assertEqual(2_513_817_600, geometry.system_payload_size)
        self.assertEqual(3_584_032_768, geometry.system_end)
        self.assertEqual(1_068_118_016, geometry.zero_tail_size)
        self.builder.validate_geometry(geometry)

    def test_rejects_geometry_that_escapes_super(self):
        invalid = self.builder.Geometry(
            super_size=64,
            system_offset=40,
            system_extent_size=32,
            system_payload_size=16,
            sector_size=8,
        )
        with self.assertRaisesRegex(ValueError, "exceeds super"):
            self.builder.validate_geometry(invalid)


if __name__ == "__main__":
    unittest.main()
