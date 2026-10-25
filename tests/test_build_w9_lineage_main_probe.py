from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_w9_lineage_main_probe.py"
SOURCE = ROOT / "scripts" / "w9_lineage_main_probe.S"
SELECTED_INIT = Path(os.environ.get("DBY_LINEAGE_INIT", ROOT / "private-fixtures/lineage-init"))
NONCE = "89abcdef0123456776543210fedcba98"
EXPECTED_INIT_SHA256 = (
    "f9aff20075a7d85e14412855c7dad7f353cba41918b2e45fe4f0285379e1e0f3"
)


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_w9_lineage_main_probe", BUILDER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {BUILDER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class W9LineageMainProbeTests(unittest.TestCase):
    def test_assembly_is_a_direct_endpoint_coded_main_probe(self):
        source = SOURCE.read_text()
        self.assertIn("dby_w9_main", source)
        self.assertIn("bti j", source)
        self.assertIn("#0xdead", source)
        self.assertIn("#0xfee1", source)
        self.assertIn("#0x1969", source)
        self.assertIn("#0x2812", source)
        self.assertIn("#0xc3d4", source)
        self.assertIn("#0xa1b2", source)
        self.assertIn("#142", source)
        self.assertIn('"edl"', source)
        self.assertIn('"bootloader"', source)
        for forbidden in ("/log", "/metadata", "/data", "/dev/block"):
            self.assertNotIn(forbidden, source)

    @unittest.skipUnless(SELECTED_INIT.is_file(), "set DBY_LINEAGE_INIT to the private Lineage init fixture")
    def test_patch_preserves_original_entry_shim_and_changes_only_main_window(self):
        builder = load_builder()
        original = SELECTED_INIT.read_bytes()
        self.assertEqual(EXPECTED_INIT_SHA256, builder.base.sha256(original))
        with tempfile.TemporaryDirectory() as directory_text:
            stub = builder.compile_stub(SOURCE, Path(directory_text))
        patched, report = builder.patch_selected_init_main(original, stub, NONCE)

        self.assertEqual(len(original), len(patched))
        self.assertEqual(0xE0000, report["elf_entrypoint_vaddr"])
        self.assertEqual(0xE0000, report["elf_entrypoint_file_offset"])
        self.assertEqual(0xE0060, report["target_vaddr"])
        self.assertEqual(0xE0060, report["target_file_offset"])
        self.assertEqual("main", report["target_name"])
        self.assertEqual(5, report["target_load_flags"])
        self.assertEqual(0x1A9D10, report["target_load_memsz"])
        self.assertEqual(0x10000, report["target_load_alignment"])
        self.assertLessEqual(report["patch_size"], 256)

        entry = report["elf_entrypoint_file_offset"]
        start = report["target_file_offset"]
        end = start + report["patch_size"]
        self.assertEqual(bytes.fromhex("7c9e0694"), original[0xE0050:0xE0054])
        self.assertEqual(original[entry:start], patched[entry:start])
        self.assertEqual(original[:start], patched[:start])
        self.assertEqual(original[end:], patched[end:])
        self.assertNotEqual(original[start:end], patched[start:end])
        self.assertEqual(start // 4096, (end - 1) // 4096)
        self.assertIn(
            b"DBY_W9_LINEAGE_MAIN_PROBE nonce=" + NONCE.encode(),
            patched[start:end],
        )
        self.assertIn(b"edl\0", patched[start:end])
        self.assertIn(b"bootloader\0", patched[start:end])


if __name__ == "__main__":
    unittest.main()
