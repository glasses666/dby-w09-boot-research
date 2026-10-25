from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_w8_lineage_entry_probe.py"
SOURCE = ROOT / "scripts" / "w8_lineage_entry_probe.S"
SELECTED_INIT = Path(os.environ.get("DBY_LINEAGE_INIT", ROOT / "private-fixtures/lineage-init"))
NONCE = "0123456789abcdeffedcba9876543210"
EXPECTED_INIT_SHA256 = (
    "f9aff20075a7d85e14412855c7dad7f353cba41918b2e45fe4f0285379e1e0f3"
)


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_w8_lineage_entry_probe", BUILDER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {BUILDER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class W8LineageEntryProbeTests(unittest.TestCase):
    def test_assembly_is_a_direct_endpoint_coded_entry_probe(self):
        source = SOURCE.read_text()
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
    def test_patch_changes_only_the_selected_init_entry_window(self):
        builder = load_builder()
        original = SELECTED_INIT.read_bytes()
        self.assertEqual(EXPECTED_INIT_SHA256, builder.sha256(original))
        with tempfile.TemporaryDirectory() as directory_text:
            stub = builder.compile_stub(SOURCE, Path(directory_text))
        patched, report = builder.patch_selected_init(original, stub, NONCE)

        self.assertEqual(len(original), len(patched))
        self.assertEqual(0xE0000, report["entrypoint_vaddr"])
        self.assertEqual(0xE0000, report["entrypoint_file_offset"])
        self.assertEqual(5, report["entry_load_flags"])
        self.assertEqual(0x1A9D10, report["entry_load_memsz"])
        self.assertEqual(0x10000, report["entry_load_alignment"])
        self.assertLessEqual(report["patch_size"], 256)
        start = report["entrypoint_file_offset"]
        end = start + report["patch_size"]
        self.assertEqual(original[:start], patched[:start])
        self.assertEqual(original[end:], patched[end:])
        self.assertNotEqual(original[start:end], patched[start:end])
        self.assertIn(b"DBY_W8_LINEAGE_ENTRY_PROBE nonce=" + NONCE.encode(), patched)
        self.assertIn(b"edl\0", patched[start:end])
        self.assertIn(b"bootloader\0", patched[start:end])

    def test_image_patch_is_one_qualified_ext4_data_block(self):
        builder = load_builder()
        block_size = 4096
        physical_block = 11
        super_offset = 3 * block_size
        selected_init = bytes(range(256)) * 16
        original_system = bytearray(b"S" * (20 * block_size))
        original_system[
            physical_block * block_size : (physical_block + 1) * block_size
        ] = selected_init
        original_super = bytearray(b"P" * (40 * block_size))
        original_super[
            super_offset : super_offset + len(original_system)
        ] = original_system
        patched_init = bytearray(selected_init)
        patched_init[:16] = b"W8-ENTRY-PROBE!!"

        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            system_source = directory / "system.ext4"
            super_source = directory / "super.img"
            system_output = directory / "system-w8.ext4"
            super_output = directory / "super-w8.img"
            system_source.write_bytes(original_system)
            super_source.write_bytes(original_super)
            result = builder.patch_images(
                system_source=system_source,
                super_source=super_source,
                patched_init=bytes(patched_init),
                system_output=system_output,
                super_output=super_output,
                block_size=block_size,
                init_entry_file_offset=0,
                init_physical_block=physical_block,
                super_system_offset=super_offset,
                clone=False,
            )

            expected_system = bytearray(original_system)
            expected_system[
                physical_block * block_size : (physical_block + 1) * block_size
            ] = patched_init
            expected_super = bytearray(original_super)
            expected_super[
                super_offset : super_offset + len(expected_system)
            ] = expected_system
            self.assertEqual(bytes(expected_system), system_output.read_bytes())
            self.assertEqual(bytes(expected_super), super_output.read_bytes())
            self.assertEqual(1, result["modified_ext4_blocks"])
            self.assertEqual(
                physical_block * block_size, result["system_patch_offset"]
            )
            self.assertEqual(
                super_offset + physical_block * block_size,
                result["super_patch_offset"],
            )


if __name__ == "__main__":
    unittest.main()
