from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_api32_diagnostic_adb_candidate.py"
SPEC = importlib.util.spec_from_file_location("diagnostic_adb_public_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
PRIVATE_SYSTEM = os.environ.get("DBY_API32_MINIMAL_SYSTEM")


def synthetic_rc() -> bytes:
    source = bytearray(b" " * 6004)
    for patch in builder.PATCHES:
        start = patch["file_offset"]
        source[start : start + len(patch["source"])] = patch["source"]
    service = b"service adbd /system/bin/adbd --root_seclabel=u:r:su:s0\n"
    source[5500 : 5500 + len(service)] = service
    return bytes(source)


class DiagnosticAdbBuilderTests(unittest.TestCase):
    def test_semantic_transformation_is_diagnostic_only(self):
        source = synthetic_rc()
        with mock.patch.object(builder, "INIT_USB_RC_SHA256", builder.sha256_bytes(source)):
            output = builder.patched_init_usb_rc(source)
        self.assertEqual(len(source), len(output))
        self.assertNotIn(b"vendor.sys.usb.adb.disabled", output)
        self.assertIn(b"setprop sys.usb.config adb", output)
        self.assertIn(b"service adbd /system/bin/adbd --root_seclabel=u:r:su:s0", output)
        allowed = set()
        for patch in builder.PATCHES:
            start = patch["file_offset"]
            self.assertEqual(len(patch["source"]), len(patch["replacement"]))
            self.assertEqual(1, source.count(patch["source"]))
            allowed.update(range(start, start + len(patch["source"])))
        differences = {i for i, (a, b) in enumerate(zip(source, output)) if a != b}
        self.assertEqual(158, len(differences))
        self.assertLessEqual(differences, allowed)

    def test_rejects_wrong_whole_file_identity(self):
        with self.assertRaisesRegex(ValueError, "source identity"):
            builder.patched_init_usb_rc(synthetic_rc())

    def test_rejects_relocated_span_even_with_matching_test_identity(self):
        source = bytearray(synthetic_rc())
        patch = builder.PATCHES[0]
        start = patch["file_offset"]
        source[start : start + len(patch["source"])] = b" " * len(patch["source"])
        source[100 : 100 + len(patch["source"])] = patch["source"]
        data = bytes(source)
        with mock.patch.object(builder, "INIT_USB_RC_SHA256", builder.sha256_bytes(data)):
            with self.assertRaisesRegex(ValueError, "source span"):
                builder.patched_init_usb_rc(data)

    def test_frozen_file_offsets_map_to_frozen_blocks(self):
        self.assertEqual(61_811 * 4096 + 747, builder.physical_offset(747))
        self.assertEqual(61_812 * 4096 + 558, builder.physical_offset(4654))
        for offset in (-1, 8192):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                builder.physical_offset(offset)

    def test_raw_patches_preserve_all_other_bytes_in_both_images(self):
        source = synthetic_rc()
        prefix = b"P" * 8192
        with tempfile.TemporaryDirectory() as directory:
            system = Path(directory) / "system.fixture"
            super_image = Path(directory) / "super.fixture"
            system.write_bytes(source)
            super_image.write_bytes(prefix + source + b"tail")
            with mock.patch.object(builder, "INIT_USB_RC_PHYSICAL_BLOCKS", (0, 1)), \
                 mock.patch.object(builder, "SYSTEM_OFFSET_IN_SUPER", len(prefix)), \
                 mock.patch.object(builder, "INIT_USB_RC_SHA256", builder.sha256_bytes(source)):
                expected = builder.patched_init_usb_rc(source)
                records = builder.apply_raw_patches(system, super_image)
            self.assertEqual(expected, system.read_bytes())
            self.assertEqual(prefix + expected + b"tail", super_image.read_bytes())
            self.assertEqual([98, 60], [r["changed_bytes"] for r in records])

    def test_raw_source_mismatch_rejects_before_first_write(self):
        with tempfile.TemporaryDirectory() as directory:
            system = Path(directory) / "system.fixture"
            super_image = Path(directory) / "super.fixture"
            original = b"X" * 8192
            system.write_bytes(original)
            super_image.write_bytes(original)
            with mock.patch.object(builder, "INIT_USB_RC_PHYSICAL_BLOCKS", (0, 1)), \
                 mock.patch.object(builder, "SYSTEM_OFFSET_IN_SUPER", 0):
                with self.assertRaisesRegex(ValueError, "raw source mismatch"):
                    builder.apply_raw_patches(system, super_image)
            self.assertEqual(original, system.read_bytes())
            self.assertEqual(original, super_image.read_bytes())

    @unittest.skipUnless(PRIVATE_SYSTEM, "optional DBY_API32_MINIMAL_SYSTEM fixture is absent")
    def test_exact_private_source_spans_and_semantics(self):
        source = builder.read_init_usb_rc(Path(PRIVATE_SYSTEM))
        output = builder.patched_init_usb_rc(source)
        self.assertEqual(6004, len(source))
        self.assertEqual(
            "9b935b3be8a9ae3637e6cffaa965d275688a61cc504d2647ad18c84e6f38c791",
            builder.sha256_bytes(output),
        )
        for patch in builder.PATCHES:
            self.assertEqual(1, source.count(patch["source"]))
            self.assertEqual(patch["file_offset"], source.find(patch["source"]))
        self.assertEqual([61_811, 61_812], builder.read_inode_state(Path(PRIVATE_SYSTEM))["blocks"])


if __name__ == "__main__":
    unittest.main()
