from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_api29_fscrypt_adb_fix.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("build_api29_fscrypt_adb_fix", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Api29FscryptAdbFixBuilderTests(unittest.TestCase):
    def test_repair_is_one_same_length_action_replacement(self):
        builder = load_builder()
        source = b"prefix\n" + builder.SOURCE_LINE + b"\nsuffix\n"
        builder.INIT_USB_RC_SHA256 = builder.sha256_bytes(source)
        expected = source.replace(builder.SOURCE_LINE, builder.REPLACEMENT_LINE)
        builder.REPAIRED_INIT_USB_RC_SHA256 = builder.sha256_bytes(expected)
        builder.LINE_OFFSET_IN_FILE = len(b"prefix\n")

        repaired = builder.repaired_rc(source)

        self.assertEqual(len(source), len(repaired))
        self.assertEqual(expected, repaired)
        self.assertNotIn(builder.SOURCE_LINE, repaired)
        self.assertIn(builder.REPLACEMENT_LINE, repaired)

    def test_repair_rejects_ambiguous_source_action(self):
        builder = load_builder()
        source = builder.SOURCE_LINE + b"\n" + builder.SOURCE_LINE
        builder.INIT_USB_RC_SHA256 = builder.sha256_bytes(source)
        builder.LINE_OFFSET_IN_FILE = 0
        with self.assertRaisesRegex(ValueError, "exactly once"):
            builder.repaired_rc(source)

    def test_exact_patch_audit_rejects_any_outside_change(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            output = root / "output.bin"
            source.write_bytes(b"prefix" + builder.SOURCE_LINE + b"suffix")
            output.write_bytes(b"prefix" + builder.REPLACEMENT_LINE + b"suffix")
            report = builder.exact_patch_audit(source, output, 6)
            self.assertTrue(report["outside_span_byte_identical"])

            changed = bytearray(output.read_bytes())
            changed[-1] ^= 1
            output.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "outside"):
                builder.exact_patch_audit(source, output, 6)

    def test_frozen_ext4_mapping_and_super_translation(self):
        builder = load_builder()
        self.assertEqual((146, 147), builder.INIT_USB_RC_BLOCKS)
        self.assertEqual(455, builder.LINE_OFFSET_IN_FILE)
        self.assertEqual(598_471, builder.PATCH_OFFSET_IN_SYSTEM)
        self.assertEqual(2_695_623, builder.PATCH_OFFSET_IN_SUPER)
        self.assertEqual(len(builder.SOURCE_LINE), len(builder.REPLACEMENT_LINE))
        self.assertEqual(
            "a5c6c8b481ab494ec7aac0751063c1012ba73a2e16ca611fe3d7bbe823a4515f",
            builder.OUTPUT_SYSTEM_SHA256,
        )
        self.assertEqual(
            "55b043413e9865ed55cb7e6eb1ff152f98ab8ddb9343df0bec1d10e5d7383281",
            builder.OUTPUT_SUPER_SHA256,
        )

    def test_output_paths_reject_alias_and_overwrite(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.img"
            source.write_bytes(b"source")
            with self.assertRaisesRegex(ValueError, "source and output"):
                builder.validate_output_paths(source, source, None)
            output = root / "output.img"
            output.write_bytes(b"existing")
            with self.assertRaisesRegex(FileExistsError, "overwrite"):
                builder.validate_output_paths(source, output, None)


if __name__ == "__main__":
    unittest.main()
