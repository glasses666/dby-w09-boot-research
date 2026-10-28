from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_api30_nfc_fscrypt_fix.py"
VERIFIER_SCRIPT = ROOT / "scripts/verify_api30_nfc_fscrypt_fix.py"


def load_builder():
    if not SCRIPT.is_file():
        raise AssertionError("API30 NFC fscrypt builder script must exist")
    spec = importlib.util.spec_from_file_location("build_api30_nfc_fscrypt_fix", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_verifier():
    if not VERIFIER_SCRIPT.is_file():
        raise AssertionError("API30 NFC fscrypt verifier script must exist")
    spec = importlib.util.spec_from_file_location("verify_api30_nfc_fscrypt_fix", VERIFIER_SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {VERIFIER_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Api30NfcFscryptFixBuilderTests(unittest.TestCase):
    def test_builder_script_exists(self):
        self.assertTrue(SCRIPT.is_file(), "API30 NFC fscrypt builder script must exist")

    def test_verifier_script_exists(self):
        self.assertTrue(
            VERIFIER_SCRIPT.is_file(),
            "API30 NFC fscrypt verifier script must exist",
        )

    def test_repair_is_one_same_length_action_replacement(self):
        builder = load_builder()
        source = b"prefix\n" + builder.SOURCE_LINE + b"\nsuffix\n"
        expected = source.replace(builder.SOURCE_LINE, builder.REPLACEMENT_LINE)

        repaired = builder.repaired_rc(
            source,
            expected_source_sha256=builder.sha256_bytes(source),
            expected_output_sha256=builder.sha256_bytes(expected),
            expected_offset=len(b"prefix\n"),
        )

        self.assertEqual(len(source), len(repaired))
        self.assertEqual(expected, repaired)
        self.assertNotIn(builder.SOURCE_LINE, repaired)
        self.assertIn(builder.REPLACEMENT_LINE, repaired)

    def test_repair_rejects_ambiguous_source_action(self):
        builder = load_builder()
        source = builder.SOURCE_LINE + b"\n" + builder.SOURCE_LINE
        with self.assertRaisesRegex(ValueError, "exactly once"):
            builder.repaired_rc(
                source,
                expected_source_sha256=builder.sha256_bytes(source),
                expected_output_sha256="unused",
                expected_offset=0,
            )

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
        self.assertEqual(tuple(range(87_527, 87_538)), builder.INIT_RC_BLOCKS)
        self.assertEqual(28_016, builder.LINE_OFFSET_IN_FILE)
        self.assertEqual(358_538_608, builder.PATCH_OFFSET_IN_SYSTEM)
        self.assertEqual(360_635_760, builder.PATCH_OFFSET_IN_SUPER)
        self.assertEqual(51, len(builder.SOURCE_LINE))
        self.assertEqual(len(builder.SOURCE_LINE), len(builder.REPLACEMENT_LINE))
        self.assertEqual(
            b"    # /data/nfc exists; skip mkdir policy collision",
            builder.REPLACEMENT_LINE,
        )
        self.assertNotIn(b"mkdir /data/nfc", builder.REPLACEMENT_LINE)

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

    def test_verifier_rejects_manifest_without_exact_patch_boundary(self):
        verifier = load_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(
                '{"schema":"dby-w09-api30-nfc-mkdir-skip-v2",'
                '"status":"offline-built-not-flashed","device_io_performed":false,'
                '"output_system":{"sha256":"expected"},'
                '"patch":{"outside_span_byte_identical":true}}'
            )
            report = verifier.verify_manifest(path, "output_system", "expected")
            self.assertEqual("expected", report["output_system"]["sha256"])
            report["patch"]["outside_span_byte_identical"] = False
            path.write_text(__import__("json").dumps(report))
            with self.assertRaisesRegex(ValueError, "manifest failed"):
                verifier.verify_manifest(path, "output_system", "expected")


if __name__ == "__main__":
    unittest.main()
