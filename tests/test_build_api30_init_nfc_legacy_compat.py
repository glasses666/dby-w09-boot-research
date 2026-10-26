import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "scripts/build_api30_init_nfc_legacy_compat.py"
VERIFIER_PATH = ROOT / "scripts/verify_api30_init_nfc_legacy_compat.py"


def load_builder():
    if not BUILDER_PATH.is_file():
        raise AssertionError("API30 init NFC legacy compatibility builder must exist")
    spec = importlib.util.spec_from_file_location("api30_init_nfc_legacy_compat", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_verifier():
    if not VERIFIER_PATH.is_file():
        raise AssertionError("API30 init NFC verifier must exist")
    spec = importlib.util.spec_from_file_location("verify_api30_init_nfc_legacy_compat", VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Api30InitNfcLegacyCompatTests(unittest.TestCase):
    def test_patch_is_one_exact_instruction_window(self):
        builder = load_builder()
        prefix = b"prefix"
        suffix = b"suffix"
        source = prefix + builder.SOURCE_INSTRUCTIONS + suffix
        expected = prefix + builder.REPLACEMENT_INSTRUCTIONS + suffix

        patched = builder.patched_init(
            source,
            expected_source_sha256=hashlib.sha256(source).hexdigest(),
            expected_output_sha256=hashlib.sha256(expected).hexdigest(),
            offset=len(prefix),
        )

        self.assertEqual(expected, patched)
        self.assertEqual(len(source), len(patched))
        self.assertEqual(
            [index for index, pair in enumerate(zip(source, patched)) if pair[0] != pair[1]],
            [6, 7, 10, 11, 12],
        )

    def test_patch_rejects_wrong_or_ambiguous_input(self):
        builder = load_builder()
        source = b"prefix" + builder.SOURCE_INSTRUCTIONS + b"suffix"
        with self.assertRaisesRegex(ValueError, "identity"):
            builder.patched_init(source, expected_source_sha256="0" * 64, offset=6)
        with self.assertRaisesRegex(ValueError, "exactly once"):
            doubled = source + builder.SOURCE_INSTRUCTIONS
            builder.patched_init(
                doubled,
                expected_source_sha256=hashlib.sha256(doubled).hexdigest(),
                offset=6,
            )

    def test_instruction_semantics_are_gsi_to_nfc_only(self):
        builder = load_builder()
        self.assertEqual("gsi", builder.decode_excluded_name(builder.SOURCE_INSTRUCTIONS))
        self.assertEqual("nfc", builder.decode_excluded_name(builder.REPLACEMENT_INSTRUCTIONS))
        self.assertEqual(0x495AC, builder.INIT_FILE_OFFSET)
        self.assertEqual(73, builder.INIT_FILE_BLOCK)
        self.assertEqual(0x5AC, builder.INIT_OFFSET_IN_BLOCK)
        self.assertEqual(81_664, builder.INIT_PHYSICAL_BLOCK)
        self.assertEqual(334_497_196, builder.PATCH_OFFSET_IN_SYSTEM)
        self.assertEqual(336_594_348, builder.PATCH_OFFSET_IN_SUPER)
        self.assertEqual(
            "349f2f8dc2e51d6e4d02b183a9c2e236314f32a679a61298bfeac0426d02ec4a",
            builder.EXPECTED_OUTPUT_INIT_SHA256,
        )
        self.assertEqual(
            "c411632f32664678005296281f78ccf3978f24363b247968de6e67e24cc094f5",
            builder.EXPECTED_OUTPUT_SYSTEM_SHA256,
        )
        self.assertEqual(
            "23b9dfa572241cf6ca3ccf7025f163db5de918cd8dc13ee73a80486eb5b06598",
            builder.EXPECTED_OUTPUT_SUPER_SHA256,
        )

    def test_exact_patch_audit_rejects_any_out_of_span_change(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            output = root / "output.bin"
            source.write_bytes(b"prefix" + builder.SOURCE_INSTRUCTIONS + b"suffix")
            output.write_bytes(b"prefix" + builder.REPLACEMENT_INSTRUCTIONS + b"suffix")

            report = builder.exact_patch_audit(source, output, 6)
            self.assertTrue(report["outside_span_byte_identical"])
            self.assertEqual(5, report["changed_bytes"])

            changed = bytearray(output.read_bytes())
            changed[-1] ^= 1
            output.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "outside"):
                builder.exact_patch_audit(source, output, 6)

    def test_patch_clone_is_non_overwriting_and_preserves_source(self):
        builder = load_builder()
        self.assertTrue(hasattr(builder, "patch_clone"), "builder must expose patch_clone")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            output = root / "output.bin"
            original = b"prefix" + builder.SOURCE_INSTRUCTIONS + b"suffix"
            expected = b"prefix" + builder.REPLACEMENT_INSTRUCTIONS + b"suffix"
            source.write_bytes(original)

            builder.patch_clone(source, output, 6)
            self.assertEqual(original, source.read_bytes())
            self.assertEqual(expected, output.read_bytes())
            with self.assertRaises(FileExistsError):
                builder.patch_clone(source, output, 6)
            with self.assertRaisesRegex(ValueError, "alias"):
                builder.patch_clone(source, source, 6)

    def test_source_is_v2_system_only_and_vendor_is_not_a_patch_target(self):
        builder = load_builder()
        self.assertEqual(
            "65070d2b8f71cc9bebd8d24df62bec3cf578e60e3586235bea40b7cd7a430e14",
            builder.SOURCE_SYSTEM_SHA256,
        )
        self.assertEqual(
            "aefb9e9a06301537bfd385160e1d7c4e45a00364bc677cf0c357ec5a819d7fec",
            builder.SOURCE_SUPER_SHA256,
        )
        self.assertNotIn("vendor", builder.PATCH_TARGETS)
        self.assertEqual(("/system/bin/init",), builder.PATCH_TARGETS)

    def test_builder_and_verifier_expose_non_mutating_help(self):
        self.assertTrue(VERIFIER_PATH.is_file(), "API30 init NFC verifier must exist")
        for script in (BUILDER_PATH, VERIFIER_PATH):
            completed = subprocess.run(
                ["python3", str(script), "--help"],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIn("--output-dir", completed.stdout)

    def test_ext4_gate_preserves_source_features_without_inventing_shared_blocks(self):
        verifier = load_verifier()
        self.assertTrue(
            hasattr(verifier, "parse_tune2fs_summary"),
            "verifier must parse the actual source filesystem contract",
        )
        text = """\
Filesystem UUID:          eb9fd075-410a-57f5-b916-141dfe22f108
Filesystem features:      ext_attr dir_index filetype extent
Filesystem state:         clean
Block size:               4096
"""
        self.assertEqual(
            {
                "uuid": "eb9fd075-410a-57f5-b916-141dfe22f108",
                "features": ("ext_attr", "dir_index", "filetype", "extent"),
                "state": "clean",
                "block_size": 4096,
            },
            verifier.parse_tune2fs_summary(text),
        )

    def test_objdump_evidence_drops_nondeterministic_temp_path(self):
        verifier = load_verifier()
        self.assertTrue(hasattr(verifier, "normalize_objdump_disassembly"))
        raw = """\
/private/tmp/random-a/init: file format elf64-littleaarch64
Disassembly of section .text:
   495a8: 528000c3      mov w3, #0x6
   495ac: 52800c64      mov w4, #0x63
   495b0: 528ccdce      mov w14, #0x666e
   495b4: 9100610f      add x15, x8, #0x18
"""
        self.assertEqual(
            "495a8: 528000c3 mov w3, #0x6\n"
            "495ac: 52800c64 mov w4, #0x63\n"
            "495b0: 528ccdce mov w14, #0x666e\n"
            "495b4: 9100610f add x15, x8, #0x18",
            verifier.normalize_objdump_disassembly(raw),
        )


if __name__ == "__main__":
    unittest.main()
