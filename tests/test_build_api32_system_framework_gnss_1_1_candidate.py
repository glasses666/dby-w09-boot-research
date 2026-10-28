from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_api32_system_framework_gnss_1_1_candidate.py"
SOURCE_MANIFEST = ROOT / "tests/fixtures/api32-framework-manifest-source.xml"


def load_builder():
    if not SCRIPT.is_file():
        raise AssertionError("GNSS 1.1-only builder is missing")
    spec = importlib.util.spec_from_file_location(
        "build_api32_system_framework_gnss_1_1_candidate_test", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Api32SystemFrameworkGnss11BuilderTests(unittest.TestCase):
    def test_builder_module_exists(self) -> None:
        self.assertTrue(SCRIPT.is_file())

    def test_discovery_output_hashes_are_frozen(self) -> None:
        builder = load_builder()
        self.assertEqual(
            "e254e96f018ae0b8a5db47e3ab891dc9e07db4202737e22c8835c00f1475d317",
            builder.EXPECTED_OUTPUT_SYSTEM_SHA256,
        )
        self.assertEqual(
            "a2826268ea5566d25ca963ec371f4cd721e25d6d4175b08662b6bbe66d5030a1",
            builder.EXPECTED_OUTPUT_SUPER_SHA256,
        )

    def test_replacement_matches_exact_target_validated_bytes(self) -> None:
        builder = load_builder()
        source = SOURCE_MANIFEST.read_bytes()
        replacement = builder.replacement_manifest(source)
        self.assertEqual(3034, len(replacement))
        self.assertEqual(
            "e1709cc931677e71ac3c51257ac9e207060f95f3449b28ec5f676f992640df07",
            builder.sha256_bytes(replacement),
        )
        semantics = builder.manifest_semantics(replacement)
        self.assertEqual(["1.1"], semantics["framework_gnss"]["versions"])
        self.assertNotIn(
            b"<version>1.0</version><version>1.1</version>", replacement
        )

    def test_replacement_preserves_every_existing_manifest_semantic(self) -> None:
        builder = load_builder()
        source = SOURCE_MANIFEST.read_bytes()
        replacement = builder.replacement_manifest(source)
        self.assertEqual(
            builder.manifest_semantics(source)["existing_hals"],
            builder.manifest_semantics(replacement)["existing_hals"],
        )

    def test_frozen_manifest_mapping_is_reused_without_boot_output(self) -> None:
        builder = load_builder()
        if not builder.SOURCE_SYSTEM.is_file() or not builder.SOURCE_SUPER.is_file():
            self.skipTest("set up the private source system/super fixtures")
        source = builder.legacy.read_manifest(builder.SOURCE_SYSTEM)
        self.assertEqual(
            source,
            builder.read_range(
                builder.SOURCE_SYSTEM,
                builder.MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM,
                len(source),
            ),
        )
        self.assertEqual(
            source,
            builder.read_range(
                builder.SOURCE_SUPER,
                builder.MANIFEST_OFFSET_IN_SUPER,
                len(source),
            ),
        )
        self.assertEqual([builder.MANIFEST_PHYSICAL_BLOCK], builder.read_inode_state(builder.SOURCE_SYSTEM)["blocks"])

    def test_exact_audit_rejects_any_change_outside_manifest(self) -> None:
        builder = load_builder()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            output = root / "output.bin"
            old = b"old-manifest"
            new = b"new-manifest"
            source.write_bytes(b"A" * 16 + old + b"Z" * 16)
            output.write_bytes(b"B" + b"A" * 15 + new + b"Z" * 16)
            with self.assertRaisesRegex(ValueError, "outside authorized manifest"):
                builder.exact_image_audit(source, output, 16, old, new)


if __name__ == "__main__":
    unittest.main()
