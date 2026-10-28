from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_api32_system_framework_gnss_1_1_candidate.py"
BUILDER = ROOT / "scripts/build_api32_system_framework_gnss_1_1_candidate.py"
SOURCE_MANIFEST = ROOT / "tests/fixtures/api32-framework-manifest-source.xml"


def load(path: Path, name: str):
    if not path.is_file():
        raise AssertionError(f"missing module: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Api32SystemFrameworkGnss11VerifierTests(unittest.TestCase):
    def test_verifier_module_exists(self) -> None:
        self.assertTrue(SCRIPT.is_file())

    def test_verifier_uses_the_frozen_discovery_hashes(self) -> None:
        verifier = load(SCRIPT, "verify_api32_system_framework_gnss_1_1_hash_test")
        self.assertEqual(
            "e254e96f018ae0b8a5db47e3ab891dc9e07db4202737e22c8835c00f1475d317",
            verifier.OUTPUT_SYSTEM_SHA256,
        )
        self.assertEqual(
            "a2826268ea5566d25ca963ec371f4cd721e25d6d4175b08662b6bbe66d5030a1",
            verifier.OUTPUT_SUPER_SHA256,
        )

    def test_manifest_validator_accepts_only_exact_1_1_declaration(self) -> None:
        verifier = load(SCRIPT, "verify_api32_system_framework_gnss_1_1_test")
        builder = load(BUILDER, "build_api32_system_framework_gnss_1_1_for_verify_test")
        source = SOURCE_MANIFEST.read_bytes()
        output = builder.replacement_manifest(source)
        semantics = verifier.validate_manifest_semantics(source, output)
        self.assertTrue(semantics["existing_semantics_preserved"])
        self.assertEqual(["1.1"], semantics["gnss"]["versions"])

    def test_manifest_validator_rejects_the_old_two_minor_candidate(self) -> None:
        verifier = load(SCRIPT, "verify_api32_system_framework_gnss_1_1_reject_test")
        builder = load(BUILDER, "build_api32_system_framework_gnss_1_1_legacy_test")
        source = SOURCE_MANIFEST.read_bytes()
        old_candidate = builder.legacy.replacement_manifest(source)
        with self.assertRaisesRegex(ValueError, "output framework manifest identity"):
            verifier.validate_manifest_semantics(source, old_candidate)


if __name__ == "__main__":
    unittest.main()
