from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/prepare_api32_reconstruction_inputs.py"
SPEC = importlib.util.spec_from_file_location("prepare_api32_inputs_public_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)

VENDOR = b"""(type zeta)
(type alpha)
(type already_mapped)
(type unversioned)
(typeattribute zeta_29_0)
(typeattribute alpha_29_0)
(typeattribute already_mapped_29_0)
(typeattribute abstract_only_29_0)
; (typeattribute comment_only_29_0)
; (type comment_only)
"""
MAPPING = b"(typeattributeset already_mapped_29_0 (already_mapped))\n"


def identity(data: bytes) -> dict[str, object]:
    return {"size": len(data), "sha256": builder.sha256_bytes(data)}


class PolicyInputTests(unittest.TestCase):
    def test_mapping_uses_sorted_unmapped_concrete_types_only(self):
        generated = builder.derive_mapping(VENDOR, MAPPING)
        self.assertEqual(
            builder.MAPPING_HEADER.encode()
            + b"(typeattributeset alpha_29_0 (alpha))\n"
            + b"(typeattributeset zeta_29_0 (zeta))\n",
            generated,
        )

    def test_empty_mapping_delta_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no missing"):
            builder.derive_mapping(b"(type absent)\n", b"")

    def test_xattr_is_exactly_one_nul_terminated_standard_label(self):
        label = (builder.FIXTURES / "sepolicy-file-context.txt").read_bytes()
        generated = builder.encode_xattr(label)
        self.assertEqual(b"u:object_r:sepolicy_file:s0\0", generated)
        builder.validate_identity(generated, builder.CONTRACT["xattr_output"], "xattr")
        for malformed in (label[:-1], label + b"\n", label.replace(b"s0", b"s1")):
            with self.subTest(label=malformed), self.assertRaises(ValueError):
                builder.encode_xattr(malformed)

    def test_production_contract_rejects_unqualified_input_without_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor, mapping, output = root / "vendor.cil", root / "mapping.cil", root / "out"
            vendor.write_bytes(VENDOR)
            mapping.write_bytes(MAPPING)
            with self.assertRaisesRegex(ValueError, "vendor public policy identity"):
                builder.prepare(vendor, mapping, output)
            self.assertFalse(output.exists())

    def test_preparation_preserves_sources_and_refuses_existing_targets(self):
        generated = builder.derive_mapping(VENDOR, MAPPING)
        contract = {
            **builder.CONTRACT,
            "vendor_public": identity(VENDOR),
            "gsi_mapping": identity(MAPPING),
            "mapping_output": {
                **identity(generated), "name": "mapping.cil", "bindings": 2,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor, mapping, output = root / "vendor.cil", root / "mapping.cil", root / "out"
            vendor.write_bytes(VENDOR)
            mapping.write_bytes(MAPPING)
            with mock.patch.object(builder, "CONTRACT", contract):
                result = builder.prepare(vendor, mapping, output)
                with self.assertRaises(FileExistsError):
                    builder.prepare(vendor, mapping, output)
            self.assertFalse(result["device_io_performed"])
            self.assertEqual(2, result["binding_count"])
            self.assertEqual(generated, (output / "mapping.cil").read_bytes())
            self.assertEqual(VENDOR, vendor.read_bytes())
            self.assertEqual(MAPPING, mapping.read_bytes())

    def test_wrong_output_contract_produces_no_files(self):
        contract = {
            **builder.CONTRACT,
            "vendor_public": identity(VENDOR),
            "gsi_mapping": identity(MAPPING),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor, mapping, output = root / "vendor.cil", root / "mapping.cil", root / "out"
            vendor.write_bytes(VENDOR)
            mapping.write_bytes(MAPPING)
            with mock.patch.object(builder, "CONTRACT", contract):
                with self.assertRaisesRegex(ValueError, "generated mapping identity"):
                    builder.prepare(vendor, mapping, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
