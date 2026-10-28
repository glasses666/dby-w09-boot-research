#!/usr/bin/env python3
"""Build the minimal API32 vendor-enhanced detector compatibility overlay."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


EXPECTED_SOURCE_SHA256 = "1927811cdf681ab289ae32b73c6e59f94e63b505a7763a445db2942f5e179156"
GET_VENDOR_ENHANCED_INFO_OFFSET = 0x102C
EXPECTED_FUNCTION_PREFIX = bytes.fromhex("10 b5 0a 48")
RETURN_ODM_ONLY_INFO = bytes.fromhex("01 20 70 47")  # movs r0, #1; bx lr


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_image(
    source: bytes, *, verify_source_hash: bool = True
) -> tuple[bytes, dict[str, object]]:
    if verify_source_hash and sha256_bytes(source) != EXPECTED_SOURCE_SHA256:
        raise ValueError("source libqti_vndfwk_detect.so identity mismatch")
    if source[:6] != b"\x7fELF\x01\x01":
        raise ValueError("source is not a little-endian ELF32 image")
    end = GET_VENDOR_ENHANCED_INFO_OFFSET + len(EXPECTED_FUNCTION_PREFIX)
    if len(source) < end:
        raise ValueError("source is too short for getVendorEnhancedInfo")
    if source[GET_VENDOR_ENHANCED_INFO_OFFSET:end] != EXPECTED_FUNCTION_PREFIX:
        raise ValueError("getVendorEnhancedInfo function prefix mismatch")

    patched = bytearray(source)
    patched[GET_VENDOR_ENHANCED_INFO_OFFSET:end] = RETURN_ODM_ONLY_INFO
    output = bytes(patched)
    differences = [
        index for index, (old, new) in enumerate(zip(source, output)) if old != new
    ]
    expected_differences = list(range(GET_VENDOR_ENHANCED_INFO_OFFSET, end))
    if differences != expected_differences:
        raise ValueError(f"unexpected byte differences: {differences!r}")

    report: dict[str, object] = {
        "schema": "dby-w09-api32-vendor-enhanced-detector-overlay-v1",
        "source_sha256": sha256_bytes(source),
        "output_sha256": sha256_bytes(output),
        "size": len(output),
        "elf_class": 32,
        "elf_endian": "little",
        "patch_offset": GET_VENDOR_ENHANCED_INFO_OFFSET,
        "source_bytes": EXPECTED_FUNCTION_PREFIX.hex(),
        "output_bytes": RETURN_ODM_ONLY_INFO.hex(),
        "semantic_result": "getVendorEnhancedInfo returns ODM-only flag 1",
        "changed_offsets": differences,
        "changed_byte_count": len(differences),
        "all_other_bytes_equal": True,
    }
    return output, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()

    source_path = args.input.resolve()
    output_path = args.output.resolve()
    manifest_path = args.manifest.resolve()
    if output_path.exists() or manifest_path.exists():
        raise RuntimeError("refusing to overwrite an existing build output")
    output, report = patch_image(source_path.read_bytes())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output)
    output_path.chmod(0o644)
    report["created_utc"] = datetime.now(timezone.utc).isoformat()
    report["input_path"] = str(source_path)
    report["output_path"] = str(output_path)
    manifest_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
