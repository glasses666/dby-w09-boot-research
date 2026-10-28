#!/usr/bin/env python3
"""Independently verify the deterministic API32 framework GNSS 1.1-only candidate."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEGACY_VERIFIER_PATH = ROOT / "scripts/verify_api32_system_framework_gnss_candidate.py"


def _load_legacy_verifier():
    spec = importlib.util.spec_from_file_location(
        "legacy_api32_system_framework_gnss_verifier", LEGACY_VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {LEGACY_VERIFIER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


legacy = _load_legacy_verifier()

SOURCE_SYSTEM = legacy.SOURCE_SYSTEM
SOURCE_SUPER = legacy.SOURCE_SUPER
SOURCE_BOOT = legacy.SOURCE_BOOT
SOURCE_SYSTEM_SIZE = legacy.SOURCE_SYSTEM_SIZE
SOURCE_SYSTEM_SHA256 = legacy.SOURCE_SYSTEM_SHA256
SOURCE_SUPER_SIZE = legacy.SOURCE_SUPER_SIZE
SOURCE_SUPER_SHA256 = legacy.SOURCE_SUPER_SHA256
SOURCE_BOOT_SIZE = legacy.SOURCE_BOOT_SIZE
SOURCE_BOOT_SHA256 = legacy.SOURCE_BOOT_SHA256
SYSTEM_OFFSET_IN_SUPER = legacy.SYSTEM_OFFSET_IN_SUPER
MANIFEST_PATH = legacy.MANIFEST_PATH
SOURCE_MANIFEST_SIZE = legacy.SOURCE_MANIFEST_SIZE
SOURCE_MANIFEST_SHA256 = legacy.SOURCE_MANIFEST_SHA256
OUTPUT_MANIFEST_SHA256 = "e1709cc931677e71ac3c51257ac9e207060f95f3449b28ec5f676f992640df07"
MANIFEST_PHYSICAL_BLOCK = legacy.MANIFEST_PHYSICAL_BLOCK
MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM = legacy.MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM
MANIFEST_OFFSET_IN_SUPER = legacy.MANIFEST_OFFSET_IN_SUPER

OUTPUT_SYSTEM_SHA256: str | None = (
    "e254e96f018ae0b8a5db47e3ab891dc9e07db4202737e22c8835c00f1475d317"
)
OUTPUT_SUPER_SHA256: str | None = (
    "a2826268ea5566d25ca963ec371f4cd721e25d6d4175b08662b6bbe66d5030a1"
)

sha256_bytes = legacy.sha256_bytes
sha256_file = legacy.sha256_file
read_range = legacy.read_range
validate_file = legacy.validate_file
exact_image_audit = legacy.exact_image_audit
read_manifest = legacy.read_manifest
read_inode_state = legacy.read_inode_state
run_e2fsck = legacy.run_e2fsck


def validate_manifest_semantics(source: bytes, output: bytes) -> dict[str, object]:
    if len(source) != SOURCE_MANIFEST_SIZE or len(output) != SOURCE_MANIFEST_SIZE:
        raise ValueError("framework manifest size changed")
    if sha256_bytes(source) != SOURCE_MANIFEST_SHA256:
        raise ValueError("unexpected source framework manifest identity")
    if sha256_bytes(output) != OUTPUT_MANIFEST_SHA256:
        raise ValueError("unexpected output framework manifest identity")
    before, before_gnss = legacy._split_semantics(source)
    after, after_gnss = legacy._split_semantics(output)
    if before_gnss:
        raise ValueError("source unexpectedly contains framework GNSS")
    if before != after:
        raise ValueError("existing framework manifest semantics changed")
    expected = {
        "name": "android.hardware.gnss",
        "transport": "hwbinder",
        "versions": ["1.1"],
        "interface": "IGnss",
        "instance": "default",
    }
    if after_gnss != [expected]:
        raise ValueError("unexpected framework GNSS 1.1-only declaration")
    return {"existing_semantics_preserved": True, "existing_entry_count": len(before), "gnss": expected}


def verify(system: Path, super_image: Path) -> dict[str, object]:
    if OUTPUT_SYSTEM_SHA256 is None or OUTPUT_SUPER_SHA256 is None:
        raise ValueError("frozen output hashes are not configured")
    validate_file(SOURCE_SYSTEM, SOURCE_SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)
    validate_file(SOURCE_SUPER, SOURCE_SUPER_SIZE, SOURCE_SUPER_SHA256)
    validate_file(SOURCE_BOOT, SOURCE_BOOT_SIZE, SOURCE_BOOT_SHA256)
    validate_file(system, SOURCE_SYSTEM_SIZE, OUTPUT_SYSTEM_SHA256)
    validate_file(super_image, SOURCE_SUPER_SIZE, OUTPUT_SUPER_SHA256)

    source_manifest = read_manifest(SOURCE_SYSTEM)
    output_manifest = read_manifest(system)
    semantics = validate_manifest_semantics(source_manifest, output_manifest)
    source_inode = read_inode_state(SOURCE_SYSTEM)
    output_inode = read_inode_state(system)
    if source_inode != output_inode or source_inode["blocks"] != [MANIFEST_PHYSICAL_BLOCK]:
        raise ValueError("framework manifest inode metadata or block map changed")
    if read_range(SOURCE_SYSTEM, MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM, SOURCE_MANIFEST_SIZE) != source_manifest:
        raise ValueError("source system manifest mapping changed")
    if read_range(system, MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM, SOURCE_MANIFEST_SIZE) != output_manifest:
        raise ValueError("candidate system manifest mapping changed")
    if read_range(SOURCE_SUPER, MANIFEST_OFFSET_IN_SUPER, SOURCE_MANIFEST_SIZE) != source_manifest:
        raise ValueError("source super manifest mapping changed")
    if read_range(super_image, MANIFEST_OFFSET_IN_SUPER, SOURCE_MANIFEST_SIZE) != output_manifest:
        raise ValueError("candidate super manifest mapping changed")
    system_audit = exact_image_audit(
        SOURCE_SYSTEM, system, MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM, source_manifest, output_manifest
    )
    super_audit = exact_image_audit(
        SOURCE_SUPER, super_image, MANIFEST_OFFSET_IN_SUPER, source_manifest, output_manifest
    )
    if sha256_file(SOURCE_SUPER, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != SOURCE_SYSTEM_SHA256:
        raise ValueError("source super system payload changed")
    if sha256_file(super_image, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != OUTPUT_SYSTEM_SHA256:
        raise ValueError("candidate super does not contain candidate system")
    e2fsck = run_e2fsck(system)
    return {
        "schema": "dby-w09-api32-system-framework-gnss-1_1-verification-v1",
        "status": "pass",
        "device_io_performed": False,
        "source_system": {"size": SOURCE_SYSTEM_SIZE, "sha256": SOURCE_SYSTEM_SHA256},
        "source_super": {"size": SOURCE_SUPER_SIZE, "sha256": SOURCE_SUPER_SHA256},
        "boot_control": {"size": SOURCE_BOOT_SIZE, "sha256": SOURCE_BOOT_SHA256, "output_emitted": False},
        "output_system": {"path": str(system.resolve()), "size": system.stat().st_size, "sha256": OUTPUT_SYSTEM_SHA256},
        "output_super": {"path": str(super_image.resolve()), "size": super_image.stat().st_size, "sha256": OUTPUT_SUPER_SHA256},
        "framework_manifest": {
            "path": MANIFEST_PATH,
            "size": SOURCE_MANIFEST_SIZE,
            "source_sha256": SOURCE_MANIFEST_SHA256,
            "output_sha256": OUTPUT_MANIFEST_SHA256,
            "inode_state": source_inode,
            "semantics": semantics,
            "target_replay_classification": "source-derived-correction-restores-aggregation",
        },
        "system_audit": system_audit,
        "super_audit": super_audit,
        "e2fsck": e2fsck,
        "claim_boundary": "offline image integrity and target VINTF identity only; live boot remains unproved",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", required=True, type=Path)
    parser.add_argument("--super", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite {args.output}")
    try:
        report = verify(args.system, args.super)
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
