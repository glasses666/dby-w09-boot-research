#!/usr/bin/env python3
"""Build a deterministic NOT-FLASHED API32 framework GNSS 1.1-only candidate."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
LEGACY_BUILDER_PATH = ROOT / "scripts/build_api32_system_framework_gnss_candidate.py"


def _load_legacy_builder():
    spec = importlib.util.spec_from_file_location(
        "legacy_api32_system_framework_gnss_builder", LEGACY_BUILDER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {LEGACY_BUILDER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


legacy = _load_legacy_builder()

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
FILESYSTEM_BLOCK_SIZE = legacy.FILESYSTEM_BLOCK_SIZE
MANIFEST_PHYSICAL_BLOCK = legacy.MANIFEST_PHYSICAL_BLOCK
MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM = legacy.MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM
MANIFEST_OFFSET_IN_SUPER = legacy.MANIFEST_OFFSET_IN_SUPER

LEGACY_TWO_MINOR_MANIFEST_SHA256 = legacy.EXPECTED_REPLACEMENT_SHA256
OUTPUT_MANIFEST_SHA256 = "e1709cc931677e71ac3c51257ac9e207060f95f3449b28ec5f676f992640df07"
EXPECTED_OUTPUT_SYSTEM_SHA256: str | None = (
    "e254e96f018ae0b8a5db47e3ab891dc9e07db4202737e22c8835c00f1475d317"
)
EXPECTED_OUTPUT_SUPER_SHA256: str | None = (
    "a2826268ea5566d25ca963ec371f4cd721e25d6d4175b08662b6bbe66d5030a1"
)

sha256_bytes = legacy.sha256_bytes
sha256_file = legacy.sha256_file
read_range = legacy.read_range
validate_source = legacy.validate_source
clone_copy = legacy.clone_copy
read_inode_state = legacy.read_inode_state
exact_image_audit = legacy.exact_image_audit
run_e2fsck = legacy.run_e2fsck


def _gnss_semantics(hal: ET.Element) -> dict[str, object]:
    interface = hal.find("interface")
    return {
        "name": hal.findtext("name"),
        "transport": hal.findtext("transport"),
        "versions": [node.text for node in hal.findall("version")],
        "interface": interface.findtext("name") if interface is not None else None,
        "instance": interface.findtext("instance") if interface is not None else None,
    }


def manifest_semantics(data: bytes) -> dict[str, object]:
    root = ET.fromstring(data)
    if root.tag != "manifest" or root.attrib != {"version": "4.0", "type": "framework"}:
        raise ValueError("unexpected framework manifest root")
    existing: list[dict[str, object]] = []
    gnss: list[ET.Element] = []
    for child in root:
        if child.tag == "hal" and child.findtext("name") == "android.hardware.gnss":
            gnss.append(child)
        else:
            existing.append(legacy._element_semantics(child))
    if len(gnss) > 1:
        raise ValueError("multiple framework GNSS declarations")
    parsed = _gnss_semantics(gnss[0]) if gnss else None
    if parsed is not None and parsed != {
        "name": "android.hardware.gnss",
        "transport": "hwbinder",
        "versions": ["1.1"],
        "interface": "IGnss",
        "instance": "default",
    }:
        raise ValueError("unexpected framework GNSS 1.1-only semantics")
    return {"existing_hals": existing, "framework_gnss": parsed}


def replacement_manifest(source: bytes) -> bytes:
    before = manifest_semantics(source)
    if before["framework_gnss"] is not None:
        raise ValueError("source already contains framework GNSS")
    legacy_candidate = legacy.replacement_manifest(source)
    if sha256_bytes(legacy_candidate) != LEGACY_TWO_MINOR_MANIFEST_SHA256:
        raise ValueError("legacy two-minor manifest identity changed")
    first = b"<version>1.0</version>"
    second = b"<version>1.1</version>"
    needle = first + second
    if legacy_candidate.count(needle) != 1:
        raise ValueError("legacy candidate lacks the exact conflicting version sequence")
    replacement = legacy_candidate.replace(needle, second + (b" " * len(first)), 1)
    if len(replacement) != len(source):
        raise AssertionError("framework manifest size changed")
    after = manifest_semantics(replacement)
    if before["existing_hals"] != after["existing_hals"]:
        raise ValueError("existing framework manifest semantics changed")
    if sha256_bytes(replacement) != OUTPUT_MANIFEST_SHA256:
        raise ValueError("target-validated GNSS 1.1-only manifest identity changed")
    return replacement


def _write_manifest_span(path: Path, offset: int, source: bytes, replacement: bytes) -> None:
    with path.open("r+b", buffering=0) as stream:
        stream.seek(offset)
        if stream.read(len(source)) != source:
            raise ValueError(f"raw source manifest mismatch: {path}")
        stream.seek(offset)
        stream.write(replacement)
        stream.flush()
        os.fsync(stream.fileno())


def build(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    system = output_dir / "system-api32-system-framework-gnss-1_1-NOT-FLASHED.ext4"
    super_image = output_dir / "super-api32-system-framework-gnss-1_1-NOT-FLASHED.img"

    validate_source(SOURCE_SYSTEM, SOURCE_SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)
    validate_source(SOURCE_SUPER, SOURCE_SUPER_SIZE, SOURCE_SUPER_SHA256)
    validate_source(SOURCE_BOOT, SOURCE_BOOT_SIZE, SOURCE_BOOT_SHA256)
    source_manifest = legacy.read_manifest(SOURCE_SYSTEM)
    if len(source_manifest) != SOURCE_MANIFEST_SIZE or sha256_bytes(source_manifest) != SOURCE_MANIFEST_SHA256:
        raise ValueError("frozen source manifest identity changed")
    replacement = replacement_manifest(source_manifest)
    source_inode = read_inode_state(SOURCE_SYSTEM)
    if source_inode["blocks"] != [MANIFEST_PHYSICAL_BLOCK]:
        raise ValueError("framework manifest block map changed")
    if read_range(SOURCE_SYSTEM, MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM, SOURCE_MANIFEST_SIZE) != source_manifest:
        raise ValueError("source system raw manifest mapping changed")
    if read_range(SOURCE_SUPER, MANIFEST_OFFSET_IN_SUPER, SOURCE_MANIFEST_SIZE) != source_manifest:
        raise ValueError("source super raw manifest mapping changed")
    if sha256_file(SOURCE_SUPER, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != SOURCE_SYSTEM_SHA256:
        raise ValueError("source super does not contain the frozen diagnostic system")

    clone_copy(SOURCE_SYSTEM, system)
    clone_copy(SOURCE_SUPER, super_image)
    _write_manifest_span(system, MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM, source_manifest, replacement)
    _write_manifest_span(super_image, MANIFEST_OFFSET_IN_SUPER, source_manifest, replacement)

    if legacy.read_manifest(system) != replacement:
        raise ValueError("framework manifest filesystem readback changed")
    if read_inode_state(system) != source_inode:
        raise ValueError("framework manifest inode metadata or block map changed")
    system_audit = exact_image_audit(
        SOURCE_SYSTEM, system, MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM, source_manifest, replacement
    )
    super_audit = exact_image_audit(
        SOURCE_SUPER, super_image, MANIFEST_OFFSET_IN_SUPER, source_manifest, replacement
    )
    e2fsck = run_e2fsck(system)
    output_system_sha256 = sha256_file(system)
    output_super_sha256 = sha256_file(super_image)
    if sha256_file(super_image, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != output_system_sha256:
        raise ValueError("candidate super does not contain the candidate system")
    if EXPECTED_OUTPUT_SYSTEM_SHA256 is not None and output_system_sha256 != EXPECTED_OUTPUT_SYSTEM_SHA256:
        raise ValueError(f"unexpected output system SHA-256: {output_system_sha256}")
    if EXPECTED_OUTPUT_SUPER_SHA256 is not None and output_super_sha256 != EXPECTED_OUTPUT_SUPER_SHA256:
        raise ValueError(f"unexpected output super SHA-256: {output_super_sha256}")

    report = {
        "schema": "dby-w09-api32-system-framework-gnss-1_1-build-v1",
        "status": (
            "offline-built-not-flashed"
            if EXPECTED_OUTPUT_SYSTEM_SHA256 and EXPECTED_OUTPUT_SUPER_SHA256
            else "discovery-built-not-flashed"
        ),
        "device_io_performed": False,
        "source_system": {"path": str(SOURCE_SYSTEM), "size": SOURCE_SYSTEM_SIZE, "sha256": SOURCE_SYSTEM_SHA256},
        "source_super": {"path": str(SOURCE_SUPER), "size": SOURCE_SUPER_SIZE, "sha256": SOURCE_SUPER_SHA256},
        "boot_control": {
            "path": str(SOURCE_BOOT),
            "size": SOURCE_BOOT_SIZE,
            "sha256": SOURCE_BOOT_SHA256,
            "output_emitted": False,
            "unchanged_required_live": True,
        },
        "output_system": {"path": str(system), "size": system.stat().st_size, "sha256": output_system_sha256},
        "output_super": {"path": str(super_image), "size": super_image.stat().st_size, "sha256": output_super_sha256},
        "framework_manifest": {
            "path": MANIFEST_PATH,
            "size": SOURCE_MANIFEST_SIZE,
            "source_sha256": SOURCE_MANIFEST_SHA256,
            "legacy_rejected_sha256": LEGACY_TWO_MINOR_MANIFEST_SHA256,
            "output_sha256": OUTPUT_MANIFEST_SHA256,
            "physical_block": MANIFEST_PHYSICAL_BLOCK,
            "inode_state": source_inode,
            "semantics": manifest_semantics(replacement),
            "exact_target_replay_classification": "source-derived-correction-restores-aggregation",
        },
        "system_audit": system_audit,
        "super_audit": super_audit,
        "e2fsck": e2fsck,
        "boundary": "one same-length framework manifest span; boot and all other super bytes source-identical",
        "claim_boundary": "target VINTF content is validated; Android boot, services, GNSS and UI remain live-only",
    }
    (output_dir / "build-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    try:
        report = build(args.output_dir)
    except (FileExistsError, FileNotFoundError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
