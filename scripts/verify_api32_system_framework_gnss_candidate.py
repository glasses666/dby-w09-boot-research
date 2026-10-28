#!/usr/bin/env python3
"""Independently verify the API32 system-framework GNSS candidate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
BASE_BUILDER_PATH = ROOT / "scripts/build_api32_candidate.py"
SOURCE_BASE = (
    ROOT
    / "analysis/firmware-20261014/api32-diagnostic-adb-offline-20261027/build-a"
)
SOURCE_SYSTEM = SOURCE_BASE / "system-api32-diagnostic-adb-NOT-FLASHED.ext4"
SOURCE_SUPER = SOURCE_BASE / "super-api32-diagnostic-adb-NOT-FLASHED.img"
SOURCE_BOOT = (
    ROOT
    / "analysis/firmware-20261014/api29-apatch-root-20261025/candidate"
    / "apatch-11224-boot.img"
)

SOURCE_SYSTEM_SIZE = 2_513_813_504
SOURCE_SYSTEM_SHA256 = "451cc674329a8b18246136d19b929b043a8549c2ca89e7a6dd9b7235604857ea"
SOURCE_SUPER_SIZE = 7_692_353_536
SOURCE_SUPER_SHA256 = "a4b91fc572aea470b8fa2233e7a3742d681d1b0ab8cc82782ef6dac7067707d6"
SOURCE_BOOT_SIZE = 100_663_296
SOURCE_BOOT_SHA256 = "dae495fdd20636469ac24e451cc6b2ff6e9201b26af4603fa0ce7c6921837f70"
OUTPUT_SYSTEM_SHA256 = "0d1bdf7e1116ce07b6923f3157f76c6555fd33cfce5082ee2a883706c186a54a"
OUTPUT_SUPER_SHA256 = "58c18e09a0d22e139ac96ee85735c9a9cba499831b0f92fed510b80d3bef6caa"

SYSTEM_OFFSET_IN_SUPER = 2_097_152
MANIFEST_PATH = "/system/etc/vintf/manifest.xml"
SOURCE_MANIFEST_SIZE = 3_034
SOURCE_MANIFEST_SHA256 = "e5fb162ac9b27f130f8a7a09c1a908a6727cc00ea32b20036a0d7253e45ed040"
OUTPUT_MANIFEST_SHA256 = "3705d4036e7e87afe2c2ab800e709df105e942994d906c8b5e6d57b76438a0f7"
FILESYSTEM_BLOCK_SIZE = 4_096
MANIFEST_PHYSICAL_BLOCK = 63_234
MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM = MANIFEST_PHYSICAL_BLOCK * FILESYSTEM_BLOCK_SIZE
MANIFEST_OFFSET_IN_SUPER = SYSTEM_OFFSET_IN_SUPER + MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM
CHUNK_SIZE = 8 * 1024 * 1024


def _load_base_builder():
    spec = importlib.util.spec_from_file_location(
        "build_api32_candidate_for_system_framework_gnss_verifier",
        BASE_BUILDER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {BASE_BUILDER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load_base_builder()


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, offset: int = 0, length: int | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = length
        while remaining is None or remaining:
            wanted = CHUNK_SIZE if remaining is None else min(CHUNK_SIZE, remaining)
            block = stream.read(wanted)
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
    if remaining not in (None, 0):
        raise ValueError(f"short read from {path}: {remaining} bytes missing")
    return digest.hexdigest()


def read_range(path: Path, offset: int, length: int) -> bytes:
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    if len(data) != length:
        raise ValueError(f"short read from {path} at {offset}")
    return data


def validate_file(path: Path, size: int, expected_sha256: str) -> None:
    if not path.is_file() or path.stat().st_size != size:
        raise ValueError(f"unexpected file size: {path}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ValueError(f"unexpected file SHA-256: {path}: {actual}")


def _element_semantics(element: ET.Element) -> dict[str, object]:
    return {
        "tag": element.tag,
        "attributes": dict(sorted(element.attrib.items())),
        "text": (element.text or "").strip(),
        "children": [_element_semantics(child) for child in element],
    }


def _split_semantics(data: bytes) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    root = ET.fromstring(data)
    if root.tag != "manifest" or root.attrib != {"version": "4.0", "type": "framework"}:
        raise ValueError("unexpected framework manifest root")
    existing: list[dict[str, object]] = []
    gnss: list[dict[str, object]] = []
    for child in root:
        if child.tag == "hal" and child.findtext("name") == "android.hardware.gnss":
            interface = child.find("interface")
            gnss.append(
                {
                    "name": child.findtext("name"),
                    "transport": child.findtext("transport"),
                    "versions": [node.text for node in child.findall("version")],
                    "interface": interface.findtext("name") if interface is not None else None,
                    "instance": interface.findtext("instance") if interface is not None else None,
                }
            )
        else:
            existing.append(_element_semantics(child))
    return existing, gnss


def validate_manifest_semantics(source: bytes, output: bytes) -> dict[str, object]:
    if len(source) != SOURCE_MANIFEST_SIZE or len(output) != SOURCE_MANIFEST_SIZE:
        raise ValueError("framework manifest size changed")
    if sha256_bytes(source) != SOURCE_MANIFEST_SHA256:
        raise ValueError("unexpected source framework manifest identity")
    if sha256_bytes(output) != OUTPUT_MANIFEST_SHA256:
        raise ValueError("unexpected output framework manifest identity")
    before, before_gnss = _split_semantics(source)
    after, after_gnss = _split_semantics(output)
    if before_gnss:
        raise ValueError("source unexpectedly contains framework GNSS")
    if before != after:
        raise ValueError("existing framework manifest semantics changed")
    expected = {
        "name": "android.hardware.gnss",
        "transport": "hwbinder",
        "versions": ["1.0", "1.1"],
        "interface": "IGnss",
        "instance": "default",
    }
    if after_gnss != [expected]:
        raise ValueError("unexpected framework GNSS declaration")
    return {
        "existing_semantics_preserved": True,
        "existing_entry_count": len(before),
        "gnss": expected,
    }


def exact_image_audit(
    source: Path,
    output: Path,
    offset: int,
    expected_source: bytes,
    expected_output: bytes,
) -> dict[str, object]:
    if len(expected_source) != len(expected_output):
        raise ValueError("authorized manifest span changed length")
    if source.stat().st_size != output.stat().st_size:
        raise ValueError("image size changed")
    if read_range(source, offset, len(expected_source)) != expected_source:
        raise ValueError("source manifest mapping changed")
    if read_range(output, offset, len(expected_output)) != expected_output:
        raise ValueError("output manifest mapping changed")
    end = offset + len(expected_source)
    changed = 0
    first: int | None = None
    last: int | None = None
    absolute = 0
    with source.open("rb") as before, output.open("rb") as after:
        while True:
            left = before.read(CHUNK_SIZE)
            right = after.read(CHUNK_SIZE)
            if not left and not right:
                break
            if len(left) != len(right):
                raise ValueError("image stream lengths changed")
            if left != right:
                for index, (old, new) in enumerate(zip(left, right)):
                    if old == new:
                        continue
                    position = absolute + index
                    if not offset <= position < end:
                        raise ValueError(
                            f"image change outside authorized manifest at {position}"
                        )
                    changed += 1
                    first = position if first is None else first
                    last = position
            absolute += len(left)
    expected_changed = sum(a != b for a, b in zip(expected_source, expected_output))
    if changed != expected_changed or changed == 0:
        raise ValueError("unexpected changed-byte count")
    return {
        "authorized_span": {"offset": offset, "length": len(expected_source)},
        "changed_bytes": changed,
        "first_changed_offset": first,
        "last_changed_offset": last,
        "outside_span_byte_identical": True,
    }


def read_manifest(image: Path) -> bytes:
    return base.debugfs(f"cat {MANIFEST_PATH}", image)


def read_inode_state(image: Path) -> dict[str, object]:
    stat = base.debugfs(f"stat {MANIFEST_PATH}", image)
    blocks = [int(base.debugfs(f"bmap {MANIFEST_PATH} 0", image).strip())]
    return {"stat_sha256": sha256_bytes(stat), "blocks": blocks}


def run_e2fsck(image: Path) -> str:
    completed = subprocess.run(
        [str(base.E2FSCK), "-fn", str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=180,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"e2fsck failed ({completed.returncode}): {completed.stdout}")
    return completed.stdout


def verify(system: Path, super_image: Path) -> dict[str, object]:
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
        SOURCE_SYSTEM,
        system,
        MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM,
        source_manifest,
        output_manifest,
    )
    super_audit = exact_image_audit(
        SOURCE_SUPER,
        super_image,
        MANIFEST_OFFSET_IN_SUPER,
        source_manifest,
        output_manifest,
    )
    if sha256_file(SOURCE_SUPER, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != SOURCE_SYSTEM_SHA256:
        raise ValueError("source super system payload changed")
    if sha256_file(super_image, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != OUTPUT_SYSTEM_SHA256:
        raise ValueError("candidate super does not contain candidate system")
    e2fsck = run_e2fsck(system)

    return {
        "schema": "dby-w09-api32-system-framework-gnss-verification-v1",
        "status": "pass",
        "device_io_performed": False,
        "source_system": {"size": SOURCE_SYSTEM_SIZE, "sha256": SOURCE_SYSTEM_SHA256},
        "source_super": {"size": SOURCE_SUPER_SIZE, "sha256": SOURCE_SUPER_SHA256},
        "boot_control": {
            "size": SOURCE_BOOT_SIZE,
            "sha256": SOURCE_BOOT_SHA256,
            "output_emitted": False,
            "unchanged_required_live": True,
        },
        "output_system": {"path": str(system.resolve()), "size": system.stat().st_size, "sha256": OUTPUT_SYSTEM_SHA256},
        "output_super": {"path": str(super_image.resolve()), "size": super_image.stat().st_size, "sha256": OUTPUT_SUPER_SHA256},
        "framework_manifest": {
            "path": MANIFEST_PATH,
            "source_sha256": SOURCE_MANIFEST_SHA256,
            "output_sha256": OUTPUT_MANIFEST_SHA256,
            "size": SOURCE_MANIFEST_SIZE,
            "inode_state": source_inode,
            "semantics": semantics,
        },
        "system_audit": system_audit,
        "super_audit": super_audit,
        "e2fsck": e2fsck,
        "boot_and_vendor_policy": "no boot output; every super byte outside the system framework manifest is source-identical",
        "claim_boundary": "Live GNSS registration, system_server survival, boot completion and UI remain unproved.",
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
