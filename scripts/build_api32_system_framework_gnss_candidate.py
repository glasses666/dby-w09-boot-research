#!/usr/bin/env python3
"""Build the API32 framework-side GNSS VINTF candidate.

The source is the live-tested diagnostic-ADB API32 system/super pair.  The
builder adds inherited GNSS 1.0/1.1 declarations to the framework manifest in
one same-length ext4 block.  It performs no device I/O, emits no boot image and
keeps every super byte outside that manifest span identical.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
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

EXPECTED_OUTPUT_SYSTEM_SHA256: str | None = (
    "0d1bdf7e1116ce07b6923f3157f76c6555fd33cfce5082ee2a883706c186a54a"
)
EXPECTED_OUTPUT_SUPER_SHA256: str | None = (
    "58c18e09a0d22e139ac96ee85735c9a9cba499831b0f92fed510b80d3bef6caa"
)

SYSTEM_OFFSET_IN_SUPER = 2_097_152
MANIFEST_PATH = "/system/etc/vintf/manifest.xml"
SOURCE_MANIFEST_SIZE = 3_034
SOURCE_MANIFEST_SHA256 = "e5fb162ac9b27f130f8a7a09c1a908a6727cc00ea32b20036a0d7253e45ed040"
EXPECTED_REPLACEMENT_SHA256 = "3705d4036e7e87afe2c2ab800e709df105e942994d906c8b5e6d57b76438a0f7"
FILESYSTEM_BLOCK_SIZE = 4_096
MANIFEST_PHYSICAL_BLOCK = 63_234
MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM = MANIFEST_PHYSICAL_BLOCK * FILESYSTEM_BLOCK_SIZE
MANIFEST_OFFSET_IN_SUPER = SYSTEM_OFFSET_IN_SUPER + MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM
CHUNK_SIZE = 8 * 1024 * 1024


def _load_base_builder():
    spec = importlib.util.spec_from_file_location(
        "build_api32_candidate_for_system_framework_gnss", BASE_BUILDER_PATH
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


def validate_source(path: Path, size: int, expected_sha256: str) -> None:
    if not path.is_file() or path.stat().st_size != size:
        raise ValueError(f"unexpected source size: {path}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ValueError(f"unexpected source SHA-256: {path}: {actual}")


def clone_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(destination)
    subprocess.run(
        ["/bin/cp", "-c", str(source), str(destination)],
        stdin=subprocess.DEVNULL,
        check=True,
    )


def read_manifest(image: Path) -> bytes:
    return base.debugfs(f"cat {MANIFEST_PATH}", image)


def read_inode_state(image: Path) -> dict[str, object]:
    stat = base.debugfs(f"stat {MANIFEST_PATH}", image)
    size = len(read_manifest(image))
    block_count = (size + FILESYSTEM_BLOCK_SIZE - 1) // FILESYSTEM_BLOCK_SIZE
    blocks = [
        int(base.debugfs(f"bmap {MANIFEST_PATH} {index}", image).strip())
        for index in range(block_count)
    ]
    return {"stat_sha256": sha256_bytes(stat), "blocks": blocks}


def _element_semantics(element: ET.Element) -> dict[str, object]:
    return {
        "tag": element.tag,
        "attributes": dict(sorted(element.attrib.items())),
        "text": (element.text or "").strip(),
        "children": [_element_semantics(child) for child in element],
    }


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
            existing.append(_element_semantics(child))
    if len(gnss) > 1:
        raise ValueError("multiple framework GNSS declarations")
    parsed_gnss = _gnss_semantics(gnss[0]) if gnss else None
    if parsed_gnss is not None and parsed_gnss != {
        "name": "android.hardware.gnss",
        "transport": "hwbinder",
        "versions": ["1.0", "1.1"],
        "interface": "IGnss",
        "instance": "default",
    }:
        raise ValueError("unexpected framework GNSS semantics")
    return {"existing_hals": existing, "framework_gnss": parsed_gnss}


def replacement_manifest(source: bytes) -> bytes:
    before = manifest_semantics(source)
    if before["framework_gnss"] is not None:
        raise ValueError("source already contains framework GNSS")
    root = ET.fromstring(source)
    gnss = ET.Element("hal", {"format": "hidl"})
    ET.SubElement(gnss, "name").text = "android.hardware.gnss"
    ET.SubElement(gnss, "transport").text = "hwbinder"
    ET.SubElement(gnss, "version").text = "1.0"
    ET.SubElement(gnss, "version").text = "1.1"
    interface = ET.SubElement(gnss, "interface")
    ET.SubElement(interface, "name").text = "IGnss"
    ET.SubElement(interface, "instance").text = "default"
    system_sdk_index = next(
        (index for index, child in enumerate(root) if child.tag == "system-sdk"),
        None,
    )
    if system_sdk_index is None:
        raise ValueError("framework manifest has no system-sdk boundary")
    root.insert(system_sdk_index, gnss)
    for element in root.iter():
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    compact = ET.tostring(root, encoding="utf-8", short_empty_elements=True) + b"\n"
    padding = len(source) - len(compact)
    if padding < 0:
        raise ValueError("framework GNSS manifest does not fit the source inode")
    replacement = compact.replace(b"</manifest>", b" " * padding + b"</manifest>", 1)
    if len(replacement) != len(source):
        raise AssertionError("framework manifest size changed")
    after = manifest_semantics(replacement)
    if before["existing_hals"] != after["existing_hals"]:
        raise ValueError("existing framework manifest semantics changed")
    if sha256_bytes(replacement) != EXPECTED_REPLACEMENT_SHA256:
        raise ValueError("unexpected framework GNSS replacement identity")
    return replacement


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


def _write_manifest_span(path: Path, offset: int, source: bytes, replacement: bytes) -> None:
    with path.open("r+b", buffering=0) as stream:
        stream.seek(offset)
        if stream.read(len(source)) != source:
            raise ValueError(f"raw source manifest mismatch: {path}")
        stream.seek(offset)
        stream.write(replacement)
        stream.flush()
        os.fsync(stream.fileno())


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


def build(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    system = output_dir / "system-api32-system-framework-gnss-NOT-FLASHED.ext4"
    super_image = output_dir / "super-api32-system-framework-gnss-NOT-FLASHED.img"
    report_path = output_dir / "build-report.json"

    validate_source(SOURCE_SYSTEM, SOURCE_SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)
    validate_source(SOURCE_SUPER, SOURCE_SUPER_SIZE, SOURCE_SUPER_SHA256)
    validate_source(SOURCE_BOOT, SOURCE_BOOT_SIZE, SOURCE_BOOT_SHA256)
    source_manifest = read_manifest(SOURCE_SYSTEM)
    if len(source_manifest) != SOURCE_MANIFEST_SIZE:
        raise ValueError("unexpected source framework manifest size")
    if sha256_bytes(source_manifest) != SOURCE_MANIFEST_SHA256:
        raise ValueError("unexpected source framework manifest identity")
    replacement = replacement_manifest(source_manifest)
    source_inode = read_inode_state(SOURCE_SYSTEM)
    if source_inode["blocks"] != [MANIFEST_PHYSICAL_BLOCK]:
        raise ValueError(f"unexpected framework manifest block map: {source_inode['blocks']}")
    if read_range(
        SOURCE_SYSTEM, MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM, SOURCE_MANIFEST_SIZE
    ) != source_manifest:
        raise ValueError("source system raw manifest mapping changed")
    if read_range(SOURCE_SUPER, MANIFEST_OFFSET_IN_SUPER, SOURCE_MANIFEST_SIZE) != source_manifest:
        raise ValueError("source super raw manifest mapping changed")
    if sha256_file(SOURCE_SUPER, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != SOURCE_SYSTEM_SHA256:
        raise ValueError("source super does not contain the frozen diagnostic system")

    clone_copy(SOURCE_SYSTEM, system)
    clone_copy(SOURCE_SUPER, super_image)
    _write_manifest_span(
        system, MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM, source_manifest, replacement
    )
    _write_manifest_span(super_image, MANIFEST_OFFSET_IN_SUPER, source_manifest, replacement)

    if read_manifest(system) != replacement:
        raise ValueError("framework manifest semantic readback changed")
    if read_inode_state(system) != source_inode:
        raise ValueError("framework manifest inode metadata or block map changed")
    system_audit = exact_image_audit(
        SOURCE_SYSTEM,
        system,
        MANIFEST_PHYSICAL_OFFSET_IN_SYSTEM,
        source_manifest,
        replacement,
    )
    super_audit = exact_image_audit(
        SOURCE_SUPER,
        super_image,
        MANIFEST_OFFSET_IN_SUPER,
        source_manifest,
        replacement,
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
        "schema": "dby-w09-api32-system-framework-gnss-build-v1",
        "status": (
            "offline-built-not-flashed"
            if EXPECTED_OUTPUT_SYSTEM_SHA256 and EXPECTED_OUTPUT_SUPER_SHA256
            else "discovery-built-not-flashed"
        ),
        "device_io_performed": False,
        "source_system": {
            "path": str(SOURCE_SYSTEM.resolve()),
            "size": SOURCE_SYSTEM_SIZE,
            "sha256": SOURCE_SYSTEM_SHA256,
        },
        "source_super": {
            "path": str(SOURCE_SUPER.resolve()),
            "size": SOURCE_SUPER_SIZE,
            "sha256": SOURCE_SUPER_SHA256,
        },
        "boot_control": {
            "path": str(SOURCE_BOOT.resolve()),
            "size": SOURCE_BOOT_SIZE,
            "sha256": SOURCE_BOOT_SHA256,
            "output_emitted": False,
            "unchanged_required_live": True,
        },
        "output_system": {
            "path": str(system),
            "size": system.stat().st_size,
            "sha256": output_system_sha256,
        },
        "output_super": {
            "path": str(super_image),
            "size": super_image.stat().st_size,
            "sha256": output_super_sha256,
        },
        "framework_manifest": {
            "path": MANIFEST_PATH,
            "size": SOURCE_MANIFEST_SIZE,
            "source_sha256": SOURCE_MANIFEST_SHA256,
            "output_sha256": sha256_bytes(replacement),
            "physical_block": MANIFEST_PHYSICAL_BLOCK,
            "inode_state": source_inode,
            "semantics": manifest_semantics(replacement),
        },
        "system_audit": system_audit,
        "super_audit": super_audit,
        "e2fsck": e2fsck,
        "boundary": (
            "one same-length framework manifest span in system; boot and vendor "
            "must remain byte-identical to the restored diagnostic baseline"
        ),
        "claim_boundary": (
            "GNSS registration and Android boot completion remain live-only; "
            "offline qualification does not prove runtime success"
        ),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
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
