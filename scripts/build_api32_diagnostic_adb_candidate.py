#!/usr/bin/env python3
"""Build the API32 candidate with a minimal early diagnostic-ADB delta.

The input is the already-qualified API32 minimal candidate.  This builder
changes exactly two same-length spans in ``/system/etc/init/hw/init.usb.rc``:

* comment out the API32-only vendor ADB-disable property bridge; and
* make the existing boot action select ``sys.usb.config=adb`` directly.

It performs no device I/O and preserves the ext4 inode, block map, metadata,
SELinux xattr, logical-partition geometry and all bytes outside those spans.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASE_BUILDER_PATH = ROOT / "scripts/build_api32_candidate.py"
BASE = ROOT / "analysis/firmware-20261014/api32-next-checkpoint-offline-20261027"
SOURCE_SYSTEM = BASE / "candidates/build-a/system-api32-minimal-NOT-FLASHED.ext4"
SOURCE_SUPER = BASE / "candidates/build-a/super-api32-minimal-NOT-FLASHED.img"

SOURCE_SYSTEM_SIZE = 2_513_813_504
SOURCE_SYSTEM_SHA256 = "13af7063948eaf1e9da88051b80c352073cd2bf839f2c9f1d2ea4462d26e6d4b"
SOURCE_SUPER_SIZE = 7_692_353_536
SOURCE_SUPER_SHA256 = "2d43e81baa366eb77fe00a34128f04d4489538e6f0df5100fa180e63320ebd82"
EXPECTED_OUTPUT_SYSTEM_SHA256: str | None = (
    "451cc674329a8b18246136d19b929b043a8549c2ca89e7a6dd9b7235604857ea"
)
EXPECTED_OUTPUT_SUPER_SHA256: str | None = (
    "a4b91fc572aea470b8fa2233e7a3742d681d1b0ab8cc82782ef6dac7067707d6"
)

INIT_USB_RC_PATH = "/system/etc/init/hw/init.usb.rc"
INIT_USB_RC_SHA256 = "91e79aab1c819397fc050c27b21853253c0e1711423760c9ee3f5af7ed10d59b"
FILESYSTEM_BLOCK_SIZE = 4096
SYSTEM_OFFSET_IN_SUPER = 2_097_152
INIT_USB_RC_PHYSICAL_BLOCKS = (61_811, 61_812)

DISABLE_BRIDGE_FILE_OFFSET = 747
DISABLE_BRIDGE_SOURCE = (
    b"on property:vendor.sys.usb.adb.disabled=*\n"
    b"    setprop sys.usb.adb.disabled ${vendor.sys.usb.adb.disabled}\n"
)
BOOT_CONFIG_FILE_OFFSET = 4_654
BOOT_CONFIG_SOURCE = (
    b"on boot && property:persist.sys.usb.config=*\n"
    b"    setprop sys.usb.config ${persist.sys.usb.config}\n"
)


def _comment_lines_same_length(source: bytes) -> bytes:
    output = bytearray()
    for line in source.splitlines(keepends=True):
        newline = b"\n" if line.endswith(b"\n") else b""
        body = line[:-1] if newline else line
        if not body:
            output.extend(newline)
            continue
        output.extend(b"#" + b" " * (len(body) - 1) + newline)
    result = bytes(output)
    if len(result) != len(source):
        raise AssertionError("same-length comment transformation changed size")
    return result


DISABLE_BRIDGE_REPLACEMENT = _comment_lines_same_length(DISABLE_BRIDGE_SOURCE)


def _padded_line(text: bytes, source_line: bytes) -> bytes:
    if not source_line.endswith(b"\n") or len(text) >= len(source_line):
        raise ValueError("replacement line does not fit its source line")
    return text + b" " * (len(source_line) - len(text) - 1) + b"\n"


_boot_lines = BOOT_CONFIG_SOURCE.splitlines(keepends=True)
BOOT_CONFIG_REPLACEMENT = (
    _padded_line(b"on boot", _boot_lines[0])
    + _padded_line(b"    setprop sys.usb.config adb", _boot_lines[1])
)


def _load_base_builder():
    spec = importlib.util.spec_from_file_location(
        "build_api32_candidate_for_diagnostic_adb", BASE_BUILDER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {BASE_BUILDER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load_base_builder()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, offset: int = 0, length: int | None = None) -> str:
    return base.sha256_file(path, offset=offset, length=length)


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


def physical_offset(file_offset: int) -> int:
    if file_offset < 0:
        raise ValueError("init.usb.rc patch offset must be non-negative")
    logical_block, offset_in_block = divmod(file_offset, FILESYSTEM_BLOCK_SIZE)
    if logical_block >= len(INIT_USB_RC_PHYSICAL_BLOCKS):
        raise ValueError("init.usb.rc patch is outside its frozen block map")
    return (
        INIT_USB_RC_PHYSICAL_BLOCKS[logical_block] * FILESYSTEM_BLOCK_SIZE
        + offset_in_block
    )


PATCHES = (
    {
        "name": "ignore_vendor_adb_disable_bridge",
        "file_offset": DISABLE_BRIDGE_FILE_OFFSET,
        "source": DISABLE_BRIDGE_SOURCE,
        "replacement": DISABLE_BRIDGE_REPLACEMENT,
    },
    {
        "name": "force_diagnostic_adb_on_boot",
        "file_offset": BOOT_CONFIG_FILE_OFFSET,
        "source": BOOT_CONFIG_SOURCE,
        "replacement": BOOT_CONFIG_REPLACEMENT,
    },
)


def patched_init_usb_rc(source: bytes) -> bytes:
    if sha256_bytes(source) != INIT_USB_RC_SHA256:
        raise ValueError("unexpected init.usb.rc source identity")
    output = bytearray(source)
    for patch in PATCHES:
        file_offset = int(patch["file_offset"])
        expected = bytes(patch["source"])
        replacement = bytes(patch["replacement"])
        if len(expected) != len(replacement):
            raise AssertionError("patch is not same-length")
        if source.count(expected) != 1 or source.find(expected) != file_offset:
            raise ValueError(f"unexpected source span for {patch['name']}")
        output[file_offset : file_offset + len(expected)] = replacement
    result = bytes(output)
    if len(result) != len(source):
        raise AssertionError("init.usb.rc size changed")
    return result


def read_init_usb_rc(image: Path) -> bytes:
    return base.debugfs(f"cat {INIT_USB_RC_PATH}", image)


def read_inode_state(image: Path) -> dict[str, object]:
    stat = base.debugfs(f"stat {INIT_USB_RC_PATH}", image)
    blocks = tuple(
        int(base.debugfs(f"bmap {INIT_USB_RC_PATH} {index}", image).strip())
        for index in range(2)
    )
    return {
        "stat_sha256": sha256_bytes(stat),
        "blocks": list(blocks),
    }


def apply_raw_patches(system: Path, super_image: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with system.open("r+b", buffering=0) as system_stream, super_image.open(
        "r+b", buffering=0
    ) as super_stream:
        for patch in PATCHES:
            expected = bytes(patch["source"])
            replacement = bytes(patch["replacement"])
            raw_offset = physical_offset(int(patch["file_offset"]))
            super_offset = SYSTEM_OFFSET_IN_SUPER + raw_offset
            system_stream.seek(raw_offset)
            if system_stream.read(len(expected)) != expected:
                raise ValueError(f"system raw source mismatch for {patch['name']}")
            super_stream.seek(super_offset)
            if super_stream.read(len(expected)) != expected:
                raise ValueError(f"super raw source mismatch for {patch['name']}")
            system_stream.seek(raw_offset)
            system_stream.write(replacement)
            super_stream.seek(super_offset)
            super_stream.write(replacement)
            records.append(
                {
                    "name": patch["name"],
                    "file_offset": patch["file_offset"],
                    "length": len(expected),
                    "system_offset": raw_offset,
                    "super_offset": super_offset,
                    "source_sha256": sha256_bytes(expected),
                    "replacement_sha256": sha256_bytes(replacement),
                    "changed_bytes": sum(a != b for a, b in zip(expected, replacement)),
                }
            )
    return records


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
    system = output_dir / "system-api32-diagnostic-adb-NOT-FLASHED.ext4"
    super_image = output_dir / "super-api32-diagnostic-adb-NOT-FLASHED.img"
    manifest = output_dir / "build-report.json"
    if manifest.exists():
        raise FileExistsError(manifest)

    validate_source(SOURCE_SYSTEM, SOURCE_SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)
    validate_source(SOURCE_SUPER, SOURCE_SUPER_SIZE, SOURCE_SUPER_SHA256)
    source_rc = read_init_usb_rc(SOURCE_SYSTEM)
    expected_rc = patched_init_usb_rc(source_rc)
    source_inode = read_inode_state(SOURCE_SYSTEM)
    if source_inode["blocks"] != list(INIT_USB_RC_PHYSICAL_BLOCKS):
        raise ValueError(f"unexpected init.usb.rc block map: {source_inode['blocks']}")
    if sha256_file(SOURCE_SUPER, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != SOURCE_SYSTEM_SHA256:
        raise ValueError("source super does not contain the frozen API32 system")

    clone_copy(SOURCE_SYSTEM, system)
    clone_copy(SOURCE_SUPER, super_image)
    records = apply_raw_patches(system, super_image)

    if read_init_usb_rc(system) != expected_rc:
        raise ValueError("patched init.usb.rc semantic readback changed")
    if read_inode_state(system) != source_inode:
        raise ValueError("init.usb.rc inode metadata or block map changed")
    e2fsck = run_e2fsck(system)
    output_system_sha256 = sha256_file(system)
    output_super_sha256 = sha256_file(super_image)
    if sha256_file(super_image, SYSTEM_OFFSET_IN_SUPER, SOURCE_SYSTEM_SIZE) != output_system_sha256:
        raise ValueError("diagnostic super does not contain the diagnostic system")
    if EXPECTED_OUTPUT_SYSTEM_SHA256 is not None and output_system_sha256 != EXPECTED_OUTPUT_SYSTEM_SHA256:
        raise ValueError(f"unexpected output system SHA-256: {output_system_sha256}")
    if EXPECTED_OUTPUT_SUPER_SHA256 is not None and output_super_sha256 != EXPECTED_OUTPUT_SUPER_SHA256:
        raise ValueError(f"unexpected output super SHA-256: {output_super_sha256}")

    report = {
        "schema": "dby-w09-api32-diagnostic-adb-build-v1",
        "candidate_status": "offline-built-not-flashed",
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
        "init_usb_rc": {
            "path": INIT_USB_RC_PATH,
            "source_sha256": INIT_USB_RC_SHA256,
            "output_sha256": sha256_bytes(expected_rc),
            "size": len(expected_rc),
            "inode_state": source_inode,
        },
        "patches": records,
        "e2fsck": e2fsck,
        "boundary": (
            "diagnostic only: two same-length init.usb.rc spans; existing API32 "
            "VINTF, SELinux, NFC, logical-partition and control-partition state unchanged"
        ),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = build(args.output_dir)
    except (FileExistsError, FileNotFoundError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
