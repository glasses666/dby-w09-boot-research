#!/usr/bin/env python3
"""Build the API29 /data/adb fscrypt repair with one same-length byte patch.

The source is the fully qualified API29 context-closed candidate.  The repair
replaces exactly one 34-byte init language statement with a 34-byte comment.
Because the replacement is the same length, ext4 metadata is left untouched.
The super builder clones the qualified super and applies the corresponding
bytes inside the fixed system extent, so it does not materialize another full
7.2 GiB copy on APFS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "analysis/firmware-20261014/api29-aosp-baseline-offline-20261025"
SOURCE_SYSTEM = BASE / "candidates/build-a/system-api29-context-closed-NOT-FLASHED.ext4"
SOURCE_SUPER = BASE / "candidates/build-a/super-api29-context-closed-NOT-FLASHED.img"

SYSTEM_SIZE = 1_474_760_704
SUPER_SIZE = 7_692_353_536
SYSTEM_OFFSET_IN_SUPER = 2_097_152
SOURCE_SYSTEM_SHA256 = "4362ba036b8923a8697f817efbf5f8974b859a974f87566a39c4f85bf51a945b"
SOURCE_SUPER_SHA256 = "9a4cce9db1bf49a95dfbd9969c2e7be2481c9295b1709d0549b2d65f836cc353"
OUTPUT_SYSTEM_SHA256 = "a5c6c8b481ab494ec7aac0751063c1012ba73a2e16ca611fe3d7bbe823a4515f"
OUTPUT_SUPER_SHA256 = "55b043413e9865ed55cb7e6eb1ff152f98ab8ddb9343df0bec1d10e5d7383281"

DEBUGFS = Path("/opt/homebrew/opt/e2fsprogs/sbin/debugfs")
DEBUGFS_SHA256 = "814284f7a5147a0286983fbc1dd64f3969826e5501b03f3fc05225f45287f2c9"
INIT_USB_RC = "/init.usb.rc"
INIT_USB_RC_SHA256 = "4dde3aa1f087c79abdc960af50897a60ae794e742c6f1086e1c7a3d252eee2c6"
REPAIRED_INIT_USB_RC_SHA256 = "a670f51c880789cf415c126289b4b274c5abb1eee19c25ce970ce6476723cda7"
FILESYSTEM_BLOCK_SIZE = 4096
INIT_USB_RC_BLOCKS = (146, 147)
LINE_OFFSET_IN_FILE = 455
SOURCE_LINE = b"    mkdir /data/adb 0700 root root"
REPLACEMENT_LINE = b"    # /data/adb exists; skip mkdir"
PATCH_OFFSET_IN_SYSTEM = INIT_USB_RC_BLOCKS[0] * FILESYSTEM_BLOCK_SIZE + LINE_OFFSET_IN_FILE
PATCH_OFFSET_IN_SUPER = SYSTEM_OFFSET_IN_SUPER + PATCH_OFFSET_IN_SYSTEM
CHUNK_SIZE = 8 * 1024 * 1024


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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clone_copy(source: Path, destination: Path) -> None:
    subprocess.run(
        ["/bin/cp", "-c", str(source), str(destination)],
        check=True,
        stdin=subprocess.DEVNULL,
    )


def debugfs(command: str, image: Path) -> bytes:
    completed = subprocess.run(
        [str(DEBUGFS), "-R", command, str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    diagnostics = completed.stderr.decode(errors="replace")
    if completed.returncode != 0 or "debugfs 1.47.4" not in diagnostics:
        raise RuntimeError(f"debugfs failed: {command}: {diagnostics}")
    return completed.stdout


def read_init_usb_rc(image: Path) -> bytes:
    return debugfs(f"cat {INIT_USB_RC}", image)


def read_init_usb_rc_blocks(image: Path) -> tuple[int, ...]:
    output = debugfs(f"blocks {INIT_USB_RC}", image).decode()
    blocks = tuple(int(item) for item in re.findall(r"\d+", output))
    if blocks != INIT_USB_RC_BLOCKS:
        raise ValueError(f"unexpected {INIT_USB_RC} block map: {blocks}")
    return blocks


def repaired_rc(source: bytes) -> bytes:
    if sha256_bytes(source) != INIT_USB_RC_SHA256:
        raise ValueError("source init.usb.rc identity changed")
    if len(SOURCE_LINE) != len(REPLACEMENT_LINE):
        raise AssertionError("repair must remain same-length")
    if source.count(SOURCE_LINE) != 1:
        raise ValueError("source mkdir action must occur exactly once")
    if source.find(SOURCE_LINE) != LINE_OFFSET_IN_FILE:
        raise ValueError("source mkdir action offset changed")
    output = source.replace(SOURCE_LINE, REPLACEMENT_LINE, 1)
    if len(output) != len(source) or sha256_bytes(output) != REPAIRED_INIT_USB_RC_SHA256:
        raise ValueError("repaired init.usb.rc identity changed")
    return output


def validate_common_source(path: Path, expected_size: int, expected_hash: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size != expected_size:
        raise ValueError(f"unexpected source size: {path}")
    actual = sha256_file(path)
    if actual != expected_hash:
        raise ValueError(f"unexpected source SHA-256: {path}: {actual}")


def validate_output_paths(source: Path, output: Path, manifest: Path | None) -> None:
    if source.resolve() == output.resolve():
        raise ValueError("source and output paths must differ")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    if manifest is not None:
        if manifest.resolve() == output.resolve():
            raise ValueError("manifest and output paths must differ")
        if manifest.exists():
            raise FileExistsError(f"refusing to overwrite {manifest}")


def exact_patch_audit(
    source: Path,
    output: Path,
    offset: int,
    source_bytes: bytes = SOURCE_LINE,
    replacement_bytes: bytes = REPLACEMENT_LINE,
) -> dict[str, object]:
    if source.stat().st_size != output.stat().st_size:
        raise ValueError("patch changed file size")
    with source.open("rb") as old, output.open("rb") as new:
        old.seek(offset)
        new.seek(offset)
        if old.read(len(source_bytes)) != source_bytes:
            raise ValueError("source bytes at patch offset changed")
        if new.read(len(replacement_bytes)) != replacement_bytes:
            raise ValueError("replacement bytes at patch offset changed")
    prefix_source = sha256_file(source, 0, offset)
    prefix_output = sha256_file(output, 0, offset)
    suffix_offset = offset + len(source_bytes)
    suffix_length = source.stat().st_size - suffix_offset
    suffix_source = sha256_file(source, suffix_offset, suffix_length)
    suffix_output = sha256_file(output, suffix_offset, suffix_length)
    if prefix_source != prefix_output or suffix_source != suffix_output:
        raise ValueError("bytes outside the exact patch span changed")
    return {
        "offset": offset,
        "length": len(source_bytes),
        "source_hex": source_bytes.hex(),
        "replacement_hex": replacement_bytes.hex(),
        "prefix_sha256": prefix_output,
        "suffix_sha256": suffix_output,
        "outside_span_byte_identical": True,
    }


def patch_clone(source: Path, output: Path, offset: int) -> None:
    partial = output.with_name(f".{output.name}.partial-{os.getpid()}")
    if partial.exists():
        raise FileExistsError(f"stale partial output exists: {partial}")
    try:
        clone_copy(source, partial)
        with partial.open("r+b", buffering=0) as stream:
            stream.seek(offset)
            if stream.read(len(SOURCE_LINE)) != SOURCE_LINE:
                raise ValueError("source patch span changed")
            stream.seek(offset)
            stream.write(REPLACEMENT_LINE)
            stream.flush()
            os.fsync(stream.fileno())
        if output.exists():
            raise FileExistsError(f"output appeared during build: {output}")
        os.replace(partial, output)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def write_manifest(path: Path | None, report: dict[str, object]) -> None:
    if path is None:
        return
    with path.open("x") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")


def build_system(source: Path, output: Path, manifest: Path | None = None) -> dict[str, object]:
    source = source.resolve()
    output = output.resolve()
    manifest = manifest.resolve() if manifest is not None else None
    validate_output_paths(source, output, manifest)
    validate_common_source(source, SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)
    if sha256_file(DEBUGFS) != DEBUGFS_SHA256:
        raise ValueError("pinned debugfs changed")
    source_rc = read_init_usb_rc(source)
    repaired_rc(source_rc)
    read_init_usb_rc_blocks(source)
    with source.open("rb") as stream:
        stream.seek(PATCH_OFFSET_IN_SYSTEM)
        if stream.read(len(SOURCE_LINE)) != SOURCE_LINE:
            raise ValueError("bound ext4 physical patch offset changed")

    patch_clone(source, output, PATCH_OFFSET_IN_SYSTEM)
    audit = exact_patch_audit(source, output, PATCH_OFFSET_IN_SYSTEM)
    output_hash = sha256_file(output)
    if OUTPUT_SYSTEM_SHA256 and output_hash != OUTPUT_SYSTEM_SHA256:
        raise ValueError(f"unexpected repaired system SHA-256: {output_hash}")
    if read_init_usb_rc(output) != repaired_rc(source_rc):
        raise ValueError("repaired init.usb.rc readback changed")
    if debugfs(f"stat {INIT_USB_RC}", source) != debugfs(f"stat {INIT_USB_RC}", output):
        raise ValueError("init.usb.rc inode metadata changed")
    if debugfs(f"ea_list {INIT_USB_RC}", source) != debugfs(f"ea_list {INIT_USB_RC}", output):
        raise ValueError("init.usb.rc xattrs changed")

    report = {
        "schema": "dby-w09-api29-fscrypt-adb-fix-v1",
        "status": "offline-built-not-flashed",
        "device_io_performed": False,
        "source_system": {
            "path": str(source),
            "size": SYSTEM_SIZE,
            "sha256": SOURCE_SYSTEM_SHA256,
        },
        "output_system": {
            "path": str(output),
            "size": SYSTEM_SIZE,
            "sha256": output_hash,
        },
        "init_usb_rc": {
            "path": INIT_USB_RC,
            "source_sha256": INIT_USB_RC_SHA256,
            "output_sha256": REPAIRED_INIT_USB_RC_SHA256,
            "blocks": list(INIT_USB_RC_BLOCKS),
            "line_offset": LINE_OFFSET_IN_FILE,
            "inode_metadata_unchanged": True,
            "xattrs_unchanged": True,
        },
        "patch": audit,
        "boundary": "only the exact same-length init.usb.rc action span changed",
    }
    write_manifest(manifest, report)
    return report


def build_super(
    source_super: Path,
    source_system: Path,
    repaired_system: Path,
    output: Path,
    manifest: Path | None = None,
) -> dict[str, object]:
    source_super = source_super.resolve()
    source_system = source_system.resolve()
    repaired_system = repaired_system.resolve()
    output = output.resolve()
    manifest = manifest.resolve() if manifest is not None else None
    validate_output_paths(source_super, output, manifest)
    validate_common_source(source_super, SUPER_SIZE, SOURCE_SUPER_SHA256)
    validate_common_source(source_system, SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)
    repaired_hash = sha256_file(repaired_system)
    if repaired_system.stat().st_size != SYSTEM_SIZE:
        raise ValueError("unexpected repaired system size")
    if OUTPUT_SYSTEM_SHA256 and repaired_hash != OUTPUT_SYSTEM_SHA256:
        raise ValueError(f"unexpected repaired system SHA-256: {repaired_hash}")
    if sha256_file(source_super, SYSTEM_OFFSET_IN_SUPER, SYSTEM_SIZE) != SOURCE_SYSTEM_SHA256:
        raise ValueError("source super does not embed the bound source system")
    exact_patch_audit(source_system, repaired_system, PATCH_OFFSET_IN_SYSTEM)

    patch_clone(source_super, output, PATCH_OFFSET_IN_SUPER)
    audit = exact_patch_audit(source_super, output, PATCH_OFFSET_IN_SUPER)
    output_hash = sha256_file(output)
    if OUTPUT_SUPER_SHA256 and output_hash != OUTPUT_SUPER_SHA256:
        raise ValueError(f"unexpected repaired super SHA-256: {output_hash}")
    if sha256_file(output, SYSTEM_OFFSET_IN_SUPER, SYSTEM_SIZE) != repaired_hash:
        raise ValueError("repaired super does not embed the repaired system")

    report = {
        "schema": "dby-w09-api29-fscrypt-adb-fix-v1",
        "status": "offline-built-not-flashed",
        "device_io_performed": False,
        "source_super": {
            "path": str(source_super),
            "size": SUPER_SIZE,
            "sha256": SOURCE_SUPER_SHA256,
        },
        "source_system": {
            "path": str(source_system),
            "size": SYSTEM_SIZE,
            "sha256": SOURCE_SYSTEM_SHA256,
        },
        "repaired_system": {
            "path": str(repaired_system),
            "size": SYSTEM_SIZE,
            "sha256": repaired_hash,
        },
        "output_super": {
            "path": str(output),
            "size": SUPER_SIZE,
            "sha256": output_hash,
        },
        "system_offset": SYSTEM_OFFSET_IN_SUPER,
        "patch": audit,
        "boundary": "only the exact same-length init.usb.rc action span changed inside system",
    }
    write_manifest(manifest, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    system_parser = subparsers.add_parser("system")
    system_parser.add_argument("source_system", type=Path)
    system_parser.add_argument("output_system", type=Path)
    system_parser.add_argument("--manifest", type=Path)
    super_parser = subparsers.add_parser("super")
    super_parser.add_argument("source_super", type=Path)
    super_parser.add_argument("source_system", type=Path)
    super_parser.add_argument("repaired_system", type=Path)
    super_parser.add_argument("output_super", type=Path)
    super_parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    if args.command == "system":
        report = build_system(args.source_system, args.output_system, args.manifest)
    else:
        report = build_super(
            args.source_super,
            args.source_system,
            args.repaired_system,
            args.output_super,
            args.manifest,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
