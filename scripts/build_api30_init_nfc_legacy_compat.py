#!/usr/bin/env python3
"""Build the API30 init-only NFC legacy mkdir compatibility candidate.

The input is the v2 system image where the duplicate system-side
``mkdir /data/nfc ... encryption=Require`` action is already disabled.  This
stage changes the exact inlined ``FscryptInferAction`` exclusion-list entry
``gsi`` to ``nfc`` inside ``/system/bin/init``.  The GSI directory keeps its
explicit ``encryption=None`` action, while Huawei's legacy plain
``mkdir /data/nfc`` stops inferring a fatal Require policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "analysis/firmware-20261014"
SOURCE_DIR = BASE / "api30-nfc-mkdir-skip-offline-20261026/build-a"
SOURCE_SYSTEM = SOURCE_DIR / "system-api30-nfc-mkdir-skip-NOT-FLASHED.ext4"
SOURCE_SUPER = SOURCE_DIR / "super-api30-nfc-mkdir-skip-NOT-FLASHED.img"
SOURCE_SYSTEM_SHA256 = "65070d2b8f71cc9bebd8d24df62bec3cf578e60e3586235bea40b7cd7a430e14"
SOURCE_SUPER_SHA256 = "aefb9e9a06301537bfd385160e1d7c4e45a00364bc677cf0c357ec5a819d7fec"
SYSTEM_SIZE = 2_513_813_504
SUPER_SIZE = 7_692_353_536

INIT_PATH = "/system/bin/init"
INIT_SHA256 = "04bd2fd33fa29f06a7912086873231b29e9db900d73ea421f5bd6c7bc278b367"
EXPECTED_OUTPUT_INIT_SHA256 = "349f2f8dc2e51d6e4d02b183a9c2e236314f32a679a61298bfeac0426d02ec4a"
EXPECTED_OUTPUT_SYSTEM_SHA256 = "c411632f32664678005296281f78ccf3978f24363b247968de6e67e24cc094f5"
EXPECTED_OUTPUT_SUPER_SHA256 = "23b9dfa572241cf6ca3ccf7025f163db5de918cd8dc13ee73a80486eb5b06598"
INIT_FILE_OFFSET = 0x495AC
INIT_FILE_BLOCK = 73
INIT_OFFSET_IN_BLOCK = 0x5AC
INIT_PHYSICAL_BLOCK = 81_664
FILESYSTEM_BLOCK_SIZE = 4096
SYSTEM_OFFSET_IN_SUPER = 2_097_152
PATCH_OFFSET_IN_SYSTEM = INIT_PHYSICAL_BLOCK * FILESYSTEM_BLOCK_SIZE + INIT_OFFSET_IN_BLOCK
PATCH_OFFSET_IN_SUPER = SYSTEM_OFFSET_IN_SUPER + PATCH_OFFSET_IN_SYSTEM

# mov w4, #0x69 ; mov w14, #0x7367  -> libc++ SSO bytes "gsi"
SOURCE_INSTRUCTIONS = bytes.fromhex("24 0d 80 52 ee 6c 8e 52")
# mov w4, #0x63 ; mov w14, #0x666e  -> libc++ SSO bytes "nfc"
REPLACEMENT_INSTRUCTIONS = bytes.fromhex("64 0c 80 52 ce cd 8c 52")
PATCH_TARGETS = (INIT_PATH,)
CHUNK_SIZE = 8 * 1024 * 1024
DEBUGFS = Path("/opt/homebrew/opt/e2fsprogs/sbin/debugfs")
DEBUGFS_SHA256 = "814284f7a5147a0286983fbc1dd64f3969826e5501b03f3fc05225f45287f2c9"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, offset: int = 0, length: int | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = length
        while remaining is None or remaining:
            wanted = CHUNK_SIZE if remaining is None else min(CHUNK_SIZE, remaining)
            chunk = stream.read(wanted)
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
        if remaining not in (None, 0):
            raise ValueError(f"short read from {path}: {remaining} bytes missing")
    return digest.hexdigest()


def _mov_wide_immediate(instruction: bytes, expected_register: int) -> int:
    if len(instruction) != 4:
        raise ValueError("AArch64 instruction must be four bytes")
    word = int.from_bytes(instruction, "little")
    if word & 0x7F800000 != 0x52800000:
        raise ValueError("instruction is not a 32-bit MOVZ immediate")
    if word & 0x1F != expected_register:
        raise ValueError("unexpected MOVZ destination register")
    if (word >> 21) & 0x3:
        raise ValueError("shifted MOVZ is not supported by this patch")
    return (word >> 5) & 0xFFFF


def decode_excluded_name(window: bytes) -> str:
    if len(window) != 8:
        raise ValueError("instruction window must be eight bytes")
    final_character = _mov_wide_immediate(window[:4], 4)
    first_pair = _mov_wide_immediate(window[4:], 14)
    raw = bytes((first_pair & 0xFF, first_pair >> 8, final_character))
    return raw.decode("ascii")


def patched_init(
    source: bytes,
    *,
    expected_source_sha256: str = INIT_SHA256,
    expected_output_sha256: str | None = None,
    offset: int = INIT_FILE_OFFSET,
) -> bytes:
    if sha256_bytes(source) != expected_source_sha256:
        raise ValueError("source init identity changed")
    if source.count(SOURCE_INSTRUCTIONS) != 1:
        raise ValueError("source instruction window must occur exactly once")
    if source.find(SOURCE_INSTRUCTIONS) != offset:
        raise ValueError("source instruction window offset changed")
    output = source[:offset] + REPLACEMENT_INSTRUCTIONS + source[offset + 8 :]
    if len(output) != len(source):
        raise AssertionError("instruction patch changed init size")
    if expected_output_sha256 is not None and sha256_bytes(output) != expected_output_sha256:
        raise ValueError("patched init identity changed")
    return output


def clone_copy(source: Path, output: Path) -> None:
    completed = subprocess.run(
        ["cp", "-c", str(source), str(output)],
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"APFS clone copy failed: {completed.stderr.strip()}")


def patch_clone(source: Path, output: Path, offset: int) -> None:
    if source.resolve() == output.resolve():
        raise ValueError("source and output alias")
    if output.exists():
        raise FileExistsError(output)
    partial = output.with_name(f".{output.name}.partial-{uuid.uuid4().hex}")
    clone_copy(source, partial)
    with partial.open("r+b", buffering=0) as stream:
        stream.seek(offset)
        if stream.read(len(SOURCE_INSTRUCTIONS)) != SOURCE_INSTRUCTIONS:
            raise ValueError("source patch span changed")
        stream.seek(offset)
        stream.write(REPLACEMENT_INSTRUCTIONS)
        stream.flush()
        os.fsync(stream.fileno())
    if output.exists():
        raise FileExistsError(f"output appeared during build: {output}")
    os.replace(partial, output)


def debugfs(command: str, image: Path) -> bytes:
    if sha256_file(DEBUGFS) != DEBUGFS_SHA256:
        raise ValueError("pinned debugfs identity changed")
    completed = subprocess.run(
        [str(DEBUGFS), "-R", command, str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    diagnostics = completed.stderr.decode(errors="replace")
    if completed.returncode != 0 or "debugfs 1.47.4" not in diagnostics:
        raise RuntimeError(f"debugfs failed: {command}: {diagnostics}")
    return completed.stdout


def validate_source(path: Path, expected_size: int, expected_sha256: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size != expected_size:
        raise ValueError(f"unexpected source size: {path}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ValueError(f"unexpected source SHA-256: {path}: {actual}")


def write_manifest(path: Path, report: dict[str, object]) -> None:
    if path.exists():
        raise FileExistsError(path)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def build_system(source: Path, output: Path, manifest: Path) -> dict[str, object]:
    source = source.resolve()
    output = output.resolve()
    manifest = manifest.resolve()
    if source == output:
        raise ValueError("source and output alias")
    if output.exists() or manifest.exists():
        raise FileExistsError("refusing to overwrite candidate output")
    validate_source(source, SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)

    source_init = debugfs(f"cat {INIT_PATH}", source)
    candidate_init = patched_init(source_init)
    if debugfs(f"bmap {INIT_PATH} {INIT_FILE_BLOCK}", source).strip() != str(
        INIT_PHYSICAL_BLOCK
    ).encode():
        raise ValueError("init physical block mapping changed")
    with source.open("rb") as stream:
        stream.seek(PATCH_OFFSET_IN_SYSTEM)
        if stream.read(8) != SOURCE_INSTRUCTIONS:
            raise ValueError("bound ext4 patch offset changed")

    patch_clone(source, output, PATCH_OFFSET_IN_SYSTEM)
    audit = exact_patch_audit(source, output, PATCH_OFFSET_IN_SYSTEM)
    output_init = debugfs(f"cat {INIT_PATH}", output)
    if output_init != candidate_init:
        raise ValueError("patched init semantic readback changed")
    output_init_sha256 = sha256_bytes(output_init)
    if output_init_sha256 != EXPECTED_OUTPUT_INIT_SHA256:
        raise ValueError("patched init frozen identity changed")
    for command in (f"stat {INIT_PATH}", f"ea_list {INIT_PATH}", f"blocks {INIT_PATH}"):
        if debugfs(command, source) != debugfs(command, output):
            raise ValueError(f"init metadata changed: {command}")

    output_system_sha256 = sha256_file(output)
    if output_system_sha256 != EXPECTED_OUTPUT_SYSTEM_SHA256:
        raise ValueError("candidate system frozen identity changed")
    report = {
        "schema": "dby-w09-api30-init-nfc-legacy-compat-v4",
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
            "sha256": output_system_sha256,
        },
        "init": {
            "path": INIT_PATH,
            "inode": 389,
            "file_offset": INIT_FILE_OFFSET,
            "file_block": INIT_FILE_BLOCK,
            "physical_block": INIT_PHYSICAL_BLOCK,
            "source_sha256": INIT_SHA256,
            "output_sha256": output_init_sha256,
            "metadata_unchanged": True,
            "xattrs_unchanged": True,
        },
        "patch": audit,
        "semantic_delta": {
            "inferred_exclusion_before": "gsi",
            "inferred_exclusion_after": "nfc",
            "gsi_actual_action_preserved_by": "/system/etc/init/gsid.rc encryption=None",
            "explicit_encryption_actions_changed": False,
            "vendor_partition_changed": False,
        },
    }
    write_manifest(manifest, report)
    return report


def build_super(
    source_super: Path,
    source_system: Path,
    candidate_system: Path,
    output: Path,
    manifest: Path,
) -> dict[str, object]:
    source_super = source_super.resolve()
    source_system = source_system.resolve()
    candidate_system = candidate_system.resolve()
    output = output.resolve()
    manifest = manifest.resolve()
    if source_super == output:
        raise ValueError("source and output alias")
    if output.exists() or manifest.exists():
        raise FileExistsError("refusing to overwrite candidate output")
    validate_source(source_super, SUPER_SIZE, SOURCE_SUPER_SHA256)
    validate_source(source_system, SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)
    if candidate_system.stat().st_size != SYSTEM_SIZE:
        raise ValueError("unexpected candidate system size")
    system_audit = exact_patch_audit(source_system, candidate_system, PATCH_OFFSET_IN_SYSTEM)
    candidate_system_sha256 = sha256_file(candidate_system)
    if sha256_file(source_super, SYSTEM_OFFSET_IN_SUPER, SYSTEM_SIZE) != SOURCE_SYSTEM_SHA256:
        raise ValueError("source super does not embed the bound v2 system")

    patch_clone(source_super, output, PATCH_OFFSET_IN_SUPER)
    audit = exact_patch_audit(source_super, output, PATCH_OFFSET_IN_SUPER)
    if sha256_file(output, SYSTEM_OFFSET_IN_SUPER, SYSTEM_SIZE) != candidate_system_sha256:
        raise ValueError("candidate super does not embed the candidate system")

    output_super_sha256 = sha256_file(output)
    if output_super_sha256 != EXPECTED_OUTPUT_SUPER_SHA256:
        raise ValueError("candidate super frozen identity changed")
    report = {
        "schema": "dby-w09-api30-init-nfc-legacy-compat-v4",
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
        "candidate_system": {
            "path": str(candidate_system),
            "size": SYSTEM_SIZE,
            "sha256": candidate_system_sha256,
            "patch": system_audit,
        },
        "output_super": {
            "path": str(output),
            "size": SUPER_SIZE,
            "sha256": output_super_sha256,
        },
        "system_offset": SYSTEM_OFFSET_IN_SUPER,
        "patch": audit,
        "vendor_partition_changed": False,
    }
    write_manifest(manifest, report)
    return report


def build_candidate(output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    system = output_dir / "system-api30-init-nfc-legacy-compat-NOT-FLASHED.ext4"
    super_image = output_dir / "super-api30-init-nfc-legacy-compat-NOT-FLASHED.img"
    system_manifest = output_dir / "system.manifest.json"
    super_manifest = output_dir / "super.manifest.json"
    system_report = build_system(SOURCE_SYSTEM, system, system_manifest)
    super_report = build_super(
        SOURCE_SUPER,
        SOURCE_SYSTEM,
        system,
        super_image,
        super_manifest,
    )
    return {"system": system_report, "super": super_report}


def exact_patch_audit(source: Path, output: Path, offset: int) -> dict[str, object]:
    if source.stat().st_size != output.stat().st_size:
        raise ValueError("patch changed file size")
    size = source.stat().st_size
    with source.open("rb") as old, output.open("rb") as new:
        old.seek(offset)
        new.seek(offset)
        if old.read(8) != SOURCE_INSTRUCTIONS:
            raise ValueError("source patch span changed")
        if new.read(8) != REPLACEMENT_INSTRUCTIONS:
            raise ValueError("replacement patch span changed")
    prefix_source = sha256_file(source, 0, offset)
    prefix_output = sha256_file(output, 0, offset)
    suffix_offset = offset + len(SOURCE_INSTRUCTIONS)
    suffix_length = size - suffix_offset
    suffix_source = sha256_file(source, suffix_offset, suffix_length)
    suffix_output = sha256_file(output, suffix_offset, suffix_length)
    if prefix_source != prefix_output or suffix_source != suffix_output:
        raise ValueError("bytes changed outside the exact patch span")
    expected_changed = [
        offset + index
        for index, pair in enumerate(zip(SOURCE_INSTRUCTIONS, REPLACEMENT_INSTRUCTIONS))
        if pair[0] != pair[1]
    ]
    return {
        "offset": offset,
        "length": len(SOURCE_INSTRUCTIONS),
        "changed_bytes": len(expected_changed),
        "changed_positions": expected_changed,
        "outside_span_byte_identical": True,
        "prefix_sha256": prefix_output,
        "suffix_sha256": suffix_output,
        "source_name": decode_excluded_name(SOURCE_INSTRUCTIONS),
        "replacement_name": decode_excluded_name(REPLACEMENT_INSTRUCTIONS),
        "size": size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build_candidate(args.output_dir), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
