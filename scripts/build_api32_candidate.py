#!/usr/bin/env python3
"""Build the minimal DBY-W09 Android 12L/API32 system and super candidate.

The builder is intentionally fixed to the audited Google API32 system image and
the recorded DBY-W09 logical-partition geometry.  It performs no device I/O.
Only these semantic changes are allowed:

* omit framework compatibility matrix level 3;
* add the 119 frozen Huawei 29.0 mapping bindings;
* retain API32 ``perfmon`` while adding the legacy kernel ``perf_event`` name;
* disable the duplicate explicit system-side NFC policy action; and
* change the one audited init inferred-policy exclusion from ``gsi`` to ``nfc``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FW = ROOT / "analysis/firmware-20261014"
BASE = FW / "api32-next-checkpoint-offline-20261027"
SOURCE_SYSTEM = BASE / "inputs/system.img"
STOCK_SUPER = Path(
    os.environ.get(
        "DBY_STOCK_SUPER",
        ROOT / "private-fixtures/MatePad-DBY-W09-stock-super.img",
    )
)
MAPPING_ADDITIONS = (
    FW / "api29-aosp-baseline-offline-20261025/"
    "huawei-29.0.missing-mapping.cil"
)
SEPOLICY_XATTR = (
    FW / "api29-aosp-baseline-offline-20261025/sepolicy_file.plat.attr"
)

SOURCE_SYSTEM_SIZE = 1_774_059_520
SOURCE_SYSTEM_SHA256 = "0d0e5645410978185e5a22e57b476d518ecbd4551fbf0a4c8db5710653dd7a1f"
SOURCE_FILESYSTEM_SIZE = 1_745_985_536
EXPANSION_CONTAINER_SIZE = 2_513_817_600
OUTPUT_FILESYSTEM_SIZE = 2_513_813_504
SUPER_SIZE = 7_692_353_536
STOCK_SUPER_SHA256 = "525336b48db57a3561613df103ba685a7caa83667079a30cae30f4bdf67abdfc"
SYSTEM_OFFSET_IN_SUPER = 2_097_152
SYSTEM_EXTENT_SIZE = 3_581_935_616

# Frozen from the independent discovery build before the two retained
# reproducibility builds.
EXPECTED_OUTPUT_SYSTEM_SHA256: str | None = (
    "13af7063948eaf1e9da88051b80c352073cd2bf839f2c9f1d2ea4462d26e6d4b"
)
EXPECTED_OUTPUT_SUPER_SHA256: str | None = (
    "2d43e81baa366eb77fe00a34128f04d4489538e6f0df5100fa180e63320ebd82"
)

DEBUGFS = Path("/opt/homebrew/opt/e2fsprogs/sbin/debugfs")
E2FSCK = Path("/opt/homebrew/opt/e2fsprogs/sbin/e2fsck")
RESIZE2FS = Path("/opt/homebrew/opt/e2fsprogs/sbin/resize2fs")
TOOL_HASHES = {
    DEBUGFS: "814284f7a5147a0286983fbc1dd64f3969826e5501b03f3fc05225f45287f2c9",
    E2FSCK: "a14c5f8efe8ccf099e6048efbd5f8aabf3938676b55457e4462b3a6e7461bf9e",
    RESIZE2FS: "cef02ad9d80bd24fc674cd5662fabf5e93fa2de5a43167121c53e72282cb21a2",
}

PLATFORM_PATH = "/system/etc/selinux/plat_sepolicy.cil"
MAPPING_PATH = "/system/etc/selinux/mapping/29.0.cil"
COMPAT_PATH = "/system/etc/selinux/mapping/29.0.compat.cil"
MATRIX3_PATH = "/system/etc/vintf/compatibility_matrix.3.xml"
INIT_PATH = "/system/bin/init"
INIT_RC_PATH = "/system/etc/init/hw/init.rc"

PLATFORM_SOURCE_SHA256 = "89b2cbca695871b5cf5d8178a24a6317f46f71cd05058f1d5b0de54629271796"
PLATFORM_OUTPUT_SHA256 = "f4919f5562c2b9dcddd9f17640c4c634a51eba6e14e6e9a6fa87f414f8114088"
MAPPING_SOURCE_SHA256 = "3b4028fcd6fe8dc2e69d0d374b1f336f409a60c7644f2b880576069c431cf540"
MAPPING_OUTPUT_SHA256 = "e09a168b8bfd103a6d584f2600fe686261e73fccb13c13198c5cbf6f0115cc9f"
COMPAT_SHA256 = "a719324d4059bcff49ea4df6ae74a8f69fb9f5907781a85ecaeb4b78c88626dc"
MAPPING_ADDITIONS_SHA256 = "54e7c7dea7db54beec9aad440c656dc782c634a2e1c0b8955c46a49e1ebf7c59"
SEPOLICY_XATTR_SHA256 = "0a15066502d71be3485a0ee0f0a70499c0018efa416bd1058a7cc5b530281530"

INIT_SHA256 = "c6fc7df5bab67434cbba100601290238e51a5c938da9d098d3c9551328ade474"
INIT_OUTPUT_SHA256 = "9d3ae511ef7abc42eabcf4446ba46c0ea3449f11c1061f1987ad3a382d58a525"
INIT_FILE_OFFSET = 0xBA510
INIT_FILE_BLOCK = 186
INIT_PHYSICAL_BLOCK = 52_889
INIT_OFFSET_IN_BLOCK = 0x510
INIT_SOURCE_INSTRUCTIONS = bytes.fromhex("24 0d 80 52 ee 6c 8e 52")
INIT_REPLACEMENT_INSTRUCTIONS = bytes.fromhex("64 0c 80 52 ce cd 8c 52")

INIT_RC_SHA256 = "0067ebdf12497f330406d0a014414901eb6ae49d19be06e3bc211dc906d7e899"
INIT_RC_OUTPUT_SHA256 = "9848d92af8e3284bc4f951c0796d86e8c0574fd937ef0906a2e453216fdbcb2b"
NFC_FILE_OFFSET = 0x8EF8
NFC_FILE_BLOCK = 8
NFC_PHYSICAL_BLOCK = 61_803
NFC_OFFSET_IN_BLOCK = 0xEF8
NFC_SOURCE_LINE = b"    mkdir /data/nfc 0770 nfc nfc encryption=Require"
NFC_REPLACEMENT_LINE = b"    # /data/nfc exists; skip mkdir policy collision"

FILESYSTEM_BLOCK_SIZE = 4096
INIT_PATCH_OFFSET_IN_SYSTEM = (
    INIT_PHYSICAL_BLOCK * FILESYSTEM_BLOCK_SIZE + INIT_OFFSET_IN_BLOCK
)
NFC_PATCH_OFFSET_IN_SYSTEM = (
    NFC_PHYSICAL_BLOCK * FILESYSTEM_BLOCK_SIZE + NFC_OFFSET_IN_BLOCK
)
INIT_PATCH_OFFSET_IN_SUPER = SYSTEM_OFFSET_IN_SUPER + INIT_PATCH_OFFSET_IN_SYSTEM
NFC_PATCH_OFFSET_IN_SUPER = SYSTEM_OFFSET_IN_SUPER + NFC_PATCH_OFFSET_IN_SYSTEM
NORMALIZATION_EPOCH = 1_230_768_000
CHUNK_SIZE = 8 * 1024 * 1024
PERFMON_TOKEN = "audit_read perfmon"
PERFMON_REPLACEMENT = "audit_read perf_event perfmon"
PERFMON_OCCURRENCES = 15
MAPPING_LINE = re.compile(
    r"^\(typeattributeset ([A-Za-z0-9_]+)_29_0 \(([A-Za-z0-9_]+)\)\)$"
)


def sha256_bytes(data: bytes) -> str:
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


def clone_copy(source: Path, destination: Path) -> None:
    subprocess.run(
        ["/bin/cp", "-c", str(source), str(destination)],
        check=True,
        stdin=subprocess.DEVNULL,
    )


def validate_file(path: Path, expected_size: int, expected_hash: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size != expected_size:
        raise ValueError(f"unexpected size for {path}: {path.stat().st_size}")
    actual = sha256_file(path)
    if actual != expected_hash:
        raise ValueError(f"unexpected SHA-256 for {path}: {actual}")


def validate_tools() -> dict[str, str]:
    result = {}
    for path, expected in TOOL_HASHES.items():
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"pinned tool changed: {path}: {actual}")
        result[str(path)] = actual
    return result


def debugfs(command: str, image: Path) -> bytes:
    completed = subprocess.run(
        [str(DEBUGFS), "-R", command, str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    diagnostics = completed.stderr.decode(errors="replace")
    if completed.returncode != 0 or "debugfs 1.47.4" not in diagnostics:
        raise RuntimeError(f"debugfs failed: {command}: {diagnostics}")
    return completed.stdout


def parse_debugfs_path_state(stdout: bytes, stderr: bytes) -> bool:
    combined = stdout.decode(errors="replace") + stderr.decode(errors="replace")
    if "File not found by ext2_lookup" in combined:
        return False
    if "Inode:" in combined:
        return True
    raise ValueError(f"ambiguous debugfs path state: {combined}")


def path_exists(image: Path, path: str) -> bool:
    completed = subprocess.run(
        [str(DEBUGFS), "-R", f"stat {path}", str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    diagnostics = completed.stderr.decode(errors="replace")
    if completed.returncode != 0 or "debugfs 1.47.4" not in diagnostics:
        raise RuntimeError(f"debugfs stat failed: {path}: {diagnostics}")
    return parse_debugfs_path_state(completed.stdout, completed.stderr)


def patch_unique_bytes(
    source: bytes,
    *,
    source_bytes: bytes,
    replacement_bytes: bytes,
    expected_offset: int,
    expected_source_sha256: str,
) -> bytes:
    if sha256_bytes(source) != expected_source_sha256:
        raise ValueError("source identity changed")
    if len(source_bytes) != len(replacement_bytes):
        raise ValueError("replacement must be same-length")
    if source.count(source_bytes) != 1:
        raise ValueError("source span must occur exactly once")
    if source.find(source_bytes) != expected_offset:
        raise ValueError("source span offset changed")
    output = source[:expected_offset] + replacement_bytes + source[expected_offset + len(source_bytes):]
    if len(output) != len(source):
        raise AssertionError("same-length patch changed file size")
    return output


def _mov_wide_immediate(instruction: bytes, expected_register: int) -> int:
    if len(instruction) != 4:
        raise ValueError("AArch64 instruction must be four bytes")
    word = int.from_bytes(instruction, "little")
    if word & 0x7F800000 != 0x52800000:
        raise ValueError("instruction is not a 32-bit MOVZ immediate")
    if word & 0x1F != expected_register:
        raise ValueError("unexpected MOVZ destination register")
    if (word >> 21) & 0x3:
        raise ValueError("shifted MOVZ is not supported")
    return (word >> 5) & 0xFFFF


def decode_excluded_name(window: bytes) -> str:
    if len(window) != 8:
        raise ValueError("instruction window must be eight bytes")
    final_character = _mov_wide_immediate(window[:4], 4)
    first_pair = _mov_wide_immediate(window[4:], 14)
    return bytes((first_pair & 0xFF, first_pair >> 8, final_character)).decode("ascii")


def patch_perf_event(source: str, *, expected_count: int = PERFMON_OCCURRENCES) -> tuple[str, int]:
    if PERFMON_REPLACEMENT in source:
        raise ValueError("platform policy already contains the patched token")
    count = source.count(PERFMON_TOKEN)
    if count != expected_count:
        raise ValueError(f"unexpected {PERFMON_TOKEN!r} occurrence count: {count}")
    return source.replace(PERFMON_TOKEN, PERFMON_REPLACEMENT), count


def merge_huawei_mapping(source: str, additions: str) -> tuple[str, int]:
    existing = {
        match.group(1)
        for line in source.splitlines()
        if (match := MAPPING_LINE.fullmatch(line.strip()))
    }
    seen: set[str] = set()
    for raw_line in additions.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        match = MAPPING_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid Huawei mapping line: {line}")
        attribute_base, concrete_type = match.groups()
        if attribute_base != concrete_type:
            raise ValueError(f"attribute/type mismatch: {line}")
        if attribute_base in existing:
            raise ValueError(f"mapping attribute already exists: {attribute_base}_29_0")
        if attribute_base in seen:
            raise ValueError(f"duplicate Huawei mapping attribute: {attribute_base}_29_0")
        seen.add(attribute_base)
    merged = source.rstrip("\n") + "\n\n" + additions.strip("\n") + "\n"
    return merged, len(seen)


def ext4_contract(image: Path) -> dict[str, object]:
    with image.open("rb") as stream:
        stream.seek(1024)
        data = stream.read(1024)
    if len(data) != 1024 or struct.unpack_from("<H", data, 0x38)[0] != 0xEF53:
        raise ValueError("missing ext4 superblock")
    block_count = struct.unpack_from("<I", data, 0x04)[0]
    block_size = 1024 << struct.unpack_from("<I", data, 0x18)[0]
    compat = struct.unpack_from("<I", data, 0x5C)[0]
    ro_compat = struct.unpack_from("<I", data, 0x64)[0]
    state = struct.unpack_from("<H", data, 0x3A)[0]
    return {
        "block_count": block_count,
        "block_size": block_size,
        "filesystem_size": block_count * block_size,
        "clean": bool(state & 1),
        "has_journal": bool(compat & 0x4),
        "shared_blocks": bool(ro_compat & 0x4000),
        "uuid": data[0x68:0x78].hex(),
    }


def validate_source_geometry(source: Path) -> dict[str, object]:
    contract = ext4_contract(source)
    if contract["filesystem_size"] != SOURCE_FILESYSTEM_SIZE:
        raise ValueError(f"unexpected source ext4 size: {contract}")
    with source.open("rb") as stream:
        stream.seek(-64, os.SEEK_END)
        footer = stream.read(64)
    if footer[:4] != b"AVBf":
        raise ValueError("source AVB footer missing")
    original_image_size = struct.unpack_from(">Q", footer, 12)[0]
    if original_image_size != SOURCE_FILESYSTEM_SIZE:
        raise ValueError("AVB footer original image size changed")
    return {
        **contract,
        "container_size": source.stat().st_size,
        "avb_tail_size": source.stat().st_size - SOURCE_FILESYSTEM_SIZE,
        "avb_footer_magic": footer[:4].decode(),
        "avb_original_image_size": original_image_size,
    }


def validate_source_semantics(source: Path) -> dict[str, object]:
    init = debugfs(f"cat {INIT_PATH}", source)
    init_rc = debugfs(f"cat {INIT_RC_PATH}", source)
    expected_init = patch_unique_bytes(
        init,
        source_bytes=INIT_SOURCE_INSTRUCTIONS,
        replacement_bytes=INIT_REPLACEMENT_INSTRUCTIONS,
        expected_offset=INIT_FILE_OFFSET,
        expected_source_sha256=INIT_SHA256,
    )
    expected_rc = patch_unique_bytes(
        init_rc,
        source_bytes=NFC_SOURCE_LINE,
        replacement_bytes=NFC_REPLACEMENT_LINE,
        expected_offset=NFC_FILE_OFFSET,
        expected_source_sha256=INIT_RC_SHA256,
    )
    if sha256_bytes(expected_init) != INIT_OUTPUT_SHA256:
        raise ValueError("patched init frozen identity changed")
    if sha256_bytes(expected_rc) != INIT_RC_OUTPUT_SHA256:
        raise ValueError("patched init.rc frozen identity changed")
    bmaps = {
        INIT_PATH: int(debugfs(f"bmap {INIT_PATH} {INIT_FILE_BLOCK}", source).strip()),
        INIT_RC_PATH: int(debugfs(f"bmap {INIT_RC_PATH} {NFC_FILE_BLOCK}", source).strip()),
    }
    if bmaps != {INIT_PATH: INIT_PHYSICAL_BLOCK, INIT_RC_PATH: NFC_PHYSICAL_BLOCK}:
        raise ValueError(f"source physical block maps changed: {bmaps}")
    with source.open("rb") as stream:
        stream.seek(INIT_PATCH_OFFSET_IN_SYSTEM)
        init_raw = stream.read(len(INIT_SOURCE_INSTRUCTIONS))
        stream.seek(NFC_PATCH_OFFSET_IN_SYSTEM)
        rc_raw = stream.read(len(NFC_SOURCE_LINE))
    if init_raw != INIT_SOURCE_INSTRUCTIONS or rc_raw != NFC_SOURCE_LINE:
        raise ValueError("raw source patch offsets changed")
    return {
        "init_sha256": sha256_bytes(init),
        "init_rc_sha256": sha256_bytes(init_rc),
        "init_file_offset": INIT_FILE_OFFSET,
        "init_physical_block": INIT_PHYSICAL_BLOCK,
        "nfc_file_offset": NFC_FILE_OFFSET,
        "nfc_physical_block": NFC_PHYSICAL_BLOCK,
    }


def build_policy_inputs(source: Path, directory: Path) -> dict[str, object]:
    platform = debugfs(f"cat {PLATFORM_PATH}", source)
    mapping = debugfs(f"cat {MAPPING_PATH}", source)
    compat = debugfs(f"cat {COMPAT_PATH}", source)
    if sha256_bytes(platform) != PLATFORM_SOURCE_SHA256:
        raise ValueError("API32 platform policy identity changed")
    if sha256_bytes(mapping) != MAPPING_SOURCE_SHA256:
        raise ValueError("API32 mapping policy identity changed")
    if sha256_bytes(compat) != COMPAT_SHA256:
        raise ValueError("API32 compatibility policy identity changed")
    additions = MAPPING_ADDITIONS.read_bytes()
    if sha256_bytes(additions) != MAPPING_ADDITIONS_SHA256:
        raise ValueError("Huawei mapping additions identity changed")

    platform_text, patch_count = patch_perf_event(platform.decode("utf-8"))
    mapping_text, addition_count = merge_huawei_mapping(
        mapping.decode("utf-8"), additions.decode("utf-8")
    )
    platform_out = platform_text.encode("utf-8")
    mapping_out = mapping_text.encode("utf-8")
    if sha256_bytes(platform_out) != PLATFORM_OUTPUT_SHA256:
        raise ValueError("composed platform policy identity changed")
    if sha256_bytes(mapping_out) != MAPPING_OUTPUT_SHA256:
        raise ValueError("composed mapping policy identity changed")
    if addition_count != 119:
        raise ValueError(f"unexpected Huawei mapping count: {addition_count}")
    platform_path = directory / "plat_sepolicy.api32-context-closed.cil"
    mapping_path = directory / "29.0.api32-context-closed.cil"
    platform_path.write_bytes(platform_out)
    mapping_path.write_bytes(mapping_out)
    return {
        "platform_path": platform_path,
        "mapping_path": mapping_path,
        "platform_size": len(platform_out),
        "platform_sha256": sha256_bytes(platform_out),
        "mapping_size": len(mapping_out),
        "mapping_sha256": sha256_bytes(mapping_out),
        "perf_event_patch_count": patch_count,
        "mapping_addition_count": addition_count,
    }


def normalize_ext4_times(image: Path, epoch: int = NORMALIZATION_EPOCH) -> list[int]:
    with image.open("r+b", buffering=0) as stream:
        stream.seek(1024)
        main = stream.read(1024)
        if len(main) != 1024 or struct.unpack_from("<H", main, 0x38)[0] != 0xEF53:
            raise ValueError("missing ext4 main superblock")
        block_size = 1024 << struct.unpack_from("<I", main, 0x18)[0]
        blocks_count = struct.unpack_from("<I", main, 0x04)[0]
        blocks_per_group = struct.unpack_from("<I", main, 0x20)[0]
        uuid = main[0x68:0x78]
        groups = (blocks_count + blocks_per_group - 1) // blocks_per_group
        offsets = [1024]
        for group in range(1, groups):
            offset = group * blocks_per_group * block_size
            stream.seek(offset)
            candidate = stream.read(1024)
            if (
                len(candidate) == 1024
                and struct.unpack_from("<H", candidate, 0x38)[0] == 0xEF53
                and candidate[0x68:0x78] == uuid
            ):
                offsets.append(offset)
        encoded = struct.pack("<I", epoch)
        for offset in offsets:
            for field in (0x30, 0x40):
                stream.seek(offset + field)
                stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return offsets


def grow_and_unshare(image: Path) -> dict[str, object]:
    if image.stat().st_size != SOURCE_FILESYSTEM_SIZE:
        raise ValueError("unexpected compact filesystem size")
    with image.open("r+b") as stream:
        stream.truncate(EXPANSION_CONTAINER_SIZE)
        stream.flush()
        os.fsync(stream.fileno())
    resize = subprocess.run(
        [str(RESIZE2FS), str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=240,
        check=False,
    )
    if resize.returncode != 0:
        raise RuntimeError(f"resize2fs failed: {resize.stdout.decode(errors='replace')}")
    if image.stat().st_size != OUTPUT_FILESYSTEM_SIZE:
        raise ValueError(f"unexpected resized filesystem size: {image.stat().st_size}")
    unshare = subprocess.run(
        [str(E2FSCK), "-fy", "-E", "unshare_blocks", str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=420,
        check=False,
    )
    if unshare.returncode != 0:
        raise RuntimeError(
            f"e2fsck unshare failed: exit={unshare.returncode}: "
            f"{unshare.stdout.decode(errors='replace')}"
        )
    offsets = normalize_ext4_times(image)
    contract = ext4_contract(image)
    if contract["shared_blocks"] or contract["filesystem_size"] != OUTPUT_FILESYSTEM_SIZE:
        raise ValueError(f"invalid expanded ext4 contract: {contract}")
    return {
        "resize2fs_output_sha256": sha256_bytes(resize.stdout),
        "unshare_output_sha256": sha256_bytes(unshare.stdout),
        "normalized_superblock_offsets": offsets,
        "contract": contract,
    }


def _write_raw_patch(image: Path, offset: int, source: bytes, replacement: bytes) -> None:
    with image.open("r+b", buffering=0) as stream:
        stream.seek(offset)
        if stream.read(len(source)) != source:
            raise ValueError(f"raw patch source changed at 0x{offset:x}")
        stream.seek(offset)
        stream.write(replacement)
        stream.flush()
        os.fsync(stream.fileno())


def edit_compact_filesystem(image: Path, policy: dict[str, object], directory: Path) -> str:
    _write_raw_patch(
        image,
        INIT_PATCH_OFFSET_IN_SYSTEM,
        INIT_SOURCE_INSTRUCTIONS,
        INIT_REPLACEMENT_INSTRUCTIONS,
    )
    _write_raw_patch(
        image,
        NFC_PATCH_OFFSET_IN_SYSTEM,
        NFC_SOURCE_LINE,
        NFC_REPLACEMENT_LINE,
    )
    commands = directory / "debugfs-api32-candidate.commands"
    commands.write_text(
        "\n".join(
            (
                f"set_current_time @{NORMALIZATION_EPOCH}",
                f"rm {PLATFORM_PATH}",
                f"write {policy['platform_path']} {PLATFORM_PATH}",
                f"ea_set -f {SEPOLICY_XATTR} {PLATFORM_PATH} security.selinux",
                f"set_inode_field {PLATFORM_PATH} mode 0100644",
                f"set_inode_field {PLATFORM_PATH} uid 0",
                f"set_inode_field {PLATFORM_PATH} gid 0",
                f"set_inode_field {PLATFORM_PATH} atime @{NORMALIZATION_EPOCH}",
                f"set_inode_field {PLATFORM_PATH} mtime @{NORMALIZATION_EPOCH}",
                f"set_inode_field {PLATFORM_PATH} ctime @{NORMALIZATION_EPOCH}",
                f"set_inode_field {PLATFORM_PATH} crtime @{NORMALIZATION_EPOCH}",
                f"rm {MAPPING_PATH}",
                f"write {policy['mapping_path']} {MAPPING_PATH}",
                f"ea_set -f {SEPOLICY_XATTR} {MAPPING_PATH} security.selinux",
                f"set_inode_field {MAPPING_PATH} mode 0100644",
                f"set_inode_field {MAPPING_PATH} uid 0",
                f"set_inode_field {MAPPING_PATH} gid 0",
                f"set_inode_field {MAPPING_PATH} atime @{NORMALIZATION_EPOCH}",
                f"set_inode_field {MAPPING_PATH} mtime @{NORMALIZATION_EPOCH}",
                f"set_inode_field {MAPPING_PATH} ctime @{NORMALIZATION_EPOCH}",
                f"set_inode_field {MAPPING_PATH} crtime @{NORMALIZATION_EPOCH}",
                f"rm {MATRIX3_PATH}",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [str(DEBUGFS), "-w", "-f", str(commands), str(image)],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=240,
        check=False,
    )
    diagnostics = completed.stdout.decode(errors="replace")
    if completed.returncode != 0 or "debugfs 1.47.4" not in diagnostics:
        raise RuntimeError(f"debugfs edit failed: {diagnostics}")
    if path_exists(image, MATRIX3_PATH):
        raise ValueError("compatibility matrix level 3 was not removed")
    return sha256_bytes(completed.stdout)


def validate_candidate_system(image: Path) -> dict[str, object]:
    expected_paths = {
        "/system/etc/vintf/compatibility_matrix.4.xml",
        "/system/etc/vintf/compatibility_matrix.5.xml",
        "/system/etc/vintf/compatibility_matrix.6.xml",
        "/system/etc/vintf/compatibility_matrix.device.xml",
    }
    if path_exists(image, MATRIX3_PATH) or not all(path_exists(image, p) for p in expected_paths):
        raise ValueError("candidate framework matrix set is wrong")
    payloads = {
        PLATFORM_PATH: debugfs(f"cat {PLATFORM_PATH}", image),
        MAPPING_PATH: debugfs(f"cat {MAPPING_PATH}", image),
        COMPAT_PATH: debugfs(f"cat {COMPAT_PATH}", image),
        INIT_PATH: debugfs(f"cat {INIT_PATH}", image),
        INIT_RC_PATH: debugfs(f"cat {INIT_RC_PATH}", image),
    }
    expected_hashes = {
        PLATFORM_PATH: PLATFORM_OUTPUT_SHA256,
        MAPPING_PATH: MAPPING_OUTPUT_SHA256,
        COMPAT_PATH: COMPAT_SHA256,
        INIT_PATH: INIT_OUTPUT_SHA256,
        INIT_RC_PATH: INIT_RC_OUTPUT_SHA256,
    }
    actual_hashes = {path: sha256_bytes(data) for path, data in payloads.items()}
    if actual_hashes != expected_hashes:
        raise ValueError(f"candidate semantic payload identity changed: {actual_hashes}")
    if payloads[INIT_PATH][INIT_FILE_OFFSET:INIT_FILE_OFFSET + 8] != INIT_REPLACEMENT_INSTRUCTIONS:
        raise ValueError("candidate init instruction patch missing")
    if NFC_SOURCE_LINE in payloads[INIT_RC_PATH] or NFC_REPLACEMENT_LINE not in payloads[INIT_RC_PATH]:
        raise ValueError("candidate NFC action patch missing")
    if b"mkdir /data/gsi 0700 root root encryption=None" not in debugfs(
        "cat /system/etc/init/gsid.rc", image
    ):
        raise ValueError("explicit GSI encryption=None action changed")
    for path in (PLATFORM_PATH, MAPPING_PATH):
        stat = debugfs(f"stat {path}", image).decode(errors="replace")
        attrs = debugfs(f"ea_list {path}", image).decode(errors="replace")
        if "User:     0   Group:     0" not in stat or "Mode:  0644" not in stat:
            raise ValueError(f"policy inode metadata changed: {path}")
        if 'u:object_r:sepolicy_file:s0\\000' not in attrs:
            raise ValueError(f"policy SELinux xattr changed: {path}")
    for path, expected in (
        (INIT_PATH, 'u:object_r:init_exec:s0\\000'),
        (INIT_RC_PATH, 'u:object_r:system_file:s0\\000'),
    ):
        attrs = debugfs(f"ea_list {path}", image).decode(errors="replace")
        if expected not in attrs:
            raise ValueError(f"runtime file SELinux xattr changed: {path}")
    fsck = subprocess.run(
        [str(E2FSCK), "-fn", str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=240,
        check=False,
    )
    if fsck.returncode != 0:
        raise RuntimeError(
            f"read-only e2fsck failed: exit={fsck.returncode}: "
            f"{fsck.stdout.decode(errors='replace')}"
        )
    contract = ext4_contract(image)
    if not contract["clean"] or contract["shared_blocks"] or contract["has_journal"]:
        raise ValueError(f"candidate ext4 contract failed: {contract}")
    return {
        "retained_framework_matrices": ["4", "5", "6", "device"],
        "removed_framework_matrices": ["3"],
        "payload_sha256": actual_hashes,
        "init_excluded_name": decode_excluded_name(
            payloads[INIT_PATH][INIT_FILE_OFFSET:INIT_FILE_OFFSET + 8]
        ),
        "nfc_system_require_action_absent": True,
        "gsi_explicit_none_preserved": True,
        "e2fsck_exit_code": fsck.returncode,
        "e2fsck_output_sha256": sha256_bytes(fsck.stdout),
        "ext4": contract,
    }


def load_super_builder():
    path = ROOT / "scripts/build_context_closed_super.py"
    spec = importlib.util.spec_from_file_location("dby_api32_super_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load super builder: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_system(
    source: Path,
    output: Path,
    manifest: Path,
    *,
    expected_output_sha256: str | None = EXPECTED_OUTPUT_SYSTEM_SHA256,
) -> dict[str, object]:
    source = source.resolve()
    output = output.resolve()
    manifest = manifest.resolve()
    if source == output or output.exists() or manifest.exists():
        raise FileExistsError("refusing to overwrite or alias candidate system")
    validate_file(source, SOURCE_SYSTEM_SIZE, SOURCE_SYSTEM_SHA256)
    tools = validate_tools()
    source_geometry = validate_source_geometry(source)
    source_semantics = validate_source_semantics(source)
    if sha256_file(SEPOLICY_XATTR) != SEPOLICY_XATTR_SHA256:
        raise ValueError("sepolicy xattr helper changed")

    partial = output.with_name(f".{output.name}.partial-{os.getpid()}")
    if partial.exists():
        raise FileExistsError(partial)
    try:
        clone_copy(source, partial)
        with partial.open("r+b") as stream:
            stream.truncate(SOURCE_FILESYSTEM_SIZE)
            stream.flush()
            os.fsync(stream.fileno())
        with tempfile.TemporaryDirectory(prefix="dby-api32-candidate-") as temporary:
            temporary_path = Path(temporary)
            policy = build_policy_inputs(source, temporary_path)
            debugfs_edit_sha256 = edit_compact_filesystem(partial, policy, temporary_path)
        compact_patched_sha256 = sha256_file(partial)
        expansion = grow_and_unshare(partial)
        validation = validate_candidate_system(partial)
        output_hash = sha256_file(partial)
        if expected_output_sha256 is not None and output_hash != expected_output_sha256:
            raise ValueError(f"unexpected output system SHA-256: {output_hash}")
        if output.exists():
            raise FileExistsError(f"output appeared during build: {output}")
        os.replace(partial, output)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise

    report = {
        "schema": "dby-w09-api32-minimal-candidate-v1",
        "status": (
            "offline-built-not-flashed"
            if expected_output_sha256 is not None
            else "discovery-build-not-flashed"
        ),
        "device_io_performed": False,
        "source_system": {
            "path": str(source),
            "size": SOURCE_SYSTEM_SIZE,
            "sha256": SOURCE_SYSTEM_SHA256,
            "geometry": source_geometry,
            "semantics": source_semantics,
        },
        "output_system": {
            "path": str(output),
            "size": output.stat().st_size,
            "sha256": output_hash,
        },
        "tools": tools,
        "policy_inputs": {
            key: value for key, value in policy.items() if not key.endswith("_path")
        },
        "compact_patched_sha256": compact_patched_sha256,
        "debugfs_edit_output_sha256": debugfs_edit_sha256,
        "expansion": expansion,
        "validation": validation,
        "semantic_delta": {
            "vintf": "omit only framework compatibility matrix level 3",
            "selinux": "add 119 Huawei 29.0 bindings and legacy perf_event while retaining perfmon",
            "init": "change one audited inferred-policy exclusion from gsi to nfc",
            "init_rc": "disable one duplicate explicit /data/nfc Require action",
            "vendor_partition_changed": False,
            "odm_partition_changed": False,
        },
    }
    manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def build_super(
    stock: Path,
    system: Path,
    output: Path,
    manifest: Path,
    *,
    expected_system_sha256: str,
    expected_output_sha256: str | None = EXPECTED_OUTPUT_SUPER_SHA256,
) -> dict[str, object]:
    core = load_super_builder()
    geometry = core.Geometry(
        super_size=SUPER_SIZE,
        system_offset=SYSTEM_OFFSET_IN_SUPER,
        system_extent_size=SYSTEM_EXTENT_SIZE,
        system_payload_size=OUTPUT_FILESYSTEM_SIZE,
    )
    report = core.build_super(
        stock,
        system,
        output,
        manifest=manifest,
        geometry=geometry,
        expected_stock_sha256=STOCK_SUPER_SHA256,
        expected_payload_sha256=expected_system_sha256,
    )
    output_hash = report["output_super"]["output_sha256"]
    if expected_output_sha256 is not None and output_hash != expected_output_sha256:
        raise ValueError(f"unexpected output super SHA-256: {output_hash}")
    report["schema"] = "dby-w09-api32-minimal-candidate-super-v1"
    report["status"] = (
        "offline-built-not-flashed"
        if expected_output_sha256 is not None
        else "discovery-build-not-flashed"
    )
    manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def build_candidate(source: Path, stock: Path, output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    system = output_dir / "system-api32-minimal-NOT-FLASHED.ext4"
    system_manifest = output_dir / "system.manifest.json"
    super_image = output_dir / "super-api32-minimal-NOT-FLASHED.img"
    super_manifest = output_dir / "super.manifest.json"
    system_report = build_system(source, system, system_manifest)
    super_report = build_super(
        stock,
        system,
        super_image,
        super_manifest,
        expected_system_sha256=system_report["output_system"]["sha256"],
    )
    report = {
        "schema": "dby-w09-api32-minimal-candidate-build-v1",
        "status": system_report["status"],
        "device_io_performed": False,
        "system": system_report["output_system"],
        "super": {
            "path": str(super_image),
            "size": super_image.stat().st_size,
            "sha256": super_report["output_super"]["output_sha256"],
        },
        "live_status": "not tested",
    }
    (output_dir / "build-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-system", type=Path, default=SOURCE_SYSTEM)
    parser.add_argument("--stock-super", type=Path, default=STOCK_SUPER)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = build_candidate(
        args.source_system.resolve(),
        args.stock_super.resolve(),
        args.output_dir,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
