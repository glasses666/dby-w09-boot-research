#!/usr/bin/env python3
"""Build the DBY-W09 W8 Lineage-entry endpoint probe.

The frozen W3 system image has one independently qualified, unshared ext4 data
block containing the selected Lineage init entrypoint.  W8 changes only bytes
inside that block, preserving the inode, metadata, SELinux xattr, filesystem
geometry, LP metadata, and every byte outside the selected init entry window.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


EXPECTED_SELECTED_INIT_SHA256 = (
    "f9aff20075a7d85e14412855c7dad7f353cba41918b2e45fe4f0285379e1e0f3"
)
EXPECTED_SYSTEM_SHA256 = (
    "8ec6599fb4d93facb4adc18436c6c17632552e15a475ae3ef8bb6f11b0d959f9"
)
EXPECTED_SUPER_SHA256 = (
    "b22c5f15fe39ce2cd1853ea1ef1129e1d7e8f5bce8bfec938ffabc598c7f4cdf"
)
EXPECTED_CONTAINER_ID = (
    "sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55"
)
EXPECTED_INTERPRETER = b"/system/bin/bootstrap/linker64\0"
EXPECTED_ENTRYPOINT = 0xE0000
EXPECTED_INIT_SIZE = 2_771_152
EXT4_BLOCK_SIZE = 4096
INIT_ENTRY_FILE_BLOCK = EXPECTED_ENTRYPOINT // EXT4_BLOCK_SIZE
INIT_ENTRY_PHYSICAL_BLOCK = 88_073
INIT_INODE = 400
SUPER_SYSTEM_OFFSET = 2_097_152
SYSTEM_SIZE = 2_513_817_600
SUPER_SIZE = 7_692_353_536
MARKER_PREFIX = b"DBY_W8_LINEAGE_ENTRY_PROBE nonce="
CHUNK_SIZE = 8 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, offset: int = 0, length: int | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        handle.seek(offset)
        remaining = length
        while remaining is None or remaining:
            wanted = CHUNK_SIZE if remaining is None else min(CHUNK_SIZE, remaining)
            block = handle.read(wanted)
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
        if remaining not in (None, 0):
            raise ValueError(f"short read from {path}: {remaining} bytes missing")
    return digest.hexdigest()


def validate_nonce(nonce: str) -> None:
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")


def _elf_sections(elf: bytes) -> tuple[list[tuple[int, ...]], list[str]]:
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        raise ValueError("expected a little-endian ELF64 object")
    section_offset = struct.unpack_from("<Q", elf, 0x28)[0]
    section_size = struct.unpack_from("<H", elf, 0x3A)[0]
    section_count = struct.unpack_from("<H", elf, 0x3C)[0]
    string_index = struct.unpack_from("<H", elf, 0x3E)[0]
    if section_size != 64 or not 0 < string_index < section_count:
        raise ValueError("unexpected ELF section geometry")
    sections = [
        struct.unpack_from("<IIQQQQIIQQ", elf, section_offset + index * section_size)
        for index in range(section_count)
    ]
    string_section = sections[string_index]
    strings = elf[string_section[4] : string_section[4] + string_section[5]]

    def name_at(offset: int) -> str:
        end = strings.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated ELF section name")
        return strings[offset:end].decode("ascii")

    return sections, [name_at(section[0]) for section in sections]


def extract_stub_text(object_bytes: bytes) -> bytes:
    sections, names = _elf_sections(object_bytes)
    try:
        text_index = names.index(".text")
    except ValueError as error:
        raise ValueError("stub object has no .text section") from error
    text_section = sections[text_index]
    for section in sections:
        if section[1] in (4, 9) and section[7] == text_index and section[5] != 0:
            raise ValueError("stub .text contains unresolved relocations")
    text = object_bytes[text_section[4] : text_section[4] + text_section[5]]
    if not text:
        raise ValueError("stub .text is empty")
    return text


def validate_stub(stub: bytes) -> dict[str, object]:
    if len(stub) > 128 or len(stub) % 4:
        raise ValueError("W8 assembly stub must be nonempty, aligned, and at most 128 bytes")
    if not stub.startswith(bytes.fromhex("9f2403d5")):
        raise ValueError("W8 stub must begin with BTI J")
    if stub.count(bytes.fromhex("010000d4")) != 2:
        raise ValueError("W8 stub must contain exactly two SVC #0 instructions")
    if b"edl\0" not in stub or b"bootloader\0" not in stub:
        raise ValueError("W8 stub is missing endpoint strings")
    for forbidden in (b"/log", b"/metadata", b"/data", b"/dev/block"):
        if forbidden in stub:
            raise ValueError(f"W8 stub contains forbidden path {forbidden!r}")
    return {
        "stub_size": len(stub),
        "stub_sha256": sha256(stub),
        "svc_instruction_count": 2,
        "first_instruction": "BTI J",
    }


def compile_stub(source: Path, directory: Path) -> bytes:
    if not source.is_file():
        raise FileNotFoundError(source)
    directory.mkdir(parents=True, exist_ok=True)
    object_path = directory / "w8-lineage-entry-probe.o"
    subprocess.run(
        [
            "/usr/bin/clang",
            "-target",
            "aarch64-linux-android29",
            "-march=armv8.5-a",
            "-c",
            str(source),
            "-o",
            str(object_path),
        ],
        check=True,
    )
    object_bytes = object_path.read_bytes()
    stub = extract_stub_text(object_bytes)
    validate_stub(stub)
    return stub


def _entrypoint_file_offset(elf: bytes) -> tuple[int, dict[str, object]]:
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        raise ValueError("selected init is not little-endian ELF64")
    elf_type, machine = struct.unpack_from("<HH", elf, 16)
    if elf_type != 3 or machine != 183:
        raise ValueError("selected init must be an AArch64 PIE executable")
    entrypoint = struct.unpack_from("<Q", elf, 0x18)[0]
    program_offset = struct.unpack_from("<Q", elf, 0x20)[0]
    program_size = struct.unpack_from("<H", elf, 0x36)[0]
    program_count = struct.unpack_from("<H", elf, 0x38)[0]
    if entrypoint != EXPECTED_ENTRYPOINT or program_size != 56:
        raise ValueError("unexpected selected-init entrypoint or program-header size")
    mapped_offset = None
    mapped_load = None
    interpreter = None
    for index in range(program_count):
        header = struct.unpack_from(
            "<IIQQQQQQ", elf, program_offset + index * program_size
        )
        kind, flags, offset, virtual, _, file_size, memory_size, alignment = header
        if kind == 1 and virtual <= entrypoint < virtual + file_size:
            mapped_offset = offset + entrypoint - virtual
            mapped_load = {
                "entry_load_flags": flags,
                "entry_load_memsz": memory_size,
                "entry_load_alignment": alignment,
            }
        if kind == 3:
            interpreter = elf[offset : offset + file_size]
    if mapped_offset is None or mapped_load is None:
        raise ValueError("selected-init entrypoint is not file-backed by PT_LOAD")
    if interpreter != EXPECTED_INTERPRETER:
        raise ValueError(f"unexpected selected-init interpreter: {interpreter!r}")
    return mapped_offset, {
        "elf_type": "ET_DYN",
        "machine": "AArch64",
        "entrypoint_vaddr": entrypoint,
        "entrypoint_file_offset": mapped_offset,
        "interpreter": EXPECTED_INTERPRETER.rstrip(b"\0").decode(),
        **mapped_load,
    }


def patch_selected_init(
    original: bytes, stub: bytes, nonce: str
) -> tuple[bytes, dict[str, object]]:
    validate_nonce(nonce)
    if len(original) != EXPECTED_INIT_SIZE:
        raise ValueError(f"unexpected selected-init size: {len(original)}")
    original_hash = sha256(original)
    if original_hash != EXPECTED_SELECTED_INIT_SHA256:
        raise ValueError(f"unexpected selected-init SHA-256: {original_hash}")
    stub_report = validate_stub(stub)
    entry_offset, elf_report = _entrypoint_file_offset(original)
    marker = MARKER_PREFIX + nonce.encode() + b"\0"
    patch = stub + marker
    patch += b"\0" * (-len(patch) % 4)
    if len(patch) > 256:
        raise ValueError("W8 entry patch exceeds its 256-byte safety window")
    if entry_offset // EXT4_BLOCK_SIZE != (entry_offset + len(patch) - 1) // EXT4_BLOCK_SIZE:
        raise ValueError("W8 entry patch crosses an ext4 block boundary")
    output = bytearray(original)
    output[entry_offset : entry_offset + len(patch)] = patch
    changed = [
        index
        for index, (before, after) in enumerate(zip(original, output))
        if before != after
    ]
    if not changed or min(changed) < entry_offset or max(changed) >= entry_offset + len(patch):
        raise ValueError("W8 changed bytes outside the entry patch")
    report = {
        **elf_report,
        **stub_report,
        "nonce": nonce,
        "marker": marker.rstrip(b"\0").decode(),
        "patch_size": len(patch),
        "patch_sha256": sha256(patch),
        "original_init_sha256": original_hash,
        "patched_init_sha256": sha256(bytes(output)),
        "changed_bytes": len(changed),
        "changed_range": {
            "start": min(changed),
            "end_exclusive": max(changed) + 1,
        },
        "persistent_write_syscalls": False,
        "success_endpoint": "EDL",
        "fallback_endpoint": "Fastboot",
    }
    return bytes(output), report


def _copy(source: Path, destination: Path, clone: bool) -> None:
    if clone:
        subprocess.run(
            ["/bin/cp", "-c", str(source), str(destination)], check=True
        )
    else:
        shutil.copyfile(source, destination)


def patch_images(
    *,
    system_source: Path,
    super_source: Path,
    patched_init: bytes,
    system_output: Path,
    super_output: Path,
    block_size: int = EXT4_BLOCK_SIZE,
    init_entry_file_offset: int = EXPECTED_ENTRYPOINT,
    init_physical_block: int = INIT_ENTRY_PHYSICAL_BLOCK,
    super_system_offset: int = SUPER_SYSTEM_OFFSET,
    clone: bool = True,
) -> dict[str, object]:
    paths = [system_source, super_source, system_output, super_output]
    if any(not isinstance(path, Path) for path in paths):
        raise TypeError("all image paths must be pathlib.Path values")
    if not system_source.is_file() or not super_source.is_file():
        raise FileNotFoundError("system and super sources must exist")
    if system_output.exists() or super_output.exists():
        raise FileExistsError("refusing to overwrite W8 image output")
    if init_entry_file_offset % block_size:
        raise ValueError("selected-init entrypoint must begin at a block boundary")
    if len(patched_init) < init_entry_file_offset + block_size:
        raise ValueError("patched init does not contain its complete entry block")
    system_patch_offset = init_physical_block * block_size
    super_patch_offset = super_system_offset + system_patch_offset
    replacement = patched_init[
        init_entry_file_offset : init_entry_file_offset + block_size
    ]
    with system_source.open("rb") as handle:
        handle.seek(system_patch_offset)
        source_block = handle.read(block_size)
    with super_source.open("rb") as handle:
        handle.seek(super_patch_offset)
        embedded_block = handle.read(block_size)
    if len(source_block) != block_size or embedded_block != source_block:
        raise ValueError("source super does not embed the qualified system entry block")
    if replacement == source_block:
        raise ValueError("W8 replacement block is unchanged")

    system_output.parent.mkdir(parents=True, exist_ok=True)
    super_output.parent.mkdir(parents=True, exist_ok=True)
    partial_system = system_output.with_name(f".{system_output.name}.partial-{os.getpid()}")
    partial_super = super_output.with_name(f".{super_output.name}.partial-{os.getpid()}")
    try:
        _copy(system_source, partial_system, clone)
        _copy(super_source, partial_super, clone)
        for path, offset in (
            (partial_system, system_patch_offset),
            (partial_super, super_patch_offset),
        ):
            with path.open("r+b", buffering=0) as handle:
                handle.seek(offset)
                handle.write(replacement)
                handle.flush()
                os.fsync(handle.fileno())
        if partial_system.stat().st_size != system_source.stat().st_size:
            raise ValueError("W8 changed system image size")
        if partial_super.stat().st_size != super_source.stat().st_size:
            raise ValueError("W8 changed super image size")
        with partial_system.open("rb") as handle:
            handle.seek(system_patch_offset)
            if handle.read(block_size) != replacement:
                raise ValueError("W8 system block readback mismatch")
        with partial_super.open("rb") as handle:
            handle.seek(super_patch_offset)
            if handle.read(block_size) != replacement:
                raise ValueError("W8 super block readback mismatch")
        os.replace(partial_system, system_output)
        os.replace(partial_super, super_output)
    except BaseException:
        partial_system.unlink(missing_ok=True)
        partial_super.unlink(missing_ok=True)
        raise
    return {
        "modified_ext4_blocks": 1,
        "block_size": block_size,
        "init_entry_file_offset": init_entry_file_offset,
        "init_entry_file_block": init_entry_file_offset // block_size,
        "init_physical_block": init_physical_block,
        "system_patch_offset": system_patch_offset,
        "super_system_offset": super_system_offset,
        "super_patch_offset": super_patch_offset,
        "replacement_block_sha256": sha256(replacement),
        "source_block_sha256": sha256(source_block),
    }


def _container_id() -> str:
    return subprocess.run(
        ["docker", "image", "inspect", "ubuntu:24.04", "--format", "{{.Id}}"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()


def qualify_system_image(path: Path, expected_init_sha256: str) -> dict[str, object]:
    container_id = _container_id()
    if container_id != EXPECTED_CONTAINER_ID:
        raise ValueError(f"unexpected ubuntu:24.04 image id: {container_id}")
    script = f"""
set -eu
e2fsck -fn /image.ext4
tune2fs -l /image.ext4 | grep -q 'shared_blocks'
test "$(debugfs -R 'bmap /system/bin/init {INIT_ENTRY_FILE_BLOCK}' /image.ext4 2>/dev/null)" = {INIT_ENTRY_PHYSICAL_BLOCK}
test "$(debugfs -R 'icheck {INIT_ENTRY_PHYSICAL_BLOCK}' /image.ext4 2>/dev/null | tail -1)" = $'{INIT_ENTRY_PHYSICAL_BLOCK}\\t{INIT_INODE}'
debugfs -R 'stat /system/bin/init' /image.ext4 2>&1
debugfs -R 'ea_list /system/bin/init' /image.ext4 2>&1
debugfs -R 'cat /system/bin/init' /image.ext4 2>/dev/null | sha256sum
""".strip()
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "-v",
            f"{path.resolve()}:/image.ext4:ro",
            "ubuntu:24.04",
            "bash",
            "-lc",
            script,
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    combined = run.stdout + run.stderr
    if f"Size: {EXPECTED_INIT_SIZE}" not in combined:
        raise ValueError("qualified system init size changed")
    if 'security.selinux (24) = "u:object_r:init_exec:s0\\000"' not in combined:
        raise ValueError("qualified system init SELinux xattr changed")
    if not re.search(rf"^{expected_init_sha256}\s+-$", combined, re.MULTILINE):
        raise ValueError("qualified system init content hash mismatch")
    return {
        "container_id": container_id,
        "e2fsprogs": "ubuntu:24.04 e2fsprogs 1.47.0",
        "network": "none",
        "mount": "read-only bind",
        "init_inode": INIT_INODE,
        "init_size": EXPECTED_INIT_SIZE,
        "init_entry_file_block": INIT_ENTRY_FILE_BLOCK,
        "init_entry_physical_block": INIT_ENTRY_PHYSICAL_BLOCK,
        "init_security_selinux": "u:object_r:init_exec:s0",
        "init_sha256": expected_init_sha256,
        "raw_output_sha256": sha256(combined.encode()),
    }


def build(args: argparse.Namespace) -> dict[str, object]:
    validate_nonce(args.nonce)
    sources = {
        "selected_init": (args.selected_init, EXPECTED_SELECTED_INIT_SHA256),
        "system": (args.system_source, EXPECTED_SYSTEM_SHA256),
        "super": (args.super_source, EXPECTED_SUPER_SHA256),
    }
    for name, (path, expected) in sources.items():
        if not path.is_file():
            raise FileNotFoundError(path)
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"unexpected {name} SHA-256: {actual}")
    if args.system_source.stat().st_size != SYSTEM_SIZE:
        raise ValueError("unexpected source system size")
    if args.super_source.stat().st_size != SUPER_SIZE:
        raise ValueError("unexpected source super size")
    if sha256_file(args.super_source, SUPER_SYSTEM_OFFSET, SYSTEM_SIZE) != EXPECTED_SYSTEM_SHA256:
        raise ValueError("source super does not embed the frozen W3 system image")
    preflight = qualify_system_image(args.system_source, EXPECTED_SELECTED_INIT_SHA256)

    with tempfile.TemporaryDirectory() as directory_text:
        stub = compile_stub(args.assembly_source, Path(directory_text))
    patched_init, init_report = patch_selected_init(
        args.selected_init.read_bytes(), stub, args.nonce
    )
    args.patched_init.parent.mkdir(parents=True, exist_ok=True)
    if args.patched_init.exists() or args.report.exists():
        raise FileExistsError("refusing to overwrite W8 output or report")
    args.patched_init.write_bytes(patched_init)
    try:
        image_report = patch_images(
            system_source=args.system_source,
            super_source=args.super_source,
            patched_init=patched_init,
            system_output=args.system_output,
            super_output=args.super_output,
        )
        postflight = qualify_system_image(
            args.system_output, init_report["patched_init_sha256"]
        )
        embedded_hash = sha256_file(
            args.super_output, SUPER_SYSTEM_OFFSET, SYSTEM_SIZE
        )
        system_hash = sha256_file(args.system_output)
        if embedded_hash != system_hash:
            raise ValueError("W8 super embedded system differs from W8 system image")
        result = {
            "schema": "dby-w09-w8-lineage-entry-probe-v1",
            "status": "offline-built-not-flashed",
            "device_io_performed": False,
            "experiment": (
                "replace only the exact selected Lineage init entry bytes with a "
                "direct restart2 endpoint probe after retaining its bootstrap linker"
            ),
            "nonce": args.nonce,
            "source": {
                name: {"path": str(path.resolve()), "sha256": expected}
                for name, (path, expected) in sources.items()
            },
            "init_patch": init_report,
            "image_patch": image_report,
            "preflight": preflight,
            "postflight": postflight,
            "outputs": {
                "patched_init": {
                    "path": str(args.patched_init.resolve()),
                    "size": args.patched_init.stat().st_size,
                    "sha256": sha256_file(args.patched_init),
                },
                "system": {
                    "path": str(args.system_output.resolve()),
                    "size": args.system_output.stat().st_size,
                    "sha256": system_hash,
                },
                "super": {
                    "path": str(args.super_output.resolve()),
                    "size": args.super_output.stat().st_size,
                    "sha256": sha256_file(args.super_output),
                    "embedded_system_sha256": embedded_hash,
                },
            },
            "endpoint_contract": {
                "EDL": (
                    "kernel exec loaded the selected PIE through its exact bootstrap "
                    "linker and transferred control to the patched init entrypoint"
                ),
                "Fastboot": "entrypoint ran but restart2(edl) was rejected",
                "Recovery": (
                    "entrypoint success was not observed; pre-entry failure and an "
                    "unobserved endpoint failure remain separate hypotheses"
                ),
            },
            "does_not_prove": [
                "the unmodified Lineage init entrypoint or main executed",
                "selinux_setup completed",
                "SecondStageMain executed",
                "Android boot completed",
            ],
            "rollback": {
                "super_sha256": "f76a7b1ab32ca5e3189d6b536a56259b64f993cf0e9c3ed56b80cb3b1c78cbb4",
                "boot_sha256": "7babcfd21286f47856b050473fb50b15d6f1532475277ceda56d9062651d4aca",
                "ramdisk_sha256": "d1afe422e88bd330ec5ccf8220ed6fbc241ade8f37fe26c3ab1cded6cf4d38da",
            },
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return result
    except BaseException:
        args.patched_init.unlink(missing_ok=True)
        args.system_output.unlink(missing_ok=True)
        args.super_output.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assembly-source", required=True, type=Path)
    parser.add_argument("--selected-init", required=True, type=Path)
    parser.add_argument("--system-source", required=True, type=Path)
    parser.add_argument("--super-source", required=True, type=Path)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--patched-init", required=True, type=Path)
    parser.add_argument("--system-output", required=True, type=Path)
    parser.add_argument("--super-output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    result = build(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
