#!/usr/bin/env python3
"""Build the DBY-W09 W9 Lineage-main endpoint probe."""

from __future__ import annotations

import argparse
import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


BASE_BUILDER = Path(__file__).with_name("build_w8_lineage_entry_probe.py")
_spec = importlib.util.spec_from_file_location("build_w8_lineage_entry_probe", BASE_BUILDER)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"cannot import {BASE_BUILDER}")
base = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = base
_spec.loader.exec_module(base)


MAIN_VADDR = 0xE0060
TARGET_NAME = "main"
MARKER_PREFIX = b"DBY_W9_LINEAGE_MAIN_PROBE nonce="
MAX_PATCH_SIZE = 256
LIBC_INIT_CALL_FILE_OFFSET = 0xE0050
LIBC_INIT_CALL_BYTES = bytes.fromhex("7c9e0694")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_offset_for_vaddr(elf: bytes, vaddr: int) -> tuple[int, dict[str, int]]:
    program_offset = struct.unpack_from("<Q", elf, 0x20)[0]
    program_size = struct.unpack_from("<H", elf, 0x36)[0]
    program_count = struct.unpack_from("<H", elf, 0x38)[0]
    if program_size != 56:
        raise ValueError("unexpected selected-init program-header size")
    for index in range(program_count):
        header = struct.unpack_from(
            "<IIQQQQQQ", elf, program_offset + index * program_size
        )
        kind, flags, offset, virtual, _, file_size, memory_size, alignment = header
        if kind == 1 and virtual <= vaddr < virtual + file_size:
            return offset + vaddr - virtual, {
                "target_load_flags": flags,
                "target_load_memsz": memory_size,
                "target_load_alignment": alignment,
            }
    raise ValueError(f"target virtual address 0x{vaddr:x} is not file-backed by PT_LOAD")


def compile_stub(source: Path, directory: Path) -> bytes:
    if not source.is_file():
        raise FileNotFoundError(source)
    directory.mkdir(parents=True, exist_ok=True)
    object_path = directory / "w9-lineage-main-probe.o"
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
    stub = base.extract_stub_text(object_path.read_bytes())
    base.validate_stub(stub)
    return stub


def patch_selected_init_main(
    original: bytes, stub: bytes, nonce: str
) -> tuple[bytes, dict[str, object]]:
    base.validate_nonce(nonce)
    if len(original) != base.EXPECTED_INIT_SIZE:
        raise ValueError(f"unexpected selected-init size: {len(original)}")
    original_hash = _sha256(original)
    if original_hash != base.EXPECTED_SELECTED_INIT_SHA256:
        raise ValueError(f"unexpected selected-init SHA-256: {original_hash}")
    stub_report = base.validate_stub(stub)
    entry_offset, entry_report = base._entrypoint_file_offset(original)
    target_offset, target_load = _file_offset_for_vaddr(original, MAIN_VADDR)
    if entry_offset >= target_offset:
        raise ValueError("Lineage main target must follow the ELF entry shim")
    if (
        original[
            LIBC_INIT_CALL_FILE_OFFSET : LIBC_INIT_CALL_FILE_OFFSET
            + len(LIBC_INIT_CALL_BYTES)
        ]
        != LIBC_INIT_CALL_BYTES
    ):
        raise ValueError("selected-init __libc_init call-site bytes changed")

    marker = MARKER_PREFIX + nonce.encode() + b"\0"
    patch = stub + marker
    patch += b"\0" * (-len(patch) % 4)
    if len(patch) > MAX_PATCH_SIZE:
        raise ValueError("W9 main patch exceeds its 256-byte safety window")
    if target_offset // base.EXT4_BLOCK_SIZE != (
        target_offset + len(patch) - 1
    ) // base.EXT4_BLOCK_SIZE:
        raise ValueError("W9 main patch crosses an ext4 block boundary")
    if entry_offset // base.EXT4_BLOCK_SIZE != target_offset // base.EXT4_BLOCK_SIZE:
        raise ValueError("W9 main patch is not in the qualified entry ext4 block")

    output = bytearray(original)
    output[target_offset : target_offset + len(patch)] = patch
    changed = [
        index
        for index, (before, after) in enumerate(zip(original, output))
        if before != after
    ]
    if (
        not changed
        or min(changed) < target_offset
        or max(changed) >= target_offset + len(patch)
    ):
        raise ValueError("W9 changed bytes outside the main patch")

    report = {
        "elf_type": entry_report["elf_type"],
        "machine": entry_report["machine"],
        "interpreter": entry_report["interpreter"],
        "elf_entrypoint_vaddr": entry_report["entrypoint_vaddr"],
        "elf_entrypoint_file_offset": entry_report["entrypoint_file_offset"],
        "target_name": TARGET_NAME,
        "target_vaddr": MAIN_VADDR,
        "target_file_offset": target_offset,
        **target_load,
        **stub_report,
        "nonce": nonce,
        "marker": marker.rstrip(b"\0").decode(),
        "patch_size": len(patch),
        "patch_sha256": _sha256(patch),
        "original_init_sha256": original_hash,
        "patched_init_sha256": _sha256(bytes(output)),
        "entry_shim_sha256": _sha256(original[entry_offset:target_offset]),
        "libc_init_call_file_offset": LIBC_INIT_CALL_FILE_OFFSET,
        "libc_init_call_bytes": LIBC_INIT_CALL_BYTES.hex(),
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


def build(args: argparse.Namespace) -> dict[str, object]:
    base.validate_nonce(args.nonce)
    sources = {
        "selected_init": (args.selected_init, base.EXPECTED_SELECTED_INIT_SHA256),
        "system": (args.system_source, base.EXPECTED_SYSTEM_SHA256),
        "super": (args.super_source, base.EXPECTED_SUPER_SHA256),
    }
    for name, (path, expected) in sources.items():
        if not path.is_file():
            raise FileNotFoundError(path)
        actual = base.sha256_file(path)
        if actual != expected:
            raise ValueError(f"unexpected {name} SHA-256: {actual}")
    if args.system_source.stat().st_size != base.SYSTEM_SIZE:
        raise ValueError("unexpected source system size")
    if args.super_source.stat().st_size != base.SUPER_SIZE:
        raise ValueError("unexpected source super size")
    if (
        base.sha256_file(
            args.super_source, base.SUPER_SYSTEM_OFFSET, base.SYSTEM_SIZE
        )
        != base.EXPECTED_SYSTEM_SHA256
    ):
        raise ValueError("source super does not embed the frozen W3 system image")
    preflight = base.qualify_system_image(
        args.system_source, base.EXPECTED_SELECTED_INIT_SHA256
    )

    with tempfile.TemporaryDirectory() as directory_text:
        stub = compile_stub(args.assembly_source, Path(directory_text))
    patched_init, init_report = patch_selected_init_main(
        args.selected_init.read_bytes(), stub, args.nonce
    )
    args.patched_init.parent.mkdir(parents=True, exist_ok=True)
    if any(
        path.exists()
        for path in (
            args.patched_init,
            args.system_output,
            args.super_output,
            args.report,
        )
    ):
        raise FileExistsError("refusing to overwrite W9 output or report")
    args.patched_init.write_bytes(patched_init)
    try:
        image_report = base.patch_images(
            system_source=args.system_source,
            super_source=args.super_source,
            patched_init=patched_init,
            system_output=args.system_output,
            super_output=args.super_output,
        )
        postflight = base.qualify_system_image(
            args.system_output, init_report["patched_init_sha256"]
        )
        embedded_hash = base.sha256_file(
            args.super_output, base.SUPER_SYSTEM_OFFSET, base.SYSTEM_SIZE
        )
        system_hash = base.sha256_file(args.system_output)
        if embedded_hash != system_hash:
            raise ValueError("W9 super embedded system differs from W9 system image")
        result = {
            "schema": "dby-w09-w9-lineage-main-probe-v1",
            "status": "offline-built-not-flashed",
            "device_io_performed": False,
            "experiment": (
                "retain the exact selected Lineage PIE entry shim and bootstrap "
                "linker, then replace only the first bytes of main with a direct "
                "restart2 endpoint probe"
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
                    "sha256": base.sha256_file(args.patched_init),
                },
                "system": {
                    "path": str(args.system_output.resolve()),
                    "size": args.system_output.stat().st_size,
                    "sha256": system_hash,
                },
                "super": {
                    "path": str(args.super_output.resolve()),
                    "size": args.super_output.stat().st_size,
                    "sha256": base.sha256_file(args.super_output),
                    "embedded_system_sha256": embedded_hash,
                },
            },
            "endpoint_contract": {
                "EDL": (
                    "the exact PIE entry shim called through __libc_init and the "
                    "bootstrap startup path transferred control to patched main"
                ),
                "Fastboot": "patched main ran but restart2(edl) was rejected",
                "Recovery": (
                    "main-entry success was not observed; pre-main failure and an "
                    "unobserved endpoint failure remain separate hypotheses"
                ),
            },
            "does_not_prove": [
                "the unmodified Lineage main prologue executed",
                "main dispatched to FirstStageMain",
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
    result = build(parser.parse_args())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
