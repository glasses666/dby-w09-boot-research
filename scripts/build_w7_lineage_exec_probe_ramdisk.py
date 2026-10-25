#!/usr/bin/env python3
"""Build the endpoint-coded DBY-W09 W7 Lineage-init exec probe ramdisk."""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_diagnostic_normal_ramdisk as base  # noqa: E402


EXPECTED_LINEAGE_INIT_SHA256 = (
    "f9aff20075a7d85e14412855c7dad7f353cba41918b2e45fe4f0285379e1e0f3"
)


def validate_nonce(nonce: str) -> None:
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")


def validate_probe(probe: bytes, nonce: str, lineage_init_sha256: str) -> dict:
    validate_nonce(nonce)
    if re.fullmatch(r"[0-9a-f]{64}", lineage_init_sha256) is None:
        raise ValueError("Lineage init SHA-256 must be 64 lowercase hex characters")
    layout = base.validate_wrapper(probe)
    elf_type = struct.unpack_from("<H", probe, 16)[0]
    if elf_type != 2:
        raise ValueError(f"W7 probe must be ET_EXEC, got ELF type {elf_type}")
    entrypoint = struct.unpack_from("<Q", probe, 24)[0]
    headers = layout["program_headers"]
    has_dynamic_segment = any(header["type"] == 2 for header in headers)
    has_writable_executable_segment = any(
        header["type"] == 1 and header["flags"] & 1 and header["flags"] & 2
        for header in headers
    )
    load_memory_bytes = sum(
        header["memsz"] for header in headers if header["type"] == 1
    )
    if entrypoint == 0:
        raise ValueError("W7 probe has a zero ELF entrypoint")
    if has_dynamic_segment:
        raise ValueError("W7 probe must not contain PT_DYNAMIC")
    if has_writable_executable_segment:
        raise ValueError("W7 probe must not contain writable-executable PT_LOAD")
    if load_memory_bytes > 256 * 1024:
        raise ValueError("W7 probe exceeds the 256 KiB loaded-memory safety limit")
    if len(probe) > 64 * 1024:
        raise ValueError("W7 probe exceeds the 64 KiB file safety limit")
    required = (
        b"DBY_W7_LINEAGE_EXEC_STAGE_PROBE nonce=" + nonce.encode(),
        nonce.encode(),
        lineage_init_sha256.encode(),
        b"/init.stock",
        b"/dby-proc/1/exe",
        b"/dby-proc/1/mountinfo",
        b"/dby-proc/1/root/system/bin/init",
        b"/system/bin/init",
        b"/vendor",
        b"/odm",
        b"CLONE_NEWNS private proc observer; parent mount namespace unchanged",
        b"EDL means exact selected Lineage init became PID1 /system/bin/init",
        b"edl",
        b"bootloader",
    )
    missing = [item.decode() for item in required if item not in probe]
    if missing:
        raise ValueError(f"W7 probe is missing required markers: {missing}")
    for forbidden in (
        b"/log",
        b"/metadata",
        b"/data/adb",
        b"/dev/block",
        b"dby-normal-witness-",
    ):
        if forbidden in probe:
            raise ValueError(f"W7 probe contains forbidden path: {forbidden!r}")
    layout.update(
        {
            "elf_type": elf_type,
            "entrypoint": entrypoint,
            "load_memory_bytes": load_memory_bytes,
            "has_dynamic_segment": has_dynamic_segment,
            "has_writable_executable_segment": has_writable_executable_segment,
        }
    )
    return layout


def build_w7(
    source: bytes,
    probe: bytes,
    nonce: str,
    lineage_init_sha256: str,
) -> tuple[bytes, dict]:
    layout = validate_probe(probe, nonce, lineage_init_sha256)
    output, report = base.build_image(source, probe)
    flags_offset = int(report["avb_offset"]) + 120
    embedded_vbmeta_flags = struct.unpack_from(">I", output, flags_offset)[0]
    if embedded_vbmeta_flags != 0:
        raise ValueError(
            f"W7 requires embedded child-vbmeta flags zero, got {embedded_vbmeta_flags}"
        )
    report.update(
        {
            "experiment": "W7 endpoint-coded Lineage-init exec probe",
            "nonce": nonce,
            "probe_sha256": base.sha256(probe),
            "probe_elf_type": "ET_EXEC",
            "probe_entrypoint": layout["entrypoint"],
            "probe_load_memory_bytes": layout["load_memory_bytes"],
            "probe_has_dynamic_segment": layout["has_dynamic_segment"],
            "probe_has_writable_executable_segment": layout[
                "has_writable_executable_segment"
            ],
            "embedded_vbmeta_flags": embedded_vbmeta_flags,
            "embedded_vbmeta_flags_offset": flags_offset,
            "executes_stock_init": True,
            "expected_lineage_init_sha256": lineage_init_sha256,
            "writes_persistent_storage": False,
            "parent_mount_namespace_untouched": True,
            "success_stage": "Lineage init exec",
            "success_endpoint": "EDL",
            "failure_or_timeout_endpoint": "Fastboot",
            "natural_target_failure_endpoint": "Recovery",
            "timeout_seconds": 30,
            "stage_observation": (
                "the post-switch-root Lineage init file first matches the exact "
                "selected SHA-256, then /proc/1/exe becomes /system/bin/init"
            ),
            "diagnostic_scope": (
                "normal ramdisk only; one private-mount-namespace observer; "
                "parent execs retained stock first-stage init; no persistent "
                "filesystem open for write, fsck, raw partition write, SELinux "
                "policy change, or parent mount-namespace change"
            ),
        }
    )
    return output, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--stub", required=True, type=Path)
    parser.add_argument("--nonce", required=True)
    parser.add_argument(
        "--lineage-init-sha256", default=EXPECTED_LINEAGE_INIT_SHA256
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.report.exists():
        parser.error("refusing to overwrite an existing output or report")
    output, report = build_w7(
        args.input.read_bytes(),
        args.stub.read_bytes(),
        args.nonce,
        args.lineage_init_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
