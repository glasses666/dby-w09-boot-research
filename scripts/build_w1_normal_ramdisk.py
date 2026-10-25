#!/usr/bin/env python3
"""Build the nonce-bound DBY-W09 W1 normal-PID-1 witness ramdisk."""

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


sha256 = base.sha256
extract_entries = base.extract_entries


def validate_nonce(nonce: str) -> None:
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")


def validate_probe(probe: bytes, nonce: str) -> dict[str, object]:
    validate_nonce(nonce)
    layout = base.validate_wrapper(probe)
    elf_type = struct.unpack_from("<H", probe, 16)[0]
    if elf_type != 2:
        raise ValueError(f"W1 probe must be ET_EXEC, got ELF type {elf_type}")
    entrypoint = struct.unpack_from("<Q", probe, 24)[0]
    if entrypoint == 0:
        raise ValueError("W1 probe has a zero ELF entrypoint")
    headers = layout["program_headers"]
    has_dynamic_segment = any(header["type"] == 2 for header in headers)
    has_writable_executable_segment = any(
        header["type"] == 1 and header["flags"] & 1 and header["flags"] & 2
        for header in headers
    )
    load_memory_bytes = sum(
        header["memsz"] for header in headers if header["type"] == 1
    )
    if has_dynamic_segment:
        raise ValueError("W1 probe must not contain a PT_DYNAMIC segment")
    if has_writable_executable_segment:
        raise ValueError("W1 probe must not contain a writable executable PT_LOAD")
    if load_memory_bytes > 256 * 1024:
        raise ValueError("W1 probe exceeds the 256 KiB loaded-memory safety limit")
    if len(probe) > 64 * 1024:
        raise ValueError("W1 probe exceeds the 64 KiB safety limit")
    required = (
        b"DBYW1REC",
        nonce.encode("ascii"),
        b"/proc/sys/kernel/random/boot_id",
        b"/proc/self/exe",
        b"/sys/class/block/",
        b"PARTNAME=log",
        b"/dby-audit-log",
        b".dby-normal-witness-",
        b"dby-normal-witness-",
        b"edl",
    )
    missing = [item.decode("ascii") for item in required if item not in probe]
    if missing:
        raise ValueError(f"W1 probe is missing required markers: {missing}")
    for forbidden in (b"/init.stock", b"/system/bin/init", b"/metadata"):
        if forbidden in probe:
            raise ValueError(f"W1 probe contains forbidden execution/sink path: {forbidden!r}")
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


def build_w1(source: bytes, probe: bytes, nonce: str) -> tuple[bytes, dict[str, object]]:
    probe_layout = validate_probe(probe, nonce)
    output, report = base.build_image(source, probe)
    avb_offset = int(report["avb_offset"])
    flags_offset = avb_offset + 120
    embedded_vbmeta_flags = struct.unpack_from(">I", output, flags_offset)[0]
    if embedded_vbmeta_flags != 0:
        raise ValueError(
            f"W1 requires embedded child-vbmeta flags zero, got {embedded_vbmeta_flags}"
        )
    report.update(
        {
            "experiment": "W1 synchronous normal-PID-1 witness",
            "nonce": nonce,
            "probe_sha256": sha256(probe),
            "probe_elf_type": "ET_EXEC",
            "probe_entrypoint": probe_layout["entrypoint"],
            "probe_load_memory_bytes": probe_layout["load_memory_bytes"],
            "probe_has_dynamic_segment": probe_layout["has_dynamic_segment"],
            "probe_has_writable_executable_segment": probe_layout[
                "has_writable_executable_segment"
            ],
            "embedded_vbmeta_flags": embedded_vbmeta_flags,
            "embedded_vbmeta_flags_offset": flags_offset,
            "executes_stock_init": False,
            "executes_lineage_init": False,
            "stock_init_retained_but_unreferenced": True,
            "qualified_sink_partition": "log",
            "qualified_sink_mountpoint": "/log",
            "qualified_sink_fsuuid": "e3ff96a2-2fe4-48d2-8c2d-aef8d068275d",
            "qualified_sink_gpt_uuid": "906d7124-62f7-d1c8-ffbf-73c97575983f",
            "software_return_request": "RESTART2(edl)",
            "fallback_return_request": "RESTART2(bootloader) only if edl syscall returns",
            "diagnostic_scope": (
                "normal ramdisk only; one synchronous PID-1; bounded current-kmsg "
                "capture; atomic new-file publication on qualified log filesystem; "
                "no stock-init or Lineage-init execution"
            ),
        }
    )
    return output, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--stub", required=True, type=Path)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.report.exists():
        parser.error("refusing to overwrite an existing output or report")
    output, report = build_w1(
        args.input.read_bytes(), args.stub.read_bytes(), args.nonce
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
