#!/usr/bin/env python3
"""Build the nonce-bound DBY-W09 W2 Lineage second-stage witness ramdisk."""

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
        raise ValueError(f"W2 probe must be ET_EXEC, got ELF type {elf_type}")
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
        raise ValueError("W2 probe has a zero ELF entrypoint")
    if has_dynamic_segment:
        raise ValueError("W2 probe must not contain PT_DYNAMIC")
    if has_writable_executable_segment:
        raise ValueError("W2 probe must not contain writable-executable PT_LOAD")
    if load_memory_bytes > 256 * 1024:
        raise ValueError("W2 probe exceeds the 256 KiB loaded-memory safety limit")
    if len(probe) > 64 * 1024:
        raise ValueError("W2 probe exceeds the 64 KiB file safety limit")
    required = (
        b"DBYW2REC",
        nonce.encode(),
        lineage_init_sha256.encode(),
        b"/init.stock",
        b"/proc/1/exe",
        b"/proc/1/cmdline",
        b"/dev/socket/property_service",
        b"PROPERTY_SERVICE_SO_PEERCRED",
        b"CLONE_FS shares root/cwd across stock FirstStage SwitchRoot",
        b"u:object_r:splash2_data_file:s0",
        b"LOG_SYSTEM_MOUNT_QUALIFIED",
        b"DBY_W2_LINEAGE_SECOND_STAGE_MARKER nonce=",
        b"dby-lineage-stage2-witness-",
        b"LINEAGE_SECOND_STAGE_OBSERVED",
        b"edl",
    )
    missing = [item.decode() for item in required if item not in probe]
    if missing:
        raise ValueError(f"W2 probe is missing required markers: {missing}")
    for forbidden in (
        b"/metadata",
        b"/data/adb",
        b"/system/bin/sh",
        b"/dev/dby-log-block",
        b"/dby-audit-log",
    ):
        if forbidden in probe:
            raise ValueError(f"W2 probe contains forbidden path: {forbidden!r}")
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


def build_w2(
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
            f"W2 requires embedded child-vbmeta flags zero, got {embedded_vbmeta_flags}"
        )
    report.update(
        {
            "experiment": "W2 Lineage second-stage property-service witness",
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
            "attempts_lineage_init": True,
            "expected_lineage_init_sha256": lineage_init_sha256,
            "second_stage_observation": (
                "exact pre-policy /proc/1/exe hash plus property_service connect "
                "and SO_PEERCRED pid=1; REA binds StartPropertyService to selected "
                "Lineage SecondStageMain"
            ),
            "qualified_sink_partition": "system-mounted /log only",
            "software_return_request": "RESTART2(edl)",
            "timeout_seconds": 90,
            "filesystem_view_contract": (
                "CLONE_FS shares root/cwd across stock FirstStage SwitchRoot"
            ),
            "diagnostic_scope": (
                "normal ramdisk only; PID1 execs retained stock first-stage init; "
                "one bounded CLONE_FS witness child; no raw mount, fsck, umount, "
                "super, system, userdata, metadata, Recovery, policy, or root change"
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
    output, report = build_w2(
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
