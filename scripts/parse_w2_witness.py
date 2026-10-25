#!/usr/bin/env python3
"""Strict parser for the DBY-W09 W2 Lineage second-stage witness."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import parse_w1_witness as common


MAGIC = b"DBYW2REC"
FORMAT = "DBY-W09-W2"
EXPECTED_PROPERTY_PATH = "/dev/socket/property_service"
EXPECTED_LOG_LABEL = "u:object_r:splash2_data_file:s0"
EXPECTED_WITNESS_CONTEXT = "u:r:kernel:s0"
EXPECTED_FILESYSTEM_VIEW_CONTRACT = (
    "CLONE_FS shares root/cwd across stock FirstStage SwitchRoot"
)
EXPECTED_OBSERVATION_RULE = (
    "property_service connect plus SO_PEERCRED pid=1 after exact pre-policy "
    "/proc/1/exe SHA-256; REA binds StartPropertyService call to selected "
    "Lineage SecondStageMain"
)
EXPECTED_PUBLICATION_PROTOCOL = (
    "O_EXCL fsync(file) renameat2(RENAME_NOREPLACE) fsync(dir) syncfs"
)
KNOWN_FLAGS_MASK = 0x7F


def _require_sha256(value: str, label: str) -> None:
    if common.SHA256_RE.fullmatch(value) is None:
        raise common.WitnessError(f"{label} must be 64 lowercase hex characters")


def parse_record(
    data: bytes,
    *,
    expected_nonce: str,
    expected_probe_sha256: str,
    expected_lineage_init_sha256: str,
    source_kind: str,
    observed_endpoint: str,
) -> dict[str, object]:
    common._validate_nonce(expected_nonce, "expected nonce")
    _require_sha256(expected_probe_sha256, "expected probe SHA-256")
    _require_sha256(expected_lineage_init_sha256, "expected Lineage init SHA-256")
    if source_kind not in common.SOURCE_KINDS:
        raise common.WitnessError(f"unsupported source kind: {source_kind}")
    if observed_endpoint not in common.OBSERVED_ENDPOINTS:
        raise common.WitnessError(f"unsupported observed endpoint: {observed_endpoint}")
    if len(data) < common.HEADER.size + 32:
        raise common.WitnessError("record is shorter than header plus checksum")

    magic, version, header_size, payload_size, flags, raw_nonce, reserved = (
        common.HEADER.unpack_from(data)
    )
    if magic != MAGIC:
        raise common.WitnessError("invalid W2 witness magic")
    if version != common.VERSION or header_size != common.HEADER.size:
        raise common.WitnessError("unsupported W2 witness header")
    if payload_size > common.MAX_PAYLOAD:
        raise common.WitnessError("W2 payload exceeds the bounded record limit")
    exact_size = header_size + payload_size + 32
    if len(data) != exact_size:
        raise common.WitnessError(
            f"exact record length is {exact_size}, observed {len(data)}"
        )
    if reserved != b"\0" * len(reserved):
        raise common.WitnessError("reserved header bytes are nonzero")
    try:
        nonce = raw_nonce.decode("ascii")
    except UnicodeDecodeError as error:
        raise common.WitnessError("header nonce is not ASCII") from error
    common._validate_nonce(nonce, "header nonce")
    if nonce != expected_nonce:
        raise common.WitnessError("W2 nonce does not match the expected candidate")

    payload = data[header_size : header_size + payload_size]
    stored_checksum = data[-32:]
    calculated_checksum = hashlib.sha256(data[:-32]).digest()
    if not hmac.compare_digest(stored_checksum, calculated_checksum):
        raise common.WitnessError("W2 checksum mismatch")
    fields = common._parse_fields(payload)
    if common._text(fields, "FORMAT") != FORMAT:
        raise common.WitnessError("W2 FORMAT is missing or invalid")
    if common._text(fields, "NONCE") != nonce:
        raise common.WitnessError("W2 payload nonce does not match header")

    failures: list[str] = []
    advisories: list[str] = []
    if flags & ~KNOWN_FLAGS_MASK:
        failures.append("unknown_header_flag_bits")

    boot_id = common._line_text(fields, "BOOT_ID")
    boot_id_valid = bool(
        boot_id is not None and common.BOOT_ID_RE.fullmatch(boot_id)
    )
    witness_hash = common._text(fields, "WITNESS_SELF_SHA256")
    witness_bound = bool(
        common._signed_decimal_field(fields, "WITNESS_SELF_SHA256_STATUS") == 0
        and witness_hash == expected_probe_sha256
        and bool(flags & (1 << 0))
    )
    if not witness_bound:
        failures.append("witness_identity_not_bound")
    if not boot_id_valid:
        failures.append("boot_id_invalid")
    witness_context = common._line_text(
        fields, "WITNESS_SELINUX_CONTEXT_AFTER_PROPERTY"
    )
    witness_context_bound = witness_context == EXPECTED_WITNESS_CONTEXT
    if not witness_context_bound:
        failures.append("witness_selinux_context_unqualified")

    property_listener_bound = bool(
        common._signed_decimal_field(fields, "PROPERTY_SERVICE_CONNECT") == 0
        and common._signed_decimal_field(fields, "PROPERTY_SERVICE_SO_PEERCRED") == 0
        and common._signed_decimal_field(fields, "PROPERTY_SERVICE_LISTENER_BOUND")
        == 1
        and common._signed_decimal_field(fields, "PROPERTY_SERVICE_PEER_PID") == 1
        and common._text(fields, "PROPERTY_SERVICE_PATH")
        == EXPECTED_PROPERTY_PATH
        and bool(flags & (1 << 2))
    )
    lineage_hash = common._text(fields, "PID1_EXE_SHA256")
    lineage_identity_bound = bool(
        common._text(fields, "LINEAGE_EXPECTED_INIT_SHA256")
        == expected_lineage_init_sha256
        and common._signed_decimal_field(fields, "PID1_EXE_SHA256_STATUS") == 0
        and lineage_hash == expected_lineage_init_sha256
        and common._signed_decimal_field(fields, "PID1_EXE_HASH_MATCH") == 1
        and common._text(fields, "PID1_EXE_LINK") == "/system/bin/init"
        and bool(flags & (1 << 1))
    )
    observation_rule_bound = (
        common._text(fields, "SECOND_STAGE_OBSERVATION_RULE")
        == EXPECTED_OBSERVATION_RULE
    )
    filesystem_view_contract_bound = (
        common._text(fields, "FILESYSTEM_VIEW_CONTRACT")
        == EXPECTED_FILESYSTEM_VIEW_CONTRACT
    )
    second_stage_observed = bool(
        property_listener_bound
        and lineage_identity_bound
        and observation_rule_bound
        and common._signed_decimal_field(fields, "LINEAGE_SECOND_STAGE_OBSERVED")
        == 1
    )
    if not property_listener_bound:
        failures.append("property_service_listener_not_bound_to_pid1")
    if not lineage_identity_bound:
        failures.append("lineage_init_identity_not_bound")
    if not observation_rule_bound:
        failures.append("second_stage_observation_rule_mismatch")
    if not filesystem_view_contract_bound:
        failures.append("filesystem_view_contract_mismatch")
    if not second_stage_observed:
        failures.append("lineage_second_stage_not_observed")
    pid1_cmdline = fields.get("PID1_CMDLINE", b"")
    if b"second_stage" not in pid1_cmdline:
        advisories.append("pid1_cmdline_lacks_second_stage_token")

    expected_marker_message = (
        "DBY_W2_LINEAGE_SECOND_STAGE_MARKER nonce=" + nonce
    )
    kmsg_write_accepted = bool(
        common._text(fields, "KMSG_MARKER_MESSAGE") == expected_marker_message
        and (writer := common._signed_decimal_field(fields, "KMSG_MARKER_WRITER_OPEN"))
        is not None
        and writer >= 0
        and common._signed_decimal_field(fields, "KMSG_MARKER_WRITE") == 0
        and common._signed_decimal_field(fields, "KMSG_MARKER_WRITER_CLOSE") == 0
        and bool(flags & (1 << 3))
    )
    if not kmsg_write_accepted:
        failures.append("current_kernel_kmsg_write_not_accepted")

    mountinfo_line = common._text(fields, "LOG_MOUNTINFO_LINE")
    mountinfo_bound = False
    if mountinfo_line is not None and " - " in mountinfo_line:
        pre_separator, post_separator = mountinfo_line.split(" - ", 1)
        pre_fields = pre_separator.split()
        post_fields = post_separator.split()
        mountinfo_bound = bool(
            len(pre_fields) >= 5
            and len(post_fields) >= 2
            and pre_fields[2] == "8:12"
            and pre_fields[3] == "/"
            and pre_fields[4] == "/log"
            and post_fields[0] == "ext4"
        )

    log_identity_bound = bool(
        common._text(fields, "LOG_DEVNAME") == common.EXPECTED_LOG_DEVNAME
        and common._text(fields, "LOG_EXPECTED_PARTUUID")
        == common.EXPECTED_LOG_PARTUUID
        and common._signed_decimal_field(fields, "LOG_PARTUUID_EXPORTED") in {0, 1}
        and common._decimal_field(fields, "LOG_MAJOR") == common.EXPECTED_LOG_MAJOR
        and common._decimal_field(fields, "LOG_MINOR") == common.EXPECTED_LOG_MINOR
        and common._decimal_field(fields, "LOG_SECTORS_512")
        == common.EXPECTED_LOG_SECTORS_512
        and common._text(fields, "LOG_EXPECTED_FSUUID")
        == common.EXPECTED_LOG_FSUUID_HEX
        and common._text(fields, "LOG_EXPECTED_SELINUX_LABEL")
        == EXPECTED_LOG_LABEL
        and common._text(fields, "LOG_SELINUX_LABEL") == EXPECTED_LOG_LABEL
        and mountinfo_bound
        and common._signed_decimal_field(fields, "LOG_SUPERBLOCK_VERIFY") == 0
        and common._signed_decimal_field(fields, "LOG_SYSTEM_MOUNT_QUALIFIED") == 0
        and common._text(fields, "PUBLICATION_PROTOCOL")
        == EXPECTED_PUBLICATION_PROTOCOL
        and bool(flags & (1 << 4))
        and bool(flags & (1 << 5))
    )
    if not log_identity_bound:
        failures.append("log_sink_identity_not_bound")
    if flags & (1 << 6):
        failures.append("payload_truncated")

    raw_final = source_kind == "edl_raw_final"
    endpoint_edl = observed_endpoint == "edl"
    if not raw_final:
        failures.append("record_not_recovered_from_edl_raw_final")
    if not endpoint_edl:
        failures.append("edl_endpoint_not_observed")
    strong_pass = bool(
        not failures
        and boot_id_valid
        and witness_bound
        and second_stage_observed
        and kmsg_write_accepted
        and log_identity_bound
        and raw_final
        and endpoint_edl
    )

    return {
        "format": FORMAT,
        "integrity": {
            "checksum_valid": True,
            "record_sha256": hashlib.sha256(data).hexdigest(),
            "record_size": len(data),
            "payload_size": payload_size,
        },
        "identity": {
            "nonce": nonce,
            "witness_sha256": witness_hash,
            "boot_id": boot_id,
            "boot_id_valid": boot_id_valid,
            "witness_selinux_context": witness_context,
            "expected_lineage_init_sha256": expected_lineage_init_sha256,
            "pid1_exe_sha256": lineage_hash,
            "pid1_exe_link": common._text(fields, "PID1_EXE_LINK"),
            "pid1_cmdline_contains_second_stage": b"second_stage" in pid1_cmdline,
            "property_service_listener_bound_to_pid1": property_listener_bound,
            "property_service_observed_iteration": common._decimal_field(
                fields, "PROPERTY_SERVICE_OBSERVED_ITERATION"
            ),
            "property_service_peer_pid": common._signed_decimal_field(
                fields, "PROPERTY_SERVICE_PEER_PID"
            ),
            "log_mountinfo_bound": mountinfo_bound,
            "log_selinux_label": common._text(fields, "LOG_SELINUX_LABEL"),
        },
        "observation": {
            "source_kind": source_kind,
            "observed_endpoint": observed_endpoint,
            "second_stage_signal": (
                "property_service listener accepts connect and reports PID1 via SO_PEERCRED"
            ),
            "rea_second_stage_main": "0x22ee70",
            "rea_start_property_service_callsite": "0x22f490",
            "rea_start_property_service": "0x250638",
            "does_not_prove_android_framework_boot": True,
            "does_not_prove_hardware_compatibility": True,
            "does_not_prove_kmsg_readback": True,
            "does_not_prove_reboot_return": True,
        },
        "flags": {"raw": flags},
        "fields": {name: common._summary(value) for name, value in fields.items()},
        "failures": failures,
        "advisories": advisories,
        "outcome": {
            "record_integrity_valid": True,
            "witness_identity_bound": witness_bound,
            "lineage_init_identity_bound": lineage_identity_bound,
            "lineage_second_stage_observed": second_stage_observed,
            "current_kernel_kmsg_write_accepted": kmsg_write_accepted,
            "sink_identity_bound": log_identity_bound,
            "edl_endpoint_observed": endpoint_edl,
            "end_to_end_success": strong_pass,
            "strong_pass": strong_pass,
            "android_framework_boot_proven": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    parser.add_argument("--expected-nonce", required=True)
    parser.add_argument("--expected-probe-sha256", required=True)
    parser.add_argument("--expected-lineage-init-sha256", required=True)
    parser.add_argument(
        "--source-kind", required=True, choices=sorted(common.SOURCE_KINDS)
    )
    parser.add_argument(
        "--observed-endpoint",
        default="unknown",
        choices=sorted(common.OBSERVED_ENDPOINTS),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = parse_record(
        args.record.read_bytes(),
        expected_nonce=args.expected_nonce,
        expected_probe_sha256=args.expected_probe_sha256,
        expected_lineage_init_sha256=args.expected_lineage_init_sha256,
        source_kind=args.source_kind,
        observed_endpoint=args.observed_endpoint,
    )
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        if args.output.exists():
            parser.error(f"refusing to overwrite existing output: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    return 0 if report["outcome"]["end_to_end_success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
