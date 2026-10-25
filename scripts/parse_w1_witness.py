#!/usr/bin/env python3
"""Strict parser and verifier for a DBY-W09 W1 witness record."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import struct
from pathlib import Path


HEADER = struct.Struct("<8sIIII32s8s")
MAGIC = b"DBYW1REC"
VERSION = 1
MAX_PAYLOAD = 128 * 1024
NONCE_RE = re.compile(r"[0-9a-f]{32}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
FIELD_NAME_RE = re.compile(rb"[A-Z][A-Z0-9_]{0,63}")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
KMSG_RECORD_RE = re.compile(
    rb"^(?P<priority>[0-9]+),(?P<sequence>[0-9]+),(?P<timestamp>[0-9]+),"
    rb"(?P<flags>[A-Za-z0-9+_-]+);(?P<message>[^\r\n]*)(?:\n)?$"
)
VENDOR_CALLER_PREFIX_RE = re.compile(
    rb"^(?P<prefix>"
    rb"(?:\[[0-9]{4}:[0-9]{2}:[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\])?"
    rb"\([0-9]+\)\[1:[\x21-\x5a\x5c\x5e-\x7e]{1,32}\])"
)
EXPECTED_LOG_DEVNAME = "sda12"
EXPECTED_LOG_PARTUUID = "906d7124-62f7-d1c8-ffbf-73c97575983f"
EXPECTED_LOG_MAJOR = 8
EXPECTED_LOG_MINOR = 12
EXPECTED_LOG_SECTORS_512 = 163_840
EXPECTED_LOG_FSUUID_HEX = "e3ff96a22fe448d28c2daef8d068275d"
EXPECTED_PUBLICATION_PROTOCOL = (
    "O_EXCL fsync(file) renameat2(RENAME_NOREPLACE) fsync(dir) umount"
)
KNOWN_FLAGS_MASK = 0xFF
SOURCE_KINDS = {"unknown", "direct", "edl_raw_final", "edl_raw_temp"}
OBSERVED_ENDPOINTS = {
    "unknown",
    "edl",
    "fastboot",
    "recovery",
    "offline",
    "bootloop",
}


class WitnessError(ValueError):
    """Raised when a witness record is malformed or fails identity checks."""


def _validate_nonce(value: str, label: str) -> None:
    if NONCE_RE.fullmatch(value) is None:
        raise WitnessError(f"{label} must be 32 lowercase hexadecimal characters")


def _validate_sha256(value: str, label: str) -> None:
    if SHA256_RE.fullmatch(value) is None:
        raise WitnessError(f"{label} must be 64 lowercase hexadecimal characters")


def _parse_fields(payload: bytes) -> dict[str, bytes]:
    fields: dict[str, bytes] = {}
    cursor = 0
    while cursor < len(payload):
        colon = payload.find(b":", cursor)
        newline = payload.find(b"\n", cursor)
        if colon < 0 or newline < 0 or colon >= newline:
            raise WitnessError(f"malformed payload field header at offset {cursor}")
        raw_name = payload[cursor:colon]
        raw_length = payload[colon + 1 : newline]
        if FIELD_NAME_RE.fullmatch(raw_name) is None:
            raise WitnessError(f"invalid payload field name at offset {cursor}")
        if not raw_length or not raw_length.isdigit():
            raise WitnessError(f"invalid payload field length at offset {cursor}")
        if len(raw_length) > 1 and raw_length.startswith(b"0"):
            raise WitnessError(f"non-canonical payload field length at offset {cursor}")
        value_length = int(raw_length)
        value_start = newline + 1
        value_end = value_start + value_length
        if value_end >= len(payload) or payload[value_end] != 0x0A:
            raise WitnessError(f"payload field overruns record at offset {cursor}")
        name = raw_name.decode("ascii")
        if name in fields:
            raise WitnessError(f"duplicate payload field: {name}")
        fields[name] = payload[value_start:value_end]
        cursor = value_end + 1
    return fields


def _text(fields: dict[str, bytes], name: str) -> str | None:
    value = fields.get(name)
    if value is None:
        return None
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _line_text(fields: dict[str, bytes], name: str) -> str | None:
    value = _text(fields, name)
    if value is None:
        return None
    if value.endswith("\n"):
        value = value[:-1]
    if value.endswith("\r"):
        value = value[:-1]
    return value


def _decimal_field(fields: dict[str, bytes], name: str) -> int | None:
    value = _text(fields, name)
    if value is None or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _signed_decimal_field(fields: dict[str, bytes], name: str) -> int | None:
    value = _text(fields, name)
    if value is None or re.fullmatch(r"0|-?[1-9][0-9]*", value) is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _summary(value: bytes) -> dict[str, object]:
    result: dict[str, object] = {
        "length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        result["base64"] = base64.b64encode(value).decode("ascii")
        return result
    if all(character.isprintable() or character in "\r\n\t" for character in decoded):
        result["text"] = decoded
    else:
        result["base64"] = base64.b64encode(value).decode("ascii")
    return result


def parse_record(
    data: bytes,
    *,
    expected_nonce: str | None = None,
    expected_probe_sha256: str | None = None,
    source_kind: str = "unknown",
    observed_endpoint: str = "unknown",
) -> dict[str, object]:
    if expected_nonce is not None:
        _validate_nonce(expected_nonce, "expected nonce")
    if expected_probe_sha256 is not None:
        _validate_sha256(expected_probe_sha256, "expected probe SHA-256")
    if source_kind not in SOURCE_KINDS:
        raise WitnessError(f"unsupported source kind: {source_kind}")
    if observed_endpoint not in OBSERVED_ENDPOINTS:
        raise WitnessError(f"unsupported observed endpoint: {observed_endpoint}")
    if len(data) < HEADER.size + 32:
        raise WitnessError("record is shorter than header plus checksum")

    magic, version, header_size, payload_size, flags, raw_nonce, reserved = (
        HEADER.unpack_from(data)
    )
    if magic != MAGIC:
        raise WitnessError("invalid witness magic")
    if version != VERSION:
        raise WitnessError(f"unsupported witness version: {version}")
    if header_size != HEADER.size:
        raise WitnessError(f"unexpected witness header size: {header_size}")
    if payload_size > MAX_PAYLOAD:
        raise WitnessError(f"payload exceeds {MAX_PAYLOAD}-byte limit")
    exact_size = header_size + payload_size + 32
    if len(data) != exact_size:
        raise WitnessError(
            f"exact record length is {exact_size} bytes, observed {len(data)}"
        )
    if reserved != b"\0" * len(reserved):
        raise WitnessError("reserved header bytes are nonzero")
    try:
        nonce = raw_nonce.decode("ascii")
    except UnicodeDecodeError as error:
        raise WitnessError("header nonce is not ASCII") from error
    _validate_nonce(nonce, "header nonce")
    if expected_nonce is not None and nonce != expected_nonce:
        raise WitnessError(
            f"expected nonce {expected_nonce}, record contains {nonce}"
        )

    payload = data[header_size : header_size + payload_size]
    stored_checksum = data[-32:]
    calculated_checksum = hashlib.sha256(data[:-32]).digest()
    if not hmac.compare_digest(stored_checksum, calculated_checksum):
        raise WitnessError("witness checksum mismatch")

    fields = _parse_fields(payload)
    if _text(fields, "FORMAT") != "DBY-W09-W1":
        raise WitnessError("payload FORMAT is missing or invalid")
    if _text(fields, "NONCE") != nonce:
        raise WitnessError("payload NONCE does not match header nonce")

    self_hash = _text(fields, "SELF_SHA256")
    if self_hash is not None and SHA256_RE.fullmatch(self_hash) is None:
        raise WitnessError("payload SELF_SHA256 is invalid")
    if (
        expected_probe_sha256 is not None
        and self_hash is not None
        and self_hash != expected_probe_sha256
    ):
        raise WitnessError(
            "expected probe SHA-256 does not match payload SELF_SHA256"
        )

    failures: list[str] = []
    advisories: list[str] = []
    unknown_flag_bits = flags & ~KNOWN_FLAGS_MASK
    if unknown_flag_bits:
        failures.append("unknown_header_flag_bits")

    proc_ready = _text(fields, "MOUNT_PROC") == "0" and bool(flags & (1 << 5))
    pid1 = _text(fields, "PID") == "1" and bool(flags & (1 << 0))
    boot_id = _line_text(fields, "BOOT_ID")
    boot_id_valid = boot_id is not None and BOOT_ID_RE.fullmatch(boot_id) is not None
    self_bound = (
        expected_probe_sha256 is not None
        and _text(fields, "SELF_SHA256_STATUS") == "0"
        and self_hash == expected_probe_sha256
        and bool(flags & (1 << 1))
    )
    nonce_expected = expected_nonce is not None and nonce == expected_nonce
    pid1_identity_bound = bool(
        nonce_expected and proc_ready and pid1 and boot_id_valid and self_bound
    )
    if not pid1_identity_bound:
        failures.append("pid1_identity_not_bound")

    marker = fields.get("KMSG_MARKER_RECORD", b"")
    marker_match = KMSG_RECORD_RE.fullmatch(marker)
    expected_marker_message = (
        b"DBY_W1_USERSPACE_MARKER nonce=" + nonce.encode("ascii")
    )
    marker_priority = (
        int(marker_match.group("priority")) if marker_match is not None else None
    )
    marker_sequence = (
        int(marker_match.group("sequence")) if marker_match is not None else None
    )
    marker_timestamp = (
        int(marker_match.group("timestamp")) if marker_match is not None else None
    )
    marker_flags = (
        marker_match.group("flags").decode("ascii", errors="replace")
        if marker_match is not None
        else None
    )
    monotonic_start_ns = _decimal_field(fields, "MONOTONIC_START_NS")
    monotonic_prepublish_ns = _decimal_field(fields, "MONOTONIC_PREPUBLISH_NS")
    marker_format_valid = bool(
        marker_match is not None
        and marker_priority is not None
        and 0 <= marker_priority <= 191
        and marker_sequence is not None
        and marker_timestamp is not None
        and marker_timestamp > 0
    )
    marker_message = marker_match.group("message") if marker_match is not None else b""
    vendor_prefix_match = VENDOR_CALLER_PREFIX_RE.match(marker_message)
    marker_vendor_prefix = (
        vendor_prefix_match.group("prefix") if vendor_prefix_match is not None else b""
    )
    marker_message_without_vendor_prefix = marker_message[len(marker_vendor_prefix) :]
    marker_message_exact = bool(
        marker_match is not None
        and marker_message_without_vendor_prefix == expected_marker_message
    )
    marker_timestamp_in_window = bool(
        marker_timestamp is not None
        and monotonic_start_ns is not None
        and monotonic_prepublish_ns is not None
        and _text(fields, "CLOCK_GETTIME_START") == "0"
        and _text(fields, "CLOCK_GETTIME_END") == "0"
        and monotonic_start_ns <= marker_timestamp * 1000 <= monotonic_prepublish_ns
    )
    marker_structured_fields_match = bool(
        marker_priority is not None
        and marker_sequence is not None
        and marker_timestamp is not None
        and _decimal_field(fields, "KMSG_MARKER_PRIORITY") == marker_priority
        and _decimal_field(fields, "KMSG_MARKER_SEQUENCE") == marker_sequence
        and _decimal_field(fields, "KMSG_MARKER_TIMESTAMP_US") == marker_timestamp
        and _signed_decimal_field(fields, "KMSG_MARKER_VENDOR_PREFIXED")
        == (1 if marker_vendor_prefix else 0)
    )
    marker_reader_open = _signed_decimal_field(fields, "KMSG_MARKER_READER_OPEN")
    marker_seek_end = _signed_decimal_field(fields, "KMSG_MARKER_SEEK_END")
    marker_writer_open = _signed_decimal_field(fields, "KMSG_MARKER_WRITER_OPEN")
    marker_operations_ok = bool(
        _signed_decimal_field(fields, "MKNOD_KMSG") == 0
        and marker_reader_open is not None
        and marker_reader_open >= 0
        and marker_seek_end is not None
        and marker_seek_end >= 0
        and marker_writer_open is not None
        and marker_writer_open >= 0
        and _signed_decimal_field(fields, "KMSG_MARKER_WRITE") == 0
        and _signed_decimal_field(fields, "KMSG_MARKER_WRITER_CLOSE") == 0
        and _signed_decimal_field(fields, "KMSG_MARKER_READER_CLOSE") == 0
        and "KMSG_MARKER_READ" not in fields
    )
    marker_status_consistent = bool(
        _text(fields, "KMSG_MARKER_STATUS") == "0"
        and bool(flags & (1 << 2))
    )
    marker_bound = bool(
        marker_format_valid
        and marker_message_exact
        and marker_structured_fields_match
        and marker_operations_ok
        and marker_status_consistent
    )
    if not marker_timestamp_in_window:
        # Linux 4.19 exports a monotonic /dev/kmsg timestamp, but printk stores
        # local_clock(), whose base is not guaranteed to equal userspace
        # CLOCK_MONOTONIC.  SEEK_END + exact nonce readback is the binding
        # evidence; the cross-clock comparison is diagnostic only.
        advisories.append("kmsg_timestamp_not_in_userspace_monotonic_window")
    if marker_match is None or not marker_format_valid:
        failures.append("kmsg_record_format_invalid")
    elif not marker_message_exact:
        failures.append("kmsg_marker_message_mismatch")
    elif not marker_structured_fields_match:
        failures.append("kmsg_structured_fields_mismatch")
    elif not marker_operations_ok:
        failures.append("kmsg_operation_failure")
    elif not marker_status_consistent:
        failures.append("kmsg_status_or_flag_inconsistent")
    kmsg_readback_bound = bool(pid1_identity_bound and marker_bound)

    log_major = _decimal_field(fields, "LOG_MAJOR")
    log_minor = _decimal_field(fields, "LOG_MINOR")
    log_sectors = _decimal_field(fields, "LOG_SECTORS_512")
    log_partuuid_exported = _signed_decimal_field(
        fields, "LOG_PARTUUID_EXPORTED"
    )
    log_partuuid = _text(fields, "LOG_PARTUUID")
    log_partuuid_observation_bound = bool(
        _text(fields, "LOG_EXPECTED_PARTUUID") == EXPECTED_LOG_PARTUUID
        and (
            (log_partuuid_exported == 1 and log_partuuid == EXPECTED_LOG_PARTUUID)
            or (log_partuuid_exported == 0 and log_partuuid is None)
        )
    )
    sink_identity_bound = bool(
        _text(fields, "LOG_DISCOVERY") == "0"
        and _text(fields, "LOG_DEVNAME") == EXPECTED_LOG_DEVNAME
        and log_partuuid_observation_bound
        and log_major == EXPECTED_LOG_MAJOR
        and log_minor == EXPECTED_LOG_MINOR
        and log_sectors == EXPECTED_LOG_SECTORS_512
        and _text(fields, "LOG_SUPERBLOCK_VERIFY") == "0"
        and _text(fields, "LOG_EXPECTED_FSUUID") == EXPECTED_LOG_FSUUID_HEX
        and _text(fields, "MOUNT_LOG") == "0"
        and _text(fields, "PUBLICATION_PROTOCOL") == EXPECTED_PUBLICATION_PROTOCOL
        and bool(flags & (1 << 3))
        and bool(flags & (1 << 7))
    )
    if not sink_identity_bound:
        failures.append("sink_identity_mismatch")

    not_truncated = (
        _text(fields, "KMSG_SNAPSHOT_TRUNCATED") == "0"
        and not bool(flags & (1 << 4))
    )
    if not not_truncated:
        advisories.append("kmsg_snapshot_truncated")

    record_integrity_valid = True
    witness_evidence_gate_pass = bool(
        record_integrity_valid
        and unknown_flag_bits == 0
        and pid1_identity_bound
        and kmsg_readback_bound
        and sink_identity_bound
    )
    recovered_from_edl_raw_final = source_kind == "edl_raw_final"
    experiment_evidence_pass = bool(
        witness_evidence_gate_pass and recovered_from_edl_raw_final
    )
    edl_endpoint_observed = observed_endpoint == "edl"
    end_to_end_success = bool(experiment_evidence_pass and edl_endpoint_observed)
    if not recovered_from_edl_raw_final:
        failures.append("not_recovered_from_edl_raw_final")
    if not edl_endpoint_observed:
        failures.append("edl_endpoint_not_observed")

    return {
        "format": "DBY-W09-W1 witness verification",
        "integrity": {
            "checksum_valid": True,
            "stored_sha256": stored_checksum.hex(),
            "calculated_sha256": calculated_checksum.hex(),
            "record_sha256": hashlib.sha256(data).hexdigest(),
            "record_size": len(data),
            "header_size": header_size,
            "payload_size": payload_size,
        },
        "identity": {
            "nonce": nonce,
            "expected_nonce_matched": nonce_expected,
            "probe_sha256": self_hash,
            "expected_probe_sha256_matched": self_bound,
            "boot_id": boot_id,
            "boot_id_valid": boot_id_valid,
            "kmsg_marker_priority": marker_priority,
            "kmsg_marker_sequence": marker_sequence,
            "kmsg_marker_timestamp_us": marker_timestamp,
            "kmsg_marker_flags": marker_flags,
            "kmsg_marker_message_exact": marker_message_exact,
            "kmsg_marker_vendor_prefix": marker_vendor_prefix.decode(
                "ascii", errors="replace"
            ),
            "kmsg_marker_timestamp_in_window": marker_timestamp_in_window,
            "log_devname": _text(fields, "LOG_DEVNAME"),
            "log_expected_partuuid": _text(fields, "LOG_EXPECTED_PARTUUID"),
            "log_partuuid_exported": log_partuuid_exported,
            "log_partuuid": log_partuuid,
            "log_partuuid_observation_bound": log_partuuid_observation_bound,
            "log_major": log_major,
            "log_minor": log_minor,
            "log_sectors_512": log_sectors,
        },
        "observation": {
            "source_kind": source_kind,
            "observed_endpoint": observed_endpoint,
            "recovered_from_edl_raw_final": recovered_from_edl_raw_final,
            "edl_endpoint_observed": edl_endpoint_observed,
            "does_not_prove_directory_fsync_return": True,
            "does_not_prove_umount_return": True,
            "does_not_prove_sync_return": True,
            "does_not_prove_reboot_syscall_acceptance": True,
            "kmsg_timestamp_window_is_advisory": True,
        },
        "flags": {
            "raw": flags,
            "pid1": bool(flags & (1 << 0)),
            "self_hash": bool(flags & (1 << 1)),
            "kmsg_marker_readback": bool(flags & (1 << 2)),
            "log_identity": bool(flags & (1 << 3)),
            "payload_truncated": bool(flags & (1 << 4)),
            "proc_ready": bool(flags & (1 << 5)),
            "sys_ready": bool(flags & (1 << 6)),
            "log_mounted": bool(flags & (1 << 7)),
        },
        "fields": {name: _summary(value) for name, value in fields.items()},
        "failures": failures,
        "advisories": advisories,
        "outcome": {
            "record_integrity_valid": record_integrity_valid,
            "pid1_identity_bound": pid1_identity_bound,
            "kmsg_readback_bound": kmsg_readback_bound,
            "sink_identity_bound": sink_identity_bound,
            "witness_evidence_gate_pass": witness_evidence_gate_pass,
            "experiment_evidence_pass": experiment_evidence_pass,
            "edl_endpoint_observed": edl_endpoint_observed,
            "end_to_end_success": end_to_end_success,
            "pid1_execution_proven": pid1_identity_bound,
            "current_kernel_kmsg_bound": kmsg_readback_bound,
            "sink_identity_and_mount_bound": sink_identity_bound,
            "capture_not_truncated": not_truncated,
            "strong_pass": end_to_end_success,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    parser.add_argument("--expected-nonce", required=True)
    parser.add_argument("--expected-probe-sha256", required=True)
    parser.add_argument(
        "--source-kind",
        required=True,
        choices=sorted(SOURCE_KINDS - {"unknown"}),
        help="how the record was obtained; only edl_raw_final can pass the experiment gate",
    )
    parser.add_argument(
        "--observed-endpoint",
        default="unknown",
        choices=sorted(OBSERVED_ENDPOINTS),
        help="independently observed device endpoint after the W1 attempt",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = parse_record(
        args.record.read_bytes(),
        expected_nonce=args.expected_nonce,
        expected_probe_sha256=args.expected_probe_sha256,
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
