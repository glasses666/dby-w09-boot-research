from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "scripts" / "parse_w1_witness.py"
NONCE = "00112233445566778899aabbccddeeff"
PROBE_SHA256 = "7a" * 32
HEADER = struct.Struct("<8sIIII32s8s")
LOG_PARTUUID = "906d7124-62f7-d1c8-ffbf-73c97575983f"
LOG_FSUUID_HEX = "e3ff96a22fe448d28c2daef8d068275d"
PUBLICATION_PROTOCOL = (
    "O_EXCL fsync(file) renameat2(RENAME_NOREPLACE) fsync(dir) umount"
)


def load_parser():
    if not PARSER.exists():
        raise AssertionError(f"missing W1 parser: {PARSER}")
    spec = importlib.util.spec_from_file_location("parse_w1_witness", PARSER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {PARSER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def field(name: str, value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return name.encode("ascii") + b":" + str(len(value)).encode() + b"\n" + value + b"\n"


def valid_record(
    *,
    boot_id: str = "12345678-1234-4abc-8def-1234567890ab",
    include_self_hash: bool = True,
    marker_record: str | None = None,
    omit_fields: frozenset[str] = frozenset(),
    field_overrides: dict[str, str] | None = None,
    flags_override: int | None = None,
) -> bytes:
    if marker_record is None:
        marker_record = f"6,10,20000,-;DBY_W1_USERSPACE_MARKER nonce={NONCE}\n"
    values = {
        "FORMAT": "DBY-W09-W1",
        "NONCE": NONCE,
        "PID": "1",
        "MOUNT_PROC": "0",
        "MOUNT_SYS": "0",
        "BOOT_ID": boot_id,
        "SELF_SHA256_STATUS": "0" if include_self_hash else "-2",
        "KMSG_MARKER_STATUS": "0",
        "MKNOD_KMSG": "0",
        "KMSG_MARKER_READER_OPEN": "3",
        "KMSG_MARKER_SEEK_END": "0",
        "KMSG_MARKER_WRITER_OPEN": "4",
        "KMSG_MARKER_WRITE": "0",
        "KMSG_MARKER_WRITER_CLOSE": "0",
        "KMSG_MARKER_READER_CLOSE": "0",
        "KMSG_MARKER_RECORD": marker_record,
        "KMSG_MARKER_PRIORITY": "6",
        "KMSG_MARKER_SEQUENCE": "10",
        "KMSG_MARKER_TIMESTAMP_US": "20000",
        "KMSG_MARKER_VENDOR_PREFIXED": "0",
        "LOG_DISCOVERY": "0",
        "LOG_DEVNAME": "sda12",
        "LOG_EXPECTED_PARTUUID": LOG_PARTUUID,
        "LOG_PARTUUID_EXPORTED": "0",
        "LOG_MAJOR": "8",
        "LOG_MINOR": "12",
        "LOG_SECTORS_512": "163840",
        "LOG_SUPERBLOCK_VERIFY": "0",
        "LOG_EXPECTED_FSUUID": LOG_FSUUID_HEX,
        "MOUNT_LOG": "0",
        "PUBLICATION_PROTOCOL": PUBLICATION_PROTOCOL,
        "CLOCK_GETTIME_START": "0",
        "MONOTONIC_START_NS": "10000000",
        "CLOCK_GETTIME_END": "0",
        "MONOTONIC_PREPUBLISH_NS": "30000000",
        "KMSG_SNAPSHOT_TRUNCATED": "0",
    }
    if include_self_hash:
        values["SELF_SHA256"] = PROBE_SHA256
    if field_overrides:
        values.update(field_overrides)
    payload = b"".join(
        field(name, value)
        for name, value in values.items()
        if name not in omit_fields
    )
    flags = 1 | 4 | 8 | 32 | 64 | 128
    if include_self_hash:
        flags |= 2
    if flags_override is not None:
        flags = flags_override
    header = HEADER.pack(
        b"DBYW1REC", 1, HEADER.size, len(payload), flags, NONCE.encode(), b"\0" * 8
    )
    return header + payload + hashlib.sha256(header + payload).digest()


class W1WitnessParserTests(unittest.TestCase):
    def test_proc_boot_id_trailing_newline_is_canonicalized(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(boot_id="12345678-1234-4abc-8def-1234567890ab\n"),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
        )

        self.assertEqual(
            "12345678-1234-4abc-8def-1234567890ab",
            report["identity"]["boot_id"],
        )
        self.assertTrue(report["outcome"]["pid1_execution_proven"])

    def test_valid_record_proves_pid1_and_current_kmsg_binding(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertTrue(report["integrity"]["checksum_valid"])
        self.assertEqual(NONCE, report["identity"]["nonce"])
        self.assertEqual("1", report["fields"]["PID"]["text"])
        self.assertTrue(report["outcome"]["pid1_execution_proven"])
        self.assertTrue(report["outcome"]["current_kernel_kmsg_bound"])
        self.assertTrue(report["outcome"]["record_integrity_valid"])
        self.assertTrue(report["outcome"]["pid1_identity_bound"])
        self.assertTrue(report["outcome"]["kmsg_readback_bound"])
        self.assertTrue(report["outcome"]["sink_identity_bound"])
        self.assertTrue(report["outcome"]["experiment_evidence_pass"])
        self.assertTrue(report["outcome"]["end_to_end_success"])
        self.assertTrue(report["outcome"]["strong_pass"])
        self.assertEqual(10, report["identity"]["kmsg_marker_sequence"])
        self.assertEqual(20000, report["identity"]["kmsg_marker_timestamp_us"])

    def test_corrupt_digest_is_rejected(self):
        parser = load_parser()
        damaged = bytearray(valid_record())
        damaged[-1] ^= 1
        with self.assertRaisesRegex(parser.WitnessError, "checksum"):
            parser.parse_record(bytes(damaged), expected_nonce=NONCE)

    def test_expected_nonce_mismatch_is_rejected(self):
        parser = load_parser()
        with self.assertRaisesRegex(parser.WitnessError, "expected nonce"):
            parser.parse_record(valid_record(), expected_nonce="ff" * 16)

    def test_trailing_bytes_are_rejected(self):
        parser = load_parser()
        with self.assertRaisesRegex(parser.WitnessError, "exact record length"):
            parser.parse_record(valid_record() + b"trailing")

    def test_malformed_length_delimited_payload_is_rejected(self):
        parser = load_parser()
        record = bytearray(valid_record())
        payload_start = HEADER.size
        record[payload_start : payload_start + len(b"FORMAT:10")] = b"FORMAT:99"
        record[-32:] = hashlib.sha256(record[:-32]).digest()
        with self.assertRaisesRegex(parser.WitnessError, "payload field"):
            parser.parse_record(bytes(record), expected_nonce=NONCE)

    def test_expected_probe_hash_mismatch_prevents_false_identity(self):
        parser = load_parser()
        with self.assertRaisesRegex(parser.WitnessError, "probe SHA-256"):
            parser.parse_record(
                valid_record(), expected_nonce=NONCE, expected_probe_sha256="bb" * 32
            )

    def test_recorded_self_hash_failure_remains_parseable_partial_evidence(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(include_self_hash=False),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
        )

        self.assertFalse(report["identity"]["expected_probe_sha256_matched"])
        self.assertFalse(report["outcome"]["pid1_execution_proven"])
        self.assertFalse(report["outcome"]["strong_pass"])

    def test_marker_without_kernel_record_prefix_is_not_kmsg_bound(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(
                marker_record=f"DBY_W1_USERSPACE_MARKER nonce={NONCE}\n"
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
        )

        self.assertTrue(report["outcome"]["pid1_execution_proven"])
        self.assertFalse(report["outcome"]["current_kernel_kmsg_bound"])
        self.assertFalse(report["outcome"]["strong_pass"])

    def test_marker_message_must_match_exactly_not_as_substring(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(
                marker_record=(
                    f"6,10,20000,-;prefix DBY_W1_USERSPACE_MARKER "
                    f"nonce={NONCE} suffix\n"
                )
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertFalse(report["outcome"]["kmsg_readback_bound"])
        self.assertFalse(report["outcome"]["experiment_evidence_pass"])

    def test_marker_timestamp_window_is_advisory_not_cross_clock_gate(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(
                marker_record=(
                    f"6,10,999999,-;DBY_W1_USERSPACE_MARKER nonce={NONCE}\n"
                ),
                field_overrides={"KMSG_MARKER_TIMESTAMP_US": "999999"},
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertTrue(report["outcome"]["kmsg_readback_bound"])
        self.assertTrue(report["outcome"]["end_to_end_success"])
        self.assertNotIn(
            "kmsg_timestamp_outside_monotonic_window", report["failures"]
        )
        self.assertIn(
            "kmsg_timestamp_not_in_userspace_monotonic_window",
            report["advisories"],
        )

    def test_structured_marker_fields_must_match_raw_kmsg_record(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(field_overrides={"KMSG_MARKER_SEQUENCE": "11"}),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertFalse(report["outcome"]["kmsg_readback_bound"])
        self.assertIn("kmsg_structured_fields_mismatch", report["failures"])

    def test_exact_vendor_pid1_prefix_is_accepted(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(
                marker_record=(
                    f"6,10,20000,-;(4)[1:init]"
                    f"DBY_W1_USERSPACE_MARKER nonce={NONCE}\n"
                ),
                field_overrides={"KMSG_MARKER_VENDOR_PREFIXED": "1"},
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertTrue(report["outcome"]["kmsg_readback_bound"])
        self.assertEqual("(4)[1:init]", report["identity"]["kmsg_marker_vendor_prefix"])

    def test_vendor_prefix_for_non_pid1_is_rejected(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(
                marker_record=(
                    f"6,10,20000,-;(4)[2:init]"
                    f"DBY_W1_USERSPACE_MARKER nonce={NONCE}\n"
                ),
                field_overrides={"KMSG_MARKER_VENDOR_PREFIXED": "1"},
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertFalse(report["outcome"]["kmsg_readback_bound"])
        self.assertIn("kmsg_marker_message_mismatch", report["failures"])

    def test_exact_timestamped_vendor_pid1_prefix_is_accepted(self):
        parser = load_parser()
        prefix = "[1970:01:01 00:00:01](7)[1:init]"
        report = parser.parse_record(
            valid_record(
                marker_record=(
                    f"6,10,20000,-;{prefix}"
                    f"DBY_W1_USERSPACE_MARKER nonce={NONCE}\n"
                ),
                field_overrides={"KMSG_MARKER_VENDOR_PREFIXED": "1"},
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertTrue(report["outcome"]["kmsg_readback_bound"])
        self.assertEqual(prefix, report["identity"]["kmsg_marker_vendor_prefix"])

    def test_malformed_vendor_timestamp_prefix_is_rejected(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(
                marker_record=(
                    f"6,10,20000,-;[1970-01-01 00:00:01](7)[1:init]"
                    f"DBY_W1_USERSPACE_MARKER nonce={NONCE}\n"
                ),
                field_overrides={"KMSG_MARKER_VENDOR_PREFIXED": "1"},
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertFalse(report["outcome"]["kmsg_readback_bound"])
        self.assertIn("kmsg_marker_message_mismatch", report["failures"])

    def test_failed_kmsg_operation_blocks_strong_result(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(field_overrides={"KMSG_MARKER_WRITE": "-5"}),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertFalse(report["outcome"]["kmsg_readback_bound"])
        self.assertFalse(report["outcome"]["strong_pass"])
        self.assertIn("kmsg_operation_failure", report["failures"])

    def test_truncated_snapshot_is_advisory_when_marker_is_bound(self):
        parser = load_parser()
        truncated_flags = 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128
        report = parser.parse_record(
            valid_record(
                field_overrides={"KMSG_SNAPSHOT_TRUNCATED": "1"},
                flags_override=truncated_flags,
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertTrue(report["outcome"]["kmsg_readback_bound"])
        self.assertTrue(report["outcome"]["witness_evidence_gate_pass"])
        self.assertTrue(report["outcome"]["strong_pass"])
        self.assertFalse(report["outcome"]["capture_not_truncated"])
        self.assertIn("kmsg_snapshot_truncated", report["advisories"])

    def test_missing_expected_partuuid_blocks_sink_identity(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(omit_fields=frozenset({"LOG_EXPECTED_PARTUUID"})),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertFalse(report["outcome"]["sink_identity_bound"])
        self.assertIn("sink_identity_mismatch", report["failures"])

    def test_exact_exported_partuuid_is_accepted(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(
                field_overrides={
                    "LOG_PARTUUID_EXPORTED": "1",
                    "LOG_PARTUUID": LOG_PARTUUID,
                }
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertTrue(report["outcome"]["sink_identity_bound"])
        self.assertTrue(report["identity"]["log_partuuid_observation_bound"])

    def test_mismatched_exported_partuuid_blocks_sink_identity(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(
                field_overrides={
                    "LOG_PARTUUID_EXPORTED": "1",
                    "LOG_PARTUUID": "00000000-0000-0000-0000-000000000000",
                }
            ),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

        self.assertFalse(report["outcome"]["sink_identity_bound"])
        self.assertIn("sink_identity_mismatch", report["failures"])

    def test_final_record_without_edl_raw_extraction_is_not_experiment_pass(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="direct",
            observed_endpoint="unknown",
        )

        self.assertTrue(report["outcome"]["witness_evidence_gate_pass"])
        self.assertFalse(report["outcome"]["experiment_evidence_pass"])
        self.assertFalse(report["outcome"]["end_to_end_success"])
        self.assertIn("not_recovered_from_edl_raw_final", report["failures"])

    def test_fastboot_endpoint_does_not_claim_requested_edl_return(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="fastboot",
        )

        self.assertTrue(report["outcome"]["experiment_evidence_pass"])
        self.assertFalse(report["outcome"]["end_to_end_success"])
        self.assertIn("edl_endpoint_not_observed", report["failures"])

    def test_cli_exit_status_tracks_end_to_end_gate(self):
        with tempfile.TemporaryDirectory() as directory_text:
            record_path = Path(directory_text) / "witness.bin"
            record_path.write_bytes(valid_record())
            base_command = [
                sys.executable,
                str(PARSER),
                str(record_path),
                "--expected-nonce",
                NONCE,
                "--expected-probe-sha256",
                PROBE_SHA256,
            ]
            partial = subprocess.run(
                base_command
                + [
                    "--source-kind",
                    "direct",
                    "--observed-endpoint",
                    "unknown",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(2, partial.returncode, partial.stderr)
            self.assertFalse(
                json.loads(partial.stdout)["outcome"]["end_to_end_success"]
            )

            complete = subprocess.run(
                base_command
                + [
                    "--source-kind",
                    "edl_raw_final",
                    "--observed-endpoint",
                    "edl",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(0, complete.returncode, complete.stderr)
            self.assertTrue(
                json.loads(complete.stdout)["outcome"]["end_to_end_success"]
            )


if __name__ == "__main__":
    unittest.main()
