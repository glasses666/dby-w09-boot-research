from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "scripts" / "parse_w2_witness.py"
NONCE = "00112233445566778899aabbccddeeff"
PROBE_SHA256 = "1" * 64
LINEAGE_INIT_SHA256 = (
    "f9aff20075a7d85e14412855c7dad7f353cba41918b2e45fe4f0285379e1e0f3"
)
BOOT_ID = "12345678-1234-4abc-8def-1234567890ab"


def load_parser():
    spec = importlib.util.spec_from_file_location("parse_w2_witness", PARSER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {PARSER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def encode_fields(fields: dict[str, bytes | str]) -> bytes:
    payload = bytearray()
    for name, value in fields.items():
        raw = value.encode() if isinstance(value, str) else value
        payload.extend(f"{name}:{len(raw)}\n".encode())
        payload.extend(raw)
        payload.extend(b"\n")
    return bytes(payload)


def valid_record(*, overrides: dict[str, bytes | str] | None = None) -> bytes:
    fields: dict[str, bytes | str] = {
        "FORMAT": "DBY-W09-W2",
        "NONCE": NONCE,
        "WITNESS_PID": "2",
        "BOOT_ID": BOOT_ID + "\n",
        "CMDLINE": "normal\n",
        "WITNESS_SELINUX_CONTEXT_AFTER_IDENTITY": "u:r:kernel:s0\n",
        "WITNESS_SELINUX_CONTEXT_AFTER_PROPERTY": "u:r:kernel:s0\n",
        "WITNESS_SELF_SHA256_STATUS": "0",
        "WITNESS_SELF_SHA256": PROBE_SHA256,
        "LINEAGE_EXPECTED_INIT_SHA256": LINEAGE_INIT_SHA256,
        "SECOND_STAGE_OBSERVATION_RULE": (
            "property_service connect plus SO_PEERCRED pid=1 after exact pre-policy "
            "/proc/1/exe SHA-256; REA binds StartPropertyService call to selected "
            "Lineage SecondStageMain"
        ),
        "PROPERTY_SERVICE_PATH": "/dev/socket/property_service",
        "FILESYSTEM_VIEW_CONTRACT": (
            "CLONE_FS shares root/cwd across stock FirstStage SwitchRoot"
        ),
        "PROPERTY_SERVICE_CONNECT": "0",
        "PROPERTY_SERVICE_SO_PEERCRED": "0",
        "PROPERTY_SERVICE_LISTENER_BOUND": "1",
        "PROPERTY_SERVICE_PEER_PID": "1",
        "PROPERTY_SERVICE_PEER_UID": "0",
        "PROPERTY_SERVICE_PEER_GID": "0",
        "PROPERTY_SERVICE_OBSERVED_ITERATION": "17",
        "PID1_EXE_READLINK": "16",
        "PID1_EXE_LINK": "/system/bin/init",
        "PID1_CMDLINE": b"/system/bin/init\0second_stage\0",
        "PID1_EXE_SHA256_STATUS": "0",
        "PID1_EXE_SHA256": LINEAGE_INIT_SHA256,
        "PID1_EXE_HASH_MATCH": "1",
        "LINEAGE_SECOND_STAGE_OBSERVED": "1",
        "KMSG_MARKER_WRITER_OPEN": "4",
        "KMSG_MARKER_WRITE": "0",
        "KMSG_MARKER_WRITER_CLOSE": "0",
        "KMSG_MARKER_MESSAGE": (
            f"DBY_W2_LINEAGE_SECOND_STAGE_MARKER nonce={NONCE}"
        ),
        "LOG_SUPERBLOCK_VERIFY": "0",
        "LOG_SYSTEM_MOUNT_QUALIFIED": "0",
        "LOG_MOUNTINFO_LINE": (
            "123 45 8:12 / /log rw,nosuid,nodev - ext4 /dev/block/sda12 rw"
        ),
        "LOG_EXPECTED_SELINUX_LABEL": "u:object_r:splash2_data_file:s0",
        "LOG_SELINUX_LABEL": "u:object_r:splash2_data_file:s0",
        "LOG_DEVNAME": "sda12",
        "LOG_EXPECTED_PARTUUID": "906d7124-62f7-d1c8-ffbf-73c97575983f",
        "LOG_PARTUUID_EXPORTED": "0",
        "LOG_MAJOR": "8",
        "LOG_MINOR": "12",
        "LOG_SECTORS_512": "163840",
        "LOG_EXPECTED_FSUUID": "e3ff96a22fe448d28c2daef8d068275d",
        "PUBLICATION_PROTOCOL": (
            "O_EXCL fsync(file) renameat2(RENAME_NOREPLACE) fsync(dir) syncfs"
        ),
    }
    if overrides:
        fields.update(overrides)
    payload = encode_fields(fields)
    flags = 0x3F
    header = struct.pack(
        "<8sIIII32s8s",
        b"DBYW2REC",
        1,
        64,
        len(payload),
        flags,
        NONCE.encode(),
        b"\0" * 8,
    )
    body = header + payload
    return body + hashlib.sha256(body).digest()


class W2WitnessParserTests(unittest.TestCase):
    def parse(self, record: bytes):
        return load_parser().parse_record(
            record,
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            expected_lineage_init_sha256=LINEAGE_INIT_SHA256,
            source_kind="edl_raw_final",
            observed_endpoint="edl",
        )

    def test_strong_record_proves_only_the_second_stage_boundary(self):
        report = self.parse(valid_record())
        self.assertTrue(report["outcome"]["strong_pass"])
        self.assertTrue(report["outcome"]["lineage_second_stage_observed"])
        self.assertFalse(report["outcome"]["android_framework_boot_proven"])
        self.assertEqual([], report["failures"])

    def test_property_socket_alone_is_not_enough(self):
        report = self.parse(
            valid_record(
                overrides={
                    "PID1_EXE_SHA256": "0" * 64,
                    "PID1_EXE_HASH_MATCH": "0",
                }
            )
        )
        self.assertFalse(report["outcome"]["strong_pass"])
        self.assertIn("lineage_init_identity_not_bound", report["failures"])

    def test_exec_identity_without_property_socket_is_not_second_stage(self):
        report = self.parse(
            valid_record(
                overrides={
                    "PROPERTY_SERVICE_CONNECT": "-2",
                    "PROPERTY_SERVICE_LISTENER_BOUND": "0",
                    "LINEAGE_SECOND_STAGE_OBSERVED": "0",
                }
            )
        )
        self.assertFalse(report["outcome"]["lineage_second_stage_observed"])
        self.assertIn(
            "property_service_listener_not_bound_to_pid1", report["failures"]
        )

    def test_untrusted_source_or_endpoint_blocks_end_to_end_success(self):
        parser = load_parser()
        report = parser.parse_record(
            valid_record(),
            expected_nonce=NONCE,
            expected_probe_sha256=PROBE_SHA256,
            expected_lineage_init_sha256=LINEAGE_INIT_SHA256,
            source_kind="direct",
            observed_endpoint="recovery",
        )
        self.assertFalse(report["outcome"]["strong_pass"])
        self.assertIn("record_not_recovered_from_edl_raw_final", report["failures"])
        self.assertIn("edl_endpoint_not_observed", report["failures"])

    def test_wrong_kmsg_message_is_rejected(self):
        report = self.parse(
            valid_record(overrides={"KMSG_MARKER_MESSAGE": "wrong"})
        )
        self.assertFalse(report["outcome"]["current_kernel_kmsg_write_accepted"])
        self.assertIn("current_kernel_kmsg_write_not_accepted", report["failures"])

    def test_property_listener_must_report_pid1(self):
        report = self.parse(
            valid_record(overrides={"PROPERTY_SERVICE_PEER_PID": "2"})
        )
        self.assertFalse(report["outcome"]["lineage_second_stage_observed"])
        self.assertIn(
            "property_service_listener_not_bound_to_pid1", report["failures"]
        )

    def test_wrong_log_label_is_rejected(self):
        report = self.parse(
            valid_record(
                overrides={"LOG_SELINUX_LABEL": "u:object_r:unlabeled:s0"}
            )
        )
        self.assertFalse(report["outcome"]["sink_identity_bound"])
        self.assertIn("log_sink_identity_not_bound", report["failures"])

    def test_wrong_log_mount_device_is_rejected(self):
        report = self.parse(
            valid_record(
                overrides={
                    "LOG_MOUNTINFO_LINE": (
                        "123 45 8:13 / /log rw - ext4 /dev/block/sda13 rw"
                    )
                }
            )
        )
        self.assertFalse(report["outcome"]["sink_identity_bound"])
        self.assertIn("log_sink_identity_not_bound", report["failures"])

    def test_witness_must_remain_in_qualified_kernel_domain(self):
        report = self.parse(
            valid_record(
                overrides={
                    "WITNESS_SELINUX_CONTEXT_AFTER_PROPERTY": "u:r:init:s0\n"
                }
            )
        )
        self.assertFalse(report["outcome"]["strong_pass"])
        self.assertIn("witness_selinux_context_unqualified", report["failures"])


if __name__ == "__main__":
    unittest.main()
