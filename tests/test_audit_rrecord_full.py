import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_rrecord_full.py"
PARTITION_SIZE = 0x800000
SLOT_SIZE = 0x140400
SLOT_COUNT = 6
COVERAGE_END = SLOT_SIZE * SLOT_COUNT
CONTROL_BASES = (0x782400, 0x782E80)
CONTROL_SIZE = 0xA80
CONTROL_HEADER_SIZE = 0x80
CONTROL_ENTRY_SIZE = 0x40
CONTROL_CAPACITY = 40


def make_control_block(sequence: int, entries: int) -> bytes:
    block = bytearray(CONTROL_SIZE)
    block[0x20:0x30] = (
        sequence.to_bytes(4, "little")
        + sequence.to_bytes(4, "little")
        + CONTROL_CAPACITY.to_bytes(4, "little")
        + sequence.to_bytes(4, "little")
    )
    for index in range(entries):
        offset = CONTROL_HEADER_SIZE + index * CONTROL_ENTRY_SIZE
        block[offset : offset + 4] = (0xA1000000 + index).to_bytes(4, "little")
    block[:0x20] = hashlib.sha256(block[0x20:]).digest()
    return bytes(block)


class AuditRrecordFullTests(unittest.TestCase):
    def test_reports_full_partition_ranges_and_unexamined_tail_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            before = bytearray(PARTITION_SIZE)
            after = bytearray(before)

            after[0x20:0x23] = b"ABC"
            slot3_start = SLOT_SIZE * 3
            after[slot3_start + 0x100] = 0x7F
            after[COVERAGE_END + 0x12] = 0x55

            before_path = tmp_path / "before.img"
            after_path = tmp_path / "after.img"
            report_path = tmp_path / "report.json"
            before_path.write_bytes(before)
            after_path.write_bytes(after)

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(before_path),
                    str(after_path),
                    "--report",
                    str(report_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["partition_size"], PARTITION_SIZE)
            self.assertEqual(report["assumed_slot_coverage_end"], COVERAGE_END)
            self.assertEqual(report["unexamined_tail_size"], PARTITION_SIZE - COVERAGE_END)

            diff = report["comparisons"][0]
            self.assertEqual(diff["changed_bytes"], 5)
            self.assertEqual(diff["changed_assumed_slots"], [0, 3])
            self.assertEqual(diff["unexamined_tail_changed_bytes"], 1)
            self.assertEqual(
                diff["changed_ranges"],
                [
                    {"start": 0x20, "end_exclusive": 0x23, "length": 3},
                    {
                        "start": slot3_start + 0x100,
                        "end_exclusive": slot3_start + 0x101,
                        "length": 1,
                    },
                    {
                        "start": COVERAGE_END + 0x12,
                        "end_exclusive": COVERAGE_END + 0x13,
                        "length": 1,
                    },
                ],
            )

    def test_decodes_mirrored_sha256_control_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            first = bytearray(PARTITION_SIZE)
            second = bytearray(PARTITION_SIZE)
            for image, sequence, entries in ((first, 7, 7), (second, 8, 8)):
                block = make_control_block(sequence, entries)
                for base in CONTROL_BASES:
                    image[base : base + CONTROL_SIZE] = block

            first_path = tmp_path / "first.img"
            second_path = tmp_path / "second.img"
            report_path = tmp_path / "report.json"
            first_path.write_bytes(first)
            second_path.write_bytes(second)

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(first_path),
                    str(second_path),
                    "--report",
                    str(report_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(report_path.read_text())
            self.assertIn("control_geometry", report)
            self.assertEqual(report["control_geometry"]["block_size"], CONTROL_SIZE)
            self.assertEqual(report["control_geometry"]["entry_capacity"], CONTROL_CAPACITY)
            latest = report["records"][1]["control_blocks"]
            self.assertTrue(latest["copies_identical"])
            self.assertEqual(latest["sequence"], 8)
            self.assertTrue(all(item["digest_valid"] for item in latest["copies"]))
            self.assertEqual(
                report["comparisons"][0]["control_sequence_delta"], 1
            )


if __name__ == "__main__":
    unittest.main()
