#!/usr/bin/env python3
"""Compare complete 8 MiB rrecord snapshots without inferring a file format."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


PARTITION_SIZE = 0x800000
ASSUMED_SLOT_SIZE = 0x140400
ASSUMED_SLOT_COUNT = 6
ASSUMED_SLOT_COVERAGE_END = ASSUMED_SLOT_SIZE * ASSUMED_SLOT_COUNT
KERNEL_STRING_OFFSET = 0x4109E
CONTROL_BASES = (0x782400, 0x782E80)
CONTROL_BLOCK_SIZE = 0xA80
CONTROL_DIGEST_SIZE = 0x20
CONTROL_HEADER_SIZE = 0x80
CONTROL_ENTRY_SIZE = 0x40
CONTROL_ENTRY_CAPACITY = 40


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def changed_ranges(indices: list[int]) -> list[dict[str, int]]:
    if not indices:
        return []
    ranges: list[dict[str, int]] = []
    start = previous = indices[0]
    for offset in indices[1:]:
        if offset != previous + 1:
            ranges.append(
                {
                    "start": start,
                    "end_exclusive": previous + 1,
                    "length": previous + 1 - start,
                }
            )
            start = offset
        previous = offset
    ranges.append(
        {
            "start": start,
            "end_exclusive": previous + 1,
            "length": previous + 1 - start,
        }
    )
    return ranges


def decode_control_blocks(data: bytes) -> dict[str, object]:
    copies = []
    raw_blocks = []
    for base in CONTROL_BASES:
        block = data[base : base + CONTROL_BLOCK_SIZE]
        raw_blocks.append(block)
        words = struct.unpack_from("<4I", block, CONTROL_DIGEST_SIZE)
        copies.append(
            {
                "base": base,
                "stored_sha256": block[:CONTROL_DIGEST_SIZE].hex(),
                "computed_sha256": sha256(block[CONTROL_DIGEST_SIZE:]),
                "digest_valid": hashlib.sha256(
                    block[CONTROL_DIGEST_SIZE:]
                ).digest()
                == block[:CONTROL_DIGEST_SIZE],
                "word_20": words[0],
                "word_24": words[1],
                "capacity_word_28": words[2],
                "word_2c": words[3],
                "nonzero_entry_count": sum(
                    any(
                        block[
                            CONTROL_HEADER_SIZE + index * CONTROL_ENTRY_SIZE :
                            CONTROL_HEADER_SIZE + (index + 1) * CONTROL_ENTRY_SIZE
                        ]
                    )
                    for index in range(CONTROL_ENTRY_CAPACITY)
                ),
            }
        )

    copies_identical = raw_blocks[0] == raw_blocks[1]
    first = copies[0]
    sequence = None
    if (
        copies_identical
        and all(item["digest_valid"] for item in copies)
        and first["capacity_word_28"] == CONTROL_ENTRY_CAPACITY
        and first["word_20"] == first["word_24"] == first["word_2c"]
    ):
        sequence = first["word_20"]
    return {
        "copies_identical": copies_identical,
        "sequence": sequence,
        "copies": copies,
    }


def load_image(path: Path) -> tuple[dict[str, object], bytes]:
    data = path.read_bytes()
    if len(data) != PARTITION_SIZE:
        raise ValueError(
            f"unexpected rrecord size: {path}: {len(data)}; expected {PARTITION_SIZE}"
        )
    record: dict[str, object] = {
        "path": str(path.resolve()),
        "size": len(data),
        "sha256": sha256(data),
        "unexamined_tail_sha256": sha256(data[ASSUMED_SLOT_COVERAGE_END:]),
        "control_blocks": decode_control_blocks(data),
    }
    return record, data


def compare(before: bytes, after: bytes) -> dict[str, object]:
    indices = [offset for offset, pair in enumerate(zip(before, after)) if pair[0] != pair[1]]
    slot_counts = []
    for slot in range(ASSUMED_SLOT_COUNT):
        start = slot * ASSUMED_SLOT_SIZE
        end = start + ASSUMED_SLOT_SIZE
        prefix_end = start + KERNEL_STRING_OFFSET
        slot_counts.append(
            {
                "slot": slot,
                "changed_bytes": sum(before[i] != after[i] for i in range(start, end)),
                "changed_bytes_before_kernel_string": sum(
                    before[i] != after[i] for i in range(start, prefix_end)
                ),
                "changed_bytes_from_kernel_string": sum(
                    before[i] != after[i] for i in range(prefix_end, end)
                ),
            }
        )
    return {
        "changed_bytes": len(indices),
        "changed_ranges": changed_ranges(indices),
        "changed_assumed_slots": [
            item["slot"] for item in slot_counts if item["changed_bytes"]
        ],
        "assumed_slot_differences": slot_counts,
        "unexamined_tail_changed_bytes": sum(
            before[i] != after[i]
            for i in range(ASSUMED_SLOT_COVERAGE_END, PARTITION_SIZE)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare complete DBY-W09 rrecord partition snapshots."
    )
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    if len(args.images) < 2:
        raise SystemExit("at least two rrecord images are required")
    if args.report.exists():
        raise SystemExit("refusing to overwrite an existing audit")

    records: list[dict[str, object]] = []
    payloads: list[bytes] = []
    for path in args.images:
        record, payload = load_image(path)
        records.append(record)
        payloads.append(payload)

    comparisons = []
    for index in range(1, len(payloads)):
        result = compare(payloads[index - 1], payloads[index])
        result["before"] = records[index - 1]["path"]
        result["after"] = records[index]["path"]
        before_sequence = records[index - 1]["control_blocks"]["sequence"]
        after_sequence = records[index]["control_blocks"]["sequence"]
        result["control_sequence_delta"] = (
            after_sequence - before_sequence
            if before_sequence is not None and after_sequence is not None
            else None
        )
        comparisons.append(result)

    report = {
        "warning": (
            "Slot geometry and the Linux-string boundary are analyst assumptions, not a "
            "decoded rrecord schema. Full-partition ranges are byte observations only."
        ),
        "partition_size": PARTITION_SIZE,
        "assumed_slot_size": ASSUMED_SLOT_SIZE,
        "assumed_slot_count": ASSUMED_SLOT_COUNT,
        "assumed_slot_coverage_end": ASSUMED_SLOT_COVERAGE_END,
        "kernel_string_offset_within_assumed_slot": KERNEL_STRING_OFFSET,
        "unexamined_tail_size": PARTITION_SIZE - ASSUMED_SLOT_COVERAGE_END,
        "control_geometry": {
            "bases": list(CONTROL_BASES),
            "block_size": CONTROL_BLOCK_SIZE,
            "digest_size": CONTROL_DIGEST_SIZE,
            "header_size": CONTROL_HEADER_SIZE,
            "entry_size": CONTROL_ENTRY_SIZE,
            "entry_capacity": CONTROL_ENTRY_CAPACITY,
            "digest_coverage": "block[0x20:0xa80]",
            "status": (
                "validated mirrored SHA-256 control blocks; field names other than "
                "capacity and candidate sequence remain unknown"
            ),
        },
        "records": records,
        "comparisons": comparisons,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    for result in comparisons:
        print(Path(str(result["before"])).name, "->", Path(str(result["after"])).name)
        print("  changed bytes:", result["changed_bytes"])
        print("  changed assumed slots:", result["changed_assumed_slots"])
        print("  unexamined tail changed bytes:", result["unexamined_tail_changed_bytes"])


if __name__ == "__main__":
    main()
