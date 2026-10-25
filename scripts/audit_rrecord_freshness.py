#!/usr/bin/env python3
"""Report RTC and payload identity without treating a new dump as a new boot."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SLOT_SIZE = 0x140400
SLOT_COUNT = 6
RTC = re.compile(rb"setting system clock to ([0-9-]+ [0-9:]+) UTC")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect(path: Path) -> tuple[dict, list[bytes]]:
    raw = path.read_bytes()
    if len(raw) != 8388608:
        raise ValueError(f"unexpected rrecord size: {path}: {len(raw)}")
    chunks = [raw[i * SLOT_SIZE : (i + 1) * SLOT_SIZE] for i in range(SLOT_COUNT)]
    slots = []
    for i, chunk in enumerate(chunks):
        start = chunk.find(b"Linux version")
        # Header counters may change independently of the persisted kernel text.
        window = chunk[start : start + 70000] if start >= 0 else b""
        slots.append({
            "slot": i,
            "rtc_utc": [x.decode("ascii") for x in RTC.findall(chunk)],
            "slot_sha256": digest(chunk),
            "kernel_start_offset": start,
            "kernel_window_sha256": digest(window),
            "kernel_window_length": len(window),
            "diagnostic_v4_marker": b"DBY_DIAGNOSTIC_V4" in chunk,
        })
    return {"path": str(path.resolve()), "sha256": digest(raw), "slots": slots}, chunks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists():
        raise SystemExit("refusing to overwrite an existing audit")
    records = []
    previous = None
    for path in args.images:
        record, chunks = inspect(path)
        if previous is not None:
            record["changed_slots_from_previous"] = [i for i in range(SLOT_COUNT) if chunks[i] != previous[i]]
            record["slot_byte_differences_from_previous"] = [sum(a != b for a, b in zip(chunks[i], previous[i])) for i in range(SLOT_COUNT)]
        records.append(record)
        previous = chunks
    report = {
        "warning": "Changed file hashes, ring slots, or headers do not establish a fresh boot. Correlate RTC, a unique image marker, actual boot mode, and the write/reset timeline.",
        "slot_size": SLOT_SIZE,
        "records": records,
    }
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    for record in records:
        print(Path(record["path"]).parent.name + "/" + Path(record["path"]).name)
        print("  RTC UTC:", [slot["rtc_utc"] for slot in record["slots"]])
        if "changed_slots_from_previous" in record:
            print("  changed slots:", record["changed_slots_from_previous"])
            print("  byte differences:", record["slot_byte_differences_from_previous"])


if __name__ == "__main__":
    main()
