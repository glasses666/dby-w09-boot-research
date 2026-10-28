#!/usr/bin/env python3
"""Compare a streamed partition readback with a frozen source without storing it."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


CHUNK_SIZE = 4 * 1024 * 1024


def compare_stream(stream_path: Path, source_path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    byte_count = 0
    mismatch_offset: int | None = None
    with stream_path.open("rb", buffering=0) as incoming, source_path.open("rb") as source:
        while True:
            chunk = incoming.read(CHUNK_SIZE)
            if not chunk:
                break
            expected = source.read(len(chunk))
            if mismatch_offset is None and chunk != expected:
                shared = min(len(chunk), len(expected))
                for index in range(shared):
                    if chunk[index] != expected[index]:
                        mismatch_offset = byte_count + index
                        break
                if mismatch_offset is None:
                    mismatch_offset = byte_count + shared
            digest.update(chunk)
            byte_count += len(chunk)
        source_has_tail = bool(source.read(1))
    source_size = source_path.stat().st_size
    passed = mismatch_offset is None and not source_has_tail and byte_count == source_size
    return {
        "schema": "dby-w09-stream-readback-compare-v1",
        "status": "passed" if passed else "failed",
        "stream_bytes": byte_count,
        "stream_sha256": digest.hexdigest(),
        "source_path": str(source_path.resolve()),
        "source_size": source_size,
        "mismatch_offset": mismatch_offset,
        "source_has_unread_tail": source_has_tail,
        "byte_identical": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stream_path", type=Path)
    parser.add_argument("source_path", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    if args.report.exists():
        raise FileExistsError(f"refusing to overwrite {args.report}")
    result = compare_stream(args.stream_path, args.source_path)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["byte_identical"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
