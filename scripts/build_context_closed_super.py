#!/usr/bin/env python3
"""Build the offline DBY-W09 super candidate by replacing only system.

This is deliberately a fixed-geometry builder.  It accepts only the recorded
stock super image and the context-closed ext4 payload, preserves every byte
outside the LP system extent, writes the payload at the recorded first sector,
and zero-fills the unused tail of that extent.  It never talks to a device.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Callable


STOCK_SUPER_SHA256 = "525336b48db57a3561613df103ba685a7caa83667079a30cae30f4bdf67abdfc"
SYSTEM_PAYLOAD_SHA256 = "8ec6599fb4d93facb4adc18436c6c17632552e15a475ae3ef8bb6f11b0d959f9"


@dataclass(frozen=True)
class Geometry:
    super_size: int
    system_offset: int
    system_extent_size: int
    system_payload_size: int
    sector_size: int = 512

    @property
    def system_end(self) -> int:
        return self.system_offset + self.system_extent_size

    @property
    def zero_tail_size(self) -> int:
        return self.system_extent_size - self.system_payload_size


DBY_W09_GEOMETRY = Geometry(
    super_size=7_692_353_536,
    system_offset=2_097_152,
    system_extent_size=3_581_935_616,
    system_payload_size=2_513_817_600,
)

CHUNK_SIZE = 8 * 1024 * 1024


def sha256_file(path: Path, offset: int = 0, length: int | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = length
        while remaining is None or remaining:
            wanted = CHUNK_SIZE if remaining is None else min(CHUNK_SIZE, remaining)
            block = stream.read(wanted)
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
        if remaining not in (None, 0):
            raise ValueError(f"short read from {path}: {remaining} bytes missing")
    return digest.hexdigest()


def range_is_zero(path: Path, offset: int, length: int) -> bool:
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = length
        zero = b"\0" * CHUNK_SIZE
        while remaining:
            wanted = min(CHUNK_SIZE, remaining)
            block = stream.read(wanted)
            if len(block) != wanted or block != zero[:wanted]:
                return False
            remaining -= wanted
    return True


def validate_geometry(geometry: Geometry) -> None:
    values = asdict(geometry)
    if any(value <= 0 for value in values.values()):
        raise ValueError(f"geometry values must be positive: {values}")
    if geometry.system_payload_size > geometry.system_extent_size:
        raise ValueError("system payload exceeds its LP extent")
    if geometry.system_end > geometry.super_size:
        raise ValueError("system extent exceeds super image")
    for name in ("super_size", "system_offset", "system_extent_size", "system_payload_size"):
        if getattr(geometry, name) % geometry.sector_size:
            raise ValueError(f"{name} is not sector aligned")


def clone_copy(source: Path, destination: Path) -> None:
    """Use APFS copy-on-write; fail rather than silently consuming 7.7 GB."""
    subprocess.run(
        ["/bin/cp", "-c", str(source), str(destination)],
        check=True,
        stdin=subprocess.DEVNULL,
    )


def regular_copy(source: Path, destination: Path) -> None:
    """Portable copier for unit tests; the production CLI uses clone_copy."""
    shutil.copyfile(source, destination)


def write_system_extent(output: Path, payload: Path, geometry: Geometry) -> None:
    zero = b"\0" * CHUNK_SIZE
    with output.open("r+b", buffering=0) as target, payload.open("rb") as source:
        target.seek(geometry.system_offset)
        remaining = geometry.system_payload_size
        while remaining:
            block = source.read(min(CHUNK_SIZE, remaining))
            if not block:
                raise ValueError("system payload ended early")
            target.write(block)
            remaining -= len(block)
        if source.read(1):
            raise ValueError("system payload is larger than declared geometry")

        remaining = geometry.zero_tail_size
        while remaining:
            block = zero[: min(CHUNK_SIZE, remaining)]
            target.write(block)
            remaining -= len(block)
        target.flush()
        os.fsync(target.fileno())


def verify_output(
    stock: Path,
    payload: Path,
    output: Path,
    geometry: Geometry,
) -> dict[str, object]:
    if output.stat().st_size != geometry.super_size:
        raise ValueError("output super size changed")

    prefix_size = geometry.system_offset
    suffix_offset = geometry.system_end
    suffix_size = geometry.super_size - suffix_offset
    prefix_stock = sha256_file(stock, 0, prefix_size)
    prefix_output = sha256_file(output, 0, prefix_size)
    suffix_stock = sha256_file(stock, suffix_offset, suffix_size)
    suffix_output = sha256_file(output, suffix_offset, suffix_size)
    payload_input = sha256_file(payload)
    payload_output = sha256_file(output, geometry.system_offset, geometry.system_payload_size)

    if prefix_output != prefix_stock:
        raise ValueError("bytes before the system extent changed")
    if suffix_output != suffix_stock:
        raise ValueError("bytes after the system extent changed")
    if payload_output != payload_input:
        raise ValueError("embedded system payload differs from input")
    if not range_is_zero(
        output,
        geometry.system_offset + geometry.system_payload_size,
        geometry.zero_tail_size,
    ):
        raise ValueError("unused system extent tail is not all zero")

    return {
        "output_sha256": sha256_file(output),
        "preserved_prefix_sha256": prefix_output,
        "embedded_payload_sha256": payload_output,
        "zero_tail_sha256": sha256_file(
            output,
            geometry.system_offset + geometry.system_payload_size,
            geometry.zero_tail_size,
        ),
        "preserved_suffix_sha256": suffix_output,
    }


def build_super(
    stock: Path,
    payload: Path,
    output: Path,
    *,
    manifest: Path | None = None,
    geometry: Geometry = DBY_W09_GEOMETRY,
    expected_stock_sha256: str = STOCK_SUPER_SHA256,
    expected_payload_sha256: str = SYSTEM_PAYLOAD_SHA256,
    copier: Callable[[Path, Path], None] = clone_copy,
) -> dict[str, object]:
    validate_geometry(geometry)
    stock = stock.resolve()
    payload = payload.resolve()
    output = output.resolve()
    if manifest is not None:
        manifest = manifest.resolve()
        if manifest == output:
            raise ValueError("manifest path must differ from output path")
    if not stock.is_file() or not payload.is_file():
        raise FileNotFoundError("stock super and system payload must both be regular files")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    if manifest is not None and manifest.exists():
        raise FileExistsError(f"refusing to overwrite {manifest}")
    if stock.stat().st_size != geometry.super_size:
        raise ValueError("unexpected stock super size")
    if payload.stat().st_size != geometry.system_payload_size:
        raise ValueError("unexpected system payload size")
    if os.path.samefile(stock, payload):
        raise ValueError("stock super and payload resolve to the same file")

    stock_hash = sha256_file(stock)
    payload_hash = sha256_file(payload)
    if stock_hash != expected_stock_sha256:
        raise ValueError(f"unexpected stock super SHA-256: {stock_hash}")
    if payload_hash != expected_payload_sha256:
        raise ValueError(f"unexpected system payload SHA-256: {payload_hash}")

    partial = output.with_name(f".{output.name}.partial-{os.getpid()}")
    if partial.exists():
        raise FileExistsError(f"stale partial output exists: {partial}")
    try:
        copier(stock, partial)
        if partial.stat().st_size != geometry.super_size:
            raise ValueError("copier changed super image size")
        write_system_extent(partial, payload, geometry)
        verification = verify_output(stock, payload, partial, geometry)
        os.replace(partial, output)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise

    result: dict[str, object] = {
        "status": "offline-built-not-flashed",
        "device_io_performed": False,
        "stock_super": {"path": str(stock), "size": geometry.super_size, "sha256": stock_hash},
        "system_payload": {
            "path": str(payload),
            "size": geometry.system_payload_size,
            "sha256": payload_hash,
        },
        "output_super": {"path": str(output), "size": geometry.super_size, **verification},
        "geometry": asdict(geometry) | {
            "system_end": geometry.system_end,
            "zero_tail_size": geometry.zero_tail_size,
        },
        "invariant": "all bytes outside the recorded system extent equal stock",
    }
    if manifest is not None:
        temporary_manifest = manifest.with_name(f".{manifest.name}.partial-{os.getpid()}")
        temporary_manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        os.replace(temporary_manifest, manifest)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock_super", type=Path)
    parser.add_argument("system_payload", type=Path)
    parser.add_argument("output_super", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    result = build_super(
        args.stock_super,
        args.system_payload,
        args.output_super,
        manifest=args.manifest,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
