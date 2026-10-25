#!/usr/bin/env python3
"""Build a bounded early-boot diagnostic ramdisk for DBY-W09.

The stock first-stage init is retained as ``/init.stock`` with every runtime
PT_LOAD byte unchanged.  A small, static AArch64 wrapper becomes ``/init`` and
immediately execs the stock binary while a bounded child captures early kmsg.
The Android boot header page and complete embedded AVB tail are preserved.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path


BOOT_MAGIC = b"ANDROID!"
NEWC_MAGIC = b"070701"
NEWC_CRC_MAGIC = b"070702"
TRAILER = "TRAILER!!!"
PT_LOAD = 1
PT_INTERP = 3
EM_AARCH64 = 183

EXPECTED_IMAGE_SIZE = 2_097_152
EXPECTED_PAGE_SIZE = 2_048
EXPECTED_RAMDISK_SIZE = 840_472
EXPECTED_AVB_OFFSET = 843_776
EXPECTED_IMAGE_SHA256 = "d1afe422e88bd330ec5ccf8220ed6fbc241ade8f37fe26c3ab1cded6cf4d38da"
EXPECTED_INIT_SHA256 = "2378dc783a7f7dcbfc36a18938d79b41309ae97bff69f6474ac8c33bcdeb7087"
STOCK_FIRST_STAGE_LOG = b"init first stage started!"
DIAGNOSTIC_FIRST_STAGE_LOG = b"DBY_V3_FIRST_STAGE_ENTRY!"


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class NewcEntry:
    magic: bytes
    fields: list[int]
    name: str
    data: bytes


def parse_newc(archive: bytes) -> list[NewcEntry]:
    entries: list[NewcEntry] = []
    offset = 0
    while True:
        if offset + 110 > len(archive):
            raise ValueError(f"truncated newc header at offset {offset}")
        magic = archive[offset : offset + 6]
        if magic not in (NEWC_MAGIC, NEWC_CRC_MAGIC):
            raise ValueError(f"unexpected newc magic {magic!r} at offset {offset}")
        raw_fields = archive[offset + 6 : offset + 110]
        fields = [int(raw_fields[index : index + 8], 16) for index in range(0, 104, 8)]
        file_size = fields[6]
        name_size = fields[11]
        if name_size < 1:
            raise ValueError(f"invalid namesize {name_size} at offset {offset}")
        name_start = offset + 110
        name_end = name_start + name_size
        if name_end > len(archive) or archive[name_end - 1] != 0:
            raise ValueError(f"invalid newc name at offset {offset}")
        name = archive[name_start : name_end - 1].decode(
            "utf-8", errors="surrogateescape"
        )
        data_start = align(name_end, 4)
        data_end = data_start + file_size
        if data_end > len(archive):
            raise ValueError(f"truncated data for {name!r}")
        entries.append(NewcEntry(magic, fields, name, archive[data_start:data_end]))
        offset = align(data_end, 4)
        if name == TRAILER:
            break
    if any(archive[offset:]):
        raise ValueError("non-zero bytes follow newc trailer")
    return entries


def write_newc(entries: list[NewcEntry]) -> bytes:
    output = bytearray()
    for entry in entries:
        name_bytes = entry.name.encode("utf-8", errors="surrogateescape") + b"\0"
        fields = list(entry.fields)
        fields[6] = len(entry.data)
        fields[11] = len(name_bytes)
        if entry.magic == NEWC_CRC_MAGIC:
            fields[12] = sum(entry.data) & 0xFFFFFFFF
        header = entry.magic + b"".join(
            f"{value:08x}".encode("ascii") for value in fields
        )
        if len(header) != 110:
            raise AssertionError("newc header length changed")
        output.extend(header)
        output.extend(name_bytes)
        output.extend(b"\0" * (align(len(output), 4) - len(output)))
        output.extend(entry.data)
        output.extend(b"\0" * (align(len(output), 4) - len(output)))
    return bytes(output)


def elf64_layout(data: bytes) -> dict[str, object]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("expected an ELF file")
    if data[4:6] != b"\x02\x01":
        raise ValueError("expected little-endian ELF64")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != EM_AARCH64:
        raise ValueError(f"expected AArch64 ELF, got machine {machine}")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    shoff = struct.unpack_from("<Q", data, 40)[0]
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(
        "<HHHHH", data, 54
    )
    if phnum and phentsize < 56:
        raise ValueError("invalid ELF64 program-header size")
    if shnum and shentsize < 64:
        raise ValueError("invalid ELF64 section-header size")

    program_headers: list[dict[str, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 56 > len(data):
            raise ValueError("program headers exceed ELF size")
        values = struct.unpack_from("<IIQQQQQQ", data, offset)
        program_headers.append(
            {
                "type": values[0],
                "flags": values[1],
                "offset": values[2],
                "filesz": values[5],
                "memsz": values[6],
            }
        )

    sections: dict[str, dict[str, int]] = {}
    if shnum:
        if shstrndx >= shnum:
            raise ValueError("invalid ELF section-string-table index")
        string_header = shoff + shstrndx * shentsize
        if string_header + 64 > len(data):
            raise ValueError("section headers exceed ELF size")
        string_offset, string_size = struct.unpack_from("<QQ", data, string_header + 24)
        if string_offset + string_size > len(data):
            raise ValueError("section string table exceeds ELF size")
        strings = data[string_offset : string_offset + string_size]
        for index in range(shnum):
            offset = shoff + index * shentsize
            if offset + 64 > len(data):
                raise ValueError("section headers exceed ELF size")
            name_offset, section_type = struct.unpack_from("<II", data, offset)
            section_offset, section_size = struct.unpack_from("<QQ", data, offset + 24)
            if name_offset >= len(strings):
                raise ValueError("section name exceeds string table")
            name_end = strings.find(b"\0", name_offset)
            if name_end < 0:
                raise ValueError("unterminated ELF section name")
            name = strings[name_offset:name_end].decode("ascii", errors="strict")
            if section_type != 8 and section_offset + section_size > len(data):
                raise ValueError(f"section {name!r} exceeds ELF size")
            sections[name] = {"offset": section_offset, "size": section_size}
    return {"program_headers": program_headers, "sections": sections}


def validate_wrapper(wrapper: bytes) -> dict[str, object]:
    layout = elf64_layout(wrapper)
    headers = layout["program_headers"]
    if not any(header["type"] == PT_LOAD for header in headers):
        raise ValueError("diagnostic wrapper has no PT_LOAD segment")
    if any(header["type"] == PT_INTERP for header in headers):
        raise ValueError("diagnostic wrapper must be static and have no PT_INTERP")
    if len(wrapper) > 32 * 1024:
        raise ValueError("diagnostic wrapper exceeds the 32 KiB safety limit")
    return layout


def clear_nonruntime_debugdata(stock_init: bytes) -> tuple[bytes, dict[str, int]]:
    layout = elf64_layout(stock_init)
    sections = layout["sections"]
    if ".gnu_debugdata" not in sections:
        raise ValueError("stock init is missing .gnu_debugdata")
    section = sections[".gnu_debugdata"]
    start = section["offset"]
    end = start + section["size"]
    for header in layout["program_headers"]:
        if header["type"] != PT_LOAD:
            continue
        load_start = header["offset"]
        load_end = load_start + header["filesz"]
        if max(start, load_start) < min(end, load_end):
            raise ValueError(".gnu_debugdata overlaps a runtime PT_LOAD segment")
    sanitized = bytearray(stock_init)
    sanitized[start:end] = b"\0" * section["size"]
    for header in layout["program_headers"]:
        if header["type"] != PT_LOAD:
            continue
        load_start = header["offset"]
        load_end = load_start + header["filesz"]
        if sanitized[load_start:load_end] != stock_init[load_start:load_end]:
            raise AssertionError("stock init PT_LOAD bytes changed")
    return bytes(sanitized), section


def patch_first_stage_log(stock_init: bytes) -> tuple[bytes, dict[str, object]]:
    if len(STOCK_FIRST_STAGE_LOG) != len(DIAGNOSTIC_FIRST_STAGE_LOG):
        raise AssertionError("first-stage log marker must be a fixed-length replacement")
    if DIAGNOSTIC_FIRST_STAGE_LOG in stock_init:
        raise ValueError("diagnostic first-stage log marker is already present")
    offsets: list[int] = []
    cursor = 0
    while True:
        cursor = stock_init.find(STOCK_FIRST_STAGE_LOG, cursor)
        if cursor < 0:
            break
        offsets.append(cursor)
        cursor += 1
    if len(offsets) != 1:
        raise ValueError(
            f"expected one stock first-stage log string, found {len(offsets)}"
        )
    start = offsets[0]
    end = start + len(STOCK_FIRST_STAGE_LOG)
    layout = elf64_layout(stock_init)
    containing_loads = []
    for header in layout["program_headers"]:
        if header["type"] != PT_LOAD:
            continue
        load_start = header["offset"]
        load_end = load_start + header["filesz"]
        if load_start <= start and end <= load_end:
            containing_loads.append((load_start, load_end))
    if len(containing_loads) != 1:
        raise ValueError("stock first-stage log is not in exactly one PT_LOAD segment")

    patched = bytearray(stock_init)
    patched[start:end] = DIAGNOSTIC_FIRST_STAGE_LOG
    for header in layout["program_headers"]:
        if header["type"] != PT_LOAD:
            continue
        load_start = header["offset"]
        load_end = load_start + header["filesz"]
        for offset in range(load_start, load_end):
            if start <= offset < end:
                continue
            if patched[offset] != stock_init[offset]:
                raise AssertionError("stock init changed outside the diagnostic log marker")
    return bytes(patched), {
        "stock_init_log_marker": DIAGNOSTIC_FIRST_STAGE_LOG.decode("ascii"),
        "stock_init_log_marker_offset": start,
        "stock_init_log_marker_occurrences": 1,
        "stock_init_log_marker_byte_differences": sum(
            left != right
            for left, right in zip(STOCK_FIRST_STAGE_LOG, DIAGNOSTIC_FIRST_STAGE_LOG)
        ),
    }


def _geometry(image: bytes, *, require_stock_ramdisk: bool = False) -> tuple[int, int, int]:
    if len(image) != EXPECTED_IMAGE_SIZE or image[:8] != BOOT_MAGIC:
        raise ValueError("unexpected stock ramdisk partition geometry")
    ramdisk_size = struct.unpack_from("<I", image, 16)[0]
    page_size = struct.unpack_from("<I", image, 36)[0]
    if image[-64:-60] != b"AVBf":
        raise ValueError("embedded AVB footer is missing")
    avb_offset = struct.unpack_from(">Q", image, len(image) - 64 + 20)[0]
    if page_size != EXPECTED_PAGE_SIZE or avb_offset != EXPECTED_AVB_OFFSET:
        raise ValueError("stock ramdisk header geometry does not match the pinned image")
    if require_stock_ramdisk and ramdisk_size != EXPECTED_RAMDISK_SIZE:
        raise ValueError("stock ramdisk payload size does not match the pinned image")
    if page_size + ramdisk_size > avb_offset:
        raise ValueError("ramdisk payload overlaps embedded AVB metadata")
    if image[avb_offset : avb_offset + 4] != b"AVB0":
        raise ValueError("embedded AVB metadata is missing")
    return page_size, ramdisk_size, avb_offset


def extract_entries(image: bytes) -> list[NewcEntry]:
    page_size, ramdisk_size, _ = _geometry(image)
    archive = gzip.decompress(image[page_size : page_size + ramdisk_size])
    return parse_newc(archive)


def build_image(
    source: bytes,
    wrapper: bytes,
    *,
    patch_stock_init_log_marker: bool = False,
) -> tuple[bytes, dict[str, object]]:
    if sha256(source) != EXPECTED_IMAGE_SHA256:
        raise ValueError("input is not the pinned DBY-W09 stock ramdisk image")
    validate_wrapper(wrapper)
    page_size, ramdisk_size, avb_offset = _geometry(
        source, require_stock_ramdisk=True
    )
    entries = parse_newc(gzip.decompress(source[page_size : page_size + ramdisk_size]))
    by_name = {entry.name: entry for entry in entries}
    if len(by_name) != len(entries):
        raise ValueError("duplicate newc path found")
    if entries[-1].name != TRAILER or "init" not in by_name or "init.stock" in by_name:
        raise ValueError("unexpected stock ramdisk entry layout")
    stock_entry = by_name["init"]
    if sha256(stock_entry.data) != EXPECTED_INIT_SHA256:
        raise ValueError("stock /init hash does not match the pinned artifact")
    sanitized_init, debug_section = clear_nonruntime_debugdata(stock_entry.data)
    marker_report: dict[str, object] = {
        "stock_init_log_marker": None,
        "stock_init_log_marker_offset": None,
        "stock_init_log_marker_occurrences": 0,
        "stock_init_log_marker_byte_differences": 0,
    }
    runtime_init = sanitized_init
    if patch_stock_init_log_marker:
        runtime_init, marker_report = patch_first_stage_log(sanitized_init)

    stock_index = entries.index(stock_entry)
    wrapper_fields = list(stock_entry.fields)
    wrapper_fields[0] = max(entry.fields[0] for entry in entries) + 1
    wrapper_entry = NewcEntry(stock_entry.magic, wrapper_fields, "init", wrapper)
    stock_entry.name = "init.stock"
    stock_entry.data = runtime_init
    entries.insert(stock_index, wrapper_entry)

    rebuilt_archive = write_newc(entries)
    rebuilt_compressed = gzip.compress(rebuilt_archive, compresslevel=9, mtime=0)
    rebuilt_end = page_size + len(rebuilt_compressed)
    if rebuilt_end > avb_offset:
        raise ValueError(
            f"rebuilt ramdisk overlaps AVB metadata by {rebuilt_end - avb_offset} bytes"
        )
    output = bytearray(source[:page_size])
    struct.pack_into("<I", output, 16, len(rebuilt_compressed))
    output.extend(rebuilt_compressed)
    output.extend(b"\0" * (avb_offset - len(output)))
    output.extend(source[avb_offset:])
    if len(output) != len(source) or output[avb_offset:] != source[avb_offset:]:
        raise AssertionError("partition size or embedded AVB tail changed")

    # Round-trip every critical property before returning the candidate.
    roundtrip_size = struct.unpack_from("<I", output, 16)[0]
    roundtrip_entries = parse_newc(
        gzip.decompress(bytes(output[page_size : page_size + roundtrip_size]))
    )
    roundtrip_by_name = {entry.name: entry for entry in roundtrip_entries}
    if roundtrip_by_name["init"].data != wrapper:
        raise AssertionError("diagnostic wrapper failed round-trip")
    if roundtrip_by_name["init.stock"].data != runtime_init:
        raise AssertionError("sanitized stock init failed round-trip")
    original_layout = elf64_layout(sanitized_init)
    preserved_except_marker = True
    marker_start = marker_report["stock_init_log_marker_offset"]
    marker_end = (
        marker_start + len(DIAGNOSTIC_FIRST_STAGE_LOG)
        if isinstance(marker_start, int)
        else -1
    )
    for header in original_layout["program_headers"]:
        if header["type"] != PT_LOAD:
            continue
        start = header["offset"]
        end = start + header["filesz"]
        for offset in range(start, end):
            if marker_start is not None and marker_start <= offset < marker_end:
                continue
            preserved_except_marker &= sanitized_init[offset] == runtime_init[offset]
    if not preserved_except_marker:
        raise AssertionError("stock init runtime segments changed outside the log marker")

    report: dict[str, object] = {
        "input_sha256": sha256(source),
        "output_sha256": sha256(output),
        "wrapper_sha256": sha256(wrapper),
        "stock_init_sha256": EXPECTED_INIT_SHA256,
        "sanitized_init_sha256": sha256(sanitized_init),
        "runtime_init_sha256": sha256(runtime_init),
        "partition_size": len(output),
        "page_size": page_size,
        "original_ramdisk_size": ramdisk_size,
        "rebuilt_ramdisk_size": len(rebuilt_compressed),
        "avb_offset": avb_offset,
        "avb_tail_sha256": sha256(source[avb_offset:]),
        "avb_tail_preserved": True,
        "stock_init_load_segments_preserved": not patch_stock_init_log_marker,
        "stock_init_load_segments_preserved_except_log_marker": (
            preserved_except_marker
        ),
        "cleared_section": ".gnu_debugdata",
        "cleared_section_offset": debug_section["offset"],
        "cleared_section_size": debug_section["size"],
        "diagnostic_scope": (
            "normal ramdisk only; bounded early-kmsg collector; stock init retained; "
            "no boot, super, vbmeta, userdata, or SELinux-policy change"
        ),
    }
    report.update(marker_report)
    return bytes(output), report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--stub", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--patch-stock-init-log-marker", action="store_true")
    args = parser.parse_args()
    if args.output.exists() or args.report.exists():
        parser.error("refusing to overwrite an existing output or report")
    output, report = build_image(
        args.input.read_bytes(),
        args.stub.read_bytes(),
        patch_stock_init_log_marker=args.patch_stock_init_log_marker,
    )
    report.update(
        {
            "input": str(args.input.resolve()),
            "stub": str(args.stub.resolve()),
            "output": str(args.output.resolve()),
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
