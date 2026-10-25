#!/usr/bin/env python3
"""Build a DBY-W09 boot image that skips AVB for logical super partitions.

The stock Android boot-v2 image contains a dedicated concatenated-DTB region.
By default this builder patches the ext4 and EROFS fstab entries for system,
vendor, odm, cust, and hw_product in each applicable DTB.  ``--system-only``
limits that patch to system_ext4 and system_erofs.  The default replacement
changes the exact ``avb`` token to the same-length unknown token ``nof``;
Android's fstab parser ignores unknown fs_mgr flags while the logical-partition
and nofail semantics remain.

Every FDT geometry remains unchanged.  All bytes outside the boot image's DTB
region, including the compressed kernel and stock AVB footer, are copied
verbatim.  The resulting boot hash descriptor is intentionally stale, so this
artifact is suitable only for an already-unlocked test device.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


ANDROID_MAGIC = b"ANDROID!"
FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9

ALLOWED_OLD_FLAGS = {
    b"wait,logical,avb\0",
    b"wait,nofail,logical,avb\0",
}
TARGET_NODES = {
    "/firmware/android/fstab/system_ext4",
    "/firmware/android/fstab/system_erofs",
    "/firmware/android/fstab/vendor_ext4",
    "/firmware/android/fstab/vendor_erofs",
    "/firmware/android/fstab/odm_ext4",
    "/firmware/android/fstab/odm_erofs",
    "/firmware/android/fstab/cust_ext4",
    "/firmware/android/fstab/cust_erofs",
    "/firmware/android/fstab/hw_product_ext4",
    "/firmware/android/fstab/hw_product_erofs",
}
SYSTEM_NODES = {
    "/firmware/android/fstab/system_ext4",
    "/firmware/android/fstab/system_erofs",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def read_c_string(data: bytes | bytearray, offset: int, limit: int) -> tuple[str, int]:
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise ValueError(f"unterminated string at offset 0x{offset:x}")
    return bytes(data[offset:end]).decode("ascii"), end + 1


def checked_fdt(data: bytes | bytearray, offset: int) -> tuple[int, tuple[int, ...]] | None:
    if offset < 0 or offset + 40 > len(data):
        return None
    fields = struct.unpack_from(">10I", data, offset)
    magic, total_size, off_struct, off_strings, off_mem, version, compat, _, strings_size, struct_size = fields
    if magic != FDT_MAGIC or total_size < 40 or offset + total_size > len(data):
        return None
    if version < 16 or compat > version:
        return None
    for section_offset, section_size in ((off_struct, struct_size), (off_strings, strings_size)):
        if section_offset < 40 or section_size < 0 or section_offset + section_size > total_size:
            return None
    if off_mem < 40 or off_mem >= total_size:
        return None
    return total_size, fields


def scan_fdts(data: bytes | bytearray) -> list[tuple[int, int, tuple[int, ...]]]:
    needle = struct.pack(">I", FDT_MAGIC)
    results: list[tuple[int, int, tuple[int, ...]]] = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            break
        parsed = checked_fdt(data, offset)
        if parsed is None:
            cursor = offset + 4
            continue
        total_size, fields = parsed
        results.append((offset, total_size, fields))
        cursor = offset + total_size
    return results


def patch_fdt(
    kernel: bytearray,
    base: int,
    fields: tuple[int, ...],
    exact_remove_avb: bool = False,
    target_nodes: set[str] = TARGET_NODES,
) -> list[dict[str, object]]:
    _, total_size, off_struct, off_strings, _, _, _, _, strings_size, struct_size = fields
    struct_start = base + off_struct
    struct_end = struct_start + struct_size
    strings_start = base + off_strings
    strings_end = strings_start + strings_size
    cursor = struct_start
    stack: list[str] = []
    changes: list[dict[str, object]] = []

    while cursor + 4 <= struct_end:
        token = struct.unpack_from(">I", kernel, cursor)[0]
        cursor += 4
        if token == FDT_BEGIN_NODE:
            name, cursor = read_c_string(kernel, cursor, struct_end)
            cursor = base + align(cursor - base, 4)
            stack.append(name)
        elif token == FDT_END_NODE:
            if not stack:
                raise ValueError(f"unbalanced FDT node stack at 0x{cursor - 4:x}")
            stack.pop()
        elif token == FDT_PROP:
            if cursor + 8 > struct_end:
                raise ValueError("truncated FDT property header")
            property_header_offset = cursor
            length, name_offset = struct.unpack_from(">II", kernel, cursor)
            cursor += 8
            data_offset = cursor
            data_end = data_offset + length
            if data_end > struct_end or name_offset >= strings_size:
                raise ValueError("FDT property exceeds declared structure or strings block")
            prop_name, _ = read_c_string(kernel, strings_start + name_offset, strings_end)
            node_path = "/" + "/".join(part for part in stack if part)
            if node_path in target_nodes and prop_name == "fsmgr_flags":
                observed = bytes(kernel[data_offset:data_end])
                if observed not in ALLOWED_OLD_FLAGS:
                    raise ValueError(
                        f"unexpected {node_path}/fsmgr_flags value {observed!r}; refusing blind patch"
                    )
                old_display = observed[:-1].decode()
                if exact_remove_avb:
                    exact_flags = observed.removesuffix(b",avb\0") + b"\0"
                    old_padded_length = align(length, 4)
                    new_padded_length = align(len(exact_flags), 4)
                    if old_padded_length - new_padded_length != 4:
                        raise AssertionError("exact replacement requires one four-byte FDT_NOP slot")
                    struct.pack_into(">I", kernel, property_header_offset, len(exact_flags))
                    kernel[data_offset : data_offset + new_padded_length] = exact_flags + b"\0" * (
                        new_padded_length - len(exact_flags)
                    )
                    struct.pack_into(">I", kernel, data_offset + new_padded_length, FDT_NOP)
                    new_display = exact_flags[:-1].decode()
                else:
                    replacement = observed.removesuffix(b"avb\0") + b"nof\0"
                    if len(replacement) != length:
                        raise AssertionError("replacement must preserve FDT property length")
                    kernel[data_offset:data_end] = replacement
                    new_display = replacement[:-1].decode()
                changes.append(
                    {
                        "node": node_path,
                        "property": prop_name,
                        "absolute_dtb_region_offset": data_offset,
                        "old": old_display,
                        "new": new_display,
                        "exact_remove_avb": exact_remove_avb,
                    }
                )
            cursor = base + align(data_end - base, 4)
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            break
        else:
            raise ValueError(f"unknown FDT structure token {token} at 0x{cursor - 4:x}")

    if cursor > base + total_size:
        raise ValueError("FDT parser escaped the declared blob")
    return changes


def patch_fdt_system_dev_probe(
    kernel: bytearray,
    base: int,
    fields: tuple[int, ...],
) -> list[dict[str, object]]:
    """Rename only the system fstab device for a runtime-DTB diagnostic boot."""
    _, total_size, off_struct, off_strings, _, _, _, _, strings_size, struct_size = fields
    struct_start = base + off_struct
    struct_end = struct_start + struct_size
    strings_start = base + off_strings
    strings_end = strings_start + strings_size
    cursor = struct_start
    stack: list[str] = []
    changes: list[dict[str, object]] = []

    while cursor + 4 <= struct_end:
        token = struct.unpack_from(">I", kernel, cursor)[0]
        cursor += 4
        if token == FDT_BEGIN_NODE:
            name, cursor = read_c_string(kernel, cursor, struct_end)
            cursor = base + align(cursor - base, 4)
            stack.append(name)
        elif token == FDT_END_NODE:
            if not stack:
                raise ValueError(f"unbalanced FDT node stack at 0x{cursor - 4:x}")
            stack.pop()
        elif token == FDT_PROP:
            if cursor + 8 > struct_end:
                raise ValueError("truncated FDT property header")
            length, name_offset = struct.unpack_from(">II", kernel, cursor)
            cursor += 8
            data_offset = cursor
            data_end = data_offset + length
            if data_end > struct_end or name_offset >= strings_size:
                raise ValueError("FDT property exceeds declared structure or strings block")
            prop_name, _ = read_c_string(kernel, strings_start + name_offset, strings_end)
            node_path = "/" + "/".join(part for part in stack if part)
            if node_path in SYSTEM_NODES and prop_name == "dev":
                observed = bytes(kernel[data_offset:data_end])
                if observed != b"system\0":
                    raise ValueError(
                        f"unexpected {node_path}/dev value {observed!r}; refusing blind patch"
                    )
                replacement = b"systxm\0"
                if len(replacement) != length:
                    raise AssertionError("probe replacement must preserve FDT property length")
                kernel[data_offset:data_end] = replacement
                changes.append(
                    {
                        "node": node_path,
                        "property": prop_name,
                        "absolute_dtb_region_offset": data_offset,
                        "old": "system",
                        "new": "systxm",
                        "diagnostic_only": True,
                    }
                )
            cursor = base + align(data_end - base, 4)
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            break
        else:
            raise ValueError(f"unknown FDT structure token {token} at 0x{cursor - 4:x}")

    if cursor > base + total_size:
        raise ValueError("FDT parser escaped the declared blob")
    return changes


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("stock_boot", type=Path)
    parser.add_argument("output_boot", type=Path)
    parser.add_argument("--manifest", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--exact-remove-avb",
        action="store_true",
        help="set the property to wait,logical and fill the saved word with FDT_NOP",
    )
    mode.add_argument(
        "--probe-system-dev",
        action="store_true",
        help="diagnostic only: rename system fstab dev to systxm without changing AVB flags",
    )
    parser.add_argument(
        "--system-only",
        action="store_true",
        help=(
            "limit AVB flag patching to system_ext4/system_erofs; the default remains all "
            "logical super partitions"
        ),
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()

    source = args.stock_boot.resolve()
    output = args.output_boot.resolve()
    manifest_path = (args.manifest or output.with_suffix(output.suffix + ".json")).resolve()
    if manifest_path == output:
        raise SystemExit("manifest path must differ from output path")
    if output.exists() or manifest_path.exists():
        raise SystemExit("refusing to overwrite an existing output or manifest")

    boot = bytearray(source.read_bytes())
    if boot[:8] != ANDROID_MAGIC or len(boot) < 4096:
        raise SystemExit("input is not a supported Android boot image")
    kernel_size = struct.unpack_from("<I", boot, 8)[0]
    ramdisk_size = struct.unpack_from("<I", boot, 16)[0]
    second_size = struct.unpack_from("<I", boot, 24)[0]
    page_size = struct.unpack_from("<I", boot, 36)[0]
    header_version = struct.unpack_from("<I", boot, 40)[0]
    if page_size == 0 or page_size & (page_size - 1):
        raise SystemExit(f"invalid boot page size: {page_size}")
    if header_version != 2:
        raise SystemExit(f"expected Android boot header v2, got v{header_version}")
    recovery_dtbo_size = struct.unpack_from("<I", boot, 1632)[0]
    header_size = struct.unpack_from("<I", boot, 1644)[0]
    dtb_size = struct.unpack_from("<I", boot, 1648)[0]
    if header_size < 1660 or header_size > page_size:
        raise SystemExit(f"invalid boot-v2 header size: {header_size}")
    kernel_offset = page_size
    kernel_end = kernel_offset + kernel_size
    if kernel_size == 0 or kernel_end > len(boot):
        raise SystemExit("invalid kernel geometry in boot header")
    dtb_offset = (
        page_size
        + align(kernel_size, page_size)
        + align(ramdisk_size, page_size)
        + align(second_size, page_size)
        + align(recovery_dtbo_size, page_size)
    )
    dtb_end = dtb_offset + dtb_size
    if dtb_size == 0 or dtb_end > len(boot):
        raise SystemExit("invalid DTB geometry in boot-v2 header")

    dtb_region = bytearray(boot[dtb_offset:dtb_end])
    dtb_region_before_sha = sha256(dtb_region)
    fdt_entries = scan_fdts(dtb_region)
    if not fdt_entries:
        raise SystemExit("no valid FDT blobs found in the boot-v2 DTB region")

    fdt_manifest: list[dict[str, object]] = []
    all_changes: list[dict[str, object]] = []
    target_nodes = SYSTEM_NODES if args.system_only else TARGET_NODES
    for index, (offset, size, fields) in enumerate(fdt_entries):
        before = bytes(dtb_region[offset : offset + size])
        if args.probe_system_dev:
            changes = patch_fdt_system_dev_probe(dtb_region, offset, fields)
        else:
            changes = patch_fdt(
                dtb_region,
                offset,
                fields,
                exact_remove_avb=args.exact_remove_avb,
                target_nodes=target_nodes,
            )
        after = bytes(dtb_region[offset : offset + size])
        entry = {
            "index": index,
            "offset": offset,
            "size": size,
            "sha256_before": sha256(before),
            "sha256_after": sha256(after),
            "changes": changes,
        }
        fdt_manifest.append(entry)
        all_changes.extend(changes)

    expected_nodes = SYSTEM_NODES if args.probe_system_dev else target_nodes
    expected_changes = len(expected_nodes) * 3
    changed_entries = [entry for entry in fdt_manifest if entry["changes"]]
    distribution_ok = len(changed_entries) == 3 and all(
        len(entry["changes"]) == len(expected_nodes)
        and {change["node"] for change in entry["changes"]} == expected_nodes
        for entry in changed_entries
    )
    if not distribution_ok:
        raise SystemExit(
            "expected the exact logical-partition node set in each of three DTBs"
        )
    if len(all_changes) != expected_changes:
        raise SystemExit(
            f"expected {expected_changes} logical-partition fstab changes across three DTBs, "
            f"got {len(all_changes)}"
        )

    before_non_dtb = bytes(boot[:dtb_offset] + boot[dtb_end:])
    boot[dtb_offset:dtb_end] = dtb_region
    after_non_dtb = bytes(boot[:dtb_offset] + boot[dtb_end:])
    if before_non_dtb != after_non_dtb:
        raise AssertionError("bytes outside the DTB region changed")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(boot)
    manifest = {
        "source": str(source),
        "output": str(output),
        "source_size": source.stat().st_size,
        "output_size": len(boot),
        "source_sha256": sha256(source.read_bytes()),
        "output_sha256": sha256(boot),
        "boot_header": {
            "header_version": header_version,
            "header_size": header_size,
            "page_size": page_size,
            "kernel_offset": kernel_offset,
            "kernel_size": kernel_size,
            "ramdisk_size": ramdisk_size,
            "second_size": second_size,
            "recovery_dtbo_size": recovery_dtbo_size,
            "dtb_offset": dtb_offset,
            "dtb_size": dtb_size,
        },
        "dtb_region": {
            "sha256_before": dtb_region_before_sha,
            "sha256_after": sha256(dtb_region),
        },
        "fdt_entries": fdt_manifest,
        "change_count": len(all_changes),
        "exact_remove_avb": args.exact_remove_avb,
        "probe_system_dev": args.probe_system_dev,
        "system_only": args.system_only,
        "unchanged_outside_dtb_region": True,
        "avb_note": (
            "The stock AVB footer is preserved byte-for-byte, so its boot hash descriptor no longer "
            "matches. This candidate is only for an unlocked device with the original top-level "
            "vbmeta chain preserved."
        ),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
