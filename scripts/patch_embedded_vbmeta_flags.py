#!/usr/bin/env python3
"""Disable verification only in an image's embedded child vbmeta header.

This preserves the top-level vbmeta chain.  libavb still records the chained
partition before observing the child VERIFICATION_DISABLED flag, but skips the
child descriptors (for boot, the now-stale hash descriptor).  The vbmeta
signature becomes invalid by construction and therefore this artifact is only
for an already-unlocked device whose libavb path allows verification errors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


AVB_FOOTER_MAGIC = b"AVBf"
AVB_VBMETA_MAGIC = b"AVB0"
AVB_FOOTER_SIZE = 64
AVB_HEADER_SIZE = 256
AVB_FLAGS_OFFSET = 120
VERIFICATION_DISABLED = 2


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_image", type=Path)
    parser.add_argument("output_image", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()

    source = args.input_image.resolve()
    output = args.output_image.resolve()
    manifest_path = (args.manifest or output.with_suffix(output.suffix + ".json")).resolve()
    if output.exists() or manifest_path.exists():
        raise SystemExit("refusing to overwrite an existing output or manifest")

    original = source.read_bytes()
    if len(original) < AVB_FOOTER_SIZE + AVB_HEADER_SIZE:
        raise SystemExit("input is too small for an AVB footer and header")
    footer_offset = len(original) - AVB_FOOTER_SIZE
    footer = original[footer_offset:]
    if footer[:4] != AVB_FOOTER_MAGIC:
        raise SystemExit("AVB footer magic not found at end of image")
    footer_major, footer_minor = struct.unpack_from(">II", footer, 4)
    original_image_size, vbmeta_offset, vbmeta_size = struct.unpack_from(">QQQ", footer, 12)
    if vbmeta_size < AVB_HEADER_SIZE or vbmeta_offset + vbmeta_size > footer_offset:
        raise SystemExit("invalid embedded vbmeta geometry")
    if original[vbmeta_offset : vbmeta_offset + 4] != AVB_VBMETA_MAGIC:
        raise SystemExit("embedded vbmeta header magic not found")

    flags_offset = vbmeta_offset + AVB_FLAGS_OFFSET
    flags_before = struct.unpack_from(">I", original, flags_offset)[0]
    if flags_before != 0:
        raise SystemExit(f"expected embedded vbmeta flags 0, got {flags_before}")

    patched = bytearray(original)
    struct.pack_into(">I", patched, flags_offset, flags_before | VERIFICATION_DISABLED)
    flags_after = struct.unpack_from(">I", patched, flags_offset)[0]

    differences = [index for index, (before, after) in enumerate(zip(original, patched)) if before != after]
    if differences != [flags_offset + 3]:
        raise AssertionError(f"unexpected byte differences: {differences}")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(patched)
    manifest = {
        "source": str(source),
        "output": str(output),
        "source_size": len(original),
        "output_size": len(patched),
        "source_sha256": sha256(original),
        "output_sha256": sha256(patched),
        "footer": {
            "offset": footer_offset,
            "version_major": footer_major,
            "version_minor": footer_minor,
            "original_image_size": original_image_size,
            "vbmeta_offset": vbmeta_offset,
            "vbmeta_size": vbmeta_size,
        },
        "embedded_vbmeta": {
            "flags_offset": flags_offset,
            "flags_before": flags_before,
            "flags_after": flags_after,
            "verification_disabled": True,
        },
        "changed_byte_offsets": differences,
        "change_count": len(differences),
        "unchanged_outside_flags_field": True,
        "safety_note": (
            "The embedded vbmeta signature is intentionally invalid after the header change. "
            "Use only as a child image on an already-unlocked device; do not disable the "
            "top-level vbmeta chain."
        ),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
