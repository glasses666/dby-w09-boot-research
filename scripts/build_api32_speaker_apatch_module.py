#!/usr/bin/env python3
"""Build a deterministic APatch module for the accepted API32 speaker fix."""

# Public source attribution: Queen_Glasser (@glasses666).

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import zipfile


MODULE_ID = "dby_api32_speaker_compat"
MODULE_PROP = """id=dby_api32_speaker_compat
name=DBY-W09 API32 Speaker Compatibility
version=1.1.0
versionCode=2
author=Queen_Glasser (@glasses666)
description=Bind-mounts the accepted ODM-only Qualcomm detector before the API32 Audio HAL starts.
""".encode("utf-8")
LIBRARY_ENTRY = "system/vendor/lib/libqti_vndfwk_detect.so"
EXPECTED_LIBRARY_SHA256 = "706c5d92e7d6416b9ed194ede6e65e61259565a8d1ffa0dfada3cd096d72560c"
EXPECTED_LIBRARY_SIZE = 14976
POST_FS_DATA = f"""#!/system/bin/sh
MODDIR=${{0%/*}}
SOURCE="$MODDIR/vendor/lib/libqti_vndfwk_detect.so"
TARGET=/vendor/lib/libqti_vndfwk_detect.so
STOCK=1927811cdf681ab289ae32b73c6e59f94e63b505a7763a445db2942f5e179156
CANDIDATE={EXPECTED_LIBRARY_SHA256}

source_hash=$(sha256sum "$SOURCE" | awk '{{print $1}}')
target_hash=$(sha256sum "$TARGET" | awk '{{print $1}}')
if [ "$source_hash" != "$CANDIDATE" ]; then
    echo "dby_api32_speaker_compat: source hash mismatch" > /dev/kmsg
    exit 1
fi
if [ "$target_hash" = "$CANDIDATE" ]; then
    echo "dby_api32_speaker_compat: candidate already active" > /dev/kmsg
    exit 0
fi
if [ "$target_hash" != "$STOCK" ]; then
    echo "dby_api32_speaker_compat: target hash mismatch" > /dev/kmsg
    exit 1
fi
mount -o bind "$SOURCE" "$TARGET" || exit 1
active_hash=$(sha256sum "$TARGET" | awk '{{print $1}}')
if [ "$active_hash" != "$CANDIDATE" ]; then
    echo "dby_api32_speaker_compat: active hash mismatch" > /dev/kmsg
    exit 1
fi
echo "dby_api32_speaker_compat: candidate bind active" > /dev/kmsg
""".encode("utf-8")
FIXED_ZIP_TIME = (2026, 10, 28, 0, 0, 0)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def zip_entry(name: str, data: bytes, mode: int) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (mode & 0xFFFF) << 16
    return info, data


def build_module(candidate: bytes, *, verify_hash: bool = True) -> tuple[bytes, dict[str, object]]:
    candidate_hash = sha256_bytes(candidate)
    if verify_hash and candidate_hash != EXPECTED_LIBRARY_SHA256:
        raise ValueError("candidate detector identity mismatch")
    if len(candidate) != EXPECTED_LIBRARY_SIZE:
        raise ValueError("candidate detector size mismatch")
    if candidate[:6] != b"\x7fELF\x01\x01":
        raise ValueError("candidate detector is not little-endian ELF32")

    entries = (
        ("module.prop", MODULE_PROP, stat.S_IFREG | 0o644),
        ("post-fs-data.sh", POST_FS_DATA, stat.S_IFREG | 0o755),
        (LIBRARY_ENTRY, candidate, stat.S_IFREG | 0o644),
    )
    from io import BytesIO

    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data, mode in entries:
            info, payload = zip_entry(name, data, mode)
            archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    module = stream.getvalue()
    manifest: dict[str, object] = {
        "schema": "dby-w09-api32-speaker-apatch-module-v1",
        "module_id": MODULE_ID,
        "module_version": "1.1.0",
        "module_version_code": 2,
        "candidate_library_sha256": candidate_hash,
        "candidate_library_size": len(candidate),
        "library_target": "/vendor/lib/libqti_vndfwk_detect.so",
        "module_zip_sha256": sha256_bytes(module),
        "module_zip_size": len(module),
        "entries": [
            {"path": name, "size": len(data), "sha256": sha256_bytes(data), "mode": oct(mode & 0o777)}
            for name, data, mode in entries
        ],
        "partition_write_required": False,
        "activation": "module post-fs-data script validates both identities and bind-mounts one file before Audio HAL startup",
        "rollback": "disable dby_api32_speaker_compat and reboot; stock vendor file is never modified",
    }
    return module, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()

    output = args.output.resolve()
    manifest_path = args.manifest.resolve()
    if output.exists() or manifest_path.exists():
        raise RuntimeError("refusing to overwrite an existing module build")
    module, manifest = build_module(args.candidate.read_bytes())
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(module)
    output.chmod(0o644)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
