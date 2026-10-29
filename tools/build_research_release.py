#!/usr/bin/env python3
"""Package manifest-listed public sources as a deterministic ZIP or TAR archive.

Original release tooling: Queen_Glasser (@glasses666).
The output directory must already exist outside the publication tree.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "PUBLIC_MANIFEST.json"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def snapshot_sources(root: Path) -> dict[str, bytes]:
    """Read only the allowlist and bind the archived bytes to its hashes."""
    manifest_path = root / MANIFEST_NAME
    if manifest_path.is_symlink():
        raise ValueError("the public manifest must not be a symlink")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    sources: dict[str, bytes] = {}
    names: set[str] = {MANIFEST_NAME.casefold()}
    records = []
    tree_digest = hashlib.sha256()
    for record in manifest["files"]:
        name = record["path"]
        path = PurePosixPath(name)
        if (
            not name
            or path.is_absolute()
            or path.as_posix() != name
            or any(part in {".", ".."} for part in path.parts)
            or any(part.casefold() == ".git" for part in path.parts)
            or "\\" in name
            or ":" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
        ):
            raise ValueError(f"unsafe manifest path: {name!r}")
        key = name.casefold()
        if key in names:
            raise ValueError(f"colliding manifest path: {name}")
        names.add(key)
        source = root
        for part in path.parts:
            source = source / part
            if source.is_symlink():
                raise ValueError(f"symlink in manifest path: {name}")
        if not stat.S_ISREG(source.stat().st_mode):
            raise ValueError(f"manifest path is not a regular file: {name}")
        data = source.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if type(record["size"]) is not int or record["size"] != len(data):
            raise ValueError(f"manifest size changed: {name}")
        if digest != record["sha256"]:
            raise ValueError(f"manifest hash changed: {name}")
        sources[name] = data
        records.append({"path": name, "size": len(data), "sha256": digest})

    # Refuse file/directory and case-insensitive extraction collisions as well.
    for name in sources:
        for parent in PurePosixPath(name).parents:
            if parent.as_posix().casefold() in names:
                raise ValueError(f"file/directory collision: {name}")
    records.sort(key=lambda record: record["path"])
    for record in records:
        tree_digest.update(record["path"].encode("utf-8"))
        tree_digest.update(b"\0")
        tree_digest.update(bytes.fromhex(record["sha256"]))
    expected = {
        "schema": "dby-w09-public-manifest-v1",
        "hash_algorithm": "sha256",
        "manifest_excluded_from_inventory": True,
        "tree_sha256": tree_digest.hexdigest(),
        "files": records,
    }
    if manifest != expected:
        raise ValueError("public manifest schema or inventory changed")
    sources[MANIFEST_NAME] = manifest_bytes
    return sources


def archive_sources(sources: dict[str, bytes], archive_format: str) -> bytes:
    stream = io.BytesIO()
    if archive_format == "zip":
        # Stored entries avoid compression-library version differences.
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, data in sorted(sources.items()):
                info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, data)
    elif archive_format == "tar":
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(sources.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(data))
    else:
        raise ValueError("archive format must be zip or tar")
    return stream.getvalue()


def build_release(output: Path) -> tuple[Path, Path, str]:
    root = ROOT.resolve()
    # Keep the existing publication gate authoritative; never regenerate it.
    subprocess.run(
        [sys.executable, "-B", str(root / "tools/validate_public_tree.py"), "--check"],
        cwd=root,
        stdin=subprocess.DEVNULL,
        check=True,
    )
    requested = output.expanduser()
    if requested.is_symlink():
        raise FileExistsError(f"refusing output symlink: {requested}")
    output = requested.parent.resolve(strict=True) / requested.name
    if output == root or root in output.parents:
        raise ValueError("release output must be outside the publication tree")
    if "\\" in output.name or any(ord(char) < 32 or ord(char) == 127 for char in output.name):
        raise ValueError("output basename is unsafe for a checksum record")
    archive_format = output.suffix.lower().removeprefix(".")
    if archive_format not in {"zip", "tar"}:
        raise ValueError("output must have a .zip or .tar suffix")
    checksum = output.with_name(output.name + ".sha256")
    for path in (output, checksum):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite: {path}")
    payload = archive_sources(snapshot_sources(root), archive_format)
    digest = hashlib.sha256(payload).hexdigest()
    created: list[Path] = []
    try:
        # Exclusive creation also refuses outputs appearing after the checks.
        with output.open("xb") as archive_handle:
            created.append(output)
            with checksum.open("x", encoding="utf-8", newline="\n") as checksum_handle:
                created.append(checksum)
                archive_handle.write(payload)
                checksum_handle.write(f"{digest}  {output.name}\n")
    except BaseException:
        for path in reversed(created):
            path.unlink()
        raise
    return output, checksum, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new .zip or .tar outside the repository")
    args = parser.parse_args()
    try:
        output, checksum, digest = build_release(args.output)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"ERROR: {error}\n")
    print(f"wrote {output}\nwrote {checksum}\nsha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
