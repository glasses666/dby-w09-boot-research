#!/usr/bin/env python3
"""Validate the sanitized DBY-W09 publication tree and its hash manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "PUBLIC_MANIFEST.json"
MAX_FILE_SIZE = 2 * 1024 * 1024
FORBIDDEN_SUFFIXES = {
    ".7z",
    ".7zz",
    ".apk",
    ".bin",
    ".dtb",
    ".elf",
    ".img",
    ".iso",
    ".o",
    ".so",
    ".tar",
    ".xz",
    ".zip",
}
SKIPPED_NAMES = {".DS_Store", "PUBLIC_MANIFEST.json"}
SKIPPED_PARTS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache"}
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
ABSOLUTE_USER_PATH_RE = re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+/")
CREDENTIAL_RE = re.compile(
    rb"(?i)(?:api[_-]?key|password|secret|access[_-]?token)"
    rb"\s*[:=]\s*['\"][^'\"\r\n]{8,}"
)
PRIVATE_KEY_MARKER = b"-----BEGIN " + b"PRIVATE KEY-----"
OPENSSH_KEY_MARKER = b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"

# These values are split so the validator can inspect its own source without
# embedding the prohibited byte sequences verbatim.
BANNED_EXACT = {
    b"".join((b"9919", b"116F")),
    b"".join((b"W3VBB", b"22426213689")),
    b"".join((b"000c30e1", b"0015006e")),
    b"".join((b"192.168.", b"100.179")),
    b"".join((b"QUSB_BULK", b"_CID")),
    b"".join((b"4405049", b"997687")),
    b"".join((b"4455014", b"555049")),
    b"".join((b"4493581", b"105183")),
    b"".join((b"4547511", b"170061")),
    b"".join((b"6288399", b"072395")),
    b"".join((b"6318033", b"994984")),
    b"".join((b"6401645", b"294186")),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def distributed_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in SKIPPED_PARTS for part in relative.parts):
            continue
        if path.name in SKIPPED_NAMES:
            continue
        if path.is_file() or path.is_symlink():
            files.append(path)
    return sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())


def build_manifest() -> dict[str, object]:
    records = []
    tree_digest = hashlib.sha256()
    for path in distributed_files():
        relative = path.relative_to(ROOT).as_posix()
        digest = sha256_file(path)
        size = path.stat().st_size
        records.append({"path": relative, "size": size, "sha256": digest})
        tree_digest.update(relative.encode("utf-8"))
        tree_digest.update(b"\0")
        tree_digest.update(bytes.fromhex(digest))
    return {
        "schema": "dby-w09-public-manifest-v1",
        "hash_algorithm": "sha256",
        "manifest_excluded_from_inventory": True,
        "tree_sha256": tree_digest.hexdigest(),
        "files": records,
    }


def validate_markdown_links(path: Path, text: str, errors: list[str]) -> None:
    for raw_target in MARKDOWN_LINK_RE.findall(text):
        target = raw_target.strip().strip("<>")
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        target = unquote(target.split("#", 1)[0])
        if not target:
            continue
        resolved = (path.parent / target).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError:
            errors.append(f"{path.relative_to(ROOT)}: link escapes publication root: {target}")
            continue
        if not resolved.exists():
            errors.append(f"{path.relative_to(ROOT)}: broken relative link: {target}")


def validate_files() -> list[str]:
    errors: list[str] = []
    for path in distributed_files():
        relative = path.relative_to(ROOT)
        label = relative.as_posix()
        if path.is_symlink():
            errors.append(f"{label}: symlinks are not allowed")
            continue
        if relative.parts[:1] == ("private-fixtures",) and label != "private-fixtures/README.md":
            errors.append(f"{label}: private fixtures must not be distributed")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"{label}: forbidden binary/archive suffix")
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            errors.append(f"{label}: {size} bytes exceeds {MAX_FILE_SIZE}")
        data = path.read_bytes()
        if ABSOLUTE_USER_PATH_RE.search(data):
            errors.append(f"{label}: contains an absolute user-home path")
        for value in sorted(BANNED_EXACT):
            if value in data:
                errors.append(f"{label}: contains a blocked private identifier")
                break
        if PRIVATE_KEY_MARKER in data or OPENSSH_KEY_MARKER in data:
            errors.append(f"{label}: contains a private-key marker")
        if CREDENTIAL_RE.search(data):
            errors.append(f"{label}: contains a credential-like assignment")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{label}: distributed files must be UTF-8 text")
            continue
        if path.suffix.lower() == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError as error:
                errors.append(f"{label}: invalid JSON: {error}")
        if path.suffix.lower() == ".md":
            validate_markdown_links(path, text, errors)
    return errors


def validate_manifest() -> list[str]:
    if not MANIFEST.is_file():
        return ["PUBLIC_MANIFEST.json is missing"]
    try:
        recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"PUBLIC_MANIFEST.json is unreadable: {error}"]
    expected = build_manifest()
    if recorded != expected:
        return [
            "PUBLIC_MANIFEST.json does not match the current tree; regenerate it "
            "with --write-manifest"
        ]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()

    errors = validate_files()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    if args.write_manifest:
        MANIFEST.write_text(
            json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {MANIFEST.relative_to(ROOT)}")
        return 0

    errors = validate_manifest()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    manifest = build_manifest()
    print(
        "PASS: "
        f"{len(manifest['files'])} files, tree_sha256={manifest['tree_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
