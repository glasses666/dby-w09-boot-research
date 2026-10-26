#!/usr/bin/env python3
"""Offline verifier for an API30 init NFC legacy compatibility build."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "scripts/build_api30_init_nfc_legacy_compat.py"
spec = importlib.util.spec_from_file_location("api30_init_nfc_legacy_compat", BUILDER_PATH)
builder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(builder)

E2FSCK = Path("/opt/homebrew/opt/e2fsprogs/sbin/e2fsck")
TUNE2FS = Path("/opt/homebrew/opt/e2fsprogs/sbin/tune2fs")


def run_text(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=180)


def parse_tune2fs_summary(text: str) -> dict[str, object]:
    def field(name: str) -> str:
        match = re.search(rf"^{re.escape(name)}:\s+(.+)$", text, re.MULTILINE)
        if match is None:
            raise ValueError(f"missing tune2fs field: {name}")
        return match.group(1).strip()

    return {
        "uuid": field("Filesystem UUID"),
        "features": tuple(field("Filesystem features").split()),
        "state": field("Filesystem state"),
        "block_size": int(field("Block size")),
    }


def normalize_objdump_disassembly(text: str) -> str:
    lines = []
    for line in text.splitlines():
        match = re.match(r"\s*(495(?:a8|ac|b0|b4)):\s+([0-9a-f]{8})\s+(.+)$", line)
        if match is None:
            continue
        instruction = re.sub(r"\s+", " ", match.group(3).strip())
        instruction = instruction.split(" //", 1)[0]
        lines.append(f"{match.group(1)}: {match.group(2)} {instruction}")
    if len(lines) != 4:
        raise ValueError("unexpected objdump instruction window")
    return "\n".join(lines)


def verify(output_dir: Path) -> dict[str, object]:
    system = output_dir / "system-api30-init-nfc-legacy-compat-NOT-FLASHED.ext4"
    super_image = output_dir / "super-api30-init-nfc-legacy-compat-NOT-FLASHED.img"
    system_manifest_path = output_dir / "system.manifest.json"
    super_manifest_path = output_dir / "super.manifest.json"
    for path in (system, super_image, system_manifest_path, super_manifest_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    system_manifest = json.loads(system_manifest_path.read_text())
    super_manifest = json.loads(super_manifest_path.read_text())
    if system_manifest["schema"] != "dby-w09-api30-init-nfc-legacy-compat-v4":
        raise ValueError("unexpected system manifest schema")
    if super_manifest["schema"] != "dby-w09-api30-init-nfc-legacy-compat-v4":
        raise ValueError("unexpected super manifest schema")
    if system_manifest["status"] != "offline-built-not-flashed":
        raise ValueError("candidate status changed")
    if system_manifest["device_io_performed"] or super_manifest["device_io_performed"]:
        raise ValueError("offline candidate unexpectedly reports device I/O")

    builder.validate_source(builder.SOURCE_SYSTEM, builder.SYSTEM_SIZE, builder.SOURCE_SYSTEM_SHA256)
    builder.validate_source(builder.SOURCE_SUPER, builder.SUPER_SIZE, builder.SOURCE_SUPER_SHA256)
    system_hash = builder.sha256_file(system)
    super_hash = builder.sha256_file(super_image)
    if system_hash != system_manifest["output_system"]["sha256"]:
        raise ValueError("candidate system hash does not match manifest")
    if super_hash != super_manifest["output_super"]["sha256"]:
        raise ValueError("candidate super hash does not match manifest")
    if system_hash != builder.EXPECTED_OUTPUT_SYSTEM_SHA256:
        raise ValueError("candidate system frozen identity changed")
    if super_hash != builder.EXPECTED_OUTPUT_SUPER_SHA256:
        raise ValueError("candidate super frozen identity changed")
    if builder.sha256_file(super_image, builder.SYSTEM_OFFSET_IN_SUPER, builder.SYSTEM_SIZE) != system_hash:
        raise ValueError("candidate super does not embed candidate system")

    system_patch = builder.exact_patch_audit(
        builder.SOURCE_SYSTEM, system, builder.PATCH_OFFSET_IN_SYSTEM
    )
    super_patch = builder.exact_patch_audit(
        builder.SOURCE_SUPER, super_image, builder.PATCH_OFFSET_IN_SUPER
    )
    source_init = builder.debugfs(f"cat {builder.INIT_PATH}", builder.SOURCE_SYSTEM)
    candidate_init = builder.debugfs(f"cat {builder.INIT_PATH}", system)
    if candidate_init != builder.patched_init(source_init):
        raise ValueError("candidate init does not equal exact expected patch")
    if builder.sha256_bytes(candidate_init) != builder.EXPECTED_OUTPUT_INIT_SHA256:
        raise ValueError("candidate init frozen identity changed")
    if builder.decode_excluded_name(source_init[builder.INIT_FILE_OFFSET : builder.INIT_FILE_OFFSET + 8]) != "gsi":
        raise ValueError("source init inferred exclusion is not gsi")
    if builder.decode_excluded_name(candidate_init[builder.INIT_FILE_OFFSET : builder.INIT_FILE_OFFSET + 8]) != "nfc":
        raise ValueError("candidate init inferred exclusion is not nfc")

    for command in (
        f"stat {builder.INIT_PATH}",
        f"ea_list {builder.INIT_PATH}",
        f"blocks {builder.INIT_PATH}",
    ):
        if builder.debugfs(command, builder.SOURCE_SYSTEM) != builder.debugfs(command, system):
            raise ValueError(f"candidate init metadata differs: {command}")
    if builder.debugfs(f"bmap {builder.INIT_PATH} {builder.INIT_FILE_BLOCK}", system).strip() != str(
        builder.INIT_PHYSICAL_BLOCK
    ).encode():
        raise ValueError("candidate init physical block mapping changed")

    gsid_rc = builder.debugfs("cat /system/etc/init/gsid.rc", system)
    init_rc = builder.debugfs("cat /system/etc/init/hw/init.rc", system)
    if b"mkdir /data/gsi 0700 root root encryption=None" not in gsid_rc:
        raise ValueError("explicit GSI encryption=None action is missing")
    if b"# /data/nfc exists; skip mkdir policy collision" not in init_rc:
        raise ValueError("v2 system-side NFC mkdir skip is missing")
    if b"mkdir /data/nfc 0770 nfc nfc encryption=Require" in init_rc:
        raise ValueError("fatal system-side NFC mkdir action returned")

    fsck = run_text([str(E2FSCK), "-fn", str(system)])
    fsck_text = fsck.stdout + fsck.stderr
    if "e2fsck 1.47.4" not in fsck_text:
        raise ValueError("unexpected e2fsck version")
    source_tune = run_text([str(TUNE2FS), "-l", str(builder.SOURCE_SYSTEM)])
    candidate_tune = run_text([str(TUNE2FS), "-l", str(system)])
    source_ext4 = parse_tune2fs_summary(source_tune.stdout + source_tune.stderr)
    candidate_ext4 = parse_tune2fs_summary(candidate_tune.stdout + candidate_tune.stderr)
    if source_ext4 != candidate_ext4:
        raise ValueError("candidate ext4 contract differs from source")
    if candidate_ext4["state"] != "clean":
        raise ValueError("candidate ext4 filesystem is not clean")
    if candidate_ext4["block_size"] != 4096:
        raise ValueError("candidate ext4 block size changed")

    with tempfile.TemporaryDirectory() as temporary:
        init_path = Path(temporary) / "init"
        init_path.write_bytes(candidate_init)
        raw_disassembly = run_text(
            [
                "/usr/bin/objdump",
                "-d",
                "--start-address=0x495a8",
                "--stop-address=0x495b8",
                str(init_path),
            ]
        ).stdout
    disassembly = normalize_objdump_disassembly(raw_disassembly)
    if "495ac: 52800c64 mov w4, #0x63" not in disassembly or "495b0: 528ccdce mov w14, #0x666e" not in disassembly:
        raise ValueError("patched AArch64 instructions do not reconstruct nfc")

    return {
        "schema": "dby-w09-api30-init-nfc-legacy-compat-v4-qualification",
        "status": "offline-qualified-not-flashed",
        "device_io_performed": False,
        "system": {"size": system.stat().st_size, "sha256": system_hash},
        "super": {"size": super_image.stat().st_size, "sha256": super_hash},
        "init": {
            "source_sha256": builder.sha256_bytes(source_init),
            "candidate_sha256": builder.sha256_bytes(candidate_init),
            "source_excluded_name": "gsi",
            "candidate_excluded_name": "nfc",
            "instruction_disassembly": disassembly,
            "inode_metadata_unchanged": True,
            "selinux_xattr_unchanged": True,
        },
        "system_patch": system_patch,
        "super_patch": super_patch,
        "gsid_explicit_none_preserved": True,
        "system_nfc_require_action_absent": True,
        "vendor_partition_changed": False,
        "ext4": {
            "e2fsck_passed": True,
            "source_contract_preserved": True,
            "uuid": candidate_ext4["uuid"],
            "features": list(candidate_ext4["features"]),
            "clean": True,
            "block_size": candidate_ext4["block_size"],
            "shared_blocks": "shared_blocks" in candidate_ext4["features"],
        },
        "live_status": "not tested",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = verify(args.output_dir)
    if args.report is not None:
        if args.report.exists():
            raise FileExistsError(args.report)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
