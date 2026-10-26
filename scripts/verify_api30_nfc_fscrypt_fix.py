#!/usr/bin/env python3
"""Offline qualification for the single-span API30 /data/nfc mkdir skip."""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE_BASE = ROOT / "analysis/firmware-20261014/api30-aosp-baseline-offline-20261026"
BASE = ROOT / "analysis/firmware-20261014/api30-nfc-mkdir-skip-offline-20261026"
BUILDER_PATH = ROOT / "scripts/build_api30_nfc_fscrypt_fix.py"
SOURCE_QUALIFICATION = SOURCE_BASE / "qualification-report.live-recheck-20261026-194900.json"
SYSTEM_A = BASE / "build-a/system-api30-nfc-mkdir-skip-NOT-FLASHED.ext4"
SYSTEM_B = BASE / "build-b/system-api30-nfc-mkdir-skip-NOT-FLASHED.ext4"
SUPER_A = BASE / "build-a/super-api30-nfc-mkdir-skip-NOT-FLASHED.img"
SUPER_B = BASE / "build-b/super-api30-nfc-mkdir-skip-NOT-FLASHED.img"
SYSTEM_MANIFEST_A = BASE / "build-a/system.manifest.json"
SYSTEM_MANIFEST_B = BASE / "build-b/system.manifest.json"
SUPER_MANIFEST_A = BASE / "build-a/super.manifest.json"
SUPER_MANIFEST_B = BASE / "build-b/super.manifest.json"
EXPECTED_SYSTEM_SHA256 = "65070d2b8f71cc9bebd8d24df62bec3cf578e60e3586235bea40b7cd7a430e14"
EXPECTED_SUPER_SHA256 = "aefb9e9a06301537bfd385160e1d7c4e45a00364bc677cf0c357ec5a819d7fec"
APATCH_BOOT = ROOT / "analysis/firmware-20261014/api29-apatch-root-20261025/candidate/apatch-11224-boot.img"
APATCH_BOOT_SHA256 = "dae495fdd20636469ac24e451cc6b2ff6e9201b26af4603fa0ce7c6921837f70"
E2FSCK = Path("/opt/homebrew/opt/e2fsprogs/sbin/e2fsck")


def load_builder():
    spec = importlib.util.spec_from_file_location("dby_api30_nfc_fix_builder", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {BUILDER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def record(path: Path) -> dict[str, object]:
    return {"path": str(path.resolve()), "size": path.stat().st_size, "sha256": sha256_file(path)}


def verify_manifest(path: Path, output_key: str, expected_hash: str) -> dict[str, object]:
    report = json.loads(path.read_text())
    if (
        report.get("schema") != "dby-w09-api30-nfc-mkdir-skip-v2"
        or report.get("status") != "offline-built-not-flashed"
        or report.get("device_io_performed") is not False
        or report.get(output_key, {}).get("sha256") != expected_hash
        or report.get("patch", {}).get("outside_span_byte_identical") is not True
    ):
        raise ValueError(f"manifest failed: {path}")
    return report


def run_checked(command: list[str], timeout: int = 300) -> bytes:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.decode(errors="replace"))
    return completed.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if output.parent != BASE.resolve():
        raise ValueError("output must be a direct child of the API30 NFC mkdir-skip directory")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")

    builder = load_builder()
    identities = {
        "system_a": record(SYSTEM_A),
        "system_b": record(SYSTEM_B),
        "super_a": record(SUPER_A),
        "super_b": record(SUPER_B),
        "apatch_boot": record(APATCH_BOOT),
    }
    if identities["system_a"]["sha256"] != EXPECTED_SYSTEM_SHA256 or identities["system_b"]["sha256"] != EXPECTED_SYSTEM_SHA256:
        raise ValueError("repaired system identity mismatch")
    if identities["super_a"]["sha256"] != EXPECTED_SUPER_SHA256 or identities["super_b"]["sha256"] != EXPECTED_SUPER_SHA256:
        raise ValueError("repaired super identity mismatch")
    if identities["apatch_boot"]["sha256"] != APATCH_BOOT_SHA256:
        raise ValueError("paired APatch boot identity mismatch")
    if not filecmp.cmp(SYSTEM_A, SYSTEM_B, shallow=False) or not filecmp.cmp(SUPER_A, SUPER_B, shallow=False):
        raise ValueError("A/B builds are not byte-identical")

    system_audit = builder.exact_patch_audit(builder.SOURCE_SYSTEM, SYSTEM_A, builder.PATCH_OFFSET_IN_SYSTEM)
    builder.exact_patch_audit(builder.SOURCE_SYSTEM, SYSTEM_B, builder.PATCH_OFFSET_IN_SYSTEM)
    super_audit = builder.exact_patch_audit(builder.SOURCE_SUPER, SUPER_A, builder.PATCH_OFFSET_IN_SUPER)
    builder.exact_patch_audit(builder.SOURCE_SUPER, SUPER_B, builder.PATCH_OFFSET_IN_SUPER)

    manifests = {
        "system_a": verify_manifest(SYSTEM_MANIFEST_A, "output_system", EXPECTED_SYSTEM_SHA256),
        "system_b": verify_manifest(SYSTEM_MANIFEST_B, "output_system", EXPECTED_SYSTEM_SHA256),
        "super_a": verify_manifest(SUPER_MANIFEST_A, "output_super", EXPECTED_SUPER_SHA256),
        "super_b": verify_manifest(SUPER_MANIFEST_B, "output_super", EXPECTED_SUPER_SHA256),
    }
    if manifests["system_a"]["patch"] != manifests["system_b"]["patch"]:
        raise ValueError("system A/B patch manifests differ")
    if manifests["super_a"]["patch"] != manifests["super_b"]["patch"]:
        raise ValueError("super A/B patch manifests differ")

    source_rc = builder.read_init_rc(builder.SOURCE_SYSTEM)
    repaired_rc = builder.repaired_rc(source_rc)
    if builder.read_init_rc(SYSTEM_A) != repaired_rc or builder.read_init_rc(SYSTEM_B) != repaired_rc:
        raise ValueError("repaired init.rc semantic readback changed")
    metadata = {}
    for command in (f"stat {builder.INIT_RC}", f"ea_list {builder.INIT_RC}"):
        source_value = builder.debugfs(command, builder.SOURCE_SYSTEM)
        if builder.debugfs(command, SYSTEM_A) != source_value or builder.debugfs(command, SYSTEM_B) != source_value:
            raise ValueError(f"metadata changed: {command}")
        metadata[command] = hashlib.sha256(source_value).hexdigest()

    fsck = {}
    for name, path in (("build_a", SYSTEM_A), ("build_b", SYSTEM_B)):
        result = run_checked([str(E2FSCK), "-fn", str(path)])
        text = result.decode(errors="replace")
        if "e2fsck 1.47.4" not in text or "473314/613724 blocks" not in text:
            raise RuntimeError(f"unexpected e2fsck result: {path}: {text}")
        fsck[name] = {"output_sha256": hashlib.sha256(result).hexdigest(), "final_line": text.strip().splitlines()[-1]}

    source_qualification = json.loads(SOURCE_QUALIFICATION.read_text())
    inputs = source_qualification.get("inputs", {})
    if (
        source_qualification.get("status") != "offline_qualified_not_flashed"
        or source_qualification.get("device_io_performed") is not False
        or source_qualification.get("network_performed") is not False
        or inputs.get("system_a", {}).get("sha256") != builder.SOURCE_SYSTEM_SHA256
        or inputs.get("super", {}).get("sha256") != builder.SOURCE_SUPER_SHA256
        or source_qualification.get("reproducible_system_builds", {}).get("byte_identical") is not True
        or source_qualification.get("super_range_readback", {}).get("prefix_equal") is not True
        or source_qualification.get("super_range_readback", {}).get("suffix_equal") is not True
        or source_qualification.get("super_range_readback", {}).get("zero_tail") is not True
        or source_qualification.get("first_stage_binding", {}).get("apatch_preserves_fstab_dtb") is not True
    ):
        raise ValueError("bound source API30 qualification is not reusable")

    test_output = run_checked(
        [sys.executable, "-B", "-m", "unittest", "tests.test_build_api30_nfc_fscrypt_fix", "-v"]
    )
    if b"Ran 8 tests" not in test_output or b"OK" not in test_output:
        raise ValueError("focused test gate did not report eight passing tests")

    report = {
        "schema": "dby-w09-api30-nfc-mkdir-skip-qualification-v2",
        "status": "offline-gates-passed-not-flashed",
        "device_io_performed": False,
        "network_performed": False,
        "identities": identities,
        "deterministic_builds": {
            "system_byte_identical": True,
            "super_byte_identical": True,
            "system_patch": system_audit,
            "super_patch": super_audit,
            "manifests_equivalent": True,
        },
        "filesystem": {"e2fsck": fsck, "metadata_unchanged": metadata},
        "source_qualification": record(SOURCE_QUALIFICATION),
        "source_gates_reused": {
            "selinux": True,
            "vintf": True,
            "abi_vndk": True,
            "logical_partition_layout": True,
            "first_stage_binding": True,
            "paired_apatch_boot_sha256": APATCH_BOOT_SHA256,
        },
        "focused_tests": {"count": 8, "output_sha256": hashlib.sha256(test_output).hexdigest()},
        "repair": {
            "source_action": builder.SOURCE_LINE.decode(),
            "replacement_action": builder.REPLACEMENT_LINE.decode(),
            "system_offset": builder.PATCH_OFFSET_IN_SYSTEM,
            "super_offset": builder.PATCH_OFFSET_IN_SUPER,
            "length": len(builder.SOURCE_LINE),
        },
        "claim_boundary": "The candidate skips only the observed /data/nfc policy-setting mkdir action. Runtime boot, framework, UI, root, and hardware remain unproved.",
    }
    with output.open("x") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"status={report['status']} system={EXPECTED_SYSTEM_SHA256} super={EXPECTED_SUPER_SHA256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
