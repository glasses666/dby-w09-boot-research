#!/usr/bin/env python3
"""Bind deterministic GNSS 1.1-only images to the exact target replay evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


MANIFEST_PATH = "/system/etc/vintf/manifest.xml"
EXPECTED_QUERIES = {
    "framework_keystore_aidl": True,
    "framework_suspend_hidl": True,
    "framework_suspend_transport": "hwbinder",
    "framework_gnss_1_0": True,
    "framework_gnss_1_1": True,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def image_identity(report: dict[str, object]) -> dict[str, object]:
    system = report.get("output_system", {})
    super_image = report.get("output_super", {})
    return {
        "system": {"size": system.get("size"), "sha256": system.get("sha256")},
        "super": {"size": super_image.get("size"), "sha256": super_image.get("sha256")},
        "manifest_sha256": report.get("framework_manifest", {}).get("output_sha256"),
    }


def corrected_manifest_fetch(replay: dict[str, object]) -> dict[str, object]:
    corrected = replay.get("normalized_evidence", {}).get("corrected", {})
    matches = [
        event
        for event in corrected.get("access_events", [])
        if event.get("operation") == "fetch"
        and event.get("status") == 0
        and event.get("path") == MANIFEST_PATH
    ]
    if len(matches) != 1 or matches[0].get("hash_source") != "host-bound-view":
        raise ValueError("target replay lacks one host-bound corrected manifest fetch")
    return matches[0]


def qualify(
    build_a: dict[str, object],
    build_b: dict[str, object],
    qualification_a: dict[str, object],
    qualification_b: dict[str, object],
    replay: dict[str, object],
) -> dict[str, object]:
    identity_a = image_identity(build_a)
    identity_b = image_identity(build_b)
    if identity_a != identity_b:
        raise ValueError("deterministic build mismatch")
    for label, build in (("a", build_a), ("b", build_b)):
        if build.get("device_io_performed") is not False:
            raise ValueError(f"build {label} performed device I/O")
        if build.get("boot_control", {}).get("output_emitted") is not False:
            raise ValueError(f"build {label} emitted a boot image")
        if not build.get("system_audit", {}).get("outside_span_byte_identical"):
            raise ValueError(f"build {label} system scope audit failed")
        if not build.get("super_audit", {}).get("outside_span_byte_identical"):
            raise ValueError(f"build {label} super scope audit failed")
    for label, qualification, identity in (
        ("a", qualification_a, identity_a),
        ("b", qualification_b, identity_b),
    ):
        if qualification.get("status") != "pass" or qualification.get("device_io_performed") is not False:
            raise ValueError(f"qualification {label} failed")
        if image_identity(qualification) != identity:
            raise ValueError(f"qualification {label} identity mismatch")
    if replay.get("classification") != "source-derived-correction-restores-aggregation":
        raise ValueError("target replay classification is not the validated correction")
    if replay.get("execution_evidence", {}).get("valid") is not True:
        raise ValueError("target replay execution evidence is invalid")
    manifest_fetch = corrected_manifest_fetch(replay)
    if manifest_fetch.get("sha256") != identity_a["manifest_sha256"]:
        raise ValueError("target replay manifest binding mismatch")
    corrected_queries = replay.get("normalized_evidence", {}).get("corrected", {}).get("queries", {})
    for key, expected in EXPECTED_QUERIES.items():
        if corrected_queries.get(key) != expected:
            raise ValueError(f"target replay query mismatch: {key}")
    return {
        "schema": "dby-w09-api32-system-framework-gnss-1_1-qualification-v1",
        "status": "offline-qualified-not-flashed",
        "device_io_performed": False,
        "live_write_gate": False,
        "deterministic_pair": {
            "byte_identical": True,
            "system": identity_a["system"],
            "super": identity_a["super"],
        },
        "target_replay_binding": {
            "classification": replay["classification"],
            "manifest_path": MANIFEST_PATH,
            "manifest_sha256": manifest_fetch["sha256"],
            "queries": {key: corrected_queries[key] for key in EXPECTED_QUERIES},
        },
        "scope": {
            "system_outside_manifest_identical": True,
            "super_outside_manifest_identical": True,
            "boot_output_emitted": False,
        },
        "next_gate": (
            "Fresh physical recovery availability, prewrite identity/readback plan, and explicit "
            "live authorization are still required before any device write."
        ),
        "claim_boundary": (
            "Image determinism, exact byte scope, filesystem health and target VINTF semantics "
            "are proved; Android boot, services, GNSS and UI are not."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-a", required=True, type=Path)
    parser.add_argument("--build-b", required=True, type=Path)
    parser.add_argument("--qualification-a", required=True, type=Path)
    parser.add_argument("--qualification-b", required=True, type=Path)
    parser.add_argument("--target-replay", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite {args.output}")
    inputs = {
        name: {"path": str(path), "sha256": sha256_file(path)}
        for name, path in (
            ("build_a", args.build_a),
            ("build_b", args.build_b),
            ("qualification_a", args.qualification_a),
            ("qualification_b", args.qualification_b),
            ("target_replay", args.target_replay),
        )
    }
    try:
        report = qualify(
            json.loads(args.build_a.read_text()),
            json.loads(args.build_b.read_text()),
            json.loads(args.qualification_a.read_text()),
            json.loads(args.qualification_b.read_text()),
            json.loads(args.target_replay.read_text()),
        )
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))
    report["inputs"] = inputs
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
