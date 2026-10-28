#!/usr/bin/env python3
"""Classify an exact target-API32 libvintf control/candidate replay."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


SCHEMA = "dby-w09-api32-target-libvintf-replay-v1"
EXPECTED_GNSS_QUERY_CHANGES = {
    "framework_gnss_1_0",
    "framework_gnss_1_1",
}
SERVICE_QUERIES = {
    "framework_keystore_aidl",
    "framework_suspend_hidl",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def trace_complete(result: dict[str, object]) -> bool:
    access_events = result.get("access_events")
    if not isinstance(access_events, list) or not access_events:
        return False
    if not result.get("property_events"):
        return False
    for event in access_events:
        if not isinstance(event, dict):
            return False
        if event.get("operation") == "fetch" and event.get("status") == 0:
            if not event.get("sha256") or event.get("hash_source") != "host-bound-view":
                return False
    return True


def normalize_result(result: dict[str, object], view_root: Path) -> dict[str, object]:
    """Bind target-process output to the exact immutable input-view bytes."""
    normalized = copy.deepcopy(result)
    for key in ("framework", "device"):
        section = normalized.get(key)
        if isinstance(section, dict) and isinstance(section.get("xml"), str):
            section["xml_sha256"] = hashlib.sha256(section["xml"].encode()).hexdigest()

    root = view_root.resolve(strict=True)
    events = normalized.get("access_events")
    if not isinstance(events, list):
        raise ValueError("access_events is not a list")
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("access event is not an object")
        if event.get("operation") != "fetch" or event.get("status") != 0:
            continue
        virtual_path = event.get("path")
        if not isinstance(virtual_path, str) or not virtual_path.startswith("/"):
            raise ValueError(f"unsafe fetch path: {virtual_path!r}")
        actual = (root / virtual_path.lstrip("/")).resolve(strict=True)
        try:
            actual.relative_to(root)
        except ValueError as error:
            raise ValueError(f"fetch path escapes bound view: {virtual_path}") from error
        if not actual.is_file():
            raise ValueError(f"successful fetch is not a file: {virtual_path}")
        actual_size = actual.stat().st_size
        if event.get("size") != actual_size:
            raise ValueError(
                f"fetch size drift for {virtual_path}: target={event.get('size')} host={actual_size}"
            )
        event["sha256"] = sha256_file(actual)
        event["hash_source"] = "host-bound-view"
    return normalized


def manifest_valid(result: dict[str, object]) -> bool:
    return (
        result.get("schema") == SCHEMA
        and result.get("framework", {}).get("status") == "ok"
        and result.get("device", {}).get("status") == "ok"
    )


def validate_execution(
    summary: dict[str, object],
    inspect_payload: list[dict[str, object]],
    linker_list: str,
    manifest: dict[str, object],
) -> dict[str, object]:
    errors: list[str] = []
    if len(inspect_payload) != 1:
        return {"valid": False, "errors": ["container-inspect-count"], "resolved_libraries": []}
    inspect = inspect_payload[0]
    host = inspect.get("HostConfig", {})
    if host.get("NetworkMode") != "none" or summary.get("network") != "none":
        errors.append("network-mode")
    if not host.get("ReadonlyRootfs") or summary.get("rootfs") != "read-only":
        errors.append("read-only-rootfs")
    if "ALL" not in (host.get("CapDrop") or []):
        errors.append("cap-drop")
    if "no-new-privileges:true" not in (host.get("SecurityOpt") or []):
        errors.append("no-new-privileges")
    if inspect.get("Config", {}).get("Image") != summary.get("image"):
        errors.append("image-name")
    if inspect.get("State", {}).get("ExitCode") != 0 or summary.get("container_exit") != 0:
        errors.append("container-exit")
    if summary.get("architecture") != "aarch64":
        errors.append("architecture")
    if summary.get("linker_list_exit") != 0:
        errors.append("linker-list-exit")
    if summary.get("control_exit") != 0:
        errors.append("control-exit")
    if summary.get("candidate_exit") not in (0, 2):
        errors.append("candidate-exit")
    if "corrected_exit" in summary and summary.get("corrected_exit") not in (0, 2):
        errors.append("corrected-exit")
    if summary.get("device_io_performed") is not False:
        errors.append("device-io")
    if summary.get("harness_tree_sha256") != manifest.get("tree", {}).get("tree_sha256"):
        errors.append("harness-tree")
    if summary.get("query_sha256") != manifest.get("runtime", {}).get("query", {}).get("sha256"):
        errors.append("query-identity")

    expected_mounts = {
        "/system": False,
        "/control": False,
        "/candidate": False,
        "/run-target-replay.sh": False,
        "/evidence": True,
    }
    if "corrected_exit" in summary:
        expected_mounts["/corrected"] = False
    actual_mounts = {
        item.get("Destination"): item.get("RW")
        for item in inspect.get("Mounts", [])
        if item.get("Type") == "bind"
    }
    if actual_mounts != expected_mounts:
        errors.append("bind-mount-contract")

    resolved = {}
    for line in linker_list.splitlines():
        if "=>" not in line:
            continue
        name, remainder = line.split("=>", 1)
        path = remainder.strip().split(" ", 1)[0]
        resolved[name.strip()] = path
    expected_libraries = sorted(
        Path(item["path"]).name
        for item in manifest.get("runtime", {}).get("objects", [])
        if str(item.get("path", "")).startswith("/system/lib64/")
        and Path(item["path"]).name != "ld-android.so"
    )
    if sorted(resolved) != expected_libraries or any(
        path != f"/system/lib64/{name}" for name, path in resolved.items()
    ):
        errors.append("resolved-library-set")
    return {
        "valid": not errors,
        "errors": errors,
        "resolved_libraries": sorted(resolved),
        "resolved_paths": dict(sorted(resolved.items())),
        "mounts": actual_mounts,
    }


def classify(
    control: dict[str, object], candidate: dict[str, object]
) -> dict[str, object]:
    if not manifest_valid(control):
        return {
            "classification": "invalid-control",
            "changed_queries": [],
            "boundary": "The control aggregation must succeed before interpreting candidate output.",
        }
    if not trace_complete(control) or not trace_complete(candidate):
        return {
            "classification": "invalid-incomplete-runtime-trace",
            "changed_queries": [],
            "boundary": "Both fresh processes must retain file-access and property-query traces.",
        }
    if candidate.get("schema") != SCHEMA:
        return {
            "classification": "invalid-candidate-schema",
            "changed_queries": [],
            "boundary": "Candidate output does not match the target replay schema.",
        }
    candidate_framework = candidate.get("framework", {}).get("status")
    candidate_device = candidate.get("device", {}).get("status")
    if candidate_framework != "ok" or candidate_device != "ok":
        return {
            "classification": "positive-candidate-aggregation-failure",
            "changed_queries": [],
            "boundary": "This supports the aggregation layer only; it does not prove service abort causality.",
        }

    control_queries = dict(control.get("queries", {}))
    candidate_queries = dict(candidate.get("queries", {}))
    changed_queries = sorted(
        key
        for key in set(control_queries) | set(candidate_queries)
        if control_queries.get(key) != candidate_queries.get(key)
    )
    service_changes = sorted(SERVICE_QUERIES.intersection(changed_queries))
    if service_changes:
        return {
            "classification": "positive-candidate-service-query-drift",
            "changed_queries": service_changes,
            "all_changed_queries": changed_queries,
            "boundary": "Each AIDL/HIDL path still needs its manager return and fatal callsite.",
        }
    if set(changed_queries).issubset(EXPECTED_GNSS_QUERY_CHANGES):
        return {
            "classification": "valid-negative-f15-content-layer",
            "changed_queries": changed_queries,
            "boundary": (
                "Target aggregation and covered service queries are unchanged; remaining runtime "
                "file-view, manager, SELinux, verity, and first-abort evidence stays unknown."
            ),
        }
    return {
        "classification": "candidate-query-drift-outside-expected-set",
        "changed_queries": changed_queries,
        "boundary": "The unexpected query delta must be explained before F15 is promoted or rejected.",
    }


def classify_triplet(
    control: dict[str, object],
    candidate: dict[str, object],
    corrected: dict[str, object],
) -> dict[str, object]:
    candidate_result = classify(control, candidate)
    if candidate_result["classification"] != "positive-candidate-aggregation-failure":
        return candidate_result
    corrected_result = classify(control, corrected)
    expected_changes = sorted(EXPECTED_GNSS_QUERY_CHANGES)
    corrected_queries = corrected.get("queries", {})
    if (
        corrected_result["classification"] == "valid-negative-f15-content-layer"
        and corrected_result.get("changed_queries") == expected_changes
        and all(corrected_queries.get(key) is True for key in EXPECTED_GNSS_QUERY_CHANGES)
    ):
        return {
            "classification": "source-derived-correction-restores-aggregation",
            "candidate_classification": candidate_result["classification"],
            "corrected_changed_queries": expected_changes,
            "boundary": (
                "The exact target content-layer rule is validated; live manager returns, "
                "SELinux, service startup, and first-abort causality remain unproved."
            ),
        }
    return {
        "classification": "source-derived-correction-did-not-restore-aggregation",
        "candidate_classification": candidate_result["classification"],
        "corrected_classification": corrected_result["classification"],
        "corrected_changed_queries": corrected_result.get("changed_queries", []),
        "boundary": "Do not build or flash a corrected image from this incomplete replay.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--corrected", type=Path)
    parser.add_argument("--corrected-root", type=Path)
    parser.add_argument("--execution-summary", type=Path, required=True)
    parser.add_argument("--container-inspect", type=Path, required=True)
    parser.add_argument("--linker-list", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.corrected) != bool(args.corrected_root):
        parser.error("--corrected and --corrected-root must be supplied together")

    manifest = json.loads(args.manifest.read_text())
    control = normalize_result(json.loads(args.control.read_text()), args.control_root)
    candidate = normalize_result(json.loads(args.candidate.read_text()), args.candidate_root)
    corrected = (
        normalize_result(json.loads(args.corrected.read_text()), args.corrected_root)
        if args.corrected is not None
        else None
    )
    execution_summary = json.loads(args.execution_summary.read_text(encoding="utf-8-sig"))
    container_inspect = json.loads(args.container_inspect.read_text(encoding="utf-8-sig"))
    execution_gate = validate_execution(
        execution_summary,
        container_inspect,
        args.linker_list.read_text(),
        manifest,
    )
    content_classification = (
        classify_triplet(control, candidate, corrected)
        if corrected is not None
        else classify(control, candidate)
    )
    classification = (
        content_classification
        if execution_gate["valid"]
        else {
            "classification": "invalid-execution-evidence",
            "changed_queries": [],
            "boundary": "Container isolation and target dynamic-link closure must validate first.",
        }
    )
    report = {
        "schema": "dby-w09-api32-target-libvintf-replay-audit-v1",
        "harness_manifest": {
            "path": str(args.manifest),
            "sha256": sha256_file(args.manifest),
            "tree_sha256": manifest.get("tree", {}).get("tree_sha256"),
        },
        "control_output": {
            "path": str(args.control),
            "sha256": sha256_file(args.control),
        },
        "candidate_output": {
            "path": str(args.candidate),
            "sha256": sha256_file(args.candidate),
        },
        "corrected_output": (
            {
                "path": str(args.corrected),
                "sha256": sha256_file(args.corrected),
            }
            if args.corrected is not None
            else None
        ),
        "execution_evidence": {
            "summary_path": str(args.execution_summary),
            "summary_sha256": sha256_file(args.execution_summary),
            "container_inspect_path": str(args.container_inspect),
            "container_inspect_sha256": sha256_file(args.container_inspect),
            "linker_list_path": str(args.linker_list),
            "linker_list_sha256": sha256_file(args.linker_list),
            **execution_gate,
        },
        "normalized_evidence": {
            "control": {
                "framework_xml_sha256": control.get("framework", {}).get("xml_sha256"),
                "device_xml_sha256": control.get("device", {}).get("xml_sha256"),
                "queries": control.get("queries", {}),
                "access_events": control.get("access_events", []),
                "property_events": control.get("property_events", []),
            },
            "candidate": {
                "framework_xml_sha256": candidate.get("framework", {}).get("xml_sha256"),
                "device_xml_sha256": candidate.get("device", {}).get("xml_sha256"),
                "queries": candidate.get("queries", {}),
                "access_events": candidate.get("access_events", []),
                "property_events": candidate.get("property_events", []),
            },
            "corrected": (
                {
                    "framework_xml_sha256": corrected.get("framework", {}).get("xml_sha256"),
                    "device_xml_sha256": corrected.get("device", {}).get("xml_sha256"),
                    "queries": corrected.get("queries", {}),
                    "access_events": corrected.get("access_events", []),
                    "property_events": corrected.get("property_events", []),
                }
                if corrected is not None
                else None
            ),
        },
        **classification,
        "device_io_performed": False,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["classification"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
