#!/usr/bin/env python3
"""Read-only verifier for the DBY-W09 W1 staged live gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def parse_inputs(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"input must use NAME=PATH syntax: {value}")
        name, raw_path = value.split("=", 1)
        if not name or not raw_path or name in result:
            raise ValueError(f"invalid or duplicate input: {value}")
        result[name] = Path(raw_path)
    return result


def verify_stage(
    manifest: dict[str, object],
    stage: str,
    inputs: dict[str, Path],
    endpoint: str,
) -> dict[str, object]:
    stages = manifest.get("stages")
    if not isinstance(stages, dict) or stage not in stages:
        raise ValueError(f"unknown stage: {stage}")
    expected = stages[stage]
    if not isinstance(expected, dict):
        raise ValueError(f"stage {stage} is malformed")

    checks: list[dict[str, object]] = []
    failures: list[str] = []
    unexpected = sorted(set(inputs) - set(expected))
    if unexpected:
        failures.append("unexpected_inputs:" + ",".join(unexpected))
    for name, rule_value in expected.items():
        rule = rule_value if isinstance(rule_value, dict) else {}
        path = inputs.get(name)
        check: dict[str, object] = {"name": name, "path": str(path) if path else None}
        if path is None:
            check["passed"] = False
            check["failure"] = "missing_input"
            failures.append(f"{name}:missing_input")
            checks.append(check)
            continue
        if not path.is_file():
            check["passed"] = False
            check["failure"] = "not_a_regular_file"
            failures.append(f"{name}:not_a_regular_file")
            checks.append(check)
            continue
        observed_size = path.stat().st_size
        check["observed_size"] = observed_size
        expected_size = rule.get("size")
        if expected_size is not None:
            check["expected_size"] = expected_size
        observed_sha256 = sha256_file(path)
        check["observed_sha256"] = observed_sha256
        expected_sha256 = rule.get("sha256")
        if expected_sha256 is not None:
            check["expected_sha256"] = expected_sha256
        size_ok = expected_size is None or observed_size == expected_size
        sha_ok = expected_sha256 is None or observed_sha256 == expected_sha256
        check["passed"] = bool(size_ok and sha_ok)
        if not size_ok:
            check["failure"] = "size_mismatch"
            failures.append(f"{name}:size_mismatch")
        elif not sha_ok:
            check["failure"] = "sha256_mismatch"
            failures.append(f"{name}:sha256_mismatch")
        checks.append(check)

    endpoint_policy = manifest.get("endpoint_policy", {})
    recognized = endpoint_policy.get("recognized", []) if isinstance(endpoint_policy, dict) else []
    endpoint_check: dict[str, object] = {
        "observed": endpoint,
        "expected": endpoint_policy.get("expected") if isinstance(endpoint_policy, dict) else None,
        "recognized": endpoint in recognized,
        "required_for_stage": stage == "post_attempt",
    }
    if endpoint not in recognized:
        failures.append("endpoint:unrecognized")
    if stage == "post_attempt" and endpoint != endpoint_check["expected"]:
        failures.append("endpoint:unexpected")
    endpoint_check["passed"] = not any(item.startswith("endpoint:") for item in failures)

    return {
        "schema": manifest.get("schema"),
        "stage": stage,
        "passed": not failures,
        "checks": checks,
        "endpoint": endpoint_check,
        "failures": failures,
        "stop_conditions": manifest.get("stop_conditions", []),
        "read_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--input", action="append", default=[])
    parser.add_argument("--endpoint", default="unknown")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    try:
        inputs = parse_inputs(args.input)
        report = verify_stage(manifest, args.stage, inputs, args.endpoint)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
