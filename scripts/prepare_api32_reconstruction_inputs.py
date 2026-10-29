#!/usr/bin/env python3
"""Derive small API32 policy helpers locally; never copy or fetch vendor policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/api32"
CONTRACT = json.loads((FIXTURES / "policy-input-contract.json").read_text())
MAPPING_HEADER = (
    "; Diagnostic-only Huawei 29.0 compatibility mapping.\n"
    "; Generated from the frozen vendor public policy and GSI 29.0 mapping.\n"
    "; This is not a boot candidate.\n\n"
)
SYMBOL = r"[A-Za-z0-9_]+"
DEFAULT_OUTPUT = (
    ROOT / "analysis/firmware-20261014/api29-aosp-baseline-offline-20261025"
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_identity(data: bytes, identity: dict[str, object], label: str) -> None:
    if len(data) != identity["size"] or sha256_bytes(data) != identity["sha256"]:
        raise ValueError(f"{label} identity mismatch")


def derive_mapping(vendor_public: bytes, gsi_mapping: bytes) -> bytes:
    """Generate identity bindings from declared, unmapped concrete types only."""
    vendor = re.sub(r";[^\n]*", "", vendor_public.decode("utf-8"))
    mapping = re.sub(r";[^\n]*", "", gsi_mapping.decode("utf-8"))
    attributes = set(re.findall(rf"\(typeattribute ({SYMBOL})_29_0\)", vendor))
    concrete_types = set(re.findall(rf"\(type ({SYMBOL})\)", vendor))
    mapped = set(re.findall(rf"\b({SYMBOL})_29_0\b", mapping))
    missing = sorted((attributes & concrete_types) - mapped)
    if not missing:
        raise ValueError("no missing concrete 29.0 bindings")
    return (
        MAPPING_HEADER
        + "".join(f"(typeattributeset {name}_29_0 ({name}))\n" for name in missing)
    ).encode("utf-8")


def encode_xattr(label: bytes) -> bytes:
    if label != b"u:object_r:sepolicy_file:s0\n":
        raise ValueError("unexpected sepolicy file context text")
    return label[:-1] + b"\0"


def prepare(vendor_path: Path, mapping_path: Path, output_dir: Path) -> dict[str, object]:
    vendor = vendor_path.read_bytes()
    mapping = mapping_path.read_bytes()
    validate_identity(vendor, CONTRACT["vendor_public"], "vendor public policy")
    validate_identity(mapping, CONTRACT["gsi_mapping"], "API29 GSI mapping")
    generated = derive_mapping(vendor, mapping)
    xattr = encode_xattr((FIXTURES / "sepolicy-file-context.txt").read_bytes())
    validate_identity(generated, CONTRACT["mapping_output"], "generated mapping")
    validate_identity(xattr, CONTRACT["xattr_output"], "generated xattr")
    binding_count = sum(line.startswith(b"(typeattributeset ") for line in generated.splitlines())
    if binding_count != CONTRACT["mapping_output"]["bindings"]:
        raise ValueError("generated mapping binding count mismatch")
    output_dir = output_dir.resolve()
    targets = (
        (output_dir / CONTRACT["mapping_output"]["name"], generated),
        (output_dir / CONTRACT["xattr_output"]["name"], xattr),
    )
    for target, _ in targets:
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"refusing to overwrite {target}")
        if target in (vendor_path.resolve(), mapping_path.resolve()):
            raise ValueError("output aliases an input")
    output_dir.mkdir(parents=True, exist_ok=True)
    for target, data in targets:
        with target.open("xb") as stream:
            stream.write(data)
    return {
        "device_io_performed": False,
        "binding_count": binding_count,
        "outputs": [
            {"name": path.name, "size": len(data), "sha256": sha256_bytes(data)}
            for path, data in targets
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor-public-policy", required=True, type=Path)
    parser.add_argument("--api29-gsi-mapping", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        report = prepare(args.vendor_public_policy, args.api29_gsi_mapping, args.output_dir)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
