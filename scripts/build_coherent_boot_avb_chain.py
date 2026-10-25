#!/usr/bin/env python3
"""Build a self-consistent unlocked-device AVB chain for a modified boot image.

Huawei's DBY-W09 top-level vbmeta contains a complete set of chained-partition
descriptors.  Disabling verification in the top-level header skips those
descriptors and trips Huawei's additional metadata-completeness check.  This
builder instead preserves every descriptor in its original order, changes only
the ``boot`` descriptor's public key, signs the modified boot payload with that
key, and signs the top-level vbmeta with the same local diagnostic key.

The result is intended only for an already-unlocked owner-operated device.  A
locked bootloader will reject the non-OEM top-level key.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_avbtool(path: Path):
    spec = importlib.util.spec_from_file_location("dby_avbtool", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import avbtool from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_image(avbtool, avb, path: Path):
    image = avbtool.ImageHandler(str(path), read_only=True)
    return avb._parse_image(image)


def embedded_public_key(avbtool, avb, path: Path) -> bytes:
    image = avbtool.ImageHandler(str(path), read_only=True)
    _, header, _, _ = avb._parse_image(image)
    vbmeta = avb._load_vbmeta_blob(image)
    offset = header.SIZE + header.authentication_data_block_size + header.public_key_offset
    return vbmeta[offset : offset + header.public_key_size]


def chain_snapshot(avbtool, descriptors) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for descriptor in descriptors:
        if isinstance(descriptor, avbtool.AvbChainPartitionDescriptor):
            result.append(
                {
                    "partition_name": descriptor.partition_name,
                    "rollback_index_location": descriptor.rollback_index_location,
                    "flags": descriptor.flags,
                    "public_key_sha1": hashlib.sha1(descriptor.public_key).hexdigest(),
                    "public_key_size": len(descriptor.public_key),
                }
            )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--avbtool", required=True, type=Path)
    parser.add_argument("--stock-vbmeta", required=True, type=Path)
    parser.add_argument("--boot-base", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--output-boot", required=True, type=Path)
    parser.add_argument("--output-vbmeta", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    outputs = (args.output_boot, args.output_vbmeta, args.report)
    if any(path.exists() for path in outputs):
        raise SystemExit("refusing to overwrite an existing output")

    avbtool = load_avbtool(args.avbtool.resolve())
    avb = avbtool.Avb()

    stock_footer, stock_header, stock_descriptors, stock_size = parse_image(
        avbtool, avb, args.stock_vbmeta.resolve()
    )
    if stock_footer is not None:
        raise ValueError("top-level stock vbmeta unexpectedly has an AVB footer")
    if stock_size != 1024 * 1024:
        raise ValueError(f"unexpected stock vbmeta partition size {stock_size}")
    if stock_header.flags != 0:
        raise ValueError(f"expected stock top-level flags 0, got {stock_header.flags}")

    boot_footer, boot_header, boot_descriptors, boot_partition_size = parse_image(
        avbtool, avb, args.boot_base.resolve()
    )
    if boot_footer is None:
        raise ValueError("boot base has no AVB footer")
    boot_hash_descriptors = [
        descriptor
        for descriptor in boot_descriptors
        if isinstance(descriptor, avbtool.AvbHashDescriptor)
        and descriptor.partition_name == "boot"
    ]
    if len(boot_hash_descriptors) != 1:
        raise ValueError("expected exactly one boot hash descriptor")
    boot_hash = boot_hash_descriptors[0]
    boot_properties = [
        f"{descriptor.key}:{descriptor.value.decode('utf-8')}"
        for descriptor in boot_descriptors
        if isinstance(descriptor, avbtool.AvbPropertyDescriptor)
    ]

    with avbtool.load_public_key(str(args.key.resolve())) as key:
        diagnostic_public_key = key.encode()
    diagnostic_public_key_sha1 = hashlib.sha1(diagnostic_public_key).hexdigest()

    stock_chain_before = chain_snapshot(avbtool, stock_descriptors)
    boot_chain = [
        descriptor
        for descriptor in stock_descriptors
        if isinstance(descriptor, avbtool.AvbChainPartitionDescriptor)
        and descriptor.partition_name == "boot"
    ]
    if len(boot_chain) != 1:
        raise ValueError("expected exactly one top-level boot chain descriptor")
    if len(diagnostic_public_key) != len(boot_chain[0].public_key):
        raise ValueError("diagnostic and stock boot AVB public-key sizes differ")
    stock_boot_key_sha1 = hashlib.sha1(boot_chain[0].public_key).hexdigest()
    boot_chain[0].public_key = diagnostic_public_key

    args.output_boot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.boot_base, args.output_boot)
    avb.add_hash_footer(
        image_filename=str(args.output_boot),
        partition_size=boot_partition_size,
        dynamic_partition_size=False,
        partition_name="boot",
        hash_algorithm=boot_hash.hash_algorithm,
        salt=boot_hash.salt.hex(),
        chain_partitions_use_ab=None,
        chain_partitions_do_not_use_ab=None,
        algorithm_name="SHA256_RSA2048",
        key_path=str(args.key.resolve()),
        public_key_metadata_path=None,
        rollback_index=boot_header.rollback_index,
        flags=0,
        rollback_index_location=boot_header.rollback_index_location,
        props=boot_properties,
        props_from_file=None,
        kernel_cmdlines=None,
        setup_rootfs_from_kernel=None,
        include_descriptors_from_image=None,
        calc_max_image_size=False,
        signing_helper=None,
        signing_helper_with_files=None,
        release_string=boot_header.release_string,
        append_to_release_string=None,
        output_vbmeta_image=None,
        do_not_append_vbmeta_image=False,
        print_required_libavb_version=False,
        use_persistent_digest=False,
        do_not_use_ab=False,
    )

    vbmeta_blob = avb._generate_vbmeta_blob(
        algorithm_name="SHA256_RSA2048",
        key_path=str(args.key.resolve()),
        public_key_metadata_path=None,
        descriptors=stock_descriptors,
        chain_partitions_use_ab=None,
        chain_partitions_do_not_use_ab=None,
        rollback_index=stock_header.rollback_index,
        flags=stock_header.flags,
        rollback_index_location=stock_header.rollback_index_location,
        props=None,
        props_from_file=None,
        kernel_cmdlines=None,
        setup_rootfs_from_kernel=None,
        ht_desc_to_setup=None,
        include_descriptors_from_image=None,
        signing_helper=None,
        signing_helper_with_files=None,
        release_string=stock_header.release_string,
        append_to_release_string=None,
        required_libavb_version_minor=stock_header.required_libavb_version_minor,
    )
    if len(vbmeta_blob) > stock_size:
        raise ValueError("rebuilt top-level vbmeta exceeds its partition")
    args.output_vbmeta.parent.mkdir(parents=True, exist_ok=True)
    args.output_vbmeta.write_bytes(vbmeta_blob + b"\0" * (stock_size - len(vbmeta_blob)))

    _, rebuilt_boot_header, rebuilt_boot_descriptors, rebuilt_boot_size = parse_image(
        avbtool, avb, args.output_boot
    )
    _, rebuilt_top_header, rebuilt_top_descriptors, rebuilt_top_size = parse_image(
        avbtool, avb, args.output_vbmeta
    )
    rebuilt_boot_hashes = [
        descriptor
        for descriptor in rebuilt_boot_descriptors
        if isinstance(descriptor, avbtool.AvbHashDescriptor)
        and descriptor.partition_name == "boot"
    ]
    if len(rebuilt_boot_hashes) != 1:
        raise AssertionError("rebuilt boot hash descriptor missing")
    rebuilt_boot_hash = rebuilt_boot_hashes[0]
    boot_payload = args.output_boot.read_bytes()[: rebuilt_boot_hash.image_size]
    expected_digest = hashlib.new(
        rebuilt_boot_hash.hash_algorithm, rebuilt_boot_hash.salt + boot_payload
    ).digest()
    if rebuilt_boot_hash.digest != expected_digest:
        raise AssertionError("rebuilt boot descriptor digest mismatch")
    if embedded_public_key(avbtool, avb, args.output_boot) != diagnostic_public_key:
        raise AssertionError("rebuilt boot embedded key mismatch")
    if embedded_public_key(avbtool, avb, args.output_vbmeta) != diagnostic_public_key:
        raise AssertionError("rebuilt top-level embedded key mismatch")

    rebuilt_chain = chain_snapshot(avbtool, rebuilt_top_descriptors)
    if [item["partition_name"] for item in rebuilt_chain] != [
        item["partition_name"] for item in stock_chain_before
    ]:
        raise AssertionError("top-level chain descriptor order changed")
    if len(rebuilt_chain) != len(stock_chain_before):
        raise AssertionError("top-level chain descriptor count changed")
    changed_chain_keys = []
    for before, after in zip(stock_chain_before, rebuilt_chain):
        comparable_before = dict(before)
        comparable_after = dict(after)
        before_key = comparable_before.pop("public_key_sha1")
        after_key = comparable_after.pop("public_key_sha1")
        if comparable_before != comparable_after:
            raise AssertionError(f"chain metadata changed for {before['partition_name']}")
        if before_key != after_key:
            changed_chain_keys.append(before["partition_name"])
    if changed_chain_keys != ["boot"]:
        raise AssertionError(f"unexpected changed chain keys: {changed_chain_keys}")
    if rebuilt_top_header.flags != 0 or rebuilt_boot_header.flags != 0:
        raise AssertionError("verification-disabling AVB flags are not allowed")
    if rebuilt_top_size != stock_size or rebuilt_boot_size != boot_partition_size:
        raise AssertionError("partition size changed")

    report = {
        "security_scope": "already-unlocked owner device only",
        "avb_strategy": (
            "preserve all top-level chain descriptors; replace only boot chain key; "
            "sign boot and top-level vbmeta with one local diagnostic key"
        ),
        "inputs": {
            "stock_vbmeta": str(args.stock_vbmeta.resolve()),
            "stock_vbmeta_sha256": sha256_file(args.stock_vbmeta),
            "boot_base": str(args.boot_base.resolve()),
            "boot_base_sha256": sha256_file(args.boot_base),
            "diagnostic_key": str(args.key.resolve()),
            "diagnostic_public_key_sha1": diagnostic_public_key_sha1,
        },
        "outputs": {
            "boot": str(args.output_boot.resolve()),
            "boot_sha256": sha256_file(args.output_boot),
            "boot_size": rebuilt_boot_size,
            "vbmeta": str(args.output_vbmeta.resolve()),
            "vbmeta_sha256": sha256_file(args.output_vbmeta),
            "vbmeta_size": rebuilt_top_size,
        },
        "boot": {
            "payload_size": rebuilt_boot_hash.image_size,
            "hash_algorithm": rebuilt_boot_hash.hash_algorithm,
            "salt": rebuilt_boot_hash.salt.hex(),
            "digest": rebuilt_boot_hash.digest.hex(),
            "embedded_public_key_sha1": hashlib.sha1(
                embedded_public_key(avbtool, avb, args.output_boot)
            ).hexdigest(),
            "flags": rebuilt_boot_header.flags,
            "properties": boot_properties,
        },
        "top_level_vbmeta": {
            "embedded_public_key_sha1": hashlib.sha1(
                embedded_public_key(avbtool, avb, args.output_vbmeta)
            ).hexdigest(),
            "flags": rebuilt_top_header.flags,
            "chain_descriptor_count": len(rebuilt_chain),
            "chain_descriptor_order_preserved": True,
            "changed_chain_public_keys": changed_chain_keys,
            "stock_boot_public_key_sha1": stock_boot_key_sha1,
            "chain": rebuilt_chain,
        },
        "validation": {
            "boot_payload_digest_matches_descriptor": True,
            "boot_and_top_level_use_same_diagnostic_key": True,
            "all_non_boot_chain_metadata_preserved": True,
            "all_verification_disabling_flags_zero": True,
            "partition_sizes_preserved": True,
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
