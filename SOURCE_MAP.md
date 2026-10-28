# Source map and publication boundary

The private research tree remains authoritative. This repository is a derived,
sanitized snapshot; files were copied into a new Git history so raw evidence
and previously removed objects cannot leak through ancestry.

## Included mappings

| Public path | Private source | Publication role |
|---|---|---|
| `scripts/audit_rrecord_*.py` | matching private scripts | Full-partition comparison without asserting an undocumented format |
| `scripts/build_*boot*.py` | matching private scripts | Offline Android boot and AVB transformations |
| `scripts/build_context_closed_super.py` | same repository-relative path | Fail-closed logical-partition payload replacement |
| `scripts/build_api29_fscrypt_adb_fix.py` | same repository-relative path | Exact one-span API29 repair and hash contract |
| `scripts/build_api32_*gnss_1_1*.py` and matching verifier/qualifier | same repository-relative paths | Deterministic API32 framework-manifest correction and whole-image qualification |
| `scripts/build_api32_vintf_target_replay.py`, `scripts/audit_api32_vintf_target_replay.py` | same repository-relative paths | Rebuild and audit the exact-target VINTF replay harness without distributing target binaries |
| `scripts/stream_readback_compare.py` | same repository-relative path | Complete streamed comparison without retaining a second partition-sized image |
| `scripts/build_diagnostic_normal_ramdisk.py` | same repository-relative path | Shared ramdisk parser and builder |
| `scripts/build_w*.py` | selected private staged builders | W1/W2/W6/W7/W8/W9 candidate construction |
| `scripts/w*.c`, `scripts/w*.S` | matching private probe sources | Minimal witnesses and endpoint probes |
| `scripts/parse_w*.py` | matching private parsers | Strict nonce, checksum and record interpretation |
| `scripts/verify_w1_live_gate.py` | same repository-relative path | Read-only manifest-bound verification |
| `tests/` | selected private tests | Synthetic checks and explicit private-fixture skips |
| `docs/`, `evidence/` | synthesized from hash-bound private reports | Sanitized API29/API32 findings and interpretation limits |

Public tests replace researcher-specific paths with explicit fixtures or test
synthetic helper functions. Production hashes remain where they are part of a
fail-closed build contract.

## Excluded categories

| Category | Reason |
|---|---|
| Firmware, partition images and downloads | Redistribution, size and device-specific risk |
| Raw logs, screenshots and partition dumps | Device identifiers and personal state |
| Firehose/EDL executables and configuration | Proprietary or device-specific transport material |
| Live write, erase, reset and recovery-root automation | This is not a one-click flashing repository |
| REA/Ghidra snapshots and proprietary disassembly packages | May embed vendor code and private paths |
| Full internal chronology and operator handoffs | Contains private identifiers and operational details |
| Generated binaries and test fixtures | Users must supply local inputs and accept their own authorization boundary |

## Integrity model

`PUBLIC_MANIFEST.json` inventories every distributed file except itself. The
validator recomputes each hash, rejects unlisted files, checks JSON and relative
Markdown links, and blocks known private identifiers, absolute user-home paths,
private-key markers, symlinks, oversized files and binary-image extensions.
