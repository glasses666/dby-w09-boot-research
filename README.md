# DBY-W09 boot research

This repository is a sanitized, source-only research snapshot for an
owner-operated Huawei MatePad 11 DBY-W09. It records three connected results:

1. staged probes narrowed the original LineageOS 21 failure from the general
   boot chain through the original init entry shim and into `main`;
2. a context-closed Android 10/API29 baseline then reached a stable AOSP
   Launcher after one exact 34-byte init-language repair;
3. an Android 11/API30 system then reached a completed core-system boot after
   a five-byte init compatibility patch for Huawei's legacy `/data/nfc` mkdir.

截至 2026-10-26，当前最强实机结论是：读回验证的 API30 v4 `super`
已进入 Android 11 / SDK 30，PID 1 为 `/system/bin/init second_stage`，
双 boot-complete 属性为 1，`/data` 是可写的文件级加密 F2FS，SELinux
为 Enforcing，Launcher3 和设置界面可用，KernelPatch 仍可提供 UID 0 与完整
capabilities。这个候选现在保留运行，没有在成功后回滚。

这不是“全硬件适配完成”。成功后重启、Wi-Fi 关联、蓝牙、相机实拍、
声学音频、休眠唤醒和长期稳定性仍待验证。该 AOSP API30 基线的安全补丁
日期为 2020-09-05，适合继续研究，不应被描述成现代安全的日用系统。

## Included

- `scripts/`: offline image builders and staged witness sources;
- `tests/`: synthetic tests plus explicit private-fixture skips;
- `docs/`: the current boundary, methodology, API29 milestone and API30 repair;
- `evidence/public-findings.json`: sanitized, machine-readable findings;
- `SOURCE_MAP.md`: private-to-public mapping and exclusions;
- `tools/validate_public_tree.py`: redaction, link and manifest checks.

The repository does **not** contain vendor firmware, partition images,
Firehose programmers, device or USB identifiers, raw device logs, screenshots,
personal backups, proprietary disassembly projects, live-write automation or a
one-click flashing workflow.

## Verify this snapshot

```bash
PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  python3 -B -m unittest discover -s tests -p 'test_*.py' -v
python3 -B tools/validate_public_tree.py --check
```

The test suite uses only Python's standard library. Some AArch64 compilation
tests use `/usr/bin/clang` on macOS. Optional proprietary inputs are never
downloaded; when absent, their tests skip explicitly. See
[`private-fixtures/README.md`](private-fixtures/README.md).

## Reading order

1. [`docs/API30_NFC_COMPATIBILITY.md`](docs/API30_NFC_COMPATIBILITY.md)
2. [`docs/API29_USABLE_BOOT.md`](docs/API29_USABLE_BOOT.md)
3. [`docs/RESEARCH_STATUS.md`](docs/RESEARCH_STATUS.md)
4. [`docs/BOOT_BOUNDARY.md`](docs/BOOT_BOUNDARY.md)
5. [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md)
6. [`docs/SAFETY_AND_SCOPE.md`](docs/SAFETY_AND_SCOPE.md)

## Publication

Public repository: <https://github.com/glasses666/dby-w09-boot-research>

Public attribution: **Queen_Glasser (@glasses666)**. No license has been
granted; unless and until a license is added, all rights are reserved. No
firmware or prebuilt flashable artifact is released from this repository.
