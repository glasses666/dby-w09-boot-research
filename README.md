# DBY-W09 boot research

This repository is a sanitized, source-only research snapshot for an
owner-operated Huawei MatePad 11 DBY-W09. It records two connected results:

1. staged probes narrowed the original LineageOS 21 failure from the general
   boot chain through the original init entry shim and into `main`;
2. a context-closed Android 10/API29 baseline then reached a stable AOSP
   Launcher after one exact 34-byte init-language repair.

截至 2026-10-25，最强的实机结论已经不再只是“执行到了 init 的哪个位置”，
而是：设备在一次正常重启后 21 秒首先枚举为 ADB，PID 1 为
`/system/bin/init second_stage`，`sys.boot_completed=1`，Launcher3 和设置界面
均可实际操作。这个候选系统仍保留在设备上，没有在成功后回滚。

这不是“全硬件适配完成”。相机目前不可用；蓝牙、音频播放、麦克风、DRM、
休眠唤醒、重启持久性和长期稳定性仍待验证。当前 API29 基线的安全补丁级别也
很旧，适合继续研究，不应被描述成现代日用系统。

## Included

- `scripts/`: offline image builders and staged witness sources;
- `tests/`: synthetic tests plus explicit private-fixture skips;
- `docs/`: the current boundary, methodology and API29 usable-boot result;
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

1. [`docs/API29_USABLE_BOOT.md`](docs/API29_USABLE_BOOT.md)
2. [`docs/RESEARCH_STATUS.md`](docs/RESEARCH_STATUS.md)
3. [`docs/BOOT_BOUNDARY.md`](docs/BOOT_BOUNDARY.md)
4. [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md)
5. [`docs/SAFETY_AND_SCOPE.md`](docs/SAFETY_AND_SCOPE.md)

## Publication

Public repository: <https://github.com/glasses666/dby-w09-boot-research>

Public attribution: **Queen_Glasser (@glasses666)**. No license has been
granted; unless and until a license is added, all rights are reserved. No
firmware or prebuilt flashable artifact is released from this repository.
