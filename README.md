# DBY-W09 boot research

This repository is a sanitized, source-only research snapshot for an
owner-operated Huawei MatePad 11 DBY-W09. It records three connected results:

1. staged probes narrowed the original LineageOS 21 failure from the general
   boot chain through the original init entry shim and into `main`;
2. a context-closed Android 10/API29 baseline then reached a stable AOSP
   Launcher after one exact 34-byte init-language repair;
3. an exact-target VINTF replay reduced the Android 12/API32 compatibility
   change to one framework GNSS 1.1 declaration, and that system reached a
   boot-complete Launcher with the original boot and vendor chain retained.

截至 2026-10-28，当前保留在设备上的系统为 Android 12/API32。PID 1 为
`/system/bin/init second_stage`，两个 boot-complete 属性均已建立，bootanimation
停止，Launcher3 和设置界面可见。`vendor-verity`、SELinux Enforcing 和既有 root
能力保留；keystore2、system_suspend、SurfaceFlinger 与 system_server 稳定，GNSS
1.0/1.1/2.0 实例和启用的 GPS provider 可见。

这不是“全硬件适配完成”。实际卫星定位、重启持久性、休眠唤醒、摄像头、
音频、蓝牙、Wi-Fi、DRM 和长期稳定性仍需在 API32 上分别验证。当前结果是新的
可回滚研究基线，不是通用刷机包或完整日用 ROM 声明。

## Included

- `scripts/`: offline image builders, exact-target VINTF replay, streamed
  readback comparison and staged witness sources;
- `tests/`: synthetic tests plus explicit private-fixture skips;
- `docs/`: the current boundary, methodology, API29 baseline and accepted
  API32/GNSS 1.1 result;
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

1. [`docs/API32_GNSS_1_1_SUCCESS.md`](docs/API32_GNSS_1_1_SUCCESS.md)
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
