from __future__ import annotations

import importlib.util
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_diagnostic_normal_ramdisk.py"
STOCK = Path(os.environ.get("DBY_STOCK_RAMDISK", ROOT / "private-fixtures/ramdisk.img"))
WRAPPER_SOURCE = ROOT / "scripts" / "diagnostic_normal_init.c"
LLD = Path(
    "/opt/homebrew/share/android-commandlinetools/"
    "build-tools/34.0.0/lld"
)


def load_builder():
    if not SCRIPT.exists():
        raise AssertionError(f"missing normal-ramdisk builder: {SCRIPT}")
    spec = importlib.util.spec_from_file_location("build_diagnostic_normal_ramdisk", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def minimal_static_arm64_elf() -> bytes:
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    size = 64 + 56 + 4
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,
        183,
        1,
        0x400078,
        64,
        0,
        0,
        64,
        56,
        1,
        64,
        0,
        0,
    )
    load = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0x400000,
        0x400000,
        size,
        size,
        0x1000,
    )
    return header + load + b"\xc0\x03\x5f\xd6"


class DiagnosticNormalRamdiskTests(unittest.TestCase):
    def test_wrapper_compiles_as_small_static_arm64_elf(self):
        builder = load_builder()
        self.assertTrue(WRAPPER_SOURCE.exists(), f"missing wrapper source: {WRAPPER_SOURCE}")
        with tempfile.TemporaryDirectory() as task_dir:
            task_root = Path(task_dir)
            task_object = task_root / "diagnostic_normal_init.o"
            task_elf = task_root / "diagnostic_normal_init"
            subprocess.run(
                [
                    "/usr/bin/clang",
                    "-target",
                    "aarch64-linux-android29",
                    "-std=c11",
                    "-Os",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-fno-asynchronous-unwind-tables",
                    "-fno-unwind-tables",
                    "-fvisibility=hidden",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-c",
                    str(WRAPPER_SOURCE),
                    "-o",
                    str(task_object),
                ],
                check=True,
            )
            subprocess.run(
                [
                    str(LLD),
                    "-flavor",
                    "gnu",
                    "-m",
                    "aarch64linux",
                    "--build-id=none",
                    "-static",
                    "-nostdlib",
                    "-e",
                    "_start",
                    "-z",
                    "max-page-size=4096",
                    "-o",
                    str(task_elf),
                    str(task_object),
                ],
                check=True,
            )
            wrapper = task_elf.read_bytes()

        builder.validate_wrapper(wrapper)
        self.assertLessEqual(len(wrapper), 16 * 1024)
        for marker in (
            b"DBY_FIRST_STAGE_V2 WRAPPER_ENTERED",
            b"DBY_FIRST_STAGE_V2 LOGGER_STARTED",
            b"/metadata/dby-first-stage-v2.log",
            b"/init.stock",
            b"HANDOFF_REACHED",
        ):
            self.assertIn(marker, wrapper)
        source = WRAPPER_SOURCE.read_text()
        self.assertIn("SYS_MKNODAT = 33", source)
        self.assertIn("dby_prepare_kmsg_node();", source)
        self.assertIn("S_IFCHR | 0600", source)

    @unittest.skipUnless(STOCK.is_file(), "set DBY_STOCK_RAMDISK to a private stock ramdisk")
    def test_build_candidate_preserves_partition_contract(self):
        builder = load_builder()
        source = STOCK.read_bytes()
        wrapper = minimal_static_arm64_elf()

        output, report = builder.build_image(source, wrapper)
        output_again, report_again = builder.build_image(source, wrapper)

        self.assertEqual(output, output_again)
        self.assertEqual(report["output_sha256"], report_again["output_sha256"])
        self.assertEqual(len(source), len(output))
        self.assertEqual(source[report["avb_offset"] :], output[report["avb_offset"] :])
        self.assertTrue(report["avb_tail_preserved"])
        self.assertTrue(report["stock_init_load_segments_preserved"])
        self.assertEqual(".gnu_debugdata", report["cleared_section"])

        entries = builder.extract_entries(output)
        by_name = {entry.name: entry for entry in entries}
        self.assertEqual(wrapper, by_name["init"].data)
        self.assertIn("init.stock", by_name)
        self.assertEqual(by_name["init"].fields[1], by_name["init.stock"].fields[1])
        self.assertEqual(builder.TRAILER, entries[-1].name)

    @unittest.skipUnless(STOCK.is_file(), "set DBY_STOCK_RAMDISK to a private stock ramdisk")
    def test_build_candidate_can_patch_one_fixed_length_stock_init_log_marker(self):
        builder = load_builder()
        source = STOCK.read_bytes()
        wrapper = minimal_static_arm64_elf()

        output, report = builder.build_image(
            source,
            wrapper,
            patch_stock_init_log_marker=True,
        )

        entries = builder.extract_entries(output)
        by_name = {entry.name: entry for entry in entries}
        patched_init = by_name["init.stock"].data
        self.assertEqual(
            len(builder.STOCK_FIRST_STAGE_LOG),
            len(builder.DIAGNOSTIC_FIRST_STAGE_LOG),
        )
        self.assertNotIn(builder.STOCK_FIRST_STAGE_LOG, patched_init)
        self.assertEqual(1, patched_init.count(builder.DIAGNOSTIC_FIRST_STAGE_LOG))
        self.assertEqual(
            builder.DIAGNOSTIC_FIRST_STAGE_LOG.decode(),
            report["stock_init_log_marker"],
        )
        self.assertEqual(1, report["stock_init_log_marker_occurrences"])
        self.assertTrue(report["stock_init_load_segments_preserved_except_log_marker"])
        self.assertFalse(report["stock_init_load_segments_preserved"])


if __name__ == "__main__":
    unittest.main()
