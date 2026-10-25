from __future__ import annotations

import importlib.util
import os
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "w6_switch_root_stage_probe.c"
BUILDER = ROOT / "scripts" / "build_w6_switch_root_probe_ramdisk.py"
STOCK = Path(os.environ.get("DBY_STOCK_RAMDISK", ROOT / "private-fixtures/ramdisk.img"))
LLD = Path(
    "/opt/homebrew/share/android-commandlinetools/build-tools/34.0.0/lld"
)
NONCE = "102132435465768798a9bacbdcedfe0f"
LINEAGE_INIT_SHA256 = (
    "f9aff20075a7d85e14412855c7dad7f353cba41918b2e45fe4f0285379e1e0f3"
)


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_w6_switch_root_probe_ramdisk", BUILDER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {BUILDER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def compile_probe(directory: Path) -> bytes:
    object_path = directory / "w6.o"
    elf_path = directory / "w6"
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
            "-Wno-unused-function",
            f'-DDBY_W6_NONCE_HEX="{NONCE}"',
            f'-DDBY_W6_EXPECTED_LINEAGE_INIT_SHA256="{LINEAGE_INIT_SHA256}"',
            "-c",
            str(SOURCE),
            "-o",
            str(object_path),
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
            str(elf_path),
            str(object_path),
        ],
        check=True,
    )
    return elf_path.read_bytes()


class W6SwitchRootProbeTests(unittest.TestCase):
    def test_source_keeps_parent_mount_namespace_clean(self):
        source = SOURCE.read_text()
        self.assertIn("W6_CLONE_NEWNS", source)
        self.assertRegex(
            source,
            re.compile(
                r"dby_mount\(\s*0,\s*\"/\",\s*0,"
                r"\s*W6_MS_REC\s*\|\s*W6_MS_PRIVATE,\s*0\s*\)",
                re.DOTALL,
            ),
        )
        self.assertRegex(
            source,
            re.compile(
                r'dby_mount\(\s*"proc",\s*"/dby-proc",\s*"proc"',
                re.DOTALL,
            ),
        )
        self.assertNotIn('"proc", "/proc", "proc"', source)
        self.assertNotIn("/log", source)
        self.assertNotIn("/metadata", source)
        self.assertNotIn("O_CREAT", source)

    def test_parent_readiness_wait_uses_ppoll_timespec_pointer(self):
        source = SOURCE.read_text()
        self.assertIn("W6_SYS_PPOLL = 73", source)
        self.assertRegex(
            source,
            re.compile(
                r"struct dby_timespec\s+ready_timeout\s*=\s*\{[^}]+\};"
                r".*?dby_syscall5\(\s*W6_SYS_PPOLL,\s*\(isize\)&pollfd,\s*1,"
                r"\s*\(isize\)&ready_timeout,\s*0,\s*0\s*\)",
                re.DOTALL,
            ),
        )

    def test_probe_passes_clang_static_analyzer_without_warnings(self):
        result = subprocess.run(
            [
                "/usr/bin/clang",
                "--analyze",
                "-target",
                "aarch64-linux-android29",
                "-std=c11",
                "-ffreestanding",
                "-fno-builtin",
                "-Wno-unused-function",
                f'-DDBY_W6_NONCE_HEX="{NONCE}"',
                f'-DDBY_W6_EXPECTED_LINEAGE_INIT_SHA256="{LINEAGE_INIT_SHA256}"',
                str(SOURCE),
                "-Xanalyzer",
                "-analyzer-output=text",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
        self.assertNotIn("warning:", result.stdout, result.stdout)

    @unittest.skipUnless(STOCK.is_file(), "set DBY_STOCK_RAMDISK to a private stock ramdisk")
    def test_probe_and_ramdisk_preserve_the_narrow_w6_contract(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as directory_text:
            probe = compile_probe(Path(directory_text))
        layout = builder.validate_probe(probe, NONCE, LINEAGE_INIT_SHA256)
        self.assertEqual(2, layout["elf_type"])
        self.assertFalse(layout["has_dynamic_segment"])
        self.assertFalse(layout["has_writable_executable_segment"])
        self.assertLessEqual(layout["load_memory_bytes"], 256 * 1024)

        image, report = builder.build_w6(
            STOCK.read_bytes(), probe, NONCE, LINEAGE_INIT_SHA256
        )
        self.assertEqual(2 * 1024 * 1024, len(image))
        self.assertEqual(0, report["embedded_vbmeta_flags"])
        self.assertTrue(report["avb_tail_preserved"])
        self.assertTrue(report["executes_stock_init"])
        self.assertFalse(report["writes_persistent_storage"])
        self.assertTrue(report["parent_mount_namespace_untouched"])

        entries = builder.base.extract_entries(image)
        by_name = {entry.name: entry for entry in entries}
        self.assertEqual(probe, by_name["init"].data)
        self.assertIn("init.stock", by_name)
        avb_offset = report["avb_offset"]
        self.assertEqual(STOCK.read_bytes()[avb_offset:], image[avb_offset:])
        self.assertEqual(0, struct.unpack_from(">I", image, avb_offset + 120)[0])

    def test_probe_rejects_wrong_expected_lineage_identity(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as directory_text:
            probe = compile_probe(Path(directory_text))
        with self.assertRaisesRegex(ValueError, "missing required markers"):
            builder.validate_probe(probe, NONCE, "0" * 64)


if __name__ == "__main__":
    unittest.main()
