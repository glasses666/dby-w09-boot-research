from __future__ import annotations

import contextlib
import io
import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_boot_system_noavb.py"
DTB_DIR = Path(os.environ.get("DBY_DTB_DIR", ROOT / "private-fixtures/dtbs"))


def load_builder():
    spec = importlib.util.spec_from_file_location("build_boot_system_noavb", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LogicalPartitionAvbPatchTests(unittest.TestCase):
    @staticmethod
    def synthetic_boot(path: Path, builder) -> None:
        boot = bytearray(4096 + 4096 + 12)
        boot[:8] = builder.ANDROID_MAGIC
        struct.pack_into("<I", boot, 8, 4)
        struct.pack_into("<I", boot, 16, 0)
        struct.pack_into("<I", boot, 24, 0)
        struct.pack_into("<I", boot, 36, 4096)
        struct.pack_into("<I", boot, 40, 2)
        struct.pack_into("<I", boot, 1632, 0)
        struct.pack_into("<I", boot, 1644, 1660)
        struct.pack_into("<I", boot, 1648, 12)
        boot[4096:4100] = b"KERN"
        path.write_bytes(boot)

    @staticmethod
    def fake_fdts():
        fields = (0,) * 10
        return [(0, 4, fields), (4, 4, fields), (8, 4, fields)]

    @staticmethod
    def changes_for(nodes):
        return [{"node": node, "property": "fsmgr_flags"} for node in nodes]

    @unittest.skipUnless(DTB_DIR.is_dir(), "set DBY_DTB_DIR to the private DTB fixture directory")
    def test_removes_avb_from_every_logical_super_partition_only(self):
        builder = load_builder()
        expected_nodes = {
            "/firmware/android/fstab/system_ext4",
            "/firmware/android/fstab/system_erofs",
            "/firmware/android/fstab/vendor_ext4",
            "/firmware/android/fstab/vendor_erofs",
            "/firmware/android/fstab/odm_ext4",
            "/firmware/android/fstab/odm_erofs",
            "/firmware/android/fstab/cust_ext4",
            "/firmware/android/fstab/cust_erofs",
            "/firmware/android/fstab/hw_product_ext4",
            "/firmware/android/fstab/hw_product_erofs",
        }

        dtbs = sorted(DTB_DIR.glob("dt-00[0-2]-*.dtb"))
        self.assertEqual(3, len(dtbs))

        for path in dtbs:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                patched = bytearray(original)
                fields = struct.unpack_from(">10I", patched, 0)
                changes = builder.patch_fdt(
                    patched,
                    0,
                    fields,
                    exact_remove_avb=False,
                )

                self.assertEqual(10, len(changes))
                self.assertEqual(expected_nodes, {change["node"] for change in changes})
                self.assertTrue(all(change["old"].endswith("avb") for change in changes))
                self.assertTrue(all(change["new"].endswith("nof") for change in changes))
                self.assertEqual(original.count(b"logical,avb"), patched.count(b"logical,nof"))
                self.assertEqual(0, patched.count(b"logical,avb"))

                # Physical first-stage entries remain protected.  They do not
                # carry the logical flag and must not be part of this patch.
                self.assertEqual(
                    original.count(b"wait,nofail,avb"),
                    patched.count(b"wait,nofail,avb"),
                )

    @unittest.skipUnless(DTB_DIR.is_dir(), "set DBY_DTB_DIR to the private DTB fixture directory")
    def test_system_only_limits_exact_avb_removal_to_two_system_nodes(self):
        builder = load_builder()
        expected_nodes = {
            "/firmware/android/fstab/system_ext4",
            "/firmware/android/fstab/system_erofs",
        }
        dtbs = sorted(DTB_DIR.glob("dt-00[0-2]-*.dtb"))
        self.assertEqual(3, len(dtbs))

        for path in dtbs:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                patched = bytearray(original)
                fields = struct.unpack_from(">10I", patched, 0)
                changes = builder.patch_fdt(
                    patched,
                    0,
                    fields,
                    exact_remove_avb=True,
                    target_nodes=builder.SYSTEM_NODES,
                )

                self.assertEqual(2, len(changes))
                self.assertEqual(expected_nodes, {change["node"] for change in changes})
                self.assertTrue(all(change["old"].endswith(",avb") for change in changes))
                self.assertTrue(all(not change["new"].endswith(",avb") for change in changes))
                self.assertEqual(
                    original.count(b"logical,avb") - 2,
                    patched.count(b"logical,avb"),
                )
                self.assertEqual(len(original), len(patched))

    def test_argument_modes_preserve_defaults_and_existing_mutual_exclusion(self):
        builder = load_builder()
        parser = builder.build_argument_parser()

        default_args = parser.parse_args(["stock.img", "output.img"])
        self.assertFalse(default_args.system_only)
        self.assertFalse(default_args.exact_remove_avb)
        self.assertFalse(default_args.probe_system_dev)

        system_only_args = parser.parse_args(
            ["stock.img", "output.img", "--exact-remove-avb", "--system-only"]
        )
        self.assertTrue(system_only_args.system_only)
        self.assertTrue(system_only_args.exact_remove_avb)
        self.assertFalse(system_only_args.probe_system_dev)

        nof_system_only_args = parser.parse_args(
            ["stock.img", "output.img", "--system-only"]
        )
        self.assertTrue(nof_system_only_args.system_only)
        self.assertFalse(nof_system_only_args.exact_remove_avb)

        probe_args = parser.parse_args(["stock.img", "output.img", "--probe-system-dev"])
        self.assertFalse(probe_args.system_only)
        self.assertTrue(probe_args.probe_system_dev)

        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "stock.img",
                        "output.img",
                        "--exact-remove-avb",
                        "--probe-system-dev",
                    ]
                )

    @unittest.skipUnless(DTB_DIR.is_dir(), "set DBY_DTB_DIR to the private DTB fixture directory")
    def test_system_dev_probe_changes_only_two_system_dev_properties(self):
        builder = load_builder()
        self.assertTrue(
            hasattr(builder, "patch_fdt_system_dev_probe"),
            "builder must provide the system-dev runtime-DTB probe",
        )
        if not hasattr(builder, "patch_fdt_system_dev_probe"):
            return

        expected_nodes = {
            "/firmware/android/fstab/system_ext4",
            "/firmware/android/fstab/system_erofs",
        }
        dtbs = sorted(DTB_DIR.glob("dt-00[0-2]-*.dtb"))
        self.assertEqual(3, len(dtbs))

        for path in dtbs:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                patched = bytearray(original)
                fields = struct.unpack_from(">10I", patched, 0)
                changes = builder.patch_fdt_system_dev_probe(patched, 0, fields)

                self.assertEqual(2, len(changes))
                self.assertEqual(expected_nodes, {change["node"] for change in changes})
                self.assertTrue(all(change["property"] == "dev" for change in changes))
                self.assertTrue(all(change["old"] == "system" for change in changes))
                self.assertTrue(all(change["new"] == "systxm" for change in changes))
                self.assertEqual(original.count(b"logical,avb"), patched.count(b"logical,avb"))
                self.assertEqual(2, patched.count(b"systxm\0"))
                self.assertEqual(
                    original.count(b"system\0") - 2,
                    patched.count(b"system\0"),
                )
                self.assertEqual(len(original), len(patched))

    def test_main_refuses_manifest_path_that_aliases_output(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "stock.img"
            output = root / "candidate.img"
            self.synthetic_boot(source, builder)
            valid = [self.changes_for(sorted(builder.SYSTEM_NODES)) for _ in range(3)]
            argv = [
                str(SCRIPT),
                str(source),
                str(output),
                "--manifest",
                str(output),
                "--system-only",
                "--exact-remove-avb",
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                builder, "scan_fdts", return_value=self.fake_fdts()
            ), mock.patch.object(builder, "patch_fdt", side_effect=valid):
                with self.assertRaisesRegex(SystemExit, "manifest.*output"):
                    builder.main()
            self.assertFalse(output.exists())

    def test_main_rejects_aggregate_only_system_node_distribution(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "stock.img"
            output = root / "candidate.img"
            manifest = root / "candidate.json"
            self.synthetic_boot(source, builder)
            nodes = sorted(builder.SYSTEM_NODES)
            malformed = [self.changes_for(nodes * 3), [], []]
            argv = [
                str(SCRIPT),
                str(source),
                str(output),
                "--manifest",
                str(manifest),
                "--system-only",
                "--exact-remove-avb",
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                builder, "scan_fdts", return_value=self.fake_fdts()
            ), mock.patch.object(builder, "patch_fdt", side_effect=malformed):
                with self.assertRaisesRegex(SystemExit, "each of three DTBs"):
                    builder.main()
            self.assertFalse(output.exists())
            self.assertFalse(manifest.exists())

    def test_main_publishes_distinct_image_and_manifest_for_three_exact_dtbs(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "stock.img"
            output = root / "candidate.img"
            manifest = root / "candidate.json"
            self.synthetic_boot(source, builder)
            valid = [self.changes_for(sorted(builder.SYSTEM_NODES)) for _ in range(3)]
            argv = [
                str(SCRIPT),
                str(source),
                str(output),
                "--manifest",
                str(manifest),
                "--system-only",
                "--exact-remove-avb",
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                builder, "scan_fdts", return_value=self.fake_fdts()
            ), mock.patch.object(builder, "patch_fdt", side_effect=valid), contextlib.redirect_stdout(
                io.StringIO()
            ):
                self.assertEqual(0, builder.main())
            self.assertEqual(source.read_bytes(), output.read_bytes())
            report = json.loads(manifest.read_text())
            self.assertEqual(str(output.resolve()), report["output"])
            self.assertEqual(6, report["change_count"])
            self.assertEqual(
                [builder.SYSTEM_NODES] * 3,
                [{change["node"] for change in entry["changes"]} for entry in report["fdt_entries"]],
            )


if __name__ == "__main__":
    unittest.main()
