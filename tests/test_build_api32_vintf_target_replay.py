from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_api32_vintf_target_replay.py"
WINDOWS_RUNNER = ROOT / "scripts/run_api32_vintf_target_replay_windows.ps1"


def load_builder():
    if not SCRIPT.is_file():
        raise AssertionError("target libvintf replay builder is missing")
    spec = importlib.util.spec_from_file_location(
        "build_api32_vintf_target_replay", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Api32TargetVintfReplayBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_builder()

    def test_frozen_control_and_candidate_identities_are_exact(self) -> None:
        b = self.builder
        self.assertEqual(
            "451cc674329a8b18246136d19b929b043a8549c2ca89e7a6dd9b7235604857ea",
            b.CONTROL_SYSTEM_SHA256,
        )
        self.assertEqual(
            "0d1bdf7e1116ce07b6923f3157f76c6555fd33cfce5082ee2a883706c186a54a",
            b.CANDIDATE_SYSTEM_SHA256,
        )
        self.assertEqual(2_513_813_504, b.EXPECTED_SYSTEM_SIZE)

    def test_runtime_closure_names_are_explicit_and_bounded(self) -> None:
        b = self.builder
        self.assertEqual(
            {
                "ld-android.so",
                "libbase.so",
                "libc++.so",
                "libc.so",
                "libdl.so",
                "libhidl-gen-utils.so",
                "liblog.so",
                "libm.so",
                "libpackagelistparser.so",
                "libpcre2.so",
                "libselinux.so",
                "libtinyxml2.so",
                "libvintf.so",
                "libz.so",
            },
            set(b.RUNTIME_LIBRARY_SOURCES),
        )

    def test_query_source_calls_target_framework_device_aidl_and_hidl_apis(self) -> None:
        source = self.builder.query_source()
        self.assertIn("getFrameworkHalManifest()", source)
        self.assertIn("getDeviceHalManifest()", source)
        self.assertIn("hasAidlInstance", source)
        self.assertIn("hasHidlInstance", source)
        self.assertIn("getHidlTransport", source)
        self.assertIn("android.system.keystore2", source)
        self.assertIn("android.system.suspend", source)
        self.assertIn("android.hardware.gnss", source)

    def test_query_source_avoids_new_libcpp_stream_abi(self) -> None:
        source = self.builder.query_source()
        self.assertNotIn("<fstream>", source)
        self.assertNotIn("<iostream>", source)
        self.assertNotIn("<sstream>", source)
        self.assertIn("::open(", source)
        self.assertIn("::read(", source)
        self.assertIn("::write(", source)
        self.assertIn("__libcpp_verbose_abort(char const*, ...) noexcept", source)

    def test_libcpp_overlay_matches_target_std_namespace(self) -> None:
        config = self.builder.libcpp_config_site()
        self.assertIn("#define _LIBCPP_ABI_NAMESPACE __1", config)
        self.assertNotIn("#define _LIBCPP_ABI_NAMESPACE __ndk1", config)
        self.assertIn("#define _LIBCPP_NO_ABI_TAG 1", config)
        self.assertIn("#define _LIBCPP_HARDENING_MODE_DEFAULT 2", config)

    def test_pair_diff_rejects_any_difference_outside_main_manifest(self) -> None:
        b = self.builder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control = root / "control"
            candidate = root / "candidate"
            for view in (control, candidate):
                target = view / "system/etc/vintf"
                target.mkdir(parents=True)
                (target / "manifest.xml").write_text("control")
                (target / "manifest/fragment.xml").parent.mkdir()
                (target / "manifest/fragment.xml").write_text("same")
            (candidate / "system/etc/vintf/manifest.xml").write_text("candidate")

            report = b.compare_views(control, candidate)
            self.assertEqual(["system/etc/vintf/manifest.xml"], report["changed_paths"])
            self.assertTrue(report["single_authorized_difference"])

            (candidate / "system/etc/vintf/manifest/fragment.xml").write_text("drift")
            report = b.compare_views(control, candidate)
            self.assertFalse(report["single_authorized_difference"])

    def test_runner_starts_control_and_candidate_as_separate_processes(self) -> None:
        script = self.builder.runner_script()
        self.assertIn("/control", script)
        self.assertIn("/candidate", script)
        self.assertIn("/corrected", script)
        self.assertIn("control.json", script)
        self.assertIn("candidate.json", script)
        self.assertIn("corrected.json", script)
        self.assertEqual(3, script.count("/system/bin/dby-vintf-replay /"))

    def test_runner_captures_architecture_and_target_linker_resolution(self) -> None:
        script = self.builder.runner_script()
        self.assertIn("uname -m", script)
        self.assertIn("/system/bin/linker64 --list", script)
        self.assertIn("linker-list.exit.txt", script)

    def test_android_aliases_are_materialized_for_windows_bind_mounts(self) -> None:
        b = self.builder
        with tempfile.TemporaryDirectory() as temporary:
            view = Path(temporary)
            product_file = view / "system/product/etc/vintf/product.xml"
            system_ext_file = view / "system/system_ext/etc/vintf/system_ext.xml"
            product_file.parent.mkdir(parents=True)
            system_ext_file.parent.mkdir(parents=True)
            product_file.write_text("product")
            system_ext_file.write_text("system_ext")

            b.materialize_android_aliases(view)

            self.assertTrue((view / "product").is_dir())
            self.assertFalse((view / "product").is_symlink())
            self.assertEqual(
                "product",
                (view / "product/etc/vintf/product.xml").read_text(),
            )
            self.assertTrue((view / "system_ext").is_dir())
            self.assertFalse((view / "system_ext").is_symlink())
            self.assertEqual(
                "system_ext",
                (view / "system_ext/etc/vintf/system_ext.xml").read_text(),
            )

    def test_missing_android_alias_source_becomes_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            view = Path(temporary)
            (view / "system").mkdir()

            self.builder.materialize_android_aliases(view)

            self.assertTrue((view / "product").is_dir())
            self.assertEqual([], list((view / "product").iterdir()))
            self.assertTrue((view / "system_ext").is_dir())
            self.assertEqual([], list((view / "system_ext").iterdir()))

    def test_windows_runner_avoids_newer_dotnet_relative_path_api(self) -> None:
        script = WINDOWS_RUNNER.read_text()
        self.assertNotIn("[System.IO.Path]::GetRelativePath", script)
        self.assertIn(".Substring($RootfsPrefix.Length)", script)

    def test_windows_runner_mounts_and_validates_corrected_process(self) -> None:
        script = WINDOWS_RUNNER.read_text()
        self.assertIn('target=/corrected,readonly', script)
        self.assertIn('"corrected.exit.txt"', script)
        self.assertIn('corrected_exit = $CorrectedExit', script)

    def test_source_derived_correction_keeps_only_highest_minor(self) -> None:
        b = self.builder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            corrected = root / "corrected"
            manifest = candidate / "system/etc/vintf/manifest.xml"
            manifest.parent.mkdir(parents=True)
            payload = (
                '<manifest version="4.0" type="framework">'
                '<hal format="hidl"><name>android.hardware.gnss</name>'
                '<version>1.0</version><version>1.1</version>'
                '<interface><name>IGnss</name><instance>default</instance></interface>'
                '</hal></manifest>'
            ).encode()
            manifest.write_bytes(payload)
            sibling = candidate / "vendor/etc/vintf/manifest.xml"
            sibling.parent.mkdir(parents=True)
            sibling.write_text("unchanged")

            report = b.build_source_derived_correction(candidate, corrected)

            corrected_payload = (corrected / "system/etc/vintf/manifest.xml").read_bytes()
            self.assertEqual(len(payload), len(corrected_payload))
            self.assertNotIn(b"<version>1.0</version>", corrected_payload)
            self.assertIn(b"<version>1.1</version>", corrected_payload)
            self.assertEqual("unchanged", (corrected / "vendor/etc/vintf/manifest.xml").read_text())
            self.assertEqual(
                ["system/etc/vintf/manifest.xml"],
                report["changed_paths"],
            )
            self.assertEqual(["1.0", "1.1"], report["before_versions"])
            self.assertEqual(["1.1"], report["after_versions"])

    def test_source_identity_hashes_tree_not_tar_container_metadata(self) -> None:
        b = self.builder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = []
            for index, mtime in enumerate((1, 2)):
                archive = root / f"source-{index}.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    info = tarfile.TarInfo("include/example.h")
                    payload = b"same source\n"
                    info.size = len(payload)
                    info.mode = 0o644
                    info.mtime = mtime
                    bundle.addfile(info, io.BytesIO(payload))
                archives.append(archive)

            self.assertNotEqual(b.sha256_file(archives[0]), b.sha256_file(archives[1]))
            self.assertEqual(
                b.source_tree_sha256(archives[0]),
                b.source_tree_sha256(archives[1]),
            )

    def test_deprecated_archive_container_hash_is_not_an_identity_gate(self) -> None:
        self.assertFalse(hasattr(self.builder, "OFFICIAL_SOURCE_SHA256"))

    def test_recorded_compile_command_does_not_embed_staging_path(self) -> None:
        b = self.builder
        staging = Path("/tmp/.harness.random/harness")
        command = [
            "/opt/android-ndk/bin/aarch64-linux-android32-clang++",
            str(staging / "source/dby_vintf_replay.cpp"),
            f"-L{staging / 'runtime/system/lib64'}",
            f"-Wl,-rpath-link,{staging / 'runtime/system/lib64'}",
            "-o",
            str(staging / "runtime/system/bin/dby-vintf-replay"),
        ]

        recorded = b.normalize_compile_command(command, staging)

        self.assertNotIn("/tmp/.harness.random", " ".join(recorded))
        self.assertIn("$HARNESS/source/dby_vintf_replay.cpp", recorded)
        self.assertIn("-L$HARNESS/runtime/system/lib64", recorded)
        self.assertIn(
            "-Wl,-rpath-link,$HARNESS/runtime/system/lib64",
            recorded,
        )


if __name__ == "__main__":
    unittest.main()
