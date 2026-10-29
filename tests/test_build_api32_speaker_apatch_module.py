import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from scripts import build_api32_speaker_apatch_module as builder
from scripts.build_api32_speaker_apatch_module import (
    EXPECTED_LIBRARY_SIZE,
    LIBRARY_ENTRY,
    MODULE_ID,
    MODULE_PROP,
    POST_FS_DATA,
    build_module,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_api32_speaker_apatch_module.py"


def synthetic_candidate() -> bytes:
    # Structural test data only; no proprietary detector bytes are distributed.
    candidate = bytearray(EXPECTED_LIBRARY_SIZE)
    candidate[:6] = b"\x7fELF\x01\x01"
    return bytes(candidate)


class Api32SpeakerApatchModuleTests(unittest.TestCase):
    def test_build_is_deterministic_and_contains_only_declared_files(self) -> None:
        first, first_manifest = build_module(synthetic_candidate(), verify_hash=False)
        second, second_manifest = build_module(synthetic_candidate(), verify_hash=False)

        self.assertEqual(first, second)
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first_manifest["module_id"], MODULE_ID)
        self.assertFalse(first_manifest["partition_write_required"])
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertEqual(archive.namelist(), ["module.prop", "post-fs-data.sh", LIBRARY_ENTRY])
            self.assertEqual(archive.read("module.prop"), MODULE_PROP)
            self.assertEqual(archive.read("post-fs-data.sh"), POST_FS_DATA)
            self.assertEqual(archive.read(LIBRARY_ENTRY), synthetic_candidate())
            self.assertEqual((archive.getinfo("module.prop").external_attr >> 16) & 0o777, 0o644)
            self.assertEqual((archive.getinfo("post-fs-data.sh").external_attr >> 16) & 0o777, 0o755)
            self.assertEqual((archive.getinfo(LIBRARY_ENTRY).external_attr >> 16) & 0o777, 0o644)

    def test_rejects_wrong_candidate_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            build_module(synthetic_candidate())

    def test_rejects_non_elf32_candidate(self) -> None:
        with self.assertRaisesRegex(ValueError, "ELF32"):
            build_module(bytes(EXPECTED_LIBRARY_SIZE), verify_hash=False)

    def test_module_identity_and_public_attribution(self) -> None:
        self.assertEqual(MODULE_ID, "dby_api32_speaker_compat")
        self.assertEqual(LIBRARY_ENTRY, "system/vendor/lib/libqti_vndfwk_detect.so")
        self.assertEqual(EXPECTED_LIBRARY_SIZE, 14976)
        self.assertEqual(
            builder.EXPECTED_LIBRARY_SHA256,
            "706c5d92e7d6416b9ed194ede6e65e61259565a8d1ffa0dfada3cd096d72560c",
        )
        properties = dict(
            line.split("=", 1) for line in MODULE_PROP.decode("utf-8").splitlines()
        )
        self.assertEqual(properties, {
            "id": "dby_api32_speaker_compat",
            "name": "DBY-W09 API32 Speaker Compatibility",
            "version": "1.1.0",
            "versionCode": "2",
            "author": "Queen_Glasser (@glasses666)",
            "description": (
                "Bind-mounts the accepted ODM-only Qualcomm detector before the "
                "API32 Audio HAL starts."
            ),
        })

    def test_bind_script_is_byte_identical_to_the_original(self) -> None:
        # Freeze the original stock/candidate gates, bind command and ordering.
        self.assertEqual(
            hashlib.sha256(POST_FS_DATA).hexdigest(),
            "6c4190e3b73f96bbfb227253141c9f1cbb61cf8714f351b296131461a11afc09",
        )

    def test_zip_timestamps_permissions_and_compression_are_fixed(self) -> None:
        module, _ = build_module(synthetic_candidate(), verify_hash=False)
        with zipfile.ZipFile(io.BytesIO(module)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.comment, b"")
            for entry, mode in zip(archive.infolist(), (0o644, 0o755, 0o644)):
                with self.subTest(entry=entry.filename):
                    self.assertEqual(entry.date_time, (2026, 10, 28, 0, 0, 0))
                    self.assertEqual(entry.create_system, 3)
                    self.assertEqual(entry.compress_type, zipfile.ZIP_DEFLATED)
                    self.assertEqual(entry.external_attr >> 16, stat.S_IFREG | mode)
                    self.assertEqual(entry.extra, b"")
                    self.assertEqual(entry.comment, b"")

    def test_manifest_hashes_sizes_and_modes_match_the_archive(self) -> None:
        candidate = synthetic_candidate()
        module, manifest = build_module(candidate, verify_hash=False)
        entries = (
            ("module.prop", MODULE_PROP, "0o644"),
            ("post-fs-data.sh", POST_FS_DATA, "0o755"),
            (LIBRARY_ENTRY, candidate, "0o644"),
        )
        self.assertEqual(manifest, {
            "schema": "dby-w09-api32-speaker-apatch-module-v1",
            "module_id": "dby_api32_speaker_compat",
            "module_version": "1.1.0",
            "module_version_code": 2,
            "candidate_library_sha256": hashlib.sha256(candidate).hexdigest(),
            "candidate_library_size": len(candidate),
            "library_target": "/vendor/lib/libqti_vndfwk_detect.so",
            "module_zip_sha256": hashlib.sha256(module).hexdigest(),
            "module_zip_size": len(module),
            "entries": [
                {
                    "path": name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "mode": mode,
                }
                for name, data, mode in entries
            ],
            "partition_write_required": False,
            "activation": (
                "module post-fs-data script validates both identities and "
                "bind-mounts one file before Audio HAL startup"
            ),
            "rollback": (
                "disable dby_api32_speaker_compat and reboot; "
                "stock vendor file is never modified"
            ),
        })

    def test_matching_candidate_hash_passes_the_default_identity_gate(self) -> None:
        candidate = synthetic_candidate()
        # Substitute only the expected digest, never the validation function.
        with mock.patch.object(
            builder, "EXPECTED_LIBRARY_SHA256", hashlib.sha256(candidate).hexdigest()
        ):
            module, manifest = build_module(candidate)
        with zipfile.ZipFile(io.BytesIO(module)) as archive:
            self.assertEqual(archive.read(LIBRARY_ENTRY), candidate)
        self.assertEqual(
            manifest["candidate_library_sha256"], hashlib.sha256(candidate).hexdigest()
        )

    def test_rejects_short_and_long_candidates_even_with_a_matching_hash(self) -> None:
        candidate = synthetic_candidate()
        for invalid in (candidate[:-1], candidate + b"\x00"):
            with self.subTest(size=len(invalid)), mock.patch.object(
                builder, "EXPECTED_LIBRARY_SHA256", hashlib.sha256(invalid).hexdigest()
            ):
                with self.assertRaisesRegex(ValueError, "size mismatch"):
                    build_module(invalid)
                with self.assertRaisesRegex(ValueError, "size mismatch"):
                    build_module(invalid, verify_hash=False)

    def test_rejects_wrong_elf_magic_class_and_endianness(self) -> None:
        for prefix in (b"BAD!\x01\x01", b"\x7fELF\x02\x01", b"\x7fELF\x01\x02"):
            candidate = prefix + synthetic_candidate()[6:]
            with self.subTest(prefix=prefix), mock.patch.object(
                builder, "EXPECTED_LIBRARY_SHA256", hashlib.sha256(candidate).hexdigest()
            ):
                with self.assertRaisesRegex(ValueError, "ELF32"):
                    build_module(candidate)
                with self.assertRaisesRegex(ValueError, "ELF32"):
                    build_module(candidate, verify_hash=False)

    def test_hash_gate_runs_before_structural_gates(self) -> None:
        for candidate in (b"", bytes(EXPECTED_LIBRARY_SIZE)):
            with self.subTest(size=len(candidate)):
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    build_module(candidate)


class Api32SpeakerApatchModuleCliTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.candidate = self.root / "candidate.so"
        self.candidate.write_bytes(synthetic_candidate())
        self.output = self.root / "output" / "speaker.zip"
        self.manifest = self.root / "manifest" / "speaker.json"

    def arguments(self) -> list[str]:
        return [
            "--candidate", str(self.candidate),
            "--output", str(self.output),
            "--manifest", str(self.manifest),
        ]

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *arguments],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def assert_no_outputs(self) -> None:
        self.assertFalse(self.output.parent.exists())
        self.assertFalse(self.manifest.parent.exists())

    def test_cli_help_and_required_arguments(self) -> None:
        help_result = self.run_cli("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn(builder.__doc__, help_result.stdout)
        missing = self.run_cli()
        self.assertEqual(missing.returncode, 2)
        for option in ("--candidate", "--output", "--manifest"):
            self.assertIn(option, help_result.stdout)
            self.assertIn(option, missing.stderr)
        self.assert_no_outputs()

    def test_cli_offers_no_hash_bypass(self) -> None:
        result = self.run_cli(*self.arguments(), "--verify-hash=false")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments", result.stderr)
        self.assert_no_outputs()

    def test_cli_rejects_synthetic_hash_before_creating_output_directories(self) -> None:
        result = self.run_cli(*self.arguments())
        self.assertEqual(result.returncode, 1)
        self.assertIn("candidate detector identity mismatch", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.candidate.read_bytes(), synthetic_candidate())
        self.assert_no_outputs()

    def test_cli_missing_candidate_does_not_create_outputs(self) -> None:
        self.candidate.unlink()
        result = self.run_cli(*self.arguments())
        self.assertEqual(result.returncode, 1)
        self.assertIn("FileNotFoundError", result.stderr)
        self.assert_no_outputs()

    def test_cli_preserves_existing_output_or_manifest_before_reading_input(self) -> None:
        self.candidate.unlink()
        for existing, other in (
            (self.output, self.manifest), (self.manifest, self.output)
        ):
            with self.subTest(existing=existing.name):
                existing.parent.mkdir()
                existing.write_bytes(b"preserve existing build\n")
                result = self.run_cli(*self.arguments())
                self.assertEqual(result.returncode, 1)
                self.assertIn("refusing to overwrite an existing module build", result.stderr)
                self.assertNotIn("FileNotFoundError", result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(existing.read_bytes(), b"preserve existing build\n")
                self.assertFalse(other.parent.exists())
                existing.unlink()
                existing.parent.rmdir()

    def test_main_writes_deterministic_zip_and_canonical_manifest(self) -> None:
        candidate = synthetic_candidate()
        expected_module, expected_manifest = build_module(candidate, verify_hash=False)
        stdout = io.StringIO()
        with mock.patch.object(
            builder, "EXPECTED_LIBRARY_SHA256", hashlib.sha256(candidate).hexdigest()
        ), mock.patch.object(
            sys, "argv", [str(SCRIPT), *self.arguments()]
        ), mock.patch.object(
            builder, "build_module", wraps=build_module
        ) as build, contextlib.redirect_stdout(stdout):
            self.assertEqual(builder.main(), 0)
        build.assert_called_once_with(candidate)
        self.assertEqual(self.output.read_bytes(), expected_module)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o644)
        manifest_text = self.manifest.read_text(encoding="utf-8")
        self.assertEqual(json.loads(manifest_text), expected_manifest)
        self.assertEqual(
            manifest_text, json.dumps(expected_manifest, indent=2, sort_keys=True) + "\n"
        )
        self.assertEqual(stdout.getvalue(), manifest_text)
        self.assertNotIn(str(self.root), manifest_text)
        self.assertEqual(self.candidate.read_bytes(), candidate)


if __name__ == "__main__":
    unittest.main()
