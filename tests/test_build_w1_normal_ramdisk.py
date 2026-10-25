from __future__ import annotations

import importlib.util
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "w1_normal_witness.c"
BUILDER = ROOT / "scripts" / "build_w1_normal_ramdisk.py"
STOCK = Path(os.environ.get("DBY_STOCK_RAMDISK", ROOT / "private-fixtures/ramdisk.img"))
LLD = Path(
    "/opt/homebrew/share/android-commandlinetools/"
    "build-tools/34.0.0/lld"
)
NONCE = "00112233445566778899aabbccddeeff"


def load_builder():
    if not BUILDER.exists():
        raise AssertionError(f"missing W1 builder: {BUILDER}")
    spec = importlib.util.spec_from_file_location("build_w1_normal_ramdisk", BUILDER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {BUILDER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def compile_probe(task_root: Path) -> bytes:
    task_object = task_root / "w1_normal_witness.o"
    task_elf = task_root / "w1_normal_witness"
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
            f'-DDBY_W1_NONCE_HEX="{NONCE}"',
            "-c",
            str(SOURCE),
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
    return task_elf.read_bytes()


class W1NormalRamdiskTests(unittest.TestCase):
    def test_arm64_marker_validator_rejects_substrings_and_overflow(self):
        if shutil.which("docker") is None:
            self.skipTest("Docker is unavailable for the ARM64 Linux harness")
        image = subprocess.run(
            ["docker", "image", "inspect", "ubuntu:24.04"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if image.returncode != 0:
            self.skipTest("local ubuntu:24.04 image is unavailable")

        with tempfile.TemporaryDirectory() as task_dir_text:
            task_dir = Path(task_dir_text)
            harness = task_dir / "w1_marker_harness.c"
            executable = task_dir / "w1_marker_harness"
            harness.write_text(
                f'''\
#define DBY_W1_NONCE_HEX "{NONCE}"
#define DBY_W1_LIBRARY_TEST 1
#include "{SOURCE}"

__attribute__((noreturn, visibility("default"))) void _start(void) {{
    static const char expected[] =
        "DBY_W1_USERSPACE_MARKER nonce={NONCE}";
    static const char valid_record[] =
        "6,10,20000,-;DBY_W1_USERSPACE_MARKER nonce={NONCE}\\n";
    static const char substring_record[] =
        "6,10,20000,-;prefix DBY_W1_USERSPACE_MARKER nonce={NONCE} suffix\\n";
    u64 priority = 0;
    u64 sequence = 0;
    u64 timestamp = 0;
    int vendor_prefixed = 0;
    int ok = dby_validate_kmsg_marker_record(
        valid_record,
        sizeof(valid_record) - 1,
        expected,
        sizeof(expected) - 1,
        &priority,
        &sequence,
        &timestamp,
        &vendor_prefixed
    ) == 0;
    ok = ok && priority == 6 && sequence == 10 && timestamp == 20000 &&
         vendor_prefixed == 0;
    static const char vendor_record[] =
        "6,11,21000,-;(4)[1:init]DBY_W1_USERSPACE_MARKER nonce={NONCE}\\n";
    ok = ok && dby_validate_kmsg_marker_record(
        vendor_record,
        sizeof(vendor_record) - 1,
        expected,
        sizeof(expected) - 1,
        &priority,
        &sequence,
        &timestamp,
        &vendor_prefixed
    ) == 0;
    ok = ok && sequence == 11 && timestamp == 21000 && vendor_prefixed == 1;
    static const char timestamped_vendor_record[] =
        "6,12,22000,-;[1970:01:01 00:00:01](7)[1:init]"
        "DBY_W1_USERSPACE_MARKER nonce={NONCE}\\n";
    ok = ok && dby_validate_kmsg_marker_record(
        timestamped_vendor_record,
        sizeof(timestamped_vendor_record) - 1,
        expected,
        sizeof(expected) - 1,
        &priority,
        &sequence,
        &timestamp,
        &vendor_prefixed
    ) == 0;
    ok = ok && sequence == 12 && timestamp == 22000 && vendor_prefixed == 1;
    ok = ok && dby_validate_kmsg_marker_record(
        substring_record,
        sizeof(substring_record) - 1,
        expected,
        sizeof(expected) - 1,
        &priority,
        &sequence,
        &timestamp,
        &vendor_prefixed
    ) == -EBADMSG;
    static const char wrong_pid_record[] =
        "6,13,23000,-;[1970:01:01 00:00:01](4)[2:init]"
        "DBY_W1_USERSPACE_MARKER nonce={NONCE}\\n";
    ok = ok && dby_validate_kmsg_marker_record(
        wrong_pid_record,
        sizeof(wrong_pid_record) - 1,
        expected,
        sizeof(expected) - 1,
        &priority,
        &sequence,
        &timestamp,
        &vendor_prefixed
    ) == -EBADMSG;
    static const char malformed_timestamp_record[] =
        "6,14,24000,-;[1970-01-01 00:00:01](4)[1:init]"
        "DBY_W1_USERSPACE_MARKER nonce={NONCE}\\n";
    ok = ok && dby_validate_kmsg_marker_record(
        malformed_timestamp_record,
        sizeof(malformed_timestamp_record) - 1,
        expected,
        sizeof(expected) - 1,
        &priority,
        &sequence,
        &timestamp,
        &vendor_prefixed
    ) == -EBADMSG;
    int decimal_valid = 0;
    (void)dby_parse_decimal(
        "18446744073709551616", 20, &decimal_valid
    );
    ok = ok && !decimal_valid;
    (void)dby_syscall1(SYS_EXIT, ok ? 0 : 1);
    for (;;) {{}}
}}
'''
            )
            object_path = task_dir / "w1_marker_harness.o"
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
                    "-Wno-unused-function",
                    "-c",
                    str(harness),
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
                    "-o",
                    str(executable),
                    str(object_path),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "-v",
                    f"{task_dir}:/work:ro",
                    "ubuntu:24.04",
                    "/work/w1_marker_harness",
                ],
                check=True,
            )

    def test_arm64_directory_open_flags_match_runtime_abi(self):
        if shutil.which("docker") is None:
            self.skipTest("Docker is unavailable for the ARM64 Linux harness")
        image = subprocess.run(
            ["docker", "image", "inspect", "ubuntu:24.04"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if image.returncode != 0:
            self.skipTest("local ubuntu:24.04 image is unavailable")

        with tempfile.TemporaryDirectory() as task_dir_text:
            task_dir = Path(task_dir_text)
            harness = task_dir / "w1_open_flags_harness.c"
            executable = task_dir / "w1_open_flags_harness"
            harness.write_text(
                f'''\
#define DBY_W1_NONCE_HEX "{NONCE}"
#define DBY_W1_LIBRARY_TEST 1
#include "{SOURCE}"

__attribute__((noreturn, visibility("default"))) void _start(void) {{
    static isize results[4];
    results[0] = dby_open("/dby-audit-log", O_RDONLY, 0);
    results[1] = dby_open("/dby-audit-log", O_RDONLY | O_DIRECTORY, 0);
    results[2] = dby_open(
        "/dby-audit-log", O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0
    );
    results[3] = dby_open(
        "/dby-audit-log",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
        0
    );
    for (usize index = 0; index < 4; ++index) {{
        if (results[index] >= 0) {{
            (void)dby_close(results[index]);
            results[index] = 0;
        }}
    }}
    isize write_result = dby_write_all(1, results, sizeof(results));
    (void)dby_syscall1(SYS_EXIT, write_result == 0 ? 0 : 1);
    for (;;) {{}}
}}
'''
            )
            object_path = task_dir / "w1_open_flags_harness.o"
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
                    "-Wno-unused-function",
                    "-c",
                    str(harness),
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
                    "-o",
                    str(executable),
                    str(object_path),
                ],
                check=True,
            )
            completed = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "-v",
                    f"{task_dir}:/work:ro",
                    "--mount",
                    "type=volume,destination=/dby-audit-log,volume-nocopy",
                    "ubuntu:24.04",
                    "/work/w1_open_flags_harness",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

        self.assertEqual(32, len(completed.stdout), completed.stderr)
        self.assertEqual((0, 0, 0, 0), struct.unpack("<qqqq", completed.stdout))

    def test_arm64_writer_and_python_parser_agree_on_atomic_record(self):
        if shutil.which("docker") is None:
            self.skipTest("Docker is unavailable for the ARM64 Linux harness")
        image = subprocess.run(
            ["docker", "image", "inspect", "ubuntu:24.04"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if image.returncode != 0:
            self.skipTest("local ubuntu:24.04 image is unavailable")

        from tests.test_parse_w1_witness import PROBE_SHA256, load_parser

        with tempfile.TemporaryDirectory() as task_dir_text:
            task_dir = Path(task_dir_text)
            harness = task_dir / "w1_record_harness.c"
            executable = task_dir / "w1_record_harness"
            harness.write_text(
                f'''\
#define DBY_W1_NONCE_HEX "{NONCE}"
#define DBY_W1_LIBRARY_TEST 1
#include "{SOURCE}"

__attribute__((noreturn, visibility("default"))) void _start(void) {{
    static const char marker[] =
        "6,10,20000,-;DBY_W1_USERSPACE_MARKER nonce={NONCE}\\n";
    dby_make_names();
    dby_append_field("FORMAT", "DBY-W09-W1", 10);
    dby_append_field("NONCE", nonce_hex, 32);
    dby_append_field("PID", "1", 1);
    dby_append_field("MOUNT_PROC", "0", 1);
    dby_append_field("MOUNT_SYS", "0", 1);
    dby_append_field("BOOT_ID", "12345678-1234-4abc-8def-1234567890ab\\n", 37);
    dby_append_field("SELF_SHA256_STATUS", "0", 1);
    dby_append_field("SELF_SHA256", "{PROBE_SHA256}", 64);
    dby_append_field("KMSG_MARKER_STATUS", "0", 1);
    dby_append_field("MKNOD_KMSG", "0", 1);
    dby_append_field("KMSG_MARKER_READER_OPEN", "3", 1);
    dby_append_field("KMSG_MARKER_SEEK_END", "0", 1);
    dby_append_field("KMSG_MARKER_WRITER_OPEN", "4", 1);
    dby_append_field("KMSG_MARKER_WRITE", "0", 1);
    dby_append_field("KMSG_MARKER_WRITER_CLOSE", "0", 1);
    dby_append_field("KMSG_MARKER_READER_CLOSE", "0", 1);
    dby_append_field("KMSG_MARKER_RECORD", marker, sizeof(marker) - 1);
    dby_append_field("KMSG_MARKER_PRIORITY", "6", 1);
    dby_append_field("KMSG_MARKER_SEQUENCE", "10", 2);
    dby_append_field("KMSG_MARKER_TIMESTAMP_US", "20000", 5);
    dby_append_field("KMSG_MARKER_VENDOR_PREFIXED", "0", 1);
    dby_append_field("LOG_DISCOVERY", "0", 1);
    dby_append_field("LOG_DEVNAME", "sda12", 5);
    dby_append_field(
        "LOG_EXPECTED_PARTUUID", "906d7124-62f7-d1c8-ffbf-73c97575983f", 36
    );
    dby_append_field("LOG_PARTUUID_EXPORTED", "0", 1);
    dby_append_field("LOG_MAJOR", "8", 1);
    dby_append_field("LOG_MINOR", "12", 2);
    dby_append_field("LOG_SECTORS_512", "163840", 6);
    dby_append_field("LOG_SUPERBLOCK_VERIFY", "0", 1);
    dby_append_field(
        "LOG_EXPECTED_FSUUID", "e3ff96a22fe448d28c2daef8d068275d", 32
    );
    dby_append_field("MOUNT_LOG", "0", 1);
    dby_append_field(
        "PUBLICATION_PROTOCOL",
        publication_protocol,
        sizeof(publication_protocol) - 1
    );
    dby_append_field("CLOCK_GETTIME_START", "0", 1);
    dby_append_field("MONOTONIC_START_NS", "10000000", 8);
    dby_append_field("CLOCK_GETTIME_END", "0", 1);
    dby_append_field("MONOTONIC_PREPUBLISH_NS", "30000000", 8);
    dby_append_field("KMSG_SNAPSHOT_TRUNCATED", "0", 1);
    isize publish_result = dby_publish_record(1 | 2 | 4 | 8 | 32 | 64 | 128);
    isize stream_result = 0;
    isize directory = dby_open(
        "/dby-audit-log",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
        0
    );
    if (directory < 0) {{
        stream_result = directory;
    }} else {{
        isize input = dby_openat(
            directory, final_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0
        );
        (void)dby_close(directory);
        if (input < 0) {{
            stream_result = input;
        }} else {{
            for (;;) {{
                isize length = dby_syscall3(
                    SYS_READ, input, (isize)file_buffer, sizeof(file_buffer)
                );
                if (length == -EINTR) {{
                    continue;
                }}
                if (length < 0) {{
                    stream_result = length;
                }}
                if (length <= 0) {{
                    break;
                }}
                stream_result = dby_write_all(1, file_buffer, (usize)length);
                if (stream_result < 0) {{
                    break;
                }}
            }}
            (void)dby_close(input);
        }}
    }}
    int exit_status = 0;
    if (stream_result < 0) {{
        exit_status = (int)(-stream_result & 0x7f);
    }} else if (publish_result < 0) {{
        exit_status = (int)(-publish_result & 0x7f);
    }}
    (void)dby_syscall1(SYS_EXIT, exit_status);
    for (;;) {{}}
}}
'''
            )
            object_path = task_dir / "w1_record_harness.o"
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
                    "-Wno-unused-function",
                    "-c",
                    str(harness),
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
                    "-o",
                    str(executable),
                    str(object_path),
                ],
                check=True,
            )
            completed = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "-v",
                    f"{task_dir}:/work:ro",
                    "--mount",
                    "type=volume,destination=/dby-audit-log,volume-nocopy",
                    "ubuntu:24.04",
                    "/work/w1_record_harness",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(
                0,
                completed.returncode,
                completed.stderr.decode("utf-8", errors="replace"),
            )

            report = load_parser().parse_record(
                completed.stdout,
                expected_nonce=NONCE,
                expected_probe_sha256=PROBE_SHA256,
                source_kind="direct",
                observed_endpoint="unknown",
            )
            self.assertTrue(report["outcome"]["witness_evidence_gate_pass"])
            self.assertFalse(report["outcome"]["experiment_evidence_pass"])

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
                f'-DDBY_W1_NONCE_HEX="{NONCE}"',
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

    def test_probe_sha256_matches_standard_vectors_on_arm64_linux(self):
        if shutil.which("docker") is None:
            self.skipTest("Docker is unavailable for the ARM64 Linux harness")
        image = subprocess.run(
            ["docker", "image", "inspect", "ubuntu:24.04"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if image.returncode != 0:
            self.skipTest("local ubuntu:24.04 image is unavailable")

        with tempfile.TemporaryDirectory() as task_dir_text:
            task_dir = Path(task_dir_text)
            harness = task_dir / "w1_sha_harness.c"
            executable = task_dir / "w1_sha_harness"
            harness.write_text(
                f'''\
#define DBY_W1_NONCE_HEX "{NONCE}"
#define DBY_W1_LIBRARY_TEST 1
#include "{SOURCE}"

static int digest_matches(const void *data, usize length, const u8 expected[32]) {{
    struct sha256_context context;
    u8 digest[32];
    dby_sha256_init(&context);
    dby_sha256_update(&context, data, length);
    dby_sha256_final(&context, digest);
    return dby_memequal(digest, expected, 32);
}}

__attribute__((noreturn, visibility("default"))) void _start(void) {{
    static const u8 empty_expected[32] = {{
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    }};
    static const u8 abc_expected[32] = {{
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    }};
    int ok = digest_matches("", 0, empty_expected) &&
             digest_matches("abc", 3, abc_expected);
    (void)dby_syscall1(SYS_EXIT, ok ? 0 : 1);
    for (;;) {{}}
}}
'''
            )
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
                    "-Wno-unused-function",
                    "-c",
                    str(harness),
                    "-o",
                    str(task_dir / "w1_sha_harness.o"),
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
                    "-o",
                    str(executable),
                    str(task_dir / "w1_sha_harness.o"),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "-v",
                    f"{task_dir}:/work:ro",
                    "ubuntu:24.04",
                    "/work/w1_sha_harness",
                ],
                check=True,
            )

    def test_probe_source_uses_strict_self_hash_and_publication_guards(self):
        source = SOURCE.read_text()

        self.assertIn("static isize dby_hash_self_exe(", source)
        self.assertIn("dby_hash_self_exe(self_digest)", source)
        self.assertNotIn('dby_hash_file("/proc/self/exe"', source)
        self.assertIn(
            'dby_append_field(\n'
            '        "PUBLICATION_PROTOCOL", publication_protocol,\n'
            '        dby_strlen(publication_protocol)\n'
            '    );',
            source,
        )
        self.assertIn("if (log_mount_result == 0)", source)
        self.assertIn("isize kmsg_node_result = dev_result == 0", source)
        self.assertIn("isize block_node_result = dev_result == 0", source)
        self.assertNotIn("if (kmsg_node_result == -EEXIST)", source)
        self.assertNotIn("if (block_node_result == -EEXIST)", source)

    @unittest.skipUnless(STOCK.is_file(), "set DBY_STOCK_RAMDISK to a private stock ramdisk")
    def test_probe_compiles_as_small_static_single_process_arm64_elf(self):
        self.assertTrue(SOURCE.exists(), f"missing W1 source: {SOURCE}")
        builder = load_builder()
        with tempfile.TemporaryDirectory() as task_dir:
            probe = compile_probe(Path(task_dir))

        layout = builder.validate_probe(probe, NONCE)
        self.assertLessEqual(len(probe), 64 * 1024)
        self.assertGreaterEqual(probe.count(NONCE.encode("ascii")), 1)
        self.assertNotIn(NONCE.encode("ascii"), STOCK.read_bytes())
        self.assertEqual(2, layout["elf_type"])
        self.assertGreater(layout["entrypoint"], 0)
        self.assertLessEqual(layout["load_memory_bytes"], 256 * 1024)
        self.assertFalse(layout["has_dynamic_segment"])
        self.assertFalse(layout["has_writable_executable_segment"])
        for marker in (
            b"DBYW1REC",
            NONCE.encode(),
            b"/proc/sys/kernel/random/boot_id",
            b"/proc/self/exe",
            b"/sys/class/block/",
            b"PARTNAME=log",
            b"/dby-audit-log",
            b".dby-normal-witness-",
            b"dby-normal-witness-",
            b"edl",
        ):
            self.assertIn(marker, probe)
        self.assertNotIn(b"/init.stock", probe)
        self.assertNotIn(b"/metadata", probe)

        source = SOURCE.read_text()
        for required in (
            "SYS_RENAMEAT2 = 276",
            "RENAME_NOREPLACE = 1",
            "O_EXCL",
            "O_NOFOLLOW",
            "SYS_FSYNC = 82",
            "SYS_UMOUNT2 = 39",
            "LINUX_REBOOT_CMD_RESTART2",
            "MAX_PAYLOAD = 128 * 1024",
            "SEEK_END",
            "O_DIRECTORY = 040000",
            "O_NOFOLLOW = 0100000",
        ):
            self.assertIn(required, source)
        self.assertNotIn("SYS_CLONE", source)
        self.assertNotIn("SYS_EXECVE", source)

    @unittest.skipUnless(STOCK.is_file(), "set DBY_STOCK_RAMDISK to a private stock ramdisk")
    def test_builder_preserves_stock_tail_and_binds_nonce_to_probe(self):
        self.assertTrue(SOURCE.exists(), f"missing W1 source: {SOURCE}")
        builder = load_builder()
        with tempfile.TemporaryDirectory() as task_dir:
            probe = compile_probe(Path(task_dir))

        output, report = builder.build_w1(STOCK.read_bytes(), probe, NONCE)

        self.assertEqual(2_097_152, len(output))
        self.assertEqual(NONCE, report["nonce"])
        self.assertEqual(builder.sha256(probe), report["probe_sha256"])
        self.assertEqual("ET_EXEC", report["probe_elf_type"])
        self.assertLessEqual(report["probe_load_memory_bytes"], 256 * 1024)
        self.assertEqual(builder.sha256(output), report["output_sha256"])
        self.assertTrue(report["avb_tail_preserved"])
        self.assertEqual(0, report["embedded_vbmeta_flags"])
        self.assertEqual(report["avb_offset"] + 120, report["embedded_vbmeta_flags_offset"])
        self.assertFalse(report["executes_stock_init"])
        self.assertFalse(report["executes_lineage_init"])
        self.assertEqual("/log", report["qualified_sink_mountpoint"])
        self.assertEqual("RESTART2(edl)", report["software_return_request"])

        entries = builder.extract_entries(output)
        by_name = {entry.name: entry for entry in entries}
        self.assertEqual(probe, by_name["init"].data)
        self.assertNotEqual(0, by_name["init"].fields[1] & 0o111)
        self.assertEqual(by_name["init"].fields[1], by_name["init.stock"].fields[1])
        self.assertIn("init.stock", by_name)
        self.assertNotIn(b"/init.stock", by_name["init"].data)

    def test_builder_rejects_invalid_nonce(self):
        self.assertTrue(SOURCE.exists(), f"missing W1 source: {SOURCE}")
        builder = load_builder()
        with self.assertRaisesRegex(ValueError, "32 lowercase hexadecimal"):
            builder.validate_nonce("not-a-128-bit-nonce")

    def test_probe_must_be_et_exec_not_pie(self):
        builder = load_builder()
        with tempfile.TemporaryDirectory() as task_dir:
            probe = bytearray(compile_probe(Path(task_dir)))
        struct.pack_into("<H", probe, 16, 3)

        with self.assertRaisesRegex(ValueError, "ET_EXEC"):
            builder.validate_probe(bytes(probe), NONCE)


if __name__ == "__main__":
    unittest.main()
