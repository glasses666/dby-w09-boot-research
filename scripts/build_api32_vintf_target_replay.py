#!/usr/bin/env python3
"""Build a hash-bound target-API32 libvintf differential replay harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "analysis/firmware-20261014/api32-target-libvintf-replay-offline-20261028"
CONTROL_SYSTEM = (
    ROOT
    / "analysis/firmware-20261014/api32-diagnostic-adb-offline-20261027/build-a/system-api32-diagnostic-adb-NOT-FLASHED.ext4"
)
CANDIDATE_SYSTEM = (
    ROOT
    / "analysis/firmware-20261014/api32-system-framework-gnss-offline-20261028/build-a/system-api32-system-framework-gnss-NOT-FLASHED.ext4"
)
CONTROL_SYSTEM_SHA256 = "451cc674329a8b18246136d19b929b043a8549c2ca89e7a6dd9b7235604857ea"
CANDIDATE_SYSTEM_SHA256 = "0d1bdf7e1116ce07b6923f3157f76c6555fd33cfce5082ee2a883706c186a54a"
EXPECTED_SYSTEM_SIZE = 2_513_813_504
CONTROL_MANIFEST_SHA256 = "e5fb162ac9b27f130f8a7a09c1a908a6727cc00ea32b20036a0d7253e45ed040"
CANDIDATE_MANIFEST_SHA256 = "3705d4036e7e87afe2c2ab800e709df105e942994d906c8b5e6d57b76438a0f7"
OFFICIAL_SOURCE_TAG = "android-12.1.0_r11"
OFFICIAL_SOURCE_URL = (
    "https://android.googlesource.com/platform/system/libvintf/+archive/"
    "refs/tags/android-12.1.0_r11.tar.gz"
)
OFFICIAL_SOURCE_TREE_SHA256 = "228fbe1d204b13a81100942b09431f4908599171a8e58c7da2bc6c52af099f70"
DEFAULT_SOURCE_ARCHIVE = BASE / "inputs/android-12.1.0_r11-libvintf.tar.gz"
STOCK_ROOT = (
    ROOT
    / "analysis/firmware-20261014/w4-platform-compat-20261018/elf-abi/.stock-extract.RyNR02"
)
DEBUGFS = Path("/opt/homebrew/opt/e2fsprogs/sbin/debugfs")
CLANGXX = Path(
    "/opt/homebrew/share/android-ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin/"
    "aarch64-linux-android32-clang++"
)
LLVM_READELF = Path(
    "/opt/homebrew/share/android-ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf"
)
NDK_PREBUILT = CLANGXX.parents[1]
NDK_LIBCPP_HEADERS = NDK_PREBUILT / "sysroot/usr/include/c++/v1"
NDK_LIBCPP_CONFIG_SITE = NDK_LIBCPP_HEADERS / "__config_site"

RUNTIME_LINKER_SOURCE = "/system/system_ext/apex/com.android.runtime/bin/linker64"
RUNTIME_LINKER_SHA256 = "28b296b86ce81863d7d4f7ee81e1bbef475b73ffc17b1801f1652dbfbd24f358"
RUNTIME_LIBRARY_SOURCES = {
    "ld-android.so": "/system/lib64/ld-android.so",
    "libbase.so": "/system/lib64/libbase.so",
    "libc++.so": "/system/lib64/libc++.so",
    "libc.so": "/system/system_ext/apex/com.android.runtime/lib64/bionic/libc.so",
    "libdl.so": "/system/system_ext/apex/com.android.runtime/lib64/bionic/libdl.so",
    "libhidl-gen-utils.so": "/system/lib64/libhidl-gen-utils.so",
    "liblog.so": "/system/lib64/liblog.so",
    "libm.so": "/system/system_ext/apex/com.android.runtime/lib64/bionic/libm.so",
    "libpackagelistparser.so": "/system/lib64/libpackagelistparser.so",
    "libpcre2.so": "/system/lib64/libpcre2.so",
    "libselinux.so": "/system/lib64/libselinux.so",
    "libtinyxml2.so": "/system/lib64/libtinyxml2.so",
    "libvintf.so": "/system/lib64/libvintf.so",
    "libz.so": "/system/lib64/libz.so",
}
RUNTIME_LIBRARY_HASHES = {
    "ld-android.so": "3be279f8ebd077f25477f57ec0b6ded9e072e4cb6d0e5002ed2d2a233bfec843",
    "libbase.so": "a079a1f5529e2ffe84496ff812d8f80ccce3e0a12e9deff1a386503372272989",
    "libc++.so": "c38a57de7b44bccc27bdffd58de033edcc5584c116fc303ec62e80416e9b2d7a",
    "libc.so": "5593964ea5dae3f37e9831b719178387cbb54bf2a62c13cc2a464a4e07e12eda",
    "libdl.so": "cab54511650fc5f56e35b0b3fc345a7d88bf293b94ba5ef3ee384eac43d56924",
    "libhidl-gen-utils.so": "6c8352031f77aa4fe94a931335b03d0c7a9ff528dbe01968235ea227857c08d3",
    "liblog.so": "8ea50e446444ec65e13c18536aa2f828ab90ebbbdb0002bfbcdf90193519b7c1",
    "libm.so": "021563c4554561098e8d97d8dc297bcc64ce7e141f7384e1550dc1d1fafc6e98",
    "libpackagelistparser.so": "765d6a7c2e015277914689de669b3a61626291a18ba16ba3a1364201aae62bac",
    "libpcre2.so": "96d8e0a9344d65fb1af4a6750a315dec8f838a46a00a044f96b646ec5dedd642",
    "libselinux.so": "32768f01708b70ee859958510957e552d73049dc25611d606e8d7dea8f60809f",
    "libtinyxml2.so": "41520c17a9ccee05654868d9eacbaa6205799fd8445162cc37b63b800c7744e4",
    "libvintf.so": "4122bc5bac1319dabec128a3cdfd39b65cd51e30977f20051975a9ea1396db6d",
    "libz.so": "d9ca6c1fee5aea4f9c03f1b41d483db47011ceed908222941b9e8aa3d9b0984a",
}
SYSTEM_VINTF_ROOTS = (
    "/system/etc/vintf",
    "/system/product/etc/vintf",
    "/system/system_ext/etc/vintf",
)
AUTHORIZED_DIFFERENCE = "system/etc/vintf/manifest.xml"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def source_tree_sha256(path: Path) -> str:
    records = []
    with tarfile.open(path, "r:*") as bundle:
        for member in sorted(bundle.getmembers(), key=lambda item: item.name):
            if member.isfile():
                stream = bundle.extractfile(member)
                if stream is None:
                    raise ValueError(f"cannot read source archive member: {member.name}")
                payload = stream.read()
                records.append(
                    {
                        "path": member.name,
                        "kind": "file",
                        "mode": member.mode & 0o777,
                        "size": len(payload),
                        "sha256": sha256_bytes(payload),
                    }
                )
            elif member.issym() or member.islnk():
                records.append(
                    {"path": member.name, "kind": "link", "target": member.linkname}
                )
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(encoded)


def normalize_compile_command(command: list[str], staging_root: Path) -> list[str]:
    """Record a rebuild recipe without a random temporary directory."""
    prefix = str(staging_root)
    return [str(argument).replace(prefix, "$HARNESS") for argument in command]


def libcpp_config_site() -> str:
    config = NDK_LIBCPP_CONFIG_SITE.read_text()
    config = config.replace(
        "#define _LIBCPP_ABI_NAMESPACE __ndk1",
        "#define _LIBCPP_ABI_NAMESPACE __1",
    )
    marker = "#define _LIBCPP_ABI_NAMESPACE __1\n"
    config = config.replace(marker, marker + "#define _LIBCPP_NO_ABI_TAG 1\n", 1)
    return config


def run_debugfs(image: Path, command: str, *, missing_ok: bool = False) -> str:
    completed = subprocess.run(
        [str(DEBUGFS), "-R", command, str(image)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    output = (completed.stdout + completed.stderr).decode(errors="replace")
    missing = "File not found" in output or "not found" in output.lower()
    if completed.returncode != 0 or (missing and not missing_ok):
        raise RuntimeError(f"debugfs {command!r} failed: {output.strip()}")
    return "" if missing else output


def debugfs_entries(listing: str) -> list[tuple[str, str]]:
    entries = []
    for line in listing.splitlines():
        if not line.startswith("/"):
            continue
        fields = line.split("/")
        if len(fields) < 7:
            continue
        mode, name = fields[2], fields[5]
        if name in {".", ".."}:
            continue
        kind = "directory" if mode.startswith("04") else "symlink" if mode.startswith("12") else "file"
        entries.append((name, kind))
    return sorted(entries)


def dump_file(image: Path, virtual_path: str, output: Path, mode: int = 0o644) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    run_debugfs(image, f"dump -p {virtual_path} {output}")
    output.chmod(mode)


def dump_tree(image: Path, virtual_root: str, output_root: Path) -> None:
    listing = run_debugfs(image, f"ls -p {virtual_root}", missing_ok=True)
    if not listing:
        return
    output_root.mkdir(parents=True, exist_ok=True)
    for name, kind in debugfs_entries(listing):
        source = f"{virtual_root.rstrip('/')}/{name}"
        target = output_root / name
        if kind == "directory":
            dump_tree(image, source, target)
        elif kind == "file":
            dump_file(image, source, target)
        else:
            # VINTF inputs should not need symlink payloads; reject rather than silently flatten.
            raise ValueError(f"unexpected symlink inside VINTF input: {source}")


def tree_files(root: Path) -> dict[str, dict[str, object]]:
    records = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            relative = str(path.relative_to(root))
            records[relative] = {
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    return records


def compare_views(control: Path, candidate: Path) -> dict[str, object]:
    control_files = tree_files(control)
    candidate_files = tree_files(candidate)
    changed = sorted(
        path
        for path in set(control_files) | set(candidate_files)
        if control_files.get(path) != candidate_files.get(path)
    )
    return {
        "changed_paths": changed,
        "single_authorized_difference": changed == [AUTHORIZED_DIFFERENCE],
        "control_file_count": len(control_files),
        "candidate_file_count": len(candidate_files),
    }


def framework_gnss_versions(payload: bytes) -> list[str]:
    root = ET.fromstring(payload.rstrip())
    for hal in root.findall("hal"):
        if hal.findtext("name") == "android.hardware.gnss":
            return [item.text or "" for item in hal.findall("version")]
    return []


def build_source_derived_correction(candidate: Path, corrected: Path) -> dict[str, object]:
    """Keep only the highest GNSS minor while preserving the manifest byte length."""
    shutil.copytree(candidate, corrected)
    manifest = corrected / AUTHORIZED_DIFFERENCE
    before = manifest.read_bytes()
    first = b"<version>1.0</version>"
    second = b"<version>1.1</version>"
    needle = first + second
    if before.count(needle) != 1:
        raise ValueError("candidate does not contain the exact two-minor GNSS sequence")
    after = before.replace(needle, second + (b" " * len(first)), 1)
    if len(after) != len(before):
        raise AssertionError("source-derived correction changed manifest length")
    manifest.write_bytes(after)
    comparison = compare_views(candidate, corrected)
    if comparison["changed_paths"] != [AUTHORIZED_DIFFERENCE]:
        raise ValueError("source-derived correction changed files outside the main manifest")
    return {
        **comparison,
        "rule": "one HIDL version per major; retain highest minor",
        "before_versions": framework_gnss_versions(before),
        "after_versions": framework_gnss_versions(after),
        "before_sha256": sha256_bytes(before),
        "after_sha256": sha256_bytes(after),
        "byte_length_preserved": len(before) == len(after),
    }


def query_source() -> str:
    return r'''// ABI declarations verified against AOSP android-12.1.0_r11.
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace std { inline namespace __1 {
[[noreturn]] void __libcpp_verbose_abort(char const*, ...) noexcept { ::abort(); }
} }

namespace android {
using status_t = int32_t;
constexpr status_t OK = 0;
constexpr status_t NAME_NOT_FOUND = -2;
constexpr status_t BAD_VALUE = -22;

namespace vintf {
struct Version {
    constexpr Version(size_t major = 0, size_t minor = 0) : majorVer(major), minorVer(minor) {}
    size_t majorVer;
    size_t minorVer;
};
enum class Transport : size_t { EMPTY = 0, PASSTHROUGH, HWBINDER };

class FileSystem {
  public:
    virtual ~FileSystem() {}
    virtual status_t fetch(const std::string&, std::string*, std::string*) const = 0;
    virtual status_t listFiles(const std::string&, std::vector<std::string>*, std::string*) const = 0;
};
class PropertyFetcher {
  public:
    virtual ~PropertyFetcher() = default;
    virtual std::string getProperty(const std::string&, const std::string& = "") const = 0;
    virtual uint64_t getUintProperty(const std::string&, uint64_t, uint64_t = UINT64_MAX) const = 0;
    virtual bool getBoolProperty(const std::string&, bool) const = 0;
};
class HalManifest {
  public:
    bool hasHidlInstance(const std::string&, const Version&, const std::string&, const std::string&) const;
    bool hasAidlInstance(const std::string&, const std::string&, const std::string&) const;
    Transport getHidlTransport(const std::string&, const Version&, const std::string&, const std::string&) const;
};
namespace SerializeFlags {
class Type {
  public:
    explicit constexpr Type(uint32_t value) : value_(value) {}
  private:
    uint32_t value_;
};
constexpr Type EVERYTHING = Type(~0u);
}
std::string toXml(const HalManifest&, SerializeFlags::Type = SerializeFlags::EVERYTHING);

class VintfObject {
  public:
    virtual ~VintfObject() = default;
    virtual std::shared_ptr<const HalManifest> getDeviceHalManifest();
    virtual std::shared_ptr<const HalManifest> getFrameworkHalManifest();
    class Builder {
      public:
        Builder();
        Builder& setFileSystem(std::unique_ptr<FileSystem>&&);
        Builder& setPropertyFetcher(std::unique_ptr<PropertyFetcher>&&);
        std::unique_ptr<VintfObject> build();
      private:
        std::unique_ptr<VintfObject> object_;
    };
};
}
}

using android::status_t;
using namespace android::vintf;

static std::string escapeJson(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) {
                    const char* hex = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(hex[(ch >> 4) & 15]);
                    out.push_back(hex[ch & 15]);
                } else {
                    out.push_back(static_cast<char>(ch));
                }
        }
    }
    return out;
}

struct AccessEvent {
    std::string operation;
    std::string path;
    int status;
    size_t size;
    std::string detail;
};

class RootedFileSystem final : public FileSystem {
  public:
    explicit RootedFileSystem(std::string root) : root_(std::move(root)) {
        while (root_.size() > 1 && root_.back() == '/') root_.pop_back();
    }
    status_t fetch(const std::string& path, std::string* fetched, std::string* error) const override {
        if (!safe(path)) return android::BAD_VALUE;
        std::string real = root_ + path;
        int fd = ::open(real.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            int saved = errno ? errno : ENOENT;
            if (error) *error = "Cannot read " + path;
            events.push_back({"fetch", path, -saved, 0, strerror(saved)});
            return -saved;
        }
        fetched->clear();
        char buffer[8192];
        for (;;) {
            ssize_t count = ::read(fd, buffer, sizeof(buffer));
            if (count == 0) break;
            if (count < 0) {
                int saved = errno ? errno : EIO;
                ::close(fd);
                if (error) *error = "Cannot read " + path;
                events.push_back({"fetch", path, -saved, fetched->size(), strerror(saved)});
                return -saved;
            }
            fetched->append(buffer, static_cast<size_t>(count));
        }
        ::close(fd);
        events.push_back({"fetch", path, android::OK, fetched->size(), ""});
        return android::OK;
    }
    status_t listFiles(const std::string& path, std::vector<std::string>* out,
                       std::string* error) const override {
        if (!safe(path)) return android::BAD_VALUE;
        DIR* dir = opendir((root_ + path).c_str());
        if (!dir) {
            int saved = errno ? errno : ENOENT;
            if (error) *error = "Cannot open " + path;
            events.push_back({"list", path, -saved, 0, strerror(saved)});
            return -saved;
        }
        errno = 0;
        while (dirent* entry = readdir(dir)) {
            if (entry->d_type != DT_DIR && std::string(entry->d_name) != "." &&
                std::string(entry->d_name) != "..") {
                out->push_back(entry->d_name);
            }
        }
        int saved = errno;
        closedir(dir);
        std::sort(out->begin(), out->end());
        events.push_back({"list", path, saved ? -saved : android::OK, out->size(), ""});
        return saved ? -saved : android::OK;
    }
    mutable std::vector<AccessEvent> events;
  private:
    bool safe(const std::string& path) const {
        return !path.empty() && path.front() == '/' && path.find("..") == std::string::npos;
    }
    std::string root_;
};

struct PropertyEvent { std::string key; std::string value; };
class FixedProperties final : public PropertyFetcher {
  public:
    FixedProperties() {
        values_["ro.boot.product.hardware.sku"] = "DBY-W09";
        values_["ro.boot.product.vendor.sku"] = "";
        values_["ro.product.first_api_level"] = "29";
        values_["ro.vendor.build.version.sdk"] = "29";
        values_["ro.vndk.version"] = "29";
    }
    std::string getProperty(const std::string& key, const std::string& fallback) const override {
        auto found = values_.find(key);
        std::string value = found == values_.end() ? fallback : found->second;
        events.push_back({key, value});
        return value;
    }
    uint64_t getUintProperty(const std::string& key, uint64_t fallback, uint64_t max) const override {
        std::string value = getProperty(key, "");
        if (value.empty()) return fallback;
        char* end = nullptr;
        unsigned long long parsed = strtoull(value.c_str(), &end, 10);
        return end && *end == '\0' ? std::min<uint64_t>(parsed, max) : fallback;
    }
    bool getBoolProperty(const std::string& key, bool fallback) const override {
        std::string value = getProperty(key, "");
        if (value == "1" || value == "true" || value == "y" || value == "yes" || value == "on") return true;
        if (value == "0" || value == "false" || value == "n" || value == "no" || value == "off") return false;
        return fallback;
    }
    mutable std::vector<PropertyEvent> events;
  private:
    std::map<std::string, std::string> values_;
};

static const char* transportName(Transport value) {
    switch (value) {
        case Transport::PASSTHROUGH: return "passthrough";
        case Transport::HWBINDER: return "hwbinder";
        default: return "";
    }
}

static void appendEvents(std::string* out, const std::vector<AccessEvent>& events) {
    *out += "\"access_events\":[";
    for (size_t i = 0; i < events.size(); ++i) {
        if (i) *out += ',';
        const auto& e = events[i];
        *out += "{\"operation\":\"" + escapeJson(e.operation)
             + "\",\"path\":\"" + escapeJson(e.path)
             + "\",\"status\":" + std::to_string(e.status)
             + ",\"size\":" + std::to_string(e.size)
             + ",\"detail\":\"" + escapeJson(e.detail) + "\"}";
    }
    *out += ']';
}

static void appendProperties(std::string* out, const std::vector<PropertyEvent>& events) {
    *out += "\"property_events\":[";
    for (size_t i = 0; i < events.size(); ++i) {
        if (i) *out += ',';
        *out += "{\"key\":\"" + escapeJson(events[i].key)
             + "\",\"value\":\"" + escapeJson(events[i].value) + "\"}";
    }
    *out += ']';
}

int main(int argc, char** argv) {
    if (argc != 2) {
        static const char usage[] = "usage: dby-vintf-replay ROOT\n";
        ::write(STDERR_FILENO, usage, sizeof(usage) - 1);
        return 64;
    }
    auto fs = std::make_unique<RootedFileSystem>(argv[1]);
    auto properties = std::make_unique<FixedProperties>();
    auto* fs_ptr = fs.get();
    auto* properties_ptr = properties.get();
    VintfObject::Builder builder;
    builder.setFileSystem(std::move(fs));
    builder.setPropertyFetcher(std::move(properties));
    auto object = builder.build();
    auto device = object->getDeviceHalManifest();
    auto framework = object->getFrameworkHalManifest();

    std::string device_xml = device ? toXml(*device) : "";
    std::string framework_xml = framework ? toXml(*framework) : "";
    auto query = [](bool value) { return value ? std::string("true") : std::string("false"); };
    bool framework_keystore = framework && framework->hasAidlInstance(
        "android.system.keystore2", "IKeystoreService", "default");
    bool framework_suspend = framework && framework->hasHidlInstance(
        "android.system.suspend", Version{1, 0}, "ISystemSuspend", "default");
    bool framework_gnss_10 = framework && framework->hasHidlInstance(
        "android.hardware.gnss", Version{1, 0}, "IGnss", "default");
    bool framework_gnss_11 = framework && framework->hasHidlInstance(
        "android.hardware.gnss", Version{1, 1}, "IGnss", "default");
    bool device_keystore = device && device->hasAidlInstance(
        "android.system.keystore2", "IKeystoreService", "default");
    bool device_suspend = device && device->hasHidlInstance(
        "android.system.suspend", Version{1, 0}, "ISystemSuspend", "default");

    std::string output = "{\"schema\":\"dby-w09-api32-target-libvintf-replay-v1\",";
    output += "\"input_root\":\"" + escapeJson(argv[1]) + "\",";
    output += "\"framework\":{\"status\":\"" + std::string(framework ? "ok" : "null")
           + "\",\"xml\":\"" + escapeJson(framework_xml) + "\"},";
    output += "\"device\":{\"status\":\"" + std::string(device ? "ok" : "null")
           + "\",\"xml\":\"" + escapeJson(device_xml) + "\"},";
    output += "\"queries\":{";
    output += "\"framework_keystore_aidl\":" + query(framework_keystore) + ',';
    output += "\"framework_suspend_hidl\":" + query(framework_suspend) + ',';
    output += "\"framework_suspend_transport\":\"";
    output += framework ? transportName(framework->getHidlTransport(
        "android.system.suspend", Version{1, 0}, "ISystemSuspend", "default")) : "";
    output += "\",\"framework_gnss_1_0\":" + query(framework_gnss_10) + ',';
    output += "\"framework_gnss_1_1\":" + query(framework_gnss_11) + ',';
    output += "\"device_keystore_aidl\":" + query(device_keystore) + ',';
    output += "\"device_suspend_hidl\":" + query(device_suspend) + "},";
    appendEvents(&output, fs_ptr->events);
    output += ',';
    appendProperties(&output, properties_ptr->events);
    output += "}\n";
    const char* data = output.data();
    size_t remaining = output.size();
    while (remaining) {
        ssize_t written = ::write(STDOUT_FILENO, data, remaining);
        if (written < 0) return 74;
        data += written;
        remaining -= static_cast<size_t>(written);
    }
    return framework && device ? 0 : 2;
}
'''


def runner_script() -> str:
    return """#!/bin/sh
set -eu
uname -m > /evidence/uname-m.txt
set +e
/system/bin/linker64 --list /system/bin/dby-vintf-replay > /evidence/linker-list.txt 2> /evidence/linker-list.stderr.txt
linker_list_exit=$?
/system/bin/dby-vintf-replay /control > /evidence/control.json 2> /evidence/control.stderr.txt
control_exit=$?
/system/bin/dby-vintf-replay /candidate > /evidence/candidate.json 2> /evidence/candidate.stderr.txt
candidate_exit=$?
/system/bin/dby-vintf-replay /corrected > /evidence/corrected.json 2> /evidence/corrected.stderr.txt
corrected_exit=$?
set -e
printf '%s\n' "$linker_list_exit" > /evidence/linker-list.exit.txt
printf '%s\n' "$control_exit" > /evidence/control.exit.txt
printf '%s\n' "$candidate_exit" > /evidence/candidate.exit.txt
printf '%s\n' "$corrected_exit" > /evidence/corrected.exit.txt
exit 0
"""


def copy_stock_inputs(view: Path) -> None:
    for partition in ("vendor", "odm"):
        source = STOCK_ROOT / partition / "etc/vintf"
        if not source.is_dir():
            raise FileNotFoundError(source)
        target = view / partition / "etc/vintf"
        shutil.copytree(source, target, symlinks=True)
    for relative in (
        "vendor/manifest.xml",
        "vendor/compatibility_matrix.xml",
        "odm/etc/manifest.xml",
    ):
        source = STOCK_ROOT / relative
        if source.is_file():
            target = view / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def materialize_android_aliases(view: Path) -> None:
    """Create portable directory aliases without Windows-host symlinks."""
    for alias, source in (
        ("product", "system/product"),
        ("system_ext", "system/system_ext"),
    ):
        source_path = view / source
        if source_path.is_dir():
            shutil.copytree(source_path, view / alias)
        else:
            (view / alias).mkdir()


def build_view(image: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    for virtual_root in SYSTEM_VINTF_ROOTS:
        dump_tree(image, virtual_root, output / virtual_root.lstrip("/"))
    copy_stock_inputs(output)
    materialize_android_aliases(output)


def extract_runtime(image: Path, runtime: Path) -> list[dict[str, object]]:
    records = []
    linker = runtime / "system/bin/linker64"
    dump_file(image, RUNTIME_LINKER_SOURCE, linker, 0o755)
    if sha256_file(linker) != RUNTIME_LINKER_SHA256:
        raise ValueError("target linker identity changed")
    records.append({"path": "/system/bin/linker64", "size": linker.stat().st_size, "sha256": sha256_file(linker)})
    for name, source in RUNTIME_LIBRARY_SOURCES.items():
        target = runtime / "system/lib64" / name
        dump_file(image, source, target)
        actual = sha256_file(target)
        if actual != RUNTIME_LIBRARY_HASHES[name]:
            raise ValueError(f"target runtime identity changed: {name}")
        records.append({"path": f"/system/lib64/{name}", "size": target.stat().st_size, "sha256": actual})
    return records


def compile_query(runtime: Path, source_path: Path) -> dict[str, object]:
    output = runtime / "system/bin/dby-vintf-replay"
    library = runtime / "system/lib64"
    overlay = source_path.parent / "libcpp-overlay"
    overlay.mkdir()
    (overlay / "__config_site").write_text(libcpp_config_site())
    command = [
        str(CLANGXX),
        "-std=c++17",
        "-O2",
        "-fno-exceptions",
        "-fno-rtti",
        "-nostdlib++",
        "-nostdinc++",
        "-isystem",
        str(overlay),
        "-isystem",
        str(NDK_LIBCPP_HEADERS),
        str(source_path),
        f"-L{library}",
        f"-Wl,-rpath-link,{library}",
        "-Wl,--dynamic-linker,/system/bin/linker64",
        "-Wl,-rpath,/system/lib64",
        "-Wl,--build-id=sha1",
        "-Wl,--allow-shlib-undefined",
        "-lvintf",
        "-lc++",
        "-o",
        str(output),
    ]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"target query compile failed:\n{completed.stdout}\n{completed.stderr}")
    output.chmod(0o755)
    dynamic = subprocess.run(
        [str(LLVM_READELF), "-d", str(output)],
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    ).stdout
    return {
        "path": "/system/bin/dby-vintf-replay",
        "size": output.stat().st_size,
        "sha256": sha256_file(output),
        "compiler": subprocess.run([str(CLANGXX), "--version"], text=True, capture_output=True, check=True).stdout.splitlines()[0],
        "command": normalize_compile_command(command, source_path.parents[1]),
        "dynamic": dynamic,
    }


def tree_record(root: Path) -> dict[str, object]:
    files = []
    symlinks = []
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            symlinks.append({"path": relative, "target": str(path.readlink())})
        elif path.is_file():
            files.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    canonical = json.dumps({"files": files, "symlinks": symlinks}, sort_keys=True, separators=(",", ":")).encode()
    return {
        "file_count": len(files),
        "symlink_count": len(symlinks),
        "total_size": sum(item["size"] for item in files),
        "tree_sha256": sha256_bytes(canonical),
        "files": files,
        "symlinks": symlinks,
    }


def verify_input(path: Path, expected_hash: str) -> dict[str, object]:
    record = {"path": str(path.relative_to(ROOT)), "size": path.stat().st_size, "sha256": sha256_file(path)}
    if record["size"] != EXPECTED_SYSTEM_SIZE or record["sha256"] != expected_hash:
        raise ValueError(f"frozen system identity changed: {record}")
    return record


def build(output: Path, source_archive: Path) -> dict[str, object]:
    if output.exists():
        raise FileExistsError(output)
    if not DEBUGFS.is_file() or not CLANGXX.is_file() or not LLVM_READELF.is_file():
        raise FileNotFoundError("required exact local tool path is missing")
    control_record = verify_input(CONTROL_SYSTEM, CONTROL_SYSTEM_SHA256)
    candidate_record = verify_input(CANDIDATE_SYSTEM, CANDIDATE_SYSTEM_SHA256)
    source_archive_sha256 = sha256_file(source_archive)
    source_tree_identity = source_tree_sha256(source_archive)
    if source_tree_identity != OFFICIAL_SOURCE_TREE_SHA256:
        raise ValueError("official libvintf source tree identity changed")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.", dir=output.parent) as temporary:
        staging = Path(temporary) / output.name
        runtime = staging / "runtime"
        runtime_records = extract_runtime(CANDIDATE_SYSTEM, runtime)
        source_dir = staging / "source"
        source_dir.mkdir(parents=True)
        source_path = source_dir / "dby_vintf_replay.cpp"
        source_path.write_text(query_source())
        query_record = compile_query(runtime, source_path)

        control_view = staging / "control"
        candidate_view = staging / "candidate"
        build_view(CONTROL_SYSTEM, control_view)
        build_view(CANDIDATE_SYSTEM, candidate_view)
        comparison = compare_views(control_view, candidate_view)
        if not comparison["single_authorized_difference"]:
            raise ValueError(f"VINTF view drift exceeds the authorized manifest: {comparison}")
        if sha256_file(control_view / AUTHORIZED_DIFFERENCE) != CONTROL_MANIFEST_SHA256:
            raise ValueError("control manifest identity changed")
        if sha256_file(candidate_view / AUTHORIZED_DIFFERENCE) != CANDIDATE_MANIFEST_SHA256:
            raise ValueError("candidate manifest identity changed")
        corrected_view = staging / "corrected"
        correction = build_source_derived_correction(candidate_view, corrected_view)

        runner = staging / "run-target-replay.sh"
        runner.write_text(runner_script())
        runner.chmod(0o755)
        tree = tree_record(staging)
        manifest = {
            "schema": "dby-w09-api32-target-libvintf-harness-v1",
            "status": "offline-harness-built-not-executed",
            "device_io_performed": False,
            "source_tag": {
                "tag": OFFICIAL_SOURCE_TAG,
                "url": OFFICIAL_SOURCE_URL,
                "archive_path": str(source_archive.relative_to(ROOT)),
                "archive_sha256": source_archive_sha256,
                "tree_sha256": source_tree_identity,
            },
            "control_system": control_record,
            "candidate_system": candidate_record,
            "view_comparison": comparison,
            "source_derived_correction": correction,
            "properties": {
                "ro.boot.product.hardware.sku": "DBY-W09",
                "ro.boot.product.vendor.sku": "",
                "ro.product.first_api_level": "29",
                "ro.vendor.build.version.sdk": "29",
                "ro.vndk.version": "29",
            },
            "runtime": {
                "linker_sha256": RUNTIME_LINKER_SHA256,
                "objects": runtime_records,
                "query": query_record,
            },
            "execution_contract": {
                "platform": "linux/arm64",
                "network": "none",
                "rootfs": "read-only",
                "fresh_processes": ["control", "candidate", "corrected"],
                "writable_paths": ["/evidence"],
                "device_access": False,
            },
            "tree": tree,
        }
        (staging / "HARNESS_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        staging.rename(output)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, default=DEFAULT_SOURCE_ARCHIVE)
    args = parser.parse_args()
    report = build(args.output.resolve(), args.source_archive.resolve())
    print(f"tree_sha256={report['tree']['tree_sha256']} query_sha256={report['runtime']['query']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
