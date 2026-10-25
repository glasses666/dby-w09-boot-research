/*
 * DBY-W09 W2: observe a Lineage second-stage-only property-service event.
 *
 * PID 1 clones one bounded witness child with CLONE_FS and then execs the
 * retained stock first-stage init.  Sharing fs_struct is required so the
 * child follows FirstStageMain's chdir/chroot root switch instead of remaining
 * trapped in the old ramdisk root.  The child does not claim success merely
 * because PID 1
 * becomes /system/bin/init.  It requires the fresh property_service socket,
 * an exact pre-policy /proc/1/exe SHA-256 match to the selected Lineage init,
 * a fresh boot ID, and a property_service connection whose SO_PEERCRED PID is
 * 1.  It waits for Android's own fs trigger to mount the qualified log
 * filesystem, publishes one new checksummed file there, and asks the kernel
 * to return to EDL.  It never mounts, repairs, or unmounts a filesystem.
 */

#ifndef DBY_W2_NONCE_HEX
#error "DBY_W2_NONCE_HEX must be a quoted 32-character lowercase hex string"
#endif

#ifndef DBY_W2_EXPECTED_LINEAGE_INIT_SHA256
#error "DBY_W2_EXPECTED_LINEAGE_INIT_SHA256 must be a quoted SHA-256"
#endif

#define DBY_W1_NONCE_HEX DBY_W2_NONCE_HEX
#define DBY_WITNESS_MARKER_PREFIX \
    "DBY_W2_LINEAGE_SECOND_STAGE_MARKER nonce="
#define DBY_PUBLICATION_PROTOCOL \
    "O_EXCL fsync(file) renameat2(RENAME_NOREPLACE) fsync(dir) syncfs"
#define DBY_W1_LIBRARY_TEST 1
#include "w1_normal_witness.c"

enum {
    W2_SYS_GETXATTR = 8,
    W2_SYS_FACCESSAT = 48,
    W2_SYS_READLINKAT = 78,
    W2_SYS_PPOLL = 73,
    W2_SYS_SOCKET = 198,
    W2_SYS_CONNECT = 203,
    W2_SYS_GETSOCKOPT = 209,
    W2_SYS_CLONE = 220,
    W2_SYS_EXECVE = 221,
    W2_SYS_SYNCFS = 267,
    W2_SIGCHLD = 17,
    W2_CLONE_FS = 0x00000200,
    W2_IDENTITY_POLL_COUNT = 30000,
    W2_EVENT_POLL_COUNT = 300,
};

enum {
    W2_AF_UNIX = 1,
    W2_SOCK_STREAM = 1,
    W2_SOCK_NONBLOCK = 04000,
    W2_SOCK_CLOEXEC = 02000000,
    W2_SOL_SOCKET = 1,
    W2_SO_ERROR = 4,
    W2_SO_PEERCRED = 17,
    W2_POLLOUT = 4,
    W2_EINPROGRESS = 115,
};

enum {
    W2_FLAG_WITNESS_SELF_HASH = 1u << 0,
    W2_FLAG_LINEAGE_INIT_HASH = 1u << 1,
    W2_FLAG_PROPERTY_LISTENER = 1u << 2,
    W2_FLAG_KMSG_WRITE = 1u << 3,
    W2_FLAG_LOG_IDENTITY = 1u << 4,
    W2_FLAG_LOG_SYSTEM_MOUNT = 1u << 5,
    W2_FLAG_PAYLOAD_TRUNCATED = 1u << 6,
};

static const char w2_expected_lineage_init_sha256[] =
    DBY_W2_EXPECTED_LINEAGE_INIT_SHA256;
static const char w2_property_socket[] = "/dev/socket/property_service";
static const char w2_filesystem_view_contract[] =
    "CLONE_FS shares root/cwd across stock FirstStage SwitchRoot";
static const char w2_observation_rule[] =
    "property_service connect plus SO_PEERCRED pid=1 after exact pre-policy "
    "/proc/1/exe SHA-256; REA binds StartPropertyService call to selected "
    "Lineage SecondStageMain";
static const char w2_expected_log_label[] =
    "u:object_r:splash2_data_file:s0";

_Static_assert(
    sizeof(w2_expected_lineage_init_sha256) == 65,
    "Lineage init SHA-256 must contain 64 hex characters"
);

static isize w2_hash_path(const char *path, u8 digest[32]) {
    isize descriptor = dby_open(path, O_RDONLY | O_CLOEXEC, 0);
    if (descriptor < 0) {
        return descriptor;
    }
    struct sha256_context context;
    dby_sha256_init(&context);
    for (;;) {
        isize result = dby_syscall3(
            SYS_READ, descriptor, (isize)file_buffer, (isize)sizeof(file_buffer)
        );
        if (result == -EINTR) {
            continue;
        }
        if (result < 0) {
            (void)dby_close(descriptor);
            return result;
        }
        if (result == 0) {
            break;
        }
        dby_sha256_update(&context, file_buffer, (usize)result);
    }
    isize close_result = dby_close(descriptor);
    if (close_result < 0) {
        return close_result;
    }
    dby_sha256_final(&context, digest);
    return 0;
}

static isize w2_readlink(const char *path, char *output, usize capacity) {
    if (capacity == 0) {
        return -1;
    }
    isize result = dby_syscall4(
        W2_SYS_READLINKAT,
        AT_FDCWD,
        (isize)path,
        (isize)output,
        (isize)(capacity - 1)
    );
    if (result >= 0) {
        output[result] = '\0';
    }
    return result;
}

struct w2_sockaddr_un {
    unsigned short family;
    char path[108];
};

struct w2_ucred {
    int pid;
    unsigned int uid;
    unsigned int gid;
};

struct w2_pollfd {
    int fd;
    short events;
    short revents;
};

static int w2_connect_property_listener(
    struct w2_ucred *peer,
    isize *connect_status,
    isize *peer_status
) {
    isize descriptor = dby_syscall3(
        W2_SYS_SOCKET,
        W2_AF_UNIX,
        W2_SOCK_STREAM | W2_SOCK_NONBLOCK | W2_SOCK_CLOEXEC,
        0
    );
    if (descriptor < 0) {
        *connect_status = descriptor;
        *peer_status = descriptor;
        return (int)descriptor;
    }
    struct w2_sockaddr_un address;
    dby_memzero(&address, sizeof(address));
    address.family = W2_AF_UNIX;
    usize path_length = dby_strlen(w2_property_socket);
    dby_memcpy(address.path, w2_property_socket, path_length + 1);
    isize result = dby_syscall3(
        W2_SYS_CONNECT,
        descriptor,
        (isize)&address,
        (isize)(sizeof(address.family) + path_length + 1)
    );
    if (result == -W2_EINPROGRESS) {
        struct w2_pollfd pollfd;
        pollfd.fd = (int)descriptor;
        pollfd.events = W2_POLLOUT;
        pollfd.revents = 0;
        struct dby_timespec poll_timeout = {0, 250000000};
        isize poll_result = dby_syscall5(
            W2_SYS_PPOLL,
            (isize)&pollfd,
            1,
            (isize)&poll_timeout,
            0,
            0
        );
        if (poll_result > 0 && (pollfd.revents & W2_POLLOUT) != 0) {
            int socket_error = 0;
            u32 socket_error_length = sizeof(socket_error);
            isize error_result = dby_syscall5(
                W2_SYS_GETSOCKOPT,
                descriptor,
                W2_SOL_SOCKET,
                W2_SO_ERROR,
                (isize)&socket_error,
                (isize)&socket_error_length
            );
            result = error_result == 0 ? -socket_error : error_result;
        } else {
            result = poll_result < 0 ? poll_result : -W2_EINPROGRESS;
        }
    }
    *connect_status = result;
    if (result != 0) {
        *peer_status = result;
        (void)dby_close(descriptor);
        return (int)result;
    }
    u32 peer_length = sizeof(*peer);
    dby_memzero(peer, sizeof(*peer));
    result = dby_syscall5(
        W2_SYS_GETSOCKOPT,
        descriptor,
        W2_SOL_SOCKET,
        W2_SO_PEERCRED,
        (isize)peer,
        (isize)&peer_length
    );
    *peer_status = result;
    isize close_result = dby_close(descriptor);
    if (result != 0 || peer_length != sizeof(*peer)) {
        return result != 0 ? (int)result : -1;
    }
    if (close_result != 0) {
        return (int)close_result;
    }
    return peer->pid == 1 ? 0 : -1;
}

static void w2_make_names(void) {
    const char *temp_prefix = ".dby-lineage-stage2-witness-";
    const char *final_prefix = "dby-lineage-stage2-witness-";
    usize nonce_length = dby_strlen(nonce_hex);
    usize temp_prefix_length = dby_strlen(temp_prefix);
    usize final_prefix_length = dby_strlen(final_prefix);
    dby_memzero(temp_name, sizeof(temp_name));
    dby_memzero(final_name, sizeof(final_name));
    dby_memcpy(temp_name, temp_prefix, temp_prefix_length);
    dby_memcpy(temp_name + temp_prefix_length, nonce_hex, nonce_length);
    dby_memcpy(temp_name + temp_prefix_length + nonce_length, ".tmp", 5);
    dby_memcpy(final_name, final_prefix, final_prefix_length);
    dby_memcpy(final_name + final_prefix_length, nonce_hex, nonce_length);
    dby_memcpy(final_name + final_prefix_length + nonce_length, ".bin", 5);
}

static isize w2_publish_record(u32 flags) {
    struct witness_header header;
    dby_memzero(&header, sizeof(header));
    dby_memcpy(header.magic, "DBYW2REC", 8);
    header.version = 1;
    header.header_size = sizeof(header);
    header.payload_size = (u32)payload_length;
    header.flags = flags;
    dby_memcpy(header.nonce, nonce_hex, 32);

    u8 digest[32];
    struct sha256_context context;
    dby_sha256_init(&context);
    dby_sha256_update(&context, &header, sizeof(header));
    dby_sha256_update(&context, payload, payload_length);
    dby_sha256_final(&context, digest);

    isize directory = dby_open(
        "/log",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
        0
    );
    if (directory < 0) {
        return directory;
    }
    isize output = dby_openat(
        directory,
        temp_name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        0600
    );
    if (output < 0) {
        (void)dby_close(directory);
        return output;
    }
    isize result = dby_write_all(output, &header, sizeof(header));
    if (result == 0) {
        result = dby_write_all(output, payload, payload_length);
    }
    if (result == 0) {
        result = dby_write_all(output, digest, sizeof(digest));
    }
    if (result == 0) {
        result = dby_syscall1(SYS_FSYNC, output);
    }
    isize close_result = dby_close(output);
    if (result == 0 && close_result < 0) {
        result = close_result;
    }
    if (result == 0) {
        result = dby_syscall5(
            SYS_RENAMEAT2,
            directory,
            (isize)temp_name,
            directory,
            (isize)final_name,
            RENAME_NOREPLACE
        );
    }
    if (result == 0) {
        result = dby_syscall1(SYS_FSYNC, directory);
    }
    if (result == 0) {
        result = dby_syscall1(W2_SYS_SYNCFS, directory);
    }
    close_result = dby_close(directory);
    if (result == 0 && close_result < 0) {
        result = close_result;
    }
    return result;
}

static int w2_exact_token(
    const char *start, usize length, const char *expected
) {
    usize expected_length = dby_strlen(expected);
    return length == expected_length &&
           dby_memequal(start, expected, expected_length);
}

static int w2_find_log_mount_line(char *line, usize capacity) {
    isize length = dby_read_file(
        "/proc/self/mountinfo", file_buffer, sizeof(file_buffer)
    );
    if (length <= 0 || (usize)length == sizeof(file_buffer)) {
        return length < 0 ? (int)length : -1;
    }
    usize position = 0;
    while (position < (usize)length) {
        usize end = position;
        while (end < (usize)length && file_buffer[end] != '\n') {
            ++end;
        }
        usize token_start[5];
        usize token_length[5];
        usize cursor = position;
        int token_count = 0;
        while (cursor < end && token_count < 5) {
            while (cursor < end && file_buffer[cursor] == ' ') {
                ++cursor;
            }
            usize start = cursor;
            while (cursor < end && file_buffer[cursor] != ' ') {
                ++cursor;
            }
            token_start[token_count] = start;
            token_length[token_count] = cursor - start;
            ++token_count;
        }
        int separator_found = 0;
        usize separator = cursor;
        while (separator + 3 < end) {
            if (file_buffer[separator] == ' ' &&
                file_buffer[separator + 1] == '-' &&
                file_buffer[separator + 2] == ' ') {
                separator_found = 1;
                break;
            }
            ++separator;
        }
        if (token_count == 5 && separator_found &&
            w2_exact_token(file_buffer + token_start[2], token_length[2], "8:12") &&
            w2_exact_token(file_buffer + token_start[3], token_length[3], "/") &&
            w2_exact_token(file_buffer + token_start[4], token_length[4], "/log") &&
            separator + 8 <= end &&
            dby_memequal(file_buffer + separator + 3, "ext4 ", 5)) {
            usize line_length = end - position;
            if (line_length + 1 > capacity) {
                return -1;
            }
            dby_memcpy(line, file_buffer + position, line_length);
            line[line_length] = '\0';
            return (int)line_length;
        }
        position = end + 1;
    }
    return 0;
}

static int w2_verify_log_superblock(void) {
    u8 superblock[1024];
    dby_memzero(superblock, sizeof(superblock));
    isize descriptor = dby_open(
        "/dev/block/sda12", O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0
    );
    if (descriptor < 0) {
        return (int)descriptor;
    }
    isize result = dby_syscall4(
        SYS_PREAD64,
        descriptor,
        (isize)superblock,
        (isize)sizeof(superblock),
        1024
    );
    isize close_result = dby_close(descriptor);
    if (result != (isize)sizeof(superblock)) {
        return result < 0 ? (int)result : -1;
    }
    if (close_result < 0) {
        return (int)close_result;
    }
    if (dby_read_le32(superblock + 0x04) != 20480 ||
        dby_read_le32(superblock + 0x18) != 2 ||
        dby_read_le16(superblock + 0x38) != 0xef53 ||
        dby_read_le32(superblock + 0xe0) != 8 ||
        !dby_memequal(superblock + 0x68, expected_log_fsuuid, 16)) {
        return -1;
    }
    return 0;
}

static int w2_verify_log_label(char *label, usize capacity) {
    isize length = dby_syscall4(
        W2_SYS_GETXATTR,
        (isize)"/log",
        (isize)"security.selinux",
        (isize)label,
        (isize)capacity
    );
    usize expected_length = dby_strlen(w2_expected_log_label);
    if (length == (isize)(expected_length + 1) &&
        label[expected_length] == '\0') {
        length = (isize)expected_length;
    }
    if (length != (isize)expected_length ||
        !dby_memequal(label, w2_expected_log_label, expected_length)) {
        return length < 0 ? (int)length : -1;
    }
    label[expected_length] = '\0';
    return (int)expected_length;
}

static int w2_qualify_system_log_mount(u32 *flags) {
    char mount_line[1024];
    int mount_line_length = w2_find_log_mount_line(
        mount_line, sizeof(mount_line)
    );
    if (mount_line_length <= 0) {
        return mount_line_length == 0 ? -1 : mount_line_length;
    }
    int find_result = dby_find_log_block();
    if (find_result != 0) {
        return find_result;
    }
    int superblock_result = w2_verify_log_superblock();
    if (superblock_result != 0) {
        return superblock_result;
    }
    char label[64];
    int label_length = w2_verify_log_label(label, sizeof(label));
    if (label_length <= 0) {
        return label_length == 0 ? -1 : label_length;
    }
    *flags |= W2_FLAG_LOG_IDENTITY | W2_FLAG_LOG_SYSTEM_MOUNT;
    dby_append_field("LOG_MOUNTINFO_LINE", mount_line, (usize)mount_line_length);
    dby_append_field("LOG_SELINUX_LABEL", label, (usize)label_length);
    dby_append_status("LOG_SUPERBLOCK_VERIFY", superblock_result);
    dby_append_field("LOG_DEVNAME", log_identity.devname, dby_strlen(log_identity.devname));
    dby_append_field(
        "LOG_EXPECTED_PARTUUID",
        expected_log_partuuid,
        dby_strlen(expected_log_partuuid)
    );
    dby_append_status("LOG_PARTUUID_EXPORTED", log_identity.partuuid_exported);
    if (log_identity.partuuid_exported) {
        dby_append_field(
            "LOG_PARTUUID",
            log_identity.partuuid,
            dby_strlen(log_identity.partuuid)
        );
    }
    dby_append_u64("LOG_MAJOR", log_identity.major);
    dby_append_u64("LOG_MINOR", log_identity.minor);
    dby_append_u64("LOG_SECTORS_512", log_identity.sectors_512);
    dby_append_field(
        "LOG_EXPECTED_FSUUID",
        expected_log_fsuuid_hex,
        dby_strlen(expected_log_fsuuid_hex)
    );
    return 0;
}

static int w2_wait_pid1_identity(int *lineage_hash_match) {
    char exe_link[192];
    isize link_result = -1;
    usize observed_iteration = W2_IDENTITY_POLL_COUNT;
    const struct dby_timespec delay = {0, 1000000};
    for (usize iteration = 0; iteration < W2_IDENTITY_POLL_COUNT; ++iteration) {
        link_result = w2_readlink("/proc/1/exe", exe_link, sizeof(exe_link));
        if (link_result == 16 && dby_strequal(exe_link, "/system/bin/init")) {
            observed_iteration = iteration;
            break;
        }
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }
    dby_append_status("PID1_EXE_READLINK", link_result);
    dby_append_u64("PID1_IDENTITY_OBSERVED_ITERATION", observed_iteration);
    if (observed_iteration != W2_IDENTITY_POLL_COUNT) {
        dby_append_field("PID1_EXE_LINK", exe_link, (usize)link_result);
    }
    dby_append_file("PID1_CMDLINE", "/proc/1/cmdline");
    u8 digest[32];
    isize hash_result = observed_iteration == W2_IDENTITY_POLL_COUNT
                            ? -1
                            : w2_hash_path("/proc/1/exe", digest);
    dby_append_status("PID1_EXE_SHA256_STATUS", hash_result);
    if (hash_result == 0) {
        char digest_hex[64];
        dby_hex(digest_hex, digest, sizeof(digest));
        dby_append_field("PID1_EXE_SHA256", digest_hex, sizeof(digest_hex));
        *lineage_hash_match = dby_memequal(
            digest_hex,
            w2_expected_lineage_init_sha256,
            sizeof(digest_hex)
        );
    }
    dby_append_status("PID1_EXE_HASH_MATCH", *lineage_hash_match);
    return *lineage_hash_match ? 0 : -1;
}

static void w2_append_monotonic(const char *status_field, const char *time_field) {
    isize status = 0;
    u64 value = dby_monotonic_ns(&status);
    dby_append_status(status_field, status);
    dby_append_u64(time_field, value);
}

static int w2_wait_proc_ready(void) {
    char self_link[192];
    const struct dby_timespec delay = {0, 1000000};
    for (usize iteration = 0; iteration < W2_IDENTITY_POLL_COUNT; ++iteration) {
        isize result = w2_readlink(
            "/proc/self/exe", self_link, sizeof(self_link)
        );
        if (result > 0) {
            dby_append_status("PROC_READY", 1);
            dby_append_u64("PROC_READY_OBSERVED_ITERATION", iteration);
            return 0;
        }
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }
    dby_append_status("PROC_READY", 0);
    dby_append_u64(
        "PROC_READY_OBSERVED_ITERATION", W2_IDENTITY_POLL_COUNT
    );
    return -1;
}

static int w2_write_kmsg_marker(void) {
    char message[128];
    usize prefix_length = dby_strlen(DBY_WITNESS_MARKER_PREFIX);
    dby_memcpy(message, DBY_WITNESS_MARKER_PREFIX, prefix_length);
    dby_memcpy(message + prefix_length, nonce_hex, 32);
    usize length = prefix_length + 32;
    message[length++] = '\n';
    dby_append_field("KMSG_MARKER_MESSAGE", message, length - 1);
    isize descriptor = dby_open(
        "/dev/kmsg", O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0
    );
    dby_append_status("KMSG_MARKER_WRITER_OPEN", descriptor);
    if (descriptor < 0) {
        dby_append_status("KMSG_MARKER_WRITE", descriptor);
        dby_append_status("KMSG_MARKER_WRITER_CLOSE", descriptor);
        return (int)descriptor;
    }
    isize result = dby_write_all(descriptor, message, length);
    dby_append_status("KMSG_MARKER_WRITE", result);
    isize close_result = dby_close(descriptor);
    dby_append_status("KMSG_MARKER_WRITER_CLOSE", close_result);
    return result == 0 && close_result == 0 ? 0 : -1;
}

__attribute__((noreturn)) static void w2_child(void) {
    u32 flags = 0;
    int property_listener_bound = 0;
    int lineage_hash_match = 0;
    usize observed_iteration = W2_EVENT_POLL_COUNT;
    const struct dby_timespec delay = {0, 100000000};

    w2_make_names();
    dby_append_field("FORMAT", "DBY-W09-W2", 10);
    dby_append_field("NONCE", nonce_hex, 32);
    dby_append_status("WITNESS_PID", dby_syscall0(SYS_GETPID));
    dby_append_field(
        "LINEAGE_EXPECTED_INIT_SHA256",
        w2_expected_lineage_init_sha256,
        64
    );
    dby_append_field(
        "SECOND_STAGE_OBSERVATION_RULE",
        w2_observation_rule,
        dby_strlen(w2_observation_rule)
    );
    dby_append_field(
        "PROPERTY_SERVICE_PATH",
        w2_property_socket,
        dby_strlen(w2_property_socket)
    );
    dby_append_field(
        "FILESYSTEM_VIEW_CONTRACT",
        w2_filesystem_view_contract,
        dby_strlen(w2_filesystem_view_contract)
    );
    dby_append_field(
        "LOG_EXPECTED_SELINUX_LABEL",
        w2_expected_log_label,
        dby_strlen(w2_expected_log_label)
    );
    (void)w2_wait_proc_ready();
    dby_append_file("BOOT_ID", "/proc/sys/kernel/random/boot_id");
    dby_append_file("CMDLINE", "/proc/cmdline");

    u8 self_digest[32];
    isize self_hash_result = dby_hash_self_exe(self_digest);
    dby_append_status("WITNESS_SELF_SHA256_STATUS", self_hash_result);
    if (self_hash_result == 0) {
        char self_hex[64];
        dby_hex(self_hex, self_digest, sizeof(self_digest));
        dby_append_field("WITNESS_SELF_SHA256", self_hex, sizeof(self_hex));
        flags |= W2_FLAG_WITNESS_SELF_HASH;
    }

    w2_append_monotonic(
        "PID1_IDENTITY_WAIT_START_STATUS", "PID1_IDENTITY_WAIT_START_NS"
    );
    if (w2_wait_pid1_identity(&lineage_hash_match) == 0) {
        flags |= W2_FLAG_LINEAGE_INIT_HASH;
    }
    dby_append_file(
        "WITNESS_SELINUX_CONTEXT_AFTER_IDENTITY", "/proc/self/attr/current"
    );
    w2_append_monotonic(
        "PID1_IDENTITY_CAPTURE_STATUS", "PID1_IDENTITY_CAPTURE_NS"
    );

    struct w2_ucred property_peer;
    isize property_connect_status = -1;
    isize property_peer_status = -1;
    for (usize iteration = 0; iteration < W2_EVENT_POLL_COUNT; ++iteration) {
        if (w2_connect_property_listener(
                &property_peer,
                &property_connect_status,
                &property_peer_status
            ) == 0) {
            property_listener_bound = 1;
            observed_iteration = iteration;
            break;
        }
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }

    dby_append_status("PROPERTY_SERVICE_CONNECT", property_connect_status);
    dby_append_status("PROPERTY_SERVICE_SO_PEERCRED", property_peer_status);
    dby_append_status("PROPERTY_SERVICE_LISTENER_BOUND", property_listener_bound);
    dby_append_u64("PROPERTY_SERVICE_OBSERVED_ITERATION", observed_iteration);
    if (property_peer_status == 0) {
        dby_append_status("PROPERTY_SERVICE_PEER_PID", property_peer.pid);
        dby_append_u64("PROPERTY_SERVICE_PEER_UID", property_peer.uid);
        dby_append_u64("PROPERTY_SERVICE_PEER_GID", property_peer.gid);
    }
    if (property_listener_bound) {
        flags |= W2_FLAG_PROPERTY_LISTENER;
    }
    int second_stage_observed = property_listener_bound && lineage_hash_match;
    dby_append_status("LINEAGE_SECOND_STAGE_OBSERVED", second_stage_observed);
    dby_append_file(
        "WITNESS_SELINUX_CONTEXT_AFTER_PROPERTY", "/proc/self/attr/current"
    );
    w2_append_monotonic(
        "PROPERTY_SERVICE_OBSERVED_STATUS", "PROPERTY_SERVICE_OBSERVED_NS"
    );

    int marker_result = w2_write_kmsg_marker();
    if (marker_result == 0) {
        flags |= W2_FLAG_KMSG_WRITE;
    }

    int log_result = -1;
    usize log_observed_iteration = W2_EVENT_POLL_COUNT;
    for (usize iteration = 0; iteration < W2_EVENT_POLL_COUNT; ++iteration) {
        log_result = w2_qualify_system_log_mount(&flags);
        if (log_result == 0) {
            log_observed_iteration = iteration;
            break;
        }
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }
    dby_append_status("LOG_SYSTEM_MOUNT_QUALIFIED", log_result);
    dby_append_u64("LOG_SYSTEM_MOUNT_OBSERVED_ITERATION", log_observed_iteration);
    dby_append_field(
        "PUBLICATION_PROTOCOL",
        publication_protocol,
        dby_strlen(publication_protocol)
    );
    if (payload_truncated) {
        flags |= W2_FLAG_PAYLOAD_TRUNCATED;
    }
    isize publish_result = -1;
    if ((flags & W2_FLAG_LOG_SYSTEM_MOUNT) != 0) {
        publish_result = w2_publish_record(flags);
    }
    dby_emit_kmsg_result("DBY_W2_PUBLISH_RESULT=", publish_result);
    dby_syscall0(SYS_SYNC);
    isize reboot_result = dby_request_reboot("edl");
    dby_emit_kmsg_result("DBY_W2_REBOOT_EDL_RETURNED=", reboot_result);
    reboot_result = dby_request_reboot("bootloader");
    dby_emit_kmsg_result("DBY_W2_REBOOT_BOOTLOADER_RETURNED=", reboot_result);
    dby_syscall1(SYS_EXIT, second_stage_observed ? 0 : 2);
    __builtin_unreachable();
}

__attribute__((noreturn, visibility("default"))) void w2_start(usize *initial_stack) {
    usize argument_count = initial_stack[0];
    char **arguments = (char **)&initial_stack[1];
    char **environment = &arguments[argument_count + 1];
    isize child = dby_syscall5(
        W2_SYS_CLONE, W2_SIGCHLD | W2_CLONE_FS, 0, 0, 0, 0
    );
    if (child == 0) {
        w2_child();
    }
    if (child < 0) {
        dby_emit_kmsg_result("DBY_W2_CLONE_FAILED=", child);
    }
    (void)dby_syscall3(
        W2_SYS_EXECVE,
        (isize)"/init.stock",
        (isize)arguments,
        (isize)environment
    );
    dby_emit_kmsg_result("DBY_W2_INIT_STOCK_EXEC_FAILED=", -1);
    dby_syscall1(SYS_EXIT, 127);
    __builtin_unreachable();
}

__asm__(
    ".text\n"
    ".global _start\n"
    ".type _start,%function\n"
    "_start:\n"
    "mov x0, sp\n"
    "bl w2_start\n"
    "mov x0, #127\n"
    "mov x8, #93\n"
    "svc #0\n"
    "b .\n"
);
