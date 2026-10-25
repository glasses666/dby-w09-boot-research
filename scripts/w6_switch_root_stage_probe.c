/*
 * DBY-W09 W6: endpoint-coded first-stage mount and switch-root probe.
 *
 * PID 1 clones one observer in a private mount namespace, waits until that
 * observer has mounted its own procfs, and then execs the retained stock init
 * with the parent's mount namespace untouched.  The observer reads PID 1 via
 * its private procfs.  It requests EDL only after the target PID 1 mount table
 * contains /, /vendor, and /odm and the post-switch-root
 * /proc/1/root/system/bin/init bytes exactly match the selected Lineage init.
 * Setup failure, identity mismatch, timeout, or stock-init exec failure request
 * Fastboot instead.  The probe never opens a persistent filesystem for write.
 */

#ifndef DBY_W6_NONCE_HEX
#error "DBY_W6_NONCE_HEX must be a quoted 32-character lowercase hex string"
#endif

#ifndef DBY_W6_EXPECTED_LINEAGE_INIT_SHA256
#error "DBY_W6_EXPECTED_LINEAGE_INIT_SHA256 must be a quoted SHA-256"
#endif

#define DBY_W1_NONCE_HEX DBY_W6_NONCE_HEX
#define DBY_W1_LIBRARY_TEST 1
#include "w1_normal_witness.c"

enum {
    W6_SYS_FACCESSAT = 48,
    W6_SYS_PIPE2 = 59,
    W6_SYS_PPOLL = 73,
    W6_SYS_READLINKAT = 78,
    W6_SYS_CLONE = 220,
    W6_SYS_EXECVE = 221,
    W6_SIGCHLD = 17,
    W6_CLONE_NEWNS = 0x00020000,
    W6_MS_REC = 16384,
    W6_MS_PRIVATE = 1u << 18,
    W6_POLLIN = 1,
    W6_LOOP_COUNT = 30000,
};

static const char w6_expected_lineage_init_sha256[] =
    DBY_W6_EXPECTED_LINEAGE_INIT_SHA256;
__attribute__((used)) static const char w6_nonce[] = DBY_W6_NONCE_HEX;
#ifdef DBY_W7_WAIT_LINEAGE_EXEC
__attribute__((used)) static const char w6_marker[] =
    "DBY_W7_LINEAGE_EXEC_STAGE_PROBE nonce=" DBY_W6_NONCE_HEX;
#else
__attribute__((used)) static const char w6_marker[] =
    "DBY_W6_SWITCH_ROOT_STAGE_PROBE nonce=" DBY_W6_NONCE_HEX;
#endif
__attribute__((used)) static const char w6_namespace_contract[] =
    "CLONE_NEWNS private proc observer; parent mount namespace unchanged";
#ifdef DBY_W7_WAIT_LINEAGE_EXEC
__attribute__((used)) static const char w6_success_contract[] =
    "EDL means exact selected Lineage init became PID1 /system/bin/init";
#else
__attribute__((used)) static const char w6_success_contract[] =
    "EDL means exact Lineage init visible after switch-root with root vendor odm mounts";
#endif
__attribute__((used)) static const char w6_required_mountpoints[] =
    "/ /vendor /odm";

static const char w6_proc_root[] = "/dby-proc";
static const char w6_pid1_exe[] = "/dby-proc/1/exe";
static const char w6_pid1_mountinfo[] = "/dby-proc/1/mountinfo";
static const char w6_lineage_init_path[] =
    "/dby-proc/1/root/system/bin/init";
static char w6_mountinfo_buffer[32768];

_Static_assert(sizeof(w6_nonce) == 33, "nonce must contain 32 hex characters");
_Static_assert(
    sizeof(w6_expected_lineage_init_sha256) == 65,
    "Lineage init SHA-256 must contain 64 hex characters"
);

struct w6_pollfd {
    int fd;
    short events;
    short revents;
};

static isize w6_readlink(const char *path, char *output, usize capacity) {
    if (capacity == 0) {
        return -1;
    }
    isize result = dby_syscall4(
        W6_SYS_READLINKAT,
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

static isize w6_hash_path(const char *path, u8 digest[32]) {
    isize descriptor = dby_open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
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

static int w6_token_equal(
    const char *data, usize start, usize length, const char *expected
) {
    usize expected_length = dby_strlen(expected);
    return length == expected_length &&
           dby_memequal(data + start, expected, expected_length);
}

static int w6_mountpoints_ready(void) {
    isize length = dby_read_file(
        w6_pid1_mountinfo, w6_mountinfo_buffer, sizeof(w6_mountinfo_buffer)
    );
    if (length <= 0 || (usize)length == sizeof(w6_mountinfo_buffer)) {
        return 0;
    }
    int root_seen = 0;
    int vendor_seen = 0;
    int odm_seen = 0;
    usize position = 0;
    while (position < (usize)length) {
        usize end = position;
        while (end < (usize)length && w6_mountinfo_buffer[end] != '\n') {
            ++end;
        }
        usize cursor = position;
        usize token_start = position;
        usize token_length = 0;
        for (int token = 0; token < 5; ++token) {
            while (cursor < end && w6_mountinfo_buffer[cursor] == ' ') {
                ++cursor;
            }
            token_start = cursor;
            while (cursor < end && w6_mountinfo_buffer[cursor] != ' ') {
                ++cursor;
            }
            token_length = cursor - token_start;
        }
        if (w6_token_equal(
                w6_mountinfo_buffer, token_start, token_length, "/"
            )) {
            root_seen = 1;
        } else if (w6_token_equal(
                       w6_mountinfo_buffer,
                       token_start,
                       token_length,
                       "/vendor"
                   )) {
            vendor_seen = 1;
        } else if (w6_token_equal(
                       w6_mountinfo_buffer,
                       token_start,
                       token_length,
                       "/odm"
                   )) {
            odm_seen = 1;
        }
        position = end + 1;
    }
    return root_seen && vendor_seen && odm_seen;
}

__attribute__((noreturn)) static void w6_reboot_forever(
    const char *primary, const char *fallback
) {
    (void)dby_request_reboot(primary);
    if (fallback != 0) {
        (void)dby_request_reboot(fallback);
    }
    const struct dby_timespec delay = {1, 0};
    for (;;) {
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }
}

__attribute__((noreturn)) static void w6_observer(int ready_descriptor) {
    isize private_result = dby_mount(
        0, "/", 0, W6_MS_REC | W6_MS_PRIVATE, 0
    );
    isize mkdir_result = private_result == 0
                             ? dby_mkdir(w6_proc_root, 0555)
                             : private_result;
    isize proc_result = mkdir_result == 0
                            ? dby_mount(
                                  "proc",
                                  "/dby-proc",
                                  "proc",
                                  MS_NOSUID | MS_NODEV | MS_NOEXEC,
                                  ""
                              )
                            : mkdir_result;
    char ready = proc_result == 0 ? 'R' : 'F';
    (void)dby_write_all(ready_descriptor, &ready, 1);
    (void)dby_close(ready_descriptor);
    if (proc_result != 0) {
        w6_reboot_forever("bootloader", 0);
    }

    char executable[192];
    int stock_init_seen = 0;
    int lineage_identity_qualified = 0;
    const struct dby_timespec delay = {0, 1000000};
    for (usize iteration = 0; iteration < W6_LOOP_COUNT; ++iteration) {
        isize exe_length = w6_readlink(
            w6_pid1_exe, executable, sizeof(executable)
        );
        if (exe_length > 0 &&
            dby_contains(executable, (usize)exe_length, "/init.stock")) {
            stock_init_seen = 1;
        }
        if (stock_init_seen && !lineage_identity_qualified &&
            w6_mountpoints_ready()) {
            isize access_result = dby_syscall4(
                W6_SYS_FACCESSAT,
                AT_FDCWD,
                (isize)w6_lineage_init_path,
                4,
                0
            );
            if (access_result == 0) {
                u8 digest[32];
                isize hash_result = w6_hash_path(w6_lineage_init_path, digest);
                if (hash_result != 0) {
                    w6_reboot_forever("bootloader", 0);
                }
                char digest_hex[64];
                dby_hex(digest_hex, digest, sizeof(digest));
                if (!dby_memequal(
                        digest_hex,
                        w6_expected_lineage_init_sha256,
                        sizeof(digest_hex)
                    )) {
                    w6_reboot_forever("bootloader", 0);
                }
#ifdef DBY_W7_WAIT_LINEAGE_EXEC
                lineage_identity_qualified = 1;
#else
                w6_reboot_forever("edl", "bootloader");
#endif
            }
        }
#ifdef DBY_W7_WAIT_LINEAGE_EXEC
        if (lineage_identity_qualified && exe_length > 0 &&
            dby_strequal(executable, "/system/bin/init")) {
            w6_reboot_forever("edl", "bootloader");
        }
#endif
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }
    w6_reboot_forever("bootloader", 0);
}

static int w6_wait_observer_ready(int descriptor) {
    struct w6_pollfd pollfd;
    pollfd.fd = descriptor;
    pollfd.events = W6_POLLIN;
    pollfd.revents = 0;
    struct dby_timespec ready_timeout = {5, 0};
    isize poll_result = dby_syscall5(
        W6_SYS_PPOLL,
        (isize)&pollfd,
        1,
        (isize)&ready_timeout,
        0,
        0
    );
    if (poll_result <= 0 || (pollfd.revents & W6_POLLIN) == 0) {
        return -1;
    }
    char ready = 0;
    isize read_result = dby_syscall3(
        SYS_READ, descriptor, (isize)&ready, 1
    );
    return read_result == 1 && ready == 'R' ? 0 : -1;
}

__attribute__((noreturn, visibility("default"))) void w6_start(
    usize *initial_stack
) {
    usize argument_count = initial_stack[0];
    char **arguments = (char **)&initial_stack[1];
    char **environment = &arguments[argument_count + 1];
    int pipe_descriptors[2] = {-1, -1};
    isize pipe_result = dby_syscall2(
        W6_SYS_PIPE2, (isize)pipe_descriptors, O_CLOEXEC
    );
    if (pipe_result != 0) {
        w6_reboot_forever("bootloader", 0);
    }
    isize child = dby_syscall5(
        W6_SYS_CLONE, W6_SIGCHLD | W6_CLONE_NEWNS, 0, 0, 0, 0
    );
    if (child == 0) {
        (void)dby_close(pipe_descriptors[0]);
        w6_observer(pipe_descriptors[1]);
    }
    (void)dby_close(pipe_descriptors[1]);
    if (child < 0 || w6_wait_observer_ready(pipe_descriptors[0]) != 0) {
        (void)dby_close(pipe_descriptors[0]);
        w6_reboot_forever("bootloader", 0);
    }
    (void)dby_close(pipe_descriptors[0]);
    (void)dby_syscall3(
        W6_SYS_EXECVE,
        (isize)"/init.stock",
        (isize)arguments,
        (isize)environment
    );
    w6_reboot_forever("bootloader", 0);
}

__asm__(
    ".text\n"
    ".global _start\n"
    ".type _start,%function\n"
    "_start:\n"
    "mov x0, sp\n"
    "bl w6_start\n"
    "mov x0, #127\n"
    "mov x8, #93\n"
    "svc #0\n"
    "b .\n"
);
