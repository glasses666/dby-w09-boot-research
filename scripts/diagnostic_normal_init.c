/*
 * DBY-W09 bounded first-stage logger.
 *
 * This is intentionally libc-free and syscall-only.  PID 1 immediately
 * execs the stock init with the original argv/envp.  Its child keeps at most
 * 1 MiB of early kmsg in memory, opens one O_DSYNC file only after /metadata
 * appears as a distinct mount, and exits at handoff or after 25 seconds.
 */

typedef unsigned long usize;
typedef long isize;

enum {
    SYS_MKNODAT = 33,
    SYS_MKDIRAT = 34,
    SYS_OPENAT = 56,
    SYS_CLOSE = 57,
    SYS_READ = 63,
    SYS_WRITE = 64,
    SYS_FSYNC = 82,
    SYS_NANOSLEEP = 101,
    SYS_READLINKAT = 78,
    SYS_EXIT = 93,
    SYS_CLONE = 220,
    SYS_EXECVE = 221,
};

enum {
    AT_FDCWD = -100,
    O_RDONLY = 0,
    O_WRONLY = 1,
    O_CREAT = 0100,
    O_TRUNC = 01000,
    O_NONBLOCK = 04000,
    O_DSYNC = 010000,
    O_CLOEXEC = 02000000,
    S_IFCHR = 0020000,
    SIGCHLD = 17,
    KMSG_DEV = 0x10b,
    EARLY_CAPACITY = 1024 * 1024,
    POLL_COUNT = 250,
};

struct dby_timespec {
    isize tv_sec;
    isize tv_nsec;
};

static unsigned char early_kmsg[EARLY_CAPACITY];
static usize early_length;
static usize dropped_bytes;
static char mountinfo[32768];
static char io_buffer[4096];
static char exe_path[256];

static inline isize dby_syscall1(isize number, isize argument0) {
    register isize x0 __asm__("x0") = argument0;
    register isize x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
}

static inline isize dby_syscall2(isize number, isize argument0, isize argument1) {
    register isize x0 __asm__("x0") = argument0;
    register isize x1 __asm__("x1") = argument1;
    register isize x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory", "cc");
    return x0;
}

static inline isize dby_syscall3(
    isize number, isize argument0, isize argument1, isize argument2
) {
    register isize x0 __asm__("x0") = argument0;
    register isize x1 __asm__("x1") = argument1;
    register isize x2 __asm__("x2") = argument2;
    register isize x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc"
    );
    return x0;
}

static inline isize dby_syscall4(
    isize number,
    isize argument0,
    isize argument1,
    isize argument2,
    isize argument3
) {
    register isize x0 __asm__("x0") = argument0;
    register isize x1 __asm__("x1") = argument1;
    register isize x2 __asm__("x2") = argument2;
    register isize x3 __asm__("x3") = argument3;
    register isize x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

static inline isize dby_syscall5(
    isize number,
    isize argument0,
    isize argument1,
    isize argument2,
    isize argument3,
    isize argument4
) {
    register isize x0 __asm__("x0") = argument0;
    register isize x1 __asm__("x1") = argument1;
    register isize x2 __asm__("x2") = argument2;
    register isize x3 __asm__("x3") = argument3;
    register isize x4 __asm__("x4") = argument4;
    register isize x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

static usize dby_strlen(const char *text) {
    usize length = 0;
    while (text[length] != '\0') {
        ++length;
    }
    return length;
}

static int dby_contains(const char *haystack, usize haystack_length, const char *needle) {
    usize needle_length = dby_strlen(needle);
    if (needle_length == 0 || needle_length > haystack_length) {
        return 0;
    }
    for (usize start = 0; start + needle_length <= haystack_length; ++start) {
        usize index = 0;
        while (index < needle_length && haystack[start + index] == needle[index]) {
            ++index;
        }
        if (index == needle_length) {
            return 1;
        }
    }
    return 0;
}

static isize dby_open(const char *path, isize flags, isize mode) {
    return dby_syscall4(SYS_OPENAT, AT_FDCWD, (isize)path, flags, mode);
}

static void dby_prepare_kmsg_node(void) {
    /* Linux dev_t encoding for char device major 1, minor 11. */
    (void)dby_syscall4(
        SYS_MKNODAT,
        AT_FDCWD,
        (isize)"/dev/kmsg",
        S_IFCHR | 0600,
        KMSG_DEV
    );
}

static void dby_close(isize descriptor) {
    if (descriptor >= 0) {
        (void)dby_syscall1(SYS_CLOSE, descriptor);
    }
}

static int dby_write_all(isize descriptor, const void *data, usize length) {
    const unsigned char *cursor = (const unsigned char *)data;
    while (length != 0) {
        isize result = dby_syscall3(SYS_WRITE, descriptor, (isize)cursor, (isize)length);
        if (result <= 0) {
            return -1;
        }
        cursor += (usize)result;
        length -= (usize)result;
    }
    return 0;
}

static void dby_write_text(isize descriptor, const char *text) {
    (void)dby_write_all(descriptor, text, dby_strlen(text));
}

static isize dby_read_file(const char *path, char *buffer, usize capacity) {
    isize descriptor = dby_open(path, O_RDONLY | O_CLOEXEC, 0);
    if (descriptor < 0) {
        return descriptor;
    }
    usize length = 0;
    while (length < capacity) {
        isize result = dby_syscall3(
            SYS_READ, descriptor, (isize)(buffer + length), (isize)(capacity - length)
        );
        if (result <= 0) {
            break;
        }
        length += (usize)result;
    }
    dby_close(descriptor);
    return (isize)length;
}

static int dby_metadata_is_mounted(void) {
    isize length = dby_read_file(
        "/proc/self/mountinfo", mountinfo, (usize)sizeof(mountinfo)
    );
    return length > 0 && dby_contains(mountinfo, (usize)length, " /metadata ");
}

static void dby_copy_named_file(isize output, const char *heading, const char *path) {
    dby_write_text(output, heading);
    isize length = dby_read_file(path, io_buffer, (usize)sizeof(io_buffer));
    if (length > 0) {
        (void)dby_write_all(output, io_buffer, (usize)length);
    } else {
        dby_write_text(output, "UNAVAILABLE\n");
    }
    dby_write_text(output, "\n");
}

static void dby_append_early(const char *data, usize length) {
    usize available = EARLY_CAPACITY - early_length;
    usize retained = length < available ? length : available;
    for (usize index = 0; index < retained; ++index) {
        early_kmsg[early_length + index] = (unsigned char)data[index];
    }
    early_length += retained;
    dropped_bytes += length - retained;
}

static void dby_drain_kmsg(isize kmsg, isize output) {
    if (kmsg < 0) {
        return;
    }
    for (;;) {
        isize length = dby_syscall3(
            SYS_READ, kmsg, (isize)io_buffer, (isize)sizeof(io_buffer)
        );
        if (length <= 0) {
            break;
        }
        if (output >= 0) {
            (void)dby_write_all(output, io_buffer, (usize)length);
        } else {
            dby_append_early(io_buffer, (usize)length);
        }
    }
}

static void dby_emit_kmsg_marker(const char *text) {
    isize descriptor = dby_open("/dev/kmsg", O_WRONLY | O_CLOEXEC, 0);
    if (descriptor >= 0) {
        dby_write_text(descriptor, text);
        dby_close(descriptor);
    }
}

static int dby_handoff_reached(void) {
    isize length = dby_syscall4(
        SYS_READLINKAT,
        AT_FDCWD,
        (isize)"/proc/1/exe",
        (isize)exe_path,
        (isize)(sizeof(exe_path) - 1)
    );
    if (length <= 0) {
        return 0;
    }
    exe_path[length] = '\0';
    return dby_contains(exe_path, (usize)length, "/system/bin/init");
}

static isize dby_open_output(void) {
    return dby_open(
        "/metadata/dby-first-stage-v2.log",
        O_WRONLY | O_CREAT | O_TRUNC | O_DSYNC | O_CLOEXEC,
        0600
    );
}

static void dby_child(void) {
    const struct dby_timespec delay = {0, 100000000};
    isize kmsg = -1;
    isize output = -1;
    for (usize iteration = 0; iteration < POLL_COUNT; ++iteration) {
        if (kmsg < 0) {
            kmsg = dby_open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
            if (kmsg >= 0) {
                dby_emit_kmsg_marker("DBY_FIRST_STAGE_V2 LOGGER_STARTED\n");
            }
        }
        dby_drain_kmsg(kmsg, output);
        if (output < 0 && dby_metadata_is_mounted()) {
            output = dby_open_output();
            if (output >= 0) {
                dby_write_text(output, "DBY_FIRST_STAGE_V2\n");
                dby_copy_named_file(output, "BOOT_ID\n", "/proc/sys/kernel/random/boot_id");
                dby_copy_named_file(output, "CMDLINE\n", "/proc/cmdline");
                dby_write_text(output, "EARLY_KMSG\n");
                (void)dby_write_all(output, early_kmsg, early_length);
                early_length = 0;
            }
        }
        if (output >= 0 && dby_handoff_reached()) {
            dby_drain_kmsg(kmsg, output);
            dby_write_text(output, "\nHANDOFF_REACHED /system/bin/init\n");
            (void)dby_syscall1(SYS_FSYNC, output);
            dby_close(output);
            dby_close(kmsg);
            dby_syscall1(SYS_EXIT, 0);
        }
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }
    dby_drain_kmsg(kmsg, output);
    if (output >= 0) {
        dby_write_text(output, "\nTIMEOUT_25_SECONDS\n");
        if (dropped_bytes != 0) {
            dby_write_text(output, "EARLY_BUFFER_TRUNCATED\n");
        }
        (void)dby_syscall1(SYS_FSYNC, output);
    }
    dby_close(output);
    dby_close(kmsg);
    dby_syscall1(SYS_EXIT, 0);
}

__attribute__((noreturn, visibility("default"))) void dby_start(usize *initial_stack) {
    usize argument_count = initial_stack[0];
    char **arguments = (char **)&initial_stack[1];
    char **environment = &arguments[argument_count + 1];
    dby_prepare_kmsg_node();
    dby_emit_kmsg_marker("DBY_FIRST_STAGE_V2 WRAPPER_ENTERED\n");
    isize child = dby_syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0);
    if (child == 0) {
        dby_child();
    }
    if (child < 0) {
        dby_emit_kmsg_marker("DBY_FIRST_STAGE_V2 CLONE_FAILED\n");
    }
    (void)dby_syscall3(
        SYS_EXECVE, (isize)"/init.stock", (isize)arguments, (isize)environment
    );
    dby_emit_kmsg_marker("DBY_FIRST_STAGE_V2 INIT_STOCK_EXEC_FAILED\n");
    dby_syscall1(SYS_EXIT, 127);
    __builtin_unreachable();
}

__asm__(
    ".text\n"
    ".global _start\n"
    ".type _start,%function\n"
    "_start:\n"
    "mov x0, sp\n"
    "bl dby_start\n"
    "mov x0, #127\n"
    "mov x8, #93\n"
    "svc #0\n"
    "b .\n"
);
