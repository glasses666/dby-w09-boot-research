/*
 * DBY-W09 W1: synchronous normal-PID-1 execution witness.
 *
 * This program is libc-free, single-process, and syscall-only. It does not
 * execute stock init or Lineage init. It captures a bounded current-kmsg
 * snapshot, reads back a nonce-bearing userspace marker through /dev/kmsg,
 * publishes one checksummed record on the prequalified log filesystem, then
 * requests RESTART2("edl").
 */

#ifndef DBY_W1_NONCE_HEX
#error "DBY_W1_NONCE_HEX must be a quoted 32-character lowercase hex string"
#endif

#ifndef DBY_WITNESS_MARKER_PREFIX
#define DBY_WITNESS_MARKER_PREFIX "DBY_W1_USERSPACE_MARKER nonce="
#endif

#ifndef DBY_PUBLICATION_PROTOCOL
#define DBY_PUBLICATION_PROTOCOL \
    "O_EXCL fsync(file) renameat2(RENAME_NOREPLACE) fsync(dir) umount"
#endif

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned long usize;
typedef long isize;

enum {
    SYS_MKNODAT = 33,
    SYS_MKDIRAT = 34,
    SYS_UMOUNT2 = 39,
    SYS_MOUNT = 40,
    SYS_OPENAT = 56,
    SYS_CLOSE = 57,
    SYS_LSEEK = 62,
    SYS_READ = 63,
    SYS_WRITE = 64,
    SYS_PREAD64 = 67,
    SYS_FSYNC = 82,
    SYS_SYNC = 81,
    SYS_NANOSLEEP = 101,
    SYS_CLOCK_GETTIME = 113,
    SYS_REBOOT = 142,
    SYS_GETPID = 172,
    SYS_EXIT = 93,
    SYS_RENAMEAT2 = 276,
};

enum {
    AT_FDCWD = -100,
    O_RDONLY = 0,
    O_WRONLY = 1,
    O_CREAT = 0100,
    O_EXCL = 0200,
    O_NONBLOCK = 04000,
    /* arm64 UAPI values; these intentionally differ from asm-generic. */
    O_DIRECTORY = 040000,
    O_NOFOLLOW = 0100000,
    O_CLOEXEC = 02000000,
    S_IFCHR = 0020000,
    S_IFBLK = 0060000,
    SEEK_SET = 0,
    SEEK_END = 2,
    MS_NOSUID = 2,
    MS_NODEV = 4,
    MS_NOEXEC = 8,
    MS_NOATIME = 1024,
    RENAME_NOREPLACE = 1,
    EAGAIN = 11,
    EBUSY = 16,
    EEXIST = 17,
    EPIPE = 32,
    EBADMSG = 74,
    ETIMEDOUT = 110,
    EINTR = 4,
    MAX_PAYLOAD = 128 * 1024,
    MAX_KMSG_SNAPSHOT = 64 * 1024,
    MAX_KMSG_MARKER = 4096,
    FILE_BUFFER_SIZE = 8192,
};

enum {
    FLAG_PID1 = 1u << 0,
    FLAG_SELF_HASH = 1u << 1,
    FLAG_KMSG_MARKER_READBACK = 1u << 2,
    FLAG_LOG_IDENTITY = 1u << 3,
    FLAG_PAYLOAD_TRUNCATED = 1u << 4,
    FLAG_PROC_READY = 1u << 5,
    FLAG_SYS_READY = 1u << 6,
    FLAG_LOG_MOUNTED = 1u << 7,
};

static const u64 LINUX_REBOOT_MAGIC1 = 0xFEE1DEADu;
static const u64 LINUX_REBOOT_MAGIC2 = 672274793u;
static const u64 LINUX_REBOOT_CMD_RESTART2 = 0xA1B2C3D4u;
static const u64 EXPECTED_LOG_SECTORS_512 = 163840u;
static const u32 EXPECTED_LOG_MAJOR = 8u;
static const u32 EXPECTED_LOG_MINOR = 12u;

static const char nonce_hex[] = DBY_W1_NONCE_HEX;
static const char expected_log_devname[] = "sda12";
static const char expected_log_partuuid[] =
    "906d7124-62f7-d1c8-ffbf-73c97575983f";
static const char expected_log_fsuuid_hex[] =
    "e3ff96a22fe448d28c2daef8d068275d";
static const char expected_log_uevent_line[] = "PARTNAME=log";
static const char publication_protocol[] =
    DBY_PUBLICATION_PROTOCOL;
static const u8 expected_log_fsuuid[16] = {
    0xe3, 0xff, 0x96, 0xa2, 0x2f, 0xe4, 0x48, 0xd2,
    0x8c, 0x2d, 0xae, 0xf8, 0xd0, 0x68, 0x27, 0x5d,
};

_Static_assert(sizeof(nonce_hex) == 33, "nonce must contain 32 hex characters");

struct dby_timespec {
    isize tv_sec;
    isize tv_nsec;
};

struct sha256_context {
    u8 block[64];
    u32 state[8];
    u64 total_bytes;
    usize block_length;
};

struct witness_header {
    u8 magic[8];
    u32 version;
    u32 header_size;
    u32 payload_size;
    u32 flags;
    char nonce[32];
    u8 reserved[8];
};

_Static_assert(sizeof(struct witness_header) == 64, "unexpected witness header size");

struct block_identity {
    u32 major;
    u32 minor;
    u64 sectors_512;
    int partuuid_exported;
    char devname[32];
    char partuuid[64];
};

static u8 payload[MAX_PAYLOAD];
static usize payload_length;
static int payload_truncated;
static u8 kmsg_snapshot[MAX_KMSG_SNAPSHOT];
static usize kmsg_snapshot_length;
static int kmsg_snapshot_truncated;
static u8 kmsg_marker[MAX_KMSG_MARKER];
static usize kmsg_marker_length;
static u64 kmsg_marker_priority;
static u64 kmsg_marker_sequence;
static u64 kmsg_marker_timestamp_us;
static int kmsg_marker_vendor_prefixed;
static char file_buffer[FILE_BUFFER_SIZE];
static char path_buffer[192];
static char temp_name[80];
static char final_name[80];
static struct block_identity log_identity;

static inline isize dby_syscall0(isize number) {
    register isize x0 __asm__("x0");
    register isize x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
}

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

static void dby_memzero(void *destination, usize length) {
    u8 *output = (u8 *)destination;
    for (usize index = 0; index < length; ++index) {
        output[index] = 0;
    }
}

static void dby_memcpy(void *destination, const void *source, usize length) {
    u8 *output = (u8 *)destination;
    const u8 *input = (const u8 *)source;
    for (usize index = 0; index < length; ++index) {
        output[index] = input[index];
    }
}

static int dby_memequal(const void *left, const void *right, usize length) {
    const u8 *a = (const u8 *)left;
    const u8 *b = (const u8 *)right;
    u8 difference = 0;
    for (usize index = 0; index < length; ++index) {
        difference |= (u8)(a[index] ^ b[index]);
    }
    return difference == 0;
}

static int dby_strequal(const char *left, const char *right) {
    usize index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) {
            return 0;
        }
        ++index;
    }
    return left[index] == right[index];
}

static int dby_contains(const void *haystack, usize haystack_length, const char *needle) {
    const u8 *data = (const u8 *)haystack;
    usize needle_length = dby_strlen(needle);
    if (needle_length == 0 || needle_length > haystack_length) {
        return 0;
    }
    for (usize start = 0; start + needle_length <= haystack_length; ++start) {
        usize index = 0;
        while (index < needle_length && data[start + index] == (u8)needle[index]) {
            ++index;
        }
        if (index == needle_length) {
            return 1;
        }
    }
    return 0;
}

static int dby_has_exact_line(
    const void *input, usize input_length, const char *expected
) {
    const u8 *data = (const u8 *)input;
    usize expected_length = dby_strlen(expected);
    for (usize start = 0; start + expected_length <= input_length; ++start) {
        if (start != 0 && data[start - 1] != '\n') {
            continue;
        }
        if (!dby_memequal(data + start, expected, expected_length)) {
            continue;
        }
        usize end = start + expected_length;
        if (end == input_length || data[end] == '\n' || data[end] == '\r') {
            return 1;
        }
    }
    return 0;
}

static usize dby_u64_decimal(char *output, u64 value) {
    char reversed[32];
    usize length = 0;
    do {
        reversed[length++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value != 0);
    for (usize index = 0; index < length; ++index) {
        output[index] = reversed[length - index - 1];
    }
    return length;
}

static usize dby_i64_decimal(char *output, isize value) {
    usize position = 0;
    u64 magnitude;
    if (value < 0) {
        output[position++] = '-';
        magnitude = (u64)(-(value + 1)) + 1;
    } else {
        magnitude = (u64)value;
    }
    return position + dby_u64_decimal(output + position, magnitude);
}

static void dby_hex(char *output, const u8 *input, usize length) {
    static const char digits[] = "0123456789abcdef";
    for (usize index = 0; index < length; ++index) {
        output[index * 2] = digits[input[index] >> 4];
        output[index * 2 + 1] = digits[input[index] & 15];
    }
}

static int dby_append_raw(const void *data, usize length) {
    if (payload_length + length > MAX_PAYLOAD) {
        payload_truncated = 1;
        return -1;
    }
    dby_memcpy(payload + payload_length, data, length);
    payload_length += length;
    return 0;
}

static int dby_append_text(const char *text) {
    return dby_append_raw(text, dby_strlen(text));
}

static void dby_append_field(const char *name, const void *data, usize length) {
    char number[32];
    usize number_length = dby_u64_decimal(number, (u64)length);
    if (dby_append_text(name) != 0 || dby_append_text(":") != 0 ||
        dby_append_raw(number, number_length) != 0 || dby_append_text("\n") != 0 ||
        dby_append_raw(data, length) != 0 || dby_append_text("\n") != 0) {
        payload_truncated = 1;
    }
}

static void dby_append_status(const char *name, isize value) {
    char number[32];
    usize length = dby_i64_decimal(number, value);
    dby_append_field(name, number, length);
}

static void dby_append_u64(const char *name, u64 value) {
    char number[32];
    usize length = dby_u64_decimal(number, value);
    dby_append_field(name, number, length);
}

static isize dby_openat(isize directory, const char *path, isize flags, isize mode) {
    return dby_syscall4(SYS_OPENAT, directory, (isize)path, flags, mode);
}

static isize dby_open(const char *path, isize flags, isize mode) {
    return dby_openat(AT_FDCWD, path, flags, mode);
}

static isize dby_close(isize descriptor) {
    if (descriptor < 0) {
        return descriptor;
    }
    return dby_syscall1(SYS_CLOSE, descriptor);
}

static isize dby_write_all(isize descriptor, const void *data, usize length) {
    const u8 *cursor = (const u8 *)data;
    while (length != 0) {
        isize result = dby_syscall3(SYS_WRITE, descriptor, (isize)cursor, (isize)length);
        if (result == -EINTR) {
            continue;
        }
        if (result <= 0) {
            return result != 0 ? result : -1;
        }
        cursor += (usize)result;
        length -= (usize)result;
    }
    return 0;
}

static isize dby_read_file(const char *path, void *buffer, usize capacity) {
    isize descriptor = dby_open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (descriptor < 0) {
        return descriptor;
    }
    usize length = 0;
    isize read_error = 0;
    while (length < capacity) {
        isize result = dby_syscall3(
            SYS_READ,
            descriptor,
            (isize)((u8 *)buffer + length),
            (isize)(capacity - length)
        );
        if (result == -EINTR) {
            continue;
        }
        if (result < 0) {
            read_error = result;
            break;
        }
        if (result == 0) {
            break;
        }
        length += (usize)result;
    }
    isize close_result = dby_close(descriptor);
    if (read_error < 0) {
        return read_error;
    }
    return close_result < 0 ? close_result : (isize)length;
}

static isize dby_mount(
    const char *source,
    const char *target,
    const char *filesystem,
    u64 flags,
    const char *data
) {
    return dby_syscall5(
        SYS_MOUNT,
        (isize)source,
        (isize)target,
        (isize)filesystem,
        (isize)flags,
        (isize)data
    );
}

static int dby_mount_ready(isize result) {
    return result == 0;
}

static isize dby_mkdir(const char *path, isize mode) {
    isize result = dby_syscall3(SYS_MKDIRAT, AT_FDCWD, (isize)path, mode);
    return result == -EEXIST ? 0 : result;
}

static u64 dby_makedev(u32 major, u32 minor) {
    return ((u64)(major & 0xfff) << 8) | (minor & 0xff) |
           ((u64)(minor & ~0xffu) << 12);
}

static u32 dby_rotr(u32 value, u32 amount) {
    return (value >> amount) | (value << (32 - amount));
}

static const u32 sha256_constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static void dby_sha256_transform(struct sha256_context *context, const u8 block[64]) {
    u32 words[64];
    for (usize index = 0; index < 16; ++index) {
        words[index] = ((u32)block[index * 4] << 24) |
                       ((u32)block[index * 4 + 1] << 16) |
                       ((u32)block[index * 4 + 2] << 8) |
                       (u32)block[index * 4 + 3];
    }
    for (usize index = 16; index < 64; ++index) {
        u32 s0 = dby_rotr(words[index - 15], 7) ^
                 dby_rotr(words[index - 15], 18) ^ (words[index - 15] >> 3);
        u32 s1 = dby_rotr(words[index - 2], 17) ^
                 dby_rotr(words[index - 2], 19) ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }

    u32 a = context->state[0];
    u32 b = context->state[1];
    u32 c = context->state[2];
    u32 d = context->state[3];
    u32 e = context->state[4];
    u32 f = context->state[5];
    u32 g = context->state[6];
    u32 h = context->state[7];
    for (usize index = 0; index < 64; ++index) {
        u32 sum1 = dby_rotr(e, 6) ^ dby_rotr(e, 11) ^ dby_rotr(e, 25);
        u32 choice = (e & f) ^ ((~e) & g);
        u32 temporary1 = h + sum1 + choice + sha256_constants[index] + words[index];
        u32 sum0 = dby_rotr(a, 2) ^ dby_rotr(a, 13) ^ dby_rotr(a, 22);
        u32 majority = (a & b) ^ (a & c) ^ (b & c);
        u32 temporary2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void dby_sha256_init(struct sha256_context *context) {
    context->state[0] = 0x6a09e667u;
    context->state[1] = 0xbb67ae85u;
    context->state[2] = 0x3c6ef372u;
    context->state[3] = 0xa54ff53au;
    context->state[4] = 0x510e527fu;
    context->state[5] = 0x9b05688cu;
    context->state[6] = 0x1f83d9abu;
    context->state[7] = 0x5be0cd19u;
    context->total_bytes = 0;
    context->block_length = 0;
}

static void dby_sha256_update(
    struct sha256_context *context, const void *input_data, usize length
) {
    const u8 *input = (const u8 *)input_data;
    context->total_bytes += length;
    while (length != 0) {
        usize available = 64 - context->block_length;
        usize chunk = length < available ? length : available;
        dby_memcpy(context->block + context->block_length, input, chunk);
        context->block_length += chunk;
        input += chunk;
        length -= chunk;
        if (context->block_length == 64) {
            dby_sha256_transform(context, context->block);
            context->block_length = 0;
        }
    }
}

static void dby_sha256_final(struct sha256_context *context, u8 digest[32]) {
    u64 total_bits = context->total_bytes * 8;
    context->block[context->block_length++] = 0x80;
    if (context->block_length > 56) {
        while (context->block_length < 64) {
            context->block[context->block_length++] = 0;
        }
        dby_sha256_transform(context, context->block);
        context->block_length = 0;
    }
    while (context->block_length < 56) {
        context->block[context->block_length++] = 0;
    }
    for (usize index = 0; index < 8; ++index) {
        context->block[63 - index] = (u8)(total_bits >> (index * 8));
    }
    dby_sha256_transform(context, context->block);
    for (usize index = 0; index < 8; ++index) {
        digest[index * 4] = (u8)(context->state[index] >> 24);
        digest[index * 4 + 1] = (u8)(context->state[index] >> 16);
        digest[index * 4 + 2] = (u8)(context->state[index] >> 8);
        digest[index * 4 + 3] = (u8)context->state[index];
    }
}

static isize dby_hash_self_exe(u8 digest[32]) {
    isize descriptor = dby_open("/proc/self/exe", O_RDONLY | O_CLOEXEC, 0);
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
            dby_close(descriptor);
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

static u32 dby_read_le16(const u8 *data) {
    return (u32)data[0] | ((u32)data[1] << 8);
}

static u32 dby_read_le32(const u8 *data) {
    return (u32)data[0] | ((u32)data[1] << 8) | ((u32)data[2] << 16) |
           ((u32)data[3] << 24);
}

static u64 dby_parse_decimal(const char *data, usize length, int *valid) {
    u64 value = 0;
    if (length == 0) {
        *valid = 0;
        return 0;
    }
    for (usize index = 0; index < length; ++index) {
        if (data[index] < '0' || data[index] > '9') {
            *valid = 0;
            return 0;
        }
        u64 digit = (u64)(data[index] - '0');
        if (value > (~(u64)0 - digit) / 10u) {
            *valid = 0;
            return 0;
        }
        value = value * 10 + digit;
    }
    *valid = 1;
    return value;
}

static isize dby_extract_line(
    const char *data,
    usize length,
    const char *key,
    char *output,
    usize output_capacity
) {
    usize key_length = dby_strlen(key);
    for (usize start = 0; start + key_length <= length; ++start) {
        if (start != 0 && data[start - 1] != '\n') {
            continue;
        }
        usize index = 0;
        while (index < key_length && data[start + index] == key[index]) {
            ++index;
        }
        if (index != key_length) {
            continue;
        }
        usize end = start + key_length;
        while (end < length && data[end] != '\n') {
            ++end;
        }
        usize value_length = end - (start + key_length);
        if (value_length + 1 > output_capacity) {
            return -1;
        }
        dby_memcpy(output, data + start + key_length, value_length);
        output[value_length] = '\0';
        return (isize)value_length;
    }
    return -1;
}

static int dby_build_block_path(char letter, u32 partition, const char *suffix) {
    usize position = 0;
    const char *prefix = "/sys/class/block/sd";
    usize prefix_length = dby_strlen(prefix);
    usize suffix_length = dby_strlen(suffix);
    if (prefix_length + 1 + 20 + suffix_length + 1 > sizeof(path_buffer)) {
        return -1;
    }
    dby_memcpy(path_buffer + position, prefix, prefix_length);
    position += prefix_length;
    path_buffer[position++] = letter;
    position += dby_u64_decimal(path_buffer + position, partition);
    dby_memcpy(path_buffer + position, suffix, suffix_length);
    position += suffix_length;
    path_buffer[position] = '\0';
    return 0;
}

static int dby_find_log_block(void) {
    char value[96];
    for (char letter = 'a'; letter <= 'f'; ++letter) {
        for (u32 partition = 1; partition <= 64; ++partition) {
            if (dby_build_block_path(letter, partition, "/uevent") != 0) {
                return -1;
            }
            isize length = dby_read_file(path_buffer, file_buffer, sizeof(file_buffer));
            if (length <= 0 ||
                !dby_has_exact_line(
                    file_buffer, (usize)length, expected_log_uevent_line
                )) {
                continue;
            }

            isize major_length = dby_extract_line(
                file_buffer, (usize)length, "MAJOR=", value, sizeof(value)
            );
            int valid = 0;
            if (major_length <= 0) {
                continue;
            }
            u64 major = dby_parse_decimal(value, (usize)major_length, &valid);
            if (!valid) {
                continue;
            }
            isize minor_length = dby_extract_line(
                file_buffer, (usize)length, "MINOR=", value, sizeof(value)
            );
            if (minor_length <= 0) {
                continue;
            }
            u64 minor = dby_parse_decimal(value, (usize)minor_length, &valid);
            if (!valid) {
                continue;
            }
            isize devname_length = dby_extract_line(
                file_buffer,
                (usize)length,
                "DEVNAME=",
                log_identity.devname,
                sizeof(log_identity.devname)
            );
            if (devname_length <= 0) {
                continue;
            }
            if (!dby_strequal(log_identity.devname, expected_log_devname)) {
                continue;
            }
            isize partuuid_length = dby_extract_line(
                file_buffer,
                (usize)length,
                "PARTUUID=",
                log_identity.partuuid,
                sizeof(log_identity.partuuid)
            );
            if (partuuid_length > 0) {
                if (!dby_strequal(
                        log_identity.partuuid, expected_log_partuuid
                    )) {
                    continue;
                }
                log_identity.partuuid_exported = 1;
            } else {
                /* Linux 4.19 normally exports PARTN/PARTNAME, not PARTUUID. */
                if (dby_contains(file_buffer, (usize)length, "PARTUUID=")) {
                    continue;
                }
                log_identity.partuuid[0] = '\0';
                log_identity.partuuid_exported = 0;
            }
            if (major != EXPECTED_LOG_MAJOR || minor != EXPECTED_LOG_MINOR) {
                continue;
            }

            if (dby_build_block_path(letter, partition, "/size") != 0) {
                continue;
            }
            length = dby_read_file(path_buffer, file_buffer, sizeof(file_buffer));
            if (length <= 0) {
                continue;
            }
            usize digits = 0;
            while (digits < (usize)length && file_buffer[digits] >= '0' &&
                   file_buffer[digits] <= '9') {
                ++digits;
            }
            u64 sectors = dby_parse_decimal(file_buffer, digits, &valid);
            if (!valid || sectors != EXPECTED_LOG_SECTORS_512) {
                continue;
            }
            log_identity.major = (u32)major;
            log_identity.minor = (u32)minor;
            log_identity.sectors_512 = sectors;
            return 0;
        }
    }
    return -1;
}

static int dby_verify_log_superblock(void) {
    u8 superblock[1024];
    dby_memzero(superblock, sizeof(superblock));
    isize descriptor = dby_open("/dev/dby-log-block", O_RDONLY | O_CLOEXEC, 0);
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
    u32 block_count = dby_read_le32(superblock + 0x04);
    u32 free_blocks = dby_read_le32(superblock + 0x0c);
    u32 log_block_size = dby_read_le32(superblock + 0x18);
    u32 magic = dby_read_le16(superblock + 0x38);
    u32 state = dby_read_le16(superblock + 0x3a);
    u32 feature_compat = dby_read_le32(superblock + 0x5c);
    u32 feature_incompat = dby_read_le32(superblock + 0x60);
    u32 feature_ro_compat = dby_read_le32(superblock + 0x64);
    u32 journal_inode = dby_read_le32(superblock + 0xe0);
    if (magic != 0xef53 || state != 1 || block_count != 20480 ||
        log_block_size != 2 || free_blocks < 256 || feature_compat != 0x3c ||
        feature_incompat != 0x42 || feature_ro_compat != 0x7b ||
        journal_inode != 8 ||
        !dby_memequal(superblock + 0x68, expected_log_fsuuid, 16)) {
        return -1;
    }
    return 0;
}

static void dby_append_file(const char *field, const char *path) {
    isize length = dby_read_file(path, file_buffer, sizeof(file_buffer));
    if (length >= 0) {
        dby_append_field(field, file_buffer, (usize)length);
    } else {
        dby_append_status(field, length);
    }
}

static u64 dby_monotonic_ns(isize *status) {
    struct dby_timespec time;
    dby_memzero(&time, sizeof(time));
    isize result = dby_syscall2(SYS_CLOCK_GETTIME, 1, (isize)&time);
    *status = result;
    if (result < 0) {
        return 0;
    }
    return (u64)time.tv_sec * 1000000000u + (u64)time.tv_nsec;
}

static void dby_capture_kmsg_snapshot(void) {
    isize descriptor = dby_open(
        "/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW, 0
    );
    dby_append_status("KMSG_SNAPSHOT_OPEN", descriptor);
    if (descriptor < 0) {
        return;
    }
    isize seek_result = dby_syscall3(SYS_LSEEK, descriptor, 0, SEEK_SET);
    dby_append_status("KMSG_SNAPSHOT_SEEK", seek_result);
    for (usize iteration = 0; iteration < 1024; ++iteration) {
        isize result = dby_syscall3(
            SYS_READ, descriptor, (isize)file_buffer, (isize)sizeof(file_buffer)
        );
        if (result == -EINTR) {
            continue;
        }
        if (result <= 0) {
            break;
        }
        usize available = MAX_KMSG_SNAPSHOT - kmsg_snapshot_length;
        usize retained = (usize)result < available ? (usize)result : available;
        dby_memcpy(kmsg_snapshot + kmsg_snapshot_length, file_buffer, retained);
        kmsg_snapshot_length += retained;
        if (retained != (usize)result) {
            kmsg_snapshot_truncated = 1;
            break;
        }
    }
    dby_append_status("KMSG_SNAPSHOT_CLOSE", dby_close(descriptor));
}

static void dby_build_marker(char *output, usize capacity) {
    const char *prefix = DBY_WITNESS_MARKER_PREFIX;
    usize prefix_length = dby_strlen(prefix);
    usize nonce_length = dby_strlen(nonce_hex);
    if (prefix_length + nonce_length + 2 > capacity) {
        output[0] = '\0';
        return;
    }
    dby_memcpy(output, prefix, prefix_length);
    dby_memcpy(output + prefix_length, nonce_hex, nonce_length);
    output[prefix_length + nonce_length] = '\n';
    output[prefix_length + nonce_length + 1] = '\0';
}

static int dby_marker_flag_character(char value) {
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '+' || value == '_' ||
           value == '-';
}

static isize dby_vendor_timestamp_prefix_length(const char *data, usize length) {
    static const char separators[] = "[:: ::]";
    static const u8 separator_offsets[] = {0, 5, 8, 11, 14, 17, 20};
    if (length < 21) {
        return 0;
    }
    for (usize index = 0; index < sizeof(separator_offsets); ++index) {
        if (data[separator_offsets[index]] != separators[index]) {
            return 0;
        }
    }
    for (usize cursor = 1; cursor < 20; ++cursor) {
        if (cursor == 5 || cursor == 8 || cursor == 11 || cursor == 14 ||
            cursor == 17) {
            continue;
        }
        if (data[cursor] < '0' || data[cursor] > '9') {
            return 0;
        }
    }
    return 21;
}

static isize dby_vendor_caller_prefix_length(const char *data, usize length) {
    isize timestamp_prefix_length = dby_vendor_timestamp_prefix_length(data, length);
    usize prefix_length = timestamp_prefix_length > 0
                              ? (usize)timestamp_prefix_length
                              : 0;
    if (prefix_length >= length || data[prefix_length] != '(') {
        return 0;
    }
    usize cursor = prefix_length + 1;
    usize cpu_start = cursor;
    while (cursor < length && data[cursor] >= '0' && data[cursor] <= '9') {
        ++cursor;
    }
    int valid = 0;
    (void)dby_parse_decimal(data + cpu_start, cursor - cpu_start, &valid);
    if (!valid || cursor + 2 >= length || data[cursor] != ')' ||
        data[cursor + 1] != '[') {
        return -EBADMSG;
    }
    cursor += 2;
    usize pid_start = cursor;
    while (cursor < length && data[cursor] >= '0' && data[cursor] <= '9') {
        ++cursor;
    }
    u64 pid = dby_parse_decimal(data + pid_start, cursor - pid_start, &valid);
    if (!valid || pid != 1 || cursor >= length || data[cursor] != ':') {
        return -EBADMSG;
    }
    usize command_start = ++cursor;
    while (cursor < length && data[cursor] != ']') {
        unsigned char value = (unsigned char)data[cursor];
        if (value < 0x21 || value > 0x7e || cursor - command_start >= 32) {
            return -EBADMSG;
        }
        ++cursor;
    }
    if (cursor == command_start || cursor >= length || data[cursor] != ']') {
        return -EBADMSG;
    }
    return (isize)(cursor + 1);
}

static int dby_validate_kmsg_marker_record(
    const char *data,
    usize length,
    const char *expected_message,
    usize expected_message_length,
    u64 *priority,
    u64 *sequence,
    u64 *timestamp_us,
    int *vendor_prefixed
) {
    *vendor_prefixed = 0;
    if (length != 0 && data[length - 1] == '\n') {
        --length;
    }
    usize cursor = 0;
    usize number_start = 0;
    int valid = 0;
    while (cursor < length && data[cursor] != ',') {
        ++cursor;
    }
    if (cursor == length) {
        return -EBADMSG;
    }
    *priority = dby_parse_decimal(data + number_start, cursor - number_start, &valid);
    if (!valid || *priority > 191u) {
        return -EBADMSG;
    }
    number_start = ++cursor;
    while (cursor < length && data[cursor] != ',') {
        ++cursor;
    }
    if (cursor == length) {
        return -EBADMSG;
    }
    *sequence = dby_parse_decimal(data + number_start, cursor - number_start, &valid);
    if (!valid) {
        return -EBADMSG;
    }
    number_start = ++cursor;
    while (cursor < length && data[cursor] != ',') {
        ++cursor;
    }
    if (cursor == length) {
        return -EBADMSG;
    }
    *timestamp_us = dby_parse_decimal(
        data + number_start, cursor - number_start, &valid
    );
    if (!valid || *timestamp_us == 0) {
        return -EBADMSG;
    }
    usize flags_start = ++cursor;
    while (cursor < length && data[cursor] != ';') {
        if (!dby_marker_flag_character(data[cursor])) {
            return -EBADMSG;
        }
        ++cursor;
    }
    if (cursor == flags_start || cursor == length) {
        return -EBADMSG;
    }
    usize message_start = cursor + 1;
    usize message_length = length - message_start;
    const char *message = data + message_start;
    if (message_length != expected_message_length ||
        !dby_memequal(message, expected_message, expected_message_length)) {
        isize prefix_length = dby_vendor_caller_prefix_length(
            message, message_length
        );
        if (prefix_length <= 0 ||
            message_length - (usize)prefix_length != expected_message_length ||
            !dby_memequal(
                message + prefix_length,
                expected_message,
                expected_message_length
            )) {
            return -EBADMSG;
        }
        *vendor_prefixed = 1;
    }
    return 0;
}

static int dby_capture_kmsg_marker(void) {
    char marker[96];
    dby_build_marker(marker, sizeof(marker));
    isize reader = dby_open(
        "/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW, 0
    );
    dby_append_status("KMSG_MARKER_READER_OPEN", reader);
    if (reader < 0) {
        return -1;
    }
    isize seek_result = dby_syscall3(SYS_LSEEK, reader, 0, SEEK_END);
    dby_append_status("KMSG_MARKER_SEEK_END", seek_result);
    if (seek_result < 0) {
        dby_close(reader);
        return -1;
    }
    isize writer = dby_open("/dev/kmsg", O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    dby_append_status("KMSG_MARKER_WRITER_OPEN", writer);
    if (writer < 0) {
        dby_close(reader);
        return -1;
    }
    isize write_result = dby_write_all(writer, marker, dby_strlen(marker));
    dby_append_status("KMSG_MARKER_WRITE", write_result);
    dby_append_status("KMSG_MARKER_WRITER_CLOSE", dby_close(writer));
    if (write_result < 0) {
        dby_close(reader);
        return -1;
    }

    const struct dby_timespec delay = {0, 10000000};
    isize clock_status = 0;
    u64 start_ns = dby_monotonic_ns(&clock_status);
    for (usize iteration = 0; iteration < 200; ++iteration) {
        isize result = dby_syscall3(
            SYS_READ, reader, (isize)file_buffer, (isize)sizeof(file_buffer)
        );
        if (result == -EINTR) {
            continue;
        }
        if (result > 0) {
            usize marker_length = dby_strlen(marker);
            usize expected_message_length = marker_length - 1;
            int validation = dby_validate_kmsg_marker_record(
                file_buffer,
                (usize)result,
                marker,
                expected_message_length,
                &kmsg_marker_priority,
                &kmsg_marker_sequence,
                &kmsg_marker_timestamp_us,
                &kmsg_marker_vendor_prefixed
            );
            if (validation == 0) {
                usize retained = (usize)result < MAX_KMSG_MARKER
                                     ? (usize)result
                                     : MAX_KMSG_MARKER;
                dby_memcpy(kmsg_marker, file_buffer, retained);
                kmsg_marker_length = retained;
                dby_append_status("KMSG_MARKER_READER_CLOSE", dby_close(reader));
                return 0;
            }
            if (dby_contains(file_buffer, (usize)result, nonce_hex) ||
                dby_contains(
                    file_buffer, (usize)result, "DBY_W1_USERSPACE_MARKER"
                )) {
                usize retained = (usize)result < MAX_KMSG_MARKER
                                     ? (usize)result
                                     : MAX_KMSG_MARKER;
                dby_memcpy(kmsg_marker, file_buffer, retained);
                kmsg_marker_length = retained;
                dby_append_status("KMSG_MARKER_READ", validation);
                dby_close(reader);
                return validation;
            }
        } else if (result != -EAGAIN) {
            dby_append_status("KMSG_MARKER_READ", result);
            dby_close(reader);
            return result == -EPIPE ? -EPIPE : result;
        }
        isize now_status = 0;
        u64 now_ns = dby_monotonic_ns(&now_status);
        if (clock_status == 0 && now_status == 0 && now_ns - start_ns > 1000000000u) {
            break;
        }
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }
    dby_append_status("KMSG_MARKER_READER_CLOSE", dby_close(reader));
    return -ETIMEDOUT;
}

static void dby_make_names(void) {
    const char *temp_prefix = ".dby-normal-witness-";
    const char *final_prefix = "dby-normal-witness-";
    usize nonce_length = dby_strlen(nonce_hex);
    usize temp_prefix_length = dby_strlen(temp_prefix);
    usize final_prefix_length = dby_strlen(final_prefix);
    dby_memcpy(temp_name, temp_prefix, temp_prefix_length);
    dby_memcpy(temp_name + temp_prefix_length, nonce_hex, nonce_length);
    dby_memcpy(temp_name + temp_prefix_length + nonce_length, ".tmp", 5);
    dby_memcpy(final_name, final_prefix, final_prefix_length);
    dby_memcpy(final_name + final_prefix_length, nonce_hex, nonce_length);
    dby_memcpy(final_name + final_prefix_length + nonce_length, ".bin", 5);
}

static isize dby_publish_record(u32 flags) {
    struct witness_header header;
    dby_memzero(&header, sizeof(header));
    dby_memcpy(header.magic, "DBYW1REC", 8);
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
        "/dby-audit-log",
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
        dby_close(directory);
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
    close_result = dby_close(directory);
    if (result == 0 && close_result < 0) {
        result = close_result;
    }
    return result;
}

static void dby_emit_kmsg_result(const char *prefix, isize value) {
    char message[128];
    usize position = 0;
    usize prefix_length = dby_strlen(prefix);
    dby_memcpy(message + position, prefix, prefix_length);
    position += prefix_length;
    position += dby_i64_decimal(message + position, value);
    message[position++] = '\n';
    isize descriptor = dby_open("/dev/kmsg", O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (descriptor >= 0) {
        (void)dby_write_all(descriptor, message, position);
        (void)dby_close(descriptor);
    }
}

static isize dby_request_reboot(const char *target) {
    return dby_syscall4(
        SYS_REBOOT,
        (isize)LINUX_REBOOT_MAGIC1,
        (isize)LINUX_REBOOT_MAGIC2,
        (isize)LINUX_REBOOT_CMD_RESTART2,
        (isize)target
    );
}

#ifndef DBY_W1_LIBRARY_TEST
__attribute__((noreturn, visibility("default"))) void dby_start(void) {
    u32 flags = 0;
    dby_make_names();
    dby_append_field("FORMAT", "DBY-W09-W1", 10);
    dby_append_field("NONCE", nonce_hex, 32);

    isize pid = dby_syscall0(SYS_GETPID);
    dby_append_status("PID", pid);
    if (pid == 1) {
        flags |= FLAG_PID1;
    }

    isize mkdir_result = dby_mkdir("/proc", 0755);
    dby_append_status("MKDIR_PROC", mkdir_result);
    mkdir_result = dby_mkdir("/sys", 0755);
    dby_append_status("MKDIR_SYS", mkdir_result);
    mkdir_result = dby_mkdir("/dev", 0755);
    dby_append_status("MKDIR_DEV", mkdir_result);
    mkdir_result = dby_mkdir("/dby-audit-log", 0755);
    dby_append_status("MKDIR_LOG_MOUNT", mkdir_result);

    isize proc_result = dby_mount(
        "proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, ""
    );
    dby_append_status("MOUNT_PROC", proc_result);
    if (dby_mount_ready(proc_result)) {
        flags |= FLAG_PROC_READY;
    }
    isize sys_result = dby_mount(
        "sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, ""
    );
    dby_append_status("MOUNT_SYS", sys_result);
    if (dby_mount_ready(sys_result)) {
        flags |= FLAG_SYS_READY;
    }
    isize dev_result = dby_mount(
        "tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=1m"
    );
    dby_append_status("MOUNT_DEV_TMPFS", dev_result);

    isize kmsg_node_result = dev_result == 0
                                 ? dby_syscall4(
                                       SYS_MKNODAT,
                                       AT_FDCWD,
                                       (isize)"/dev/kmsg",
                                       S_IFCHR | 0600,
                                       (isize)dby_makedev(1, 11)
                                   )
                                 : dev_result;
    dby_append_status("MKNOD_KMSG", kmsg_node_result);

    dby_append_file("BOOT_ID", "/proc/sys/kernel/random/boot_id");
    dby_append_file("CMDLINE", "/proc/cmdline");
    dby_append_file("KERNEL_VERSION", "/proc/version");
    isize clock_status = 0;
    u64 monotonic_start = dby_monotonic_ns(&clock_status);
    dby_append_status("CLOCK_GETTIME_START", clock_status);
    dby_append_u64("MONOTONIC_START_NS", monotonic_start);

    u8 self_digest[32];
    isize self_hash_result = dby_hash_self_exe(self_digest);
    dby_append_status("SELF_SHA256_STATUS", self_hash_result);
    if (self_hash_result == 0) {
        char self_hex[64];
        dby_hex(self_hex, self_digest, sizeof(self_digest));
        dby_append_field("SELF_SHA256", self_hex, sizeof(self_hex));
        flags |= FLAG_SELF_HASH;
    }

    dby_capture_kmsg_snapshot();
    dby_append_field("KMSG_SNAPSHOT", kmsg_snapshot, kmsg_snapshot_length);
    dby_append_status("KMSG_SNAPSHOT_TRUNCATED", kmsg_snapshot_truncated);
    int marker_result = dby_capture_kmsg_marker();
    dby_append_status("KMSG_MARKER_STATUS", marker_result);
    dby_append_field("KMSG_MARKER_RECORD", kmsg_marker, kmsg_marker_length);
    if (marker_result == 0) {
        dby_append_u64("KMSG_MARKER_PRIORITY", kmsg_marker_priority);
        dby_append_u64("KMSG_MARKER_SEQUENCE", kmsg_marker_sequence);
        dby_append_u64("KMSG_MARKER_TIMESTAMP_US", kmsg_marker_timestamp_us);
        dby_append_status(
            "KMSG_MARKER_VENDOR_PREFIXED", kmsg_marker_vendor_prefixed
        );
        flags |= FLAG_KMSG_MARKER_READBACK;
    }

    int find_result = dby_find_log_block();
    dby_append_status("LOG_DISCOVERY", find_result);
    if (find_result == 0) {
        dby_append_field("LOG_DEVNAME", log_identity.devname, dby_strlen(log_identity.devname));
        dby_append_field(
            "LOG_EXPECTED_PARTUUID", expected_log_partuuid,
            dby_strlen(expected_log_partuuid)
        );
        dby_append_status(
            "LOG_PARTUUID_EXPORTED", log_identity.partuuid_exported
        );
        if (log_identity.partuuid_exported) {
            dby_append_field(
                "LOG_PARTUUID", log_identity.partuuid,
                dby_strlen(log_identity.partuuid)
            );
        }
        dby_append_u64("LOG_MAJOR", log_identity.major);
        dby_append_u64("LOG_MINOR", log_identity.minor);
        dby_append_u64("LOG_SECTORS_512", log_identity.sectors_512);
        isize block_node_result = dev_result == 0
                                      ? dby_syscall4(
                                            SYS_MKNODAT,
                                            AT_FDCWD,
                                            (isize)"/dev/dby-log-block",
                                            S_IFBLK | 0600,
                                            (isize)dby_makedev(
                                                log_identity.major,
                                                log_identity.minor
                                            )
                                        )
                                      : dev_result;
        dby_append_status("MKNOD_LOG_BLOCK", block_node_result);
        int superblock_result = block_node_result == 0
                                    ? dby_verify_log_superblock()
                                    : (int)block_node_result;
        dby_append_status("LOG_SUPERBLOCK_VERIFY", superblock_result);
        dby_append_field(
            "LOG_EXPECTED_FSUUID", expected_log_fsuuid_hex,
            dby_strlen(expected_log_fsuuid_hex)
        );
        if (superblock_result == 0) {
            flags |= FLAG_LOG_IDENTITY;
        }
    }

    isize log_mount_result = -1;
    if ((flags & FLAG_LOG_IDENTITY) != 0) {
        log_mount_result = dby_mount(
            "/dev/dby-log-block",
            "/dby-audit-log",
            "ext4",
            MS_NOSUID | MS_NODEV | MS_NOATIME,
            "noauto_da_alloc,commit=1,nodelalloc"
        );
        if (log_mount_result == 0) {
            flags |= FLAG_LOG_MOUNTED;
        }
    }
    dby_append_status("MOUNT_LOG", log_mount_result);
    dby_append_field(
        "PUBLICATION_PROTOCOL", publication_protocol,
        dby_strlen(publication_protocol)
    );
    isize end_clock_status = 0;
    u64 monotonic_end = dby_monotonic_ns(&end_clock_status);
    dby_append_status("CLOCK_GETTIME_END", end_clock_status);
    dby_append_u64("MONOTONIC_PREPUBLISH_NS", monotonic_end);
    if (payload_truncated) {
        flags |= FLAG_PAYLOAD_TRUNCATED;
    }

    isize publish_result = -1;
    if ((flags & FLAG_LOG_MOUNTED) != 0) {
        publish_result = dby_publish_record(flags);
    }
    dby_emit_kmsg_result("DBY_W1_PUBLISH_RESULT=", publish_result);

    if ((flags & FLAG_LOG_MOUNTED) != 0) {
        isize unmount_result = dby_syscall2(
            SYS_UMOUNT2, (isize)"/dby-audit-log", 0
        );
        dby_emit_kmsg_result("DBY_W1_UNMOUNT_RESULT=", unmount_result);
    }
    (void)dby_syscall0(SYS_SYNC);

    isize reboot_result = dby_request_reboot("edl");
    dby_emit_kmsg_result("DBY_W1_REBOOT_EDL_RETURNED=", reboot_result);
    reboot_result = dby_request_reboot("bootloader");
    dby_emit_kmsg_result("DBY_W1_REBOOT_BOOTLOADER_RETURNED=", reboot_result);

    const struct dby_timespec delay = {1, 0};
    for (;;) {
        (void)dby_syscall2(SYS_NANOSLEEP, (isize)&delay, 0);
    }
}

__asm__(
    ".text\n"
    ".global _start\n"
    ".type _start,%function\n"
    "_start:\n"
    "bl dby_start\n"
    "mov x0, #127\n"
    "mov x8, #93\n"
    "svc #0\n"
    "b .\n"
);
#endif
