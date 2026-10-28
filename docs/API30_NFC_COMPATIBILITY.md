# API30 NFC legacy-compatibility milestone

## Why clean userdata did not solve the boot

The Android 11/API30 candidate reached second-stage init but repeatedly entered
Huawei Recovery with `set_policy_failed:/data/nfc`. A vendor Recovery factory
reset removed stale-userdata ambiguity, yet a clean-data API30 boot reproduced
the same reason.

Two system-side controls then isolated the rule:

1. removing only the explicit `encryption=Require` argument still failed;
2. removing the complete system-side NFC mkdir still failed, leaving Huawei's
   Android 10 vendor rc line `mkdir /data/nfc` as the remaining caller.

Android 11 init infers fscrypt action Require for otherwise unknown top-level
`/data/*` directories. Therefore a legacy plain vendor mkdir can become fatal
even though it did not spell out an encryption action.

## Rejected vendor edit

A direct experiment changed two `mkdir` tokens inside vendor EROFS. It was
later invalidated before reuse: both changes were inside the vendor AVB
footer's authenticated original payload, while the candidate preserved the
old footer, vbmeta and hash-tree metadata. Its observed endpoint cannot prove
execution of the modified vendor userspace.

This distinction matters generally: a byte-exact patch can still be an invalid
boot candidate when authenticated partition metadata is not rebuilt.

## System-init-only repair

The accepted v4 leaves vendor, ODM, hw_product and cust byte-identical. It
changes only two AArch64 MOVZ instructions in the exact Android 11
`/system/bin/init`. Those instructions construct one three-byte member of the
inlined inferred-action exclusion list:

```text
52800d24 528e6cee    # constructs "gsi"
52800c64 528ccdce    # constructs "nfc"
```

Five encoded bytes change. Legacy plain `/data/nfc` now resolves to fscrypt
action None. `/data/gsi` remains None because `gsid.rc` explicitly specifies
`encryption=None`; only its redundant inferred exception is repurposed.

Qualified identities:

| Artifact | SHA-256 |
|---|---|
| patched init | `349f2f8dc2e51d6e4d02b183a9c2e236314f32a679a61298bfeac0426d02ec4a` |
| patched system | `c411632f32664678005296281f78ccf3978f24363b247968de6e67e24cc094f5` |
| v4 super | `23b9dfa572241cf6ca3ccf7025f163db5de918cd8dc13ee73a80486eb5b06598` |

Independent system/super builds and normalized qualification reports were
byte-identical. The init inode, ownership, mode, SELinux xattr, file block map,
ext4 UUID/features/clean state and every byte outside the exact patch window
remained fixed.

## Live result

The live gate completely read the installed predecessor and five control
partitions before writing only v4 `super`. The complete 7,692,353,536-byte
postwrite `super` readback matched v4, and boot, ramdisk, vbmeta,
recovery_ramdisk and zero misc remained unchanged.

After one normal reset, Android ADB appeared instead of Recovery. Authorized
runtime evidence established:

- Android 11 / SDK 30, build `RP1A.200720.009`;
- both boot-complete properties and a stopped boot animation;
- `/system/bin/init second_stage` as PID 1;
- zygote64, SystemServer, SurfaceFlinger, Launcher3 and Settings;
- writable file-encrypted F2FS `/data` and SELinux Enforcing;
- retained KernelPatch UID 0 with full capability sets;
- independent visual confirmation of the Android 11 version page.

No firmware, partition image, screenshot, raw log, identifier, Firehose
programmer or live-write automation is distributed here. The public builders
require locally supplied, hash-matching inputs and remain offline-only.

## Remaining limits

This establishes an API30 core-system boot, not a finished device port. A
post-success reboot, Wi-Fi association, Bluetooth, camera capture, acoustic
audio, suspend/resume and long-duration stability remain unverified. The AOSP
security patch level is `2020-09-05`, so this milestone is a research baseline,
not a claim of modern daily-use security.
