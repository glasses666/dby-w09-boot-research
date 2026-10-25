# API29 usable-boot milestone

## Why the baseline changed

The original LineageOS 21 investigation proved progressively later init
boundaries but still combined a modern userspace with an older vendor stack.
The next strategy was to establish a context-closed Android 10/API29 baseline
with VNDK29, matching the device's vendor generation before attempting another
large version jump.

## First API29 failure

The first qualified candidate reached Android second-stage init and then
entered Recovery. Fresh Recovery evidence named
`set_policy_failed:/data/adb`. Static binding mapped that reason to the
`post-fs-data` action:

```text
mkdir /data/adb 0700 root root
```

The directory already existed with a file-encryption policy that the generic
init action could not reapply. This was a localized runtime incompatibility,
not evidence that the kernel or all of second-stage init had failed.

## One-span repair

The repaired builder replaces only that 34-byte action with an equal-length
comment:

```text
# /data/adb exists; skip mkdir
```

The public builder fixes the source hashes, ext4 block map, file offset,
super-partition translation and output hashes. It rejects an unexpected source,
an ambiguous action, path aliasing, an existing output, changed metadata or any
byte difference outside the exact patch span.

Qualified output identities:

| Artifact | SHA-256 |
|---|---|
| repaired system payload | `a5c6c8b481ab494ec7aac0751063c1012ba73a2e16ca611fe3d7bbe823a4515f` |
| repaired super image | `55b043413e9865ed55cb7e6eb1ff152f98ab8ddb9343df0bec1d10e5d7383281` |
| paired boot image | `2fe0e69809aa47ff32e11b4735a4295ce36025e497f38878451390dc50d58fb4` |

These hashes identify private build artifacts; the artifacts themselves are
not distributed here.

## Live result

After complete identity, rollback and readback gates, exactly one normal reset
was issued. ADB was the first observed endpoint 21 seconds later. Fresh runtime
evidence established:

- Android 10 / SDK 29 and `/system/bin/init second_stage` as PID 1;
- `sys.boot_completed=1` and `dev.bootcomplete=1`;
- zygotes, SystemServer, SurfaceFlinger and Launcher3 running;
- a usable AOSP home screen, Settings launch and return to home;
- display and direct-touch mapping, writable `/data`, and initial service
  presence for audio, media, Wi-Fi and sensors;
- reversible Wi-Fi enable/disable at the framework level.

The candidate was deliberately retained after crossing the usable-UI threshold.
That differs from failed probes, whose rollback was part of experiment closure.

## Remaining limits

Camera is not usable: the legacy provider is declared, but CameraService does
not expose a usable back-facing camera. Network association was not attempted,
and the live record does not yet establish Bluetooth, audio playback,
microphone, DRM, suspend/resume, reboot persistence or long-duration stability.

This baseline is valuable because it converts the project from early-boot
blindness into ordinary bring-up work. It is not a claim that API29 is the
desired final system or that a newer Android release will inherit this result.
