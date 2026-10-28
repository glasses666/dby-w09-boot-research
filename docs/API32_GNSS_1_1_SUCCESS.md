# Android 12/API32 GNSS 1.1 milestone

## Result

The retained DBY-W09 research system now boots Android 12/API32 to a visible
Launcher while keeping the previously qualified boot and vendor chain. This is
the first higher-generation result in this project that closes all of the
following gates in one attempt:

- exact candidate construction and independent whole-image verification;
- fresh device, storage and partition-layout identity;
- complete prewrite and postwrite partition comparisons;
- second-stage init, boot-complete properties and stopped bootanimation;
- read-only `vendor-verity`, SELinux Enforcing and encrypted writable data;
- stable keystore2, system_suspend, SurfaceFlinger and system_server;
- visible GNSS 1.0, 1.1 and 2.0 instances, enabled GPS provider and active
  GNSS Manager;
- visible Settings and Launcher UI.

The accepted candidate super has SHA-256
`a2826268ea5566d25ca963ec371f4cd721e25d6d4175b08662b6bbe66d5030a1`.
The runtime framework manifest has SHA-256
`e1709cc931677e71ac3c51257ac9e207060f95f3449b28ec5f676f992640df07`.
No boot image was emitted by this candidate.

## Why one GNSS declaration mattered

The first framework-only attempt declared both inherited GNSS 1.0 and 1.1
versions. Host-side compatibility checks accepted it, but the exact target
API32 `libvintf` aggregation did not: the target implementation rejected the
same-major duplicate declaration before the system reached the old GNSS
boundary.

The correction was established by replaying the actual target-side VINTF
implementation and dependencies against three inputs:

1. the unmodified diagnostic API32 control;
2. the rejected 1.0-plus-1.1 candidate;
3. a source-derived 1.1-only declaration.

The corrected input restored target aggregation while preserving the inherited
1.0 view. Two independent builds then produced byte-identical system and super
images. The only system payload change remained inside the existing 3,034-byte
framework manifest span.

## Live gate

The private live workflow did not treat a successful transport command as a
successful system. Before the only write, the complete installed super plus
boot, ramdisk, vbmeta, recovery ramdisk and misc controls were read and compared
with frozen sources. Only physical `super` was written. The complete candidate
and all five protected controls were read again before the only normal reset.

The accepted runtime was then bound to the exact framework manifest hash and
required boot-complete, UI, service and GNSS evidence. The successful candidate
was retained instead of rolling back.

Raw transport logs, screenshots, device identifiers, partition images and the
Firehose programmer remain private and are not required to understand the
published source-level result.

## Remaining limits

This milestone proves GNSS registration and framework availability, not an
actual satellite fix. It also does not yet prove reboot persistence,
suspend/resume, camera, audio, Bluetooth, Wi-Fi, DRM or long-duration stability.
Those surfaces must be tested independently on the retained API32 baseline.

The public scripts intentionally stop at deterministic construction, target
replay, qualification and readback comparison. They do not implement a live
write, reset, erase or one-click flashing workflow.
