# Research status

## Current result

The latest positive experiment is the GNSS 1.1-only API32 candidate. It reached
a stable Android 12 desktop with second-stage init, both boot-complete
properties, SystemServer, SurfaceFlinger and Launcher3 running. Settings opened
and the device returned to the home screen. The candidate remains installed.

The current engineering boundary is API32 hardware bring-up and persistence,
not basic Android startup or the old GNSS registration gate. The project can
retain API32 as its working baseline while testing hardware surfaces
independently.

It does **not** prove an actual satellite fix, camera, Bluetooth, audio,
microphone, DRM, Wi-Fi, suspend/resume, reboot persistence, long-duration
stability or compatibility with a release newer than API32.

## Evidence to finding

| Evidence | Observed result | Supported finding | Limit |
|---|---|---|---|
| W1 nonce-bound PID-1 witness | Fresh record bound PID 1, current boot identity, executable hash and current-kernel evidence | Normal kernel reached the custom PID 1 | Stock or Lineage init was not proved |
| W6 endpoint-coded probe | Fresh endpoint followed mounts and `switch_root` | Stock first-stage completed logical mounts and root switch | Lineage init execution was not proved |
| W8/W9 entry probes | Bootstrap linker reached the executable entry shim, `__libc_init` and relocated `main` | Failure moved into unmodified `main` or later work | Framework startup remained unknown |
| API29 context-closed candidate | Recovery recorded `set_policy_failed:/data/adb` | API29 second-stage reached the exact `mkdir /data/adb` post-fs-data action | Android UI had not yet booted |
| Exact fscrypt repair | One 34-byte action was replaced by a same-length comment; every byte outside that span matched | The candidate changed one proved trigger without changing ext4 metadata | Offline qualification alone was not execution evidence |
| API29 repaired live attempt | ADB was the first endpoint after 21 seconds; PID 1 was second-stage init; boot completed; Launcher and Settings were usable | The repaired candidate crossed the previous Recovery boundary and produced the first evidence-complete usable custom-ROM UI | Hardware bring-up remains incomplete |
| Exact-target API32 VINTF replay | Target `libvintf` rejected the duplicate same-major GNSS input and accepted the source-derived 1.1-only correction | Host compatibility was insufficient; the target aggregation rule selected the minimal framework change | This was still offline evidence |
| API32 GNSS 1.1-only live attempt | Complete prewrite/write/readback gates passed; boot completed; Launcher was visible; keystore2/system_suspend remained stable; GNSS 1.0/1.1/2.0 and an enabled GPS provider were visible | The corrected framework declaration crossed both the prior service-abort family and GNSS registration boundary while preserving boot/vendor | Satellite fix, persistence and the broader hardware matrix remain open |

## Chronology

| Stage | Question | Result |
|---|---|---|
| W1 | Can a fresh normal-kernel PID 1 export bound evidence? | Pass |
| W2–W4 | Can capture, SELinux policy and offline compatibility assumptions be closed? | Closed to a live runtime boundary |
| W6 | Did stock first-stage mount and switch root to the selected system? | Pass |
| W7 | Did the selected Lineage init remain observable after exec? | Inconclusive; Recovery followed |
| W8 | Did the bootstrap linker transfer to the Lineage entrypoint? | Pass |
| W9 | Did the original entry shim and libc startup transfer to `main`? | Pass |
| Later private checkpoints | Could the original init path be advanced safely enough to choose a better baseline? | Yes; evidence retained privately |
| API29 baseline | Would a context-closed Android 10/VNDK29 system reach second-stage? | Yes; one `/data/adb` fscrypt action caused Recovery |
| API29 repair | Does removing only that exact action cross the boundary? | Yes; stable AOSP Launcher and Settings |
| API32 diagnostic baseline | Can Android 12 reach second-stage with early ADB and expose the first framework blocker? | Yes; the blocker localized to GNSS VINTF inheritance |
| API32 target replay | Does target aggregation accept the original two-version framework patch? | No; a 1.1-only source-derived correction restores aggregation |
| API32 corrected live | Does the corrected candidate preserve core services and reach a usable UI? | Yes; boot-complete Launcher, stable core services and GNSS registration |

## Next research questions

1. Prove API32 reboot persistence before changing the retained system.
2. Test actual satellite positioning separately from GNSS registration.
3. Complete reversible API32 smoke tests for display/input/GPU, Wi-Fi,
   Bluetooth, audio/microphone, camera, DRM and suspend/resume.
4. Localize each failure to framework, policy, vendor HAL or kernel before
   considering another system generation.
5. Treat every newer system as a new compatibility experiment; do not infer
   success from API level alone.
