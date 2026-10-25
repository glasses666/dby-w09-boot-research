# Research status

## Current result

The latest positive experiment is the repaired API29 candidate. It reached a
stable Android 10 desktop with second-stage init, both boot-complete properties,
SystemServer, SurfaceFlinger and Launcher3 running. Settings opened and the
device returned to the home screen. The candidate remains installed.

The current engineering boundary is hardware bring-up and system generation,
not basic Android startup. Camera is the first localized compatibility gap.
The project can now use this working API29/VNDK29 baseline to evaluate newer
systems without losing the first proven usable state.

It does **not** prove camera, Bluetooth, audio playback, microphone, DRM,
suspend/resume, reboot persistence, long-duration stability or compatibility
with a higher Android release.

## Evidence to finding

| Evidence | Observed result | Supported finding | Limit |
|---|---|---|---|
| W1 nonce-bound PID-1 witness | Fresh record bound PID 1, current boot identity, executable hash and current-kernel evidence | Normal kernel reached the custom PID 1 | Stock or Lineage init was not proved |
| W6 endpoint-coded probe | Fresh endpoint followed mounts and `switch_root` | Stock first-stage completed logical mounts and root switch | Lineage init execution was not proved |
| W8/W9 entry probes | Bootstrap linker reached the executable entry shim, `__libc_init` and relocated `main` | Failure moved into unmodified `main` or later work | Framework startup remained unknown |
| API29 context-closed candidate | Recovery recorded `set_policy_failed:/data/adb` | API29 second-stage reached the exact `mkdir /data/adb` post-fs-data action | Android UI had not yet booted |
| Exact fscrypt repair | One 34-byte action was replaced by a same-length comment; every byte outside that span matched | The candidate changed one proved trigger without changing ext4 metadata | Offline qualification alone was not execution evidence |
| API29 repaired live attempt | ADB was the first endpoint after 21 seconds; PID 1 was second-stage init; boot completed; Launcher and Settings were usable | The repaired candidate crossed the previous Recovery boundary and produced the first evidence-complete usable custom-ROM UI | Hardware bring-up remains incomplete |

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

## Next research questions

1. Preserve the known-good API29 state and localize camera provider/manifest
   compatibility without broadening the boot patch.
2. Complete reversible smoke tests for the unproved hardware and persistence
   surfaces.
3. Freeze a rollbackable API29 reference package before attempting a higher
   Android generation.
4. Treat every newer system as a new compatibility experiment; do not infer
   success from API level alone.
