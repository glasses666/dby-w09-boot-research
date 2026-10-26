# Research status

## Current result

The latest positive experiment is the API30 v4 candidate. It reached Android
11/SDK30 with second-stage init, both boot-complete properties, writable
file-encrypted data, SELinux Enforcing, SystemServer, SurfaceFlinger,
Launcher3 and Settings. KernelPatch still returned UID 0 with full capability
sets. The readback-verified candidate remains installed.

The current engineering boundary is API30 hardware and persistence acceptance,
not basic Android startup. The successful API29/VNDK29 baseline remains the
rollback reference and explains how the higher-system repair was bounded.

It does **not** prove post-success reboot persistence, Wi-Fi association,
Bluetooth, camera capture, acoustic audio, suspend/resume or long-duration
stability. Its 2020 security patch level is not modern daily-use security.

## Evidence to finding

| Evidence | Observed result | Supported finding | Limit |
|---|---|---|---|
| W1 nonce-bound PID-1 witness | Fresh record bound PID 1, current boot identity, executable hash and current-kernel evidence | Normal kernel reached the custom PID 1 | Stock or Lineage init was not proved |
| W6 endpoint-coded probe | Fresh endpoint followed mounts and `switch_root` | Stock first-stage completed logical mounts and root switch | Lineage init execution was not proved |
| W8/W9 entry probes | Bootstrap linker reached the executable entry shim, `__libc_init` and relocated `main` | Failure moved into unmodified `main` or later work | Framework startup remained unknown |
| API29 context-closed candidate | Recovery recorded `set_policy_failed:/data/adb` | API29 second-stage reached the exact `mkdir /data/adb` post-fs-data action | Android UI had not yet booted |
| Exact fscrypt repair | One 34-byte action was replaced by a same-length comment; every byte outside that span matched | The candidate changed one proved trigger without changing ext4 metadata | Offline qualification alone was not execution evidence |
| API29 repaired live attempt | ADB was the first endpoint after 21 seconds; PID 1 was second-stage init; boot completed; Launcher and Settings were usable | The repaired candidate crossed the previous Recovery boundary and produced the first evidence-complete usable custom-ROM UI | Hardware bring-up remains incomplete |
| API30 clean-data and system-side controls | `set_policy_failed:/data/nfc` remained after clean userdata and removal of the system mkdir | Android 11 init inferred fatal Require for Huawei's legacy plain vendor `/data/nfc` mkdir | This did not yet supply a valid repair |
| Rejected vendor edit | Vendor payload bytes changed while its AVB footer and authentication metadata remained unchanged | The candidate was structurally invalid and its endpoint was not execution evidence | It must not be reused |
| API30 v4 offline repair | Five init instruction bytes repurposed the redundant inferred `gsi` exclusion as `nfc`; all other scoped bytes and metadata matched | The repair was system-only, deterministic and vendor-preserving | Offline qualification was not execution evidence |
| API30 v4 live attempt | Complete pre/post readbacks passed; Android 11 boot completed with encrypted data, Enforcing, Launcher/Settings and retained UID 0 | The NFC compatibility patch crossed the Recovery boundary and produced an accepted API30 core system | Reboot persistence and the remaining hardware matrix are pending |

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
| API30 clean-data controls | Is stale userdata the only reason API30 fails at `/data/nfc`? | No; Android 11 init also infers Require for the vendor plain mkdir |
| API30 vendor edit | Can vendor rc be patched in place while preserving its AVB footer? | No; the experiment is invalidated |
| API30 v4 | Can a vendor-preserving init-only exception cross the NFC boundary? | Yes; Android 11 core system accepted |

## Next research questions

1. Verify one post-success reboot without changing the installed image.
2. Complete reversible API30 smoke tests for network association, Bluetooth,
   camera, acoustic audio and suspend/resume.
3. Preserve the rollbackable API29 reference and current API30 readback
   identities before attempting Android 12L/API32.
4. Treat every newer system as a new compatibility experiment; do not infer
   hardware support or security suitability from API level alone.
