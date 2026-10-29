# Research status

## Current result

The retained GNSS 1.1-only API32 candidate is now a substantially usable
Android 12 tablet baseline. It has crossed repeated cold boots with second-stage
init, both boot-complete properties, SystemServer, SurfaceFlinger, Launcher3,
Enforcing, encrypted data and retained root. Reversible bring-up passed display,
touch, GPU, sensors, storage, Wi-Fi, Bluetooth discovery, camera capture, DRM
capability and nonzero microphone sampling.

Speaker playback was localized beyond the initial hardware-variant hypothesis.
The real TFA9874 amplifier path was correct; missing vendor-enhanced state made
the Audio HAL select an absent Cirrus protection path. A four-byte
hash-qualified candidate restored mono/stereo playback, and a root-managed
single-file bind passed cold-boot machine gates without a partition write.

Optional systemless Google services and a local two-path Android VPN also passed
their bounded acceptance gates. Their packages, account material, server
addresses and credentials remain private.

Browser hardware-passkey authentication now also passed end to end. A fresh
Chrome request reached GMS but stopped at its API32 STORAGE permission check.
Granting GMS only `READ_EXTERNAL_STORAGE` restored the FIDO2 UI, USB YubiKey
CTAP2 assertion and user-confirmed ChatGPT login. See
[the permission-level diagnosis](API32_PASSKEY_AND_TERMUX.md).
The same report bounds the Termux launcher repair: a UID-level harness passed,
while confirmation from the real foreground terminal remains pending.

The current boundary is no longer basic boot or general hardware enumeration.
It is actual satellite positioning, unplugged suspend/resume, rear torch,
Bluetooth pairing, long-duration stability, post-persistence human stereo
confirmation and compatibility with any release newer than API32.

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
| API30 v4 live attempt | Complete pre/post readbacks passed; Android 11 boot completed with encrypted data, Enforcing, Launcher/Settings and retained UID 0 | The NFC compatibility patch crossed the Recovery boundary and produced an accepted API30 core system | Reboot persistence and the remaining hardware matrix were still pending at that stage |
| Exact-target API32 VINTF replay | Target `libvintf` rejected the duplicate same-major GNSS input and accepted the source-derived 1.1-only correction | Host compatibility was insufficient; the target aggregation rule selected the minimal framework change | This was still offline evidence |
| API32 GNSS 1.1-only live attempt | Complete prewrite/write/readback gates passed; boot completed; Launcher was visible; keystore2/system_suspend remained stable; GNSS 1.0/1.1/2.0 and an enabled GPS provider were visible | The corrected framework declaration crossed both the prior service-abort family and GNSS registration boundary while preserving boot/vendor | Satellite fix, persistence and the broader hardware matrix remain open |
| API32 hardware snapshot | Thirteen bounded sections plus reversible app tests covered display/input/GPU, sensors, storage, Wi-Fi, Bluetooth discovery, DRM, camera and microphone | Most daily hardware surfaces work on the retained API32 baseline | GNSS fix, torch, pairing and USB-free suspend remain open |
| API32 speaker candidate | Exact hardware identity, property/arbitration flow, four-byte builder and repeated audible mono/stereo trials agreed | Missing vendor-enhanced state, not the amplifier family, selected the wrong speaker-protection branch | Vendor binary and persistent payload remain private |
| API32 persistent speaker layer | Cold boot retained root and Enforcing; one hash-gated bind produced the candidate live hash and corrected HAL path | Speaker compatibility can be delivered systemlessly without a partition rewrite | The post-persistence left/right sequence passed machine gates but lacks separate human confirmation |
| API32 Google services | Read-only systemless mounts registered GSF, GMS and Play Store; a real account was added with no credential capture | The minimum Google service layer is usable on this API32 build | App download, certification and Integrity are not claimed |
| API32 local VPN | Two private selectable paths returned HTTPS 204 with distinct egress identities through the tablet core | A removable Android VPN layer works without changing the system image | Profile and infrastructure remain private and are not published |
| API32 browser passkey | GMS API149 permission failure, one runtime permission grant, fresh CTAP2 assertion and user-confirmed login | The observed no-popup failure was localized to GMS's STORAGE precheck and repaired at permission level | Scope is the installed API32/GMS combination; no credential or assertion payload is published |

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
| API32 diagnostic baseline | Can Android 12 reach second-stage with early ADB and expose the first framework blocker? | Yes; the blocker localized to GNSS VINTF inheritance |
| API32 target replay | Does target aggregation accept the original two-version framework patch? | No; a 1.1-only source-derived correction restores aggregation |
| API32 corrected live | Does the corrected candidate preserve core services and reach a usable UI? | Yes; boot-complete Launcher, stable core services and GNSS registration |
| API32 hardware bring-up | Do the main tablet hardware surfaces work on the retained system? | Most pass; actual GNSS fix, torch, pairing and USB-free suspend remain open |
| API32 speaker bring-up | Can playback be restored without rewriting vendor? | Yes; a four-byte detector candidate and hash-gated boot-time bind select the correct generic path |
| API32 optional services | Can Google services and a removable VPN coexist with root, Enforcing and the speaker layer? | Yes within the published acceptance limits |
| API32 browser passkey | Can Chrome invoke the existing USB security-key credential? | Yes after one evidence-bound GMS runtime permission repair |

## Next research questions

1. Test actual satellite positioning separately from GNSS registration.
2. Prove suspend and wake with USB absent and a separate return path.
3. Complete rear-torch, Bluetooth-pairing and post-persistence human stereo
   acceptance as separate reversible tests.
4. Run a longer stability window and a real Play Store application download.
5. Treat every newer system as a new compatibility experiment; do not infer
   success from API level alone.
