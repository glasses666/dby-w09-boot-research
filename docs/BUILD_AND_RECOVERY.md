# Build and recovery boundaries

This release kit contains original research source and sanitized findings by
Queen_Glasser (@glasses666). A ZIP or TAR produced by the release tool is a
source archive. It is not a firmware image, recovery package, flashable ROM or
APatch module. Passing the public tests establishes source-level behavior;
it does not establish that another tablet will boot or recover.

## Exact API32 inputs

The accepted recipes describe one owner-operated DBY-W09 and exact,
hash-qualified inputs. Reproduction requires your own lawfully obtained stock
firmware, vendor files, selected system image and the tools/dependencies pinned
by the relevant builder. The public scripts do not obtain those inputs.
Changing hashes to accept a different build creates a new experiment and does
not reproduce the accepted recipe.

[The reconstruction input map](API32_RECONSTRUCTION_INPUTS.md) lists upstream
downloads, exact hashes, the now-published diagnostic stage and locally generated
policy inputs. The final CLI still requires the owner's exact rooted boot;
the complete pipeline is not transferable from stock inputs alone.

The accepted GNSS 1.1-only system/super recipe is documented in
[the API32 milestone](API32_GNSS_1_1_SUCCESS.md), with offline construction in
[the candidate builder](../scripts/build_api32_system_framework_gnss_1_1_candidate.py),
[independent verification](../scripts/verify_api32_system_framework_gnss_1_1_candidate.py)
and [paired-build qualification](../scripts/qualify_api32_system_framework_gnss_1_1_candidate.py).
Exact-target VINTF replay also requires owner-extracted target libraries and
their dependency closure; a host-side compatibility pass is insufficient.
Some image recipes need separately installed native filesystem/image tools;
Python's standard library alone does not rebuild every accepted image.

The full `super` retains private proprietary vendor material. No full image,
vendor ELF, stock dump or other proprietary binary is released without
redistribution rights. Image hashes document identity, not download locations
or redistribution permission. The retained rooted `boot` is device/build
specific and is not transferable. The API32 GNSS candidate emits no boot image;
these sources do not supply a root installer, unlock method or replacement
boot chain. See [the publication boundary](../SOURCE_MAP.md) and
[safety and scope](SAFETY_AND_SCOPE.md).

## Build a speaker module locally

The [four-byte overlay builder](../scripts/build_api32_vendor_enhanced_detector_overlay.py)
accepts your own extracted `libqti_vndfwk_detect.so` only when it matches the
recorded stock library: 14,976-byte little-endian ELF32, SHA-256
`1927811cdf681ab289ae32b73c6e59f94e63b505a7763a445db2942f5e179156`.
It changes exactly four bytes at offset `0x102c`, retaining all other bytes.
The accepted candidate SHA-256 is
`706c5d92e7d6416b9ed194ede6e65e61259565a8d1ffa0dfada3cd096d72560c`.

The source-only [speaker module builder](../scripts/build_api32_speaker_apatch_module.py)
packages that exact candidate into a deterministic APatch module and emits a
separate build manifest. It preserves the original single-file, hash-gated
boot-time bind behavior. Neither the input library, patched ELF nor built
module ZIP is included in the public release.

For an offline local build, run from the repository root with an existing,
private output directory outside this checkout. Supply your own paths in
`STOCK_DETECTOR` and `PRIVATE_OUT`; all named outputs must be new files:

```bash
python3 -B scripts/build_api32_vendor_enhanced_detector_overlay.py \
  --input "$STOCK_DETECTOR" \
  --output "$PRIVATE_OUT/libqti_vndfwk_detect.so" \
  --manifest "$PRIVATE_OUT/speaker-overlay.json"
python3 -B scripts/build_api32_speaker_apatch_module.py \
  --candidate "$PRIVATE_OUT/libqti_vndfwk_detect.so" \
  --output "$PRIVATE_OUT/dby-api32-speaker.zip" \
  --manifest "$PRIVATE_OUT/speaker-module.json"
```

The module targets only `/vendor/lib/libqti_vndfwk_detect.so`. Its
`post-fs-data.sh` checks the candidate and stock identities, accepts an already
active candidate and otherwise bind-mounts the candidate before Audio HAL
startup. It does not rewrite the stock vendor file. APatch installation is a
manual, owner-controlled step requiring an already qualified root environment;
building a module does not install or activate it. Manual installation,
activation and rollback were tested only on the owner's device. This is not a
general APatch compatibility or recovery claim.

The recorded speaker rollback is to disable module
`dby_api32_speaker_compat` and reboot using the owner's established recovery
path. Disabling a bind layer is distinct from restoring an image. Keep a
working way to disable the module when Android cannot start; this repository
provides no automated recovery-root or live-device commands. Audible mono and
stereo trials were accepted before persistence. After persistence, cold-boot
hash/mount/HAL and stereo-frame machine gates passed; a separate human
confirmation of the persistent left/right sequence remains unrecorded. See
[the bring-up findings](API32_DAILY_BRINGUP.md).

## Recovery is a separate acceptance gate

Before any independently authorized live experiment, retain your own exact
stock/recovery inputs, complete rollback material, partition layout and hashes,
and a physically available recovery route. The accepted owner workflow bound
the candidate to fresh identity checks and complete prewrite/postwrite
comparisons while protecting `boot`, `ramdisk`, `vbmeta`, `recovery_ramdisk`
and `misc`. A successful transfer or matching partition hash proves neither
Android startup nor usable audio. Failed startup requires evidence preservation
and the scoped rollback path, not broader writes or a data wipe inferred from
this guide. Recovery acceptance requires verified restoration plus the expected
runtime endpoint. See [the methodology](METHODOLOGY.md).

There are no one-click flash instructions here. Public offline builders and
source archives do not replace the device-specific write/recovery gates.

## Package the public sources

From the repository root, with an existing output directory outside this
checkout:

```bash
python3 -B tools/validate_public_tree.py --check
python3 -B tools/build_research_release.py --output "$RELEASE_OUT/dby-w09-research.zip"
python3 -B tools/build_research_release.py --output "$RELEASE_OUT/dby-w09-research.tar"
```

Set `RELEASE_OUT` to that external directory. The standard-library packager
first invokes the existing validator with `--check`. A stale manifest or
failed publication gate stops packaging before any output is written. It does
not regenerate the manifest: the release owner must review the public inventory
and refresh it through the existing publication workflow before packaging new
files.

Only exact paths listed in `PUBLIC_MANIFEST.json`, plus the manifest itself,
are archived. The packager rechecks sizes and hashes against the bytes it
archives. It never includes `.git` or unlisted/untracked private material;
the validator can also reject extra files before the packager reaches that
allowlist. Archive paths must be safe, unique regular files without symlinks
or extraction collisions. Contents are sorted and archive timestamps,
ownership and permissions are normalized. ZIP entries are stored without
compression; TAR uses uncompressed USTAR. Rebuilding unchanged inputs produces
identical archive bytes, independent of local file times and modes.

Each archive has an adjacent `.sha256` file naming its SHA-256 and basename.
Existing archives or checksum files, including dangling symlinks, are refused.
Output inside the repository is refused, including paths resolving there
through a directory symlink. Use a new output name for each build. The archive
contains the public validator and tests, so an extracted copy can be checked
with the same source-level commands used for the checkout:

```bash
python3 -B -m unittest discover -s tests -p 'test_build_api32_speaker_apatch_module.py' -v
python3 -B tools/validate_public_tree.py --check
```
