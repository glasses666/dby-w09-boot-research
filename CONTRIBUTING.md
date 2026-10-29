# Contributing

Start with one small, reproducible finding. Describe model/build/API level, the exact failing
stage, relevant redacted errors, input SHA-256 values, the proposed change and its rollback.
Distinguish observations from causes and offline checks from device execution.

Keep PINs, credentials, credential IDs, private keys, whole device dumps and personal
screenshots out of issues and pull requests. Prefer synthetic fixtures to proprietary binaries.

Run the unit tests and `python3 -B tools/validate_public_tree.py --check`. After reviewing
a changed public file set, regenerate its inventory using `--write-manifest`.

Describe AI/tool assistance honestly when relevant, retain upstream notices and cite the
research you build upon. A contribution does not silently change the current license policy;
agree redistribution terms with the maintainer before submitting new code.
