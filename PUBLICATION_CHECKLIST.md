# Publication checklist

| Gate | State | Evidence or decision |
|---|---|---|
| Raw research preserved | Pass | Private source tree remains authoritative; this is an isolated snapshot |
| Public tests | Pass | 178 tests run successfully; 19 private-fixture or Docker-only checks skip explicitly |
| Automated redaction and inventory | Pass | `validate_public_tree.py --check` validates the complete distributed inventory |
| Manual identifier review | Pass | No device, USB, host, account-secret or personal-data identifiers are published |
| Redistribution review | Pass | Original source and synthesized findings only; no vendor binary or raw capture |
| License | Deliberately absent | All rights reserved until the owner chooses a license |
| Attribution | Set | Queen_Glasser (@glasses666); no private contact address |
| Remote repository | Set | `https://github.com/glasses666/dby-w09-boot-research` |
| Release artifacts | Source kit | Deterministic manifest-allowlisted ZIP/TAR and SHA-256 checksums; no firmware, partition image, probe binary or prebuilt candidate |
| API30 milestone | Pass | Sanitized rules, offline builders/tests and bounded findings only; no screenshot, identifier, raw log or live-write automation |
| API32 milestone | Pass | Sanitized target replay, deterministic builders/tests and bounded live findings only; no firmware, target binary, identifier, raw log or live-write automation |
| API32 post-boot bring-up | Pass | Sanitized hardware/audio/service findings and source-only overlay/module builders; no vendor binary, built module, GApps package, account data, VPN profile or infrastructure identifier |
| Browser passkey | Pass | Fresh GMS permission failure, narrow repair, CTAP2 assertion and owner-confirmed login; only sanitized excerpts published |
| Reconstruction completeness | Explicitly bounded | Missing diagnostic/input derivation sources included; owner-bound boot and exact host tools still prevent stock-only end-to-end reproduction |
| Citation and attribution | Set | CITATION.cff, AUTHORS.md, COPYRIGHT.md and public milestone links; no worldwide priority or legal protection guarantee |

The Git history starts at this sanitized snapshot. It does not inherit the
private research repository's history or deleted objects.
