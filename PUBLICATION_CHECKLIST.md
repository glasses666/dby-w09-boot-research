# Publication checklist

| Gate | State | Evidence or decision |
|---|---|---|
| Raw research preserved | Pass | Private source tree remains authoritative; this is an isolated snapshot |
| Public tests | Pass | 148 tests pass; 18 private-fixture or Docker-only checks skip explicitly |
| Automated redaction and inventory | Pass | `validate_public_tree.py --check` validates all 78 distributed files |
| Manual identifier review | Pass | No device, USB, host, account-secret or personal-data identifiers are published |
| Redistribution review | Pass | Original source and synthesized findings only; no vendor binary or raw capture |
| License | Deliberately absent | All rights reserved until the owner chooses a license |
| Attribution | Set | Queen_Glasser (@glasses666); no private contact address |
| Remote repository | Set | `https://github.com/glasses666/dby-w09-boot-research` |
| Release artifacts | None | No firmware, partition image, probe binary or prebuilt candidate attached |
| API30 milestone | Pass | Sanitized rules, offline builders/tests and bounded findings only; no screenshot, identifier, raw log or live-write automation |
| API32 milestone | Pass | Sanitized target replay, deterministic builders/tests and bounded live findings only; no firmware, target binary, identifier, raw log or live-write automation |
| API32 post-boot bring-up | Pass | Sanitized hardware/audio/service findings and one offline four-byte builder; no vendor binary, module, GApps package, account data, VPN profile or infrastructure identifier |

The Git history starts at this sanitized snapshot. It does not inherit the
private research repository's history or deleted objects.
