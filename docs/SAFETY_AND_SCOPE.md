# Safety and scope

This work was performed on the researcher's own tablet under an explicit,
device-scoped authorization record. The public tree documents research methods
and offline tooling; it does not grant authority over another device.

## Included scope

- offline parsing, image geometry checks and deterministic candidate building;
- minimal early-boot probes whose stage meaning is fixed before execution;
- readback, hash comparison and rollback verification;
- analysis of public Android boot semantics and owner-supplied firmware.
- offline construction of one exact speaker-compatibility candidate and
  sanitized post-boot acceptance findings.

## Deliberately excluded from this tree

- proprietary firmware, partition dumps and Firehose programmer binaries;
- device identifiers, raw USB/Sahara output and personal data;
- persistent-root payloads or a general Huawei unlock bypass;
- Google service packages, account material, VPN profiles, server addresses or
  proxy credentials;
- commands that automatically write, erase, format or reset a live device;
- one-click flashing wrappers.

Even a correctly built image can permanently disable a device when applied to
different firmware, geometry or hardware. Source availability is not a safety
claim. Any future live experiment must independently establish ownership,
identity, rollback material, exact hashes, transport stability and a bounded
write set.
