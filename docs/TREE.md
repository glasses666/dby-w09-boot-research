# Repository tree

```text
dby-w09-boot-research/
├── README.md                    publication entry and current result
├── SOURCE_MAP.md                private-to-public mapping and exclusions
├── PUBLIC_MANIFEST.json         per-file SHA-256 inventory
├── PUBLICATION_CHECKLIST.md     completed publication gates
├── docs/
│   ├── API29_USABLE_BOOT.md     first usable Android UI milestone
│   ├── API30_NFC_COMPATIBILITY.md Android 11 NFC repair and live result
│   ├── API32_GNSS_1_1_SUCCESS.md accepted Android 12/GNSS milestone
│   ├── RESEARCH_STATUS.md       evidence, limits and next questions
│   ├── BOOT_BOUNDARY.md         proven control-flow boundary
│   ├── METHODOLOGY.md           evidence and rollback discipline
│   ├── SAFETY_AND_SCOPE.md      authorization and non-goals
│   └── TREE.md                  this map
├── evidence/
│   └── public-findings.json     sanitized machine-readable findings
├── private-fixtures/
│   └── README.md                local-only fixture contract; no binaries
├── scripts/
│   ├── audit_rrecord_*.py       persistent-record comparison
│   ├── build_*boot*.py          boot and AVB offline builders
│   ├── build_context_closed_super.py
│   ├── build_api29_fscrypt_adb_fix.py
│   ├── build_api30_*              Android 11 NFC controls and repair
│   ├── build_api32_*             target VINTF replay and GNSS 1.1 candidate
│   ├── audit_api32_*             exact-target replay audit
│   ├── qualify_api32_*           paired-build and replay qualification
│   ├── build_diagnostic_normal_ramdisk.py
│   ├── stream_readback_compare.py complete FIFO readback comparison
│   ├── build_w*.py              staged probe builders
│   ├── w*.c / w*.S              minimal stage witnesses
│   ├── parse_w*.py              strict witness parsers
│   └── verify_w1_live_gate.py   read-only manifest gate
├── tests/
│   ├── fixtures/               sanitized source XML used by semantic tests
│   └── test_*.py               synthetic and fixture-aware tests
└── tools/
    └── validate_public_tree.py  redaction, link and manifest gate
```

The private source tree remains much larger because it preserves raw chronology,
device-specific evidence, screenshots and immutable artifact paths. This
public repository is intentionally a source-and-findings view, not a
recoverable firmware bundle or live flashing workflow.
