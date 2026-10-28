# Boot boundary

The investigation first used single-question probes to locate the failing
Lineage path, then pivoted to a context-closed API29/VNDK29 system that matched
the vendor generation closely enough to reach a usable desktop.

```mermaid
flowchart TD
    A[Huawei ABL and AVB policy] --> B[Stock kernel]
    B --> C[Stock first-stage init]
    C --> D[logical mounts and switch_root]
    D --> E[Android init entry and libc dispatch]
    E --> F[second-stage init]
    F --> G[post-fs-data actions]
    G --> H[zygote and SystemServer]
    H --> I[SurfaceFlinger and Launcher3]
    I --> J[API29 hardware reference]
    J --> K[API30 legacy fscrypt compatibility]
    K --> L[API30 core system]
    L --> M[API32 target VINTF compatibility]
    M --> N[API32 core system and GNSS registration]
    N --> O[API32 hardware and persistence]

    C -. W1 .-> C
    D -. W6 .-> D
    E -. W8 and W9 .-> E
    G -. first API29 attempt localized fscrypt failure .-> G
    I -. repaired API29 live pass .-> I
    K -. clean-data and caller controls .-> K
    L -. init-only v4 live pass .-> L
    M -. exact-target libvintf replay .-> M
    N -. GNSS 1.1-only live pass .-> N
    N:::current
    O:::future

    classDef current fill:#fff4cc,stroke:#9a6b00,color:#241a00;
    classDef future fill:#eef2ff,stroke:#4f46e5,color:#1e1b4b;
```

The original Lineage path remains a valuable control-flow result, but the
strongest live boundary is now later: Android 12/API32 reached second-stage,
boot completion, a usable launcher and Settings, stable core services and GNSS
registration while retaining the qualified boot/vendor chain. An actual
satellite fix, reboot persistence and the remaining hardware surfaces are
outside that proof.

The successful attempt remained bound to fixed candidate hashes, complete
prewrite and postwrite partition comparisons and one declared normal reset.
Familiar UI alone was not accepted as proof: the record also required
second-stage PID 1, fresh boot identity, boot-complete properties, encrypted
writable data, Enforcing, service state, foreground activity and the exact
runtime framework-manifest identity.
