# Private fixtures

No firmware or extracted proprietary binary is distributed here. Optional
integration tests accept owner-supplied local fixtures through environment
variables:

| Variable | Expected private input |
|---|---|
| `DBY_STOCK_RAMDISK` | Exact stock normal ramdisk used by the recorded build |
| `DBY_LINEAGE_INIT` | Exact selected Lineage `/system/bin/init` |
| `DBY_DTB_DIR` | Directory containing the three extracted target DTBs |
| `DBY_W1_LIVE_GATE_MANIFEST` | Exact private W1 gate manifest |

The tests validate built-in sizes and SHA-256 identities before relying on
these files. A missing fixture causes an explicit skip. Do not copy fixture
files into this directory before publication; `.gitignore` excludes them as a
second guard.
