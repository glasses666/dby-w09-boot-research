# Methodology

This project treats early boot as an evidence-binding problem rather than a
sequence of blind image edits.

## One question per experiment

Each probe changes the smallest qualified byte range that can answer one
question. W8 changes only the executable entry window. W9 restores that window
and changes only `main`. The unchanged regions are hashed and compared so a
positive endpoint cannot silently inherit a second explanation.

## Bind execution to a fresh attempt

A useful positive result needs more than a string in an image or a familiar
screen. Depending on the stage, the experiment binds a fresh nonce, exact
candidate hash, complete partition readback, current boot identity, current
kernel evidence, fresh transport enumeration and a predeclared endpoint.

## Separate observations from implications

Every result records both `proved` and `not_proved`. For example, W8 proves
entrypoint transfer but intentionally says nothing about the original entry
instructions. W9 proves transfer to `main` but not execution of the original
main body.

## Fail closed

Builders reject unexpected source hashes, geometry, ELF layout, patch ranges,
existing outputs and incomplete manifests. Evidence parsers reject trailing
bytes, malformed lengths, checksum mismatches, nonce mismatches and ambiguous
capture origins.

## Rollback or explicit retention closes the experiment

The write phase is not complete when an endpoint appears. The experiment ends
only after either the frozen baseline is restored and every scoped partition is
read back, or a predeclared usable-system threshold is met and the owner
explicitly retains the verified candidate. Failed probes follow the rollback
path. The first usable API29 UI followed the retention path so later hardware
tests would not consume another flash cycle. The accepted API32 experiment used
the same rule: it retained the candidate only after complete postwrite
readback, boot completion, visible UI, stable core services and GNSS
registration. A transport retry begins from offset zero; a failed read is not
converted into a second write.

## Replay the target semantics

Host-side compatibility tools can disagree with the exact target libraries.
The API32 GNSS correction therefore replayed the target `libvintf` binary and
its dependency closure against a control, rejected candidate and
source-derived correction. The live candidate was built only after the target
replay and two independent image builds agreed. This pattern is now preferred
for every compatibility component whose host and target behavior can diverge.

## Reproducibility layers

1. Standard-library synthetic tests exercise parsers and geometry without any
   vendor image.
2. Private-fixture tests bind builders to exact stock and Lineage inputs.
3. Static AArch64 checks inspect the compiled probes.
4. Live evidence is kept privately because it contains device-specific data.
5. The public findings file exports conclusions and artifact hashes without
   device identifiers or raw logs.
