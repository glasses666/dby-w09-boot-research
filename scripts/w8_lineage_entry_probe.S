/*
 * DBY-W09 W8 Lineage entry probe.
 *
 * This fragment replaces only the selected Lineage init's first entry block.
 * The Android bootstrap linker and all of init's dynamic dependencies must load
 * before control reaches this code.  Reaching it requests EDL immediately; a
 * rejected EDL restart falls back to bootloader.  It performs no filesystem or
 * persistent-storage operation.
 */

    .text
    .p2align 2
    .global dby_w8_entry
    .type dby_w8_entry, %function
dby_w8_entry:
    bti j

    movz w0, #0xdead
    movk w0, #0xfee1, lsl #16
    movz w1, #0x1969
    movk w1, #0x2812, lsl #16
    movz w2, #0xc3d4
    movk w2, #0xa1b2, lsl #16
    adr x3, .Ledl
    mov x8, #142
    svc #0

    movz w0, #0xdead
    movk w0, #0xfee1, lsl #16
    adr x3, .Lbootloader
    mov x8, #142
    svc #0

.Lhang:
    wfe
    b .Lhang

.Ledl:
    .asciz "edl"
.Lbootloader:
    .asciz "bootloader"
    .p2align 2
    .size dby_w8_entry, . - dby_w8_entry
