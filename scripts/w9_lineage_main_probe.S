/*
 * DBY-W09 W9 Lineage main-entry probe.
 *
 * The original PIE entry shim and bootstrap-linker path remain byte-exact.
 * Reaching this replacement for main therefore proves that __libc_init and
 * constructor dispatch transferred control to main.  The probe performs no
 * filesystem or persistent-storage operation.
 */

    .text
    .p2align 2
    .global dby_w9_main
    .type dby_w9_main, %function
dby_w9_main:
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
    .size dby_w9_main, . - dby_w9_main
