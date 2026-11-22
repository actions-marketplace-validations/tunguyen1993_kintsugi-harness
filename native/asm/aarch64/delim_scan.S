/*
 * Experimental Tier 4 AArch64 NEON Assembly Kernel (`native/asm/aarch64/delim_scan.S`)
 *
 * Strictly complies with Kintsugi Assembly Policy (Section J):
 * - Zero syscalls (`svc` never used)
 * - Zero filesystem/network/allocation operations
 * - Pure AAPCS64 leaf function using only caller-saved registers
 *   (`x0-x15`, `v0-v7`, `v16-v23`; never touches `x18`, `x19-x28`, `v8-v15`)
 * - Strict bounds checking on `data == NULL`, `len == 0`, `out_offsets == NULL`, and `out_cap`
 *
 * Signature:
 *   size_t logforge_asm_scan_delimiters(
 *       const uint8_t *data,   // x0
 *       size_t len,            // x1
 *       uint8_t delim,         // w2
 *       uint64_t *out_offsets, // x3
 *       size_t out_cap         // x4
 *   );
 */

#if defined(__aarch64__)

#if defined(__APPLE__)
#define ASM_SYM(name) _##name
#else
#define ASM_SYM(name) name
#endif

.text
.align 4
.globl ASM_SYM(logforge_asm_scan_delimiters)

ASM_SYM(logforge_asm_scan_delimiters):
    // Null pointer or zero-length buffer -> return 0 immediately.
    cbz     x0, .Lret_zero
    cbz     x1, .Lret_zero

    // Clamp out_cap to 0 if out_offsets is NULL so no null store is possible.
    cmp     x3, #0
    csel    x4, xzr, x4, eq

    // Mask delim to low 8 bits and broadcast across v0.16b.
    and     w2, w2, #0xff
    dup     v0.16b, w2

    // Construct NEON bit-weight vector in v1 without .rodata relocations:
    // bytes [0..7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80], repeated in [8..15].
    movz    x9, #0x0201
    movk    x9, #0x0804, lsl #16
    movk    x9, #0x2010, lsl #32
    movk    x9, #0x8040, lsl #48
    dup     v1.2d, x9

    mov     x5, #0              // x5 = current byte offset
    mov     x6, #0              // x6 = total matched delimiters

    // Check if len >= 64 for 64-byte unrolled NEON block loop.
    cmp     x1, #64
    b.lo    .Ltry16
    sub     x7, x1, #64         // x7 = last safe start offset for 64-byte load

.Lloop64:
    add     x14, x0, x5
    ld1     {v2.16b, v3.16b, v4.16b, v5.16b}, [x14]

    cmeq    v16.16b, v2.16b, v0.16b
    cmeq    v17.16b, v3.16b, v0.16b
    cmeq    v18.16b, v4.16b, v0.16b
    cmeq    v19.16b, v5.16b, v0.16b

    and     v16.16b, v16.16b, v1.16b
    and     v17.16b, v17.16b, v1.16b
    and     v18.16b, v18.16b, v1.16b
    and     v19.16b, v19.16b, v1.16b

    addp    v20.16b, v16.16b, v17.16b
    addp    v21.16b, v18.16b, v19.16b
    addp    v22.16b, v20.16b, v21.16b
    addp    v22.16b, v22.16b, v22.16b

    umov    x9, v22.d[0]
    cbz     x9, .Lnext64

.Lmask64_loop:
    rbit    x10, x9
    clz     x10, x10            // x10 = trailing zero bit index (0..63)
    add     x11, x5, x10        // x11 = exact byte offset
    cmp     x6, x4
    b.hs    .Lskip_store64
    str     x11, [x3, x6, lsl #3]
.Lskip_store64:
    add     x6, x6, #1
    sub     x12, x9, #1
    and     x9, x9, x12
    cbnz    x9, .Lmask64_loop

.Lnext64:
    add     x5, x5, #64
    cmp     x5, x7
    b.ls    .Lloop64

.Ltry16:
    sub     x13, x1, x5
    cmp     x13, #16
    b.lo    .Ltry_tail
    sub     x7, x1, #16         // x7 = last safe start offset for 16-byte load

.Lloop16:
    add     x14, x0, x5
    ld1     {v2.16b}, [x14]
    cmeq    v16.16b, v2.16b, v0.16b
    and     v16.16b, v16.16b, v1.16b
    addp    v20.16b, v16.16b, v16.16b
    addp    v20.16b, v20.16b, v20.16b
    addp    v20.16b, v20.16b, v20.16b
    umov    w9, v20.h[0]
    cbz     x9, .Lnext16

.Lmask16_loop:
    rbit    x10, x9
    clz     x10, x10
    add     x11, x5, x10
    cmp     x6, x4
    b.hs    .Lskip_store16
    str     x11, [x3, x6, lsl #3]
.Lskip_store16:
    add     x6, x6, #1
    sub     x12, x9, #1
    and     x9, x9, x12
    cbnz    x9, .Lmask16_loop

.Lnext16:
    add     x5, x5, #16
    cmp     x5, x7
    b.ls    .Lloop16

.Ltry_tail:
    cmp     x5, x1
    b.hs    .Ldone

.Ltail_loop:
    ldrb    w13, [x0, x5]
    cmp     w13, w2
    b.ne    .Ltail_next
    cmp     x6, x4
    b.hs    .Ltail_inc
    str     x5, [x3, x6, lsl #3]
.Ltail_inc:
    add     x6, x6, #1
.Ltail_next:
    add     x5, x5, #1
    cmp     x5, x1
    b.lo    .Ltail_loop

.Ldone:
    mov     x0, x6
    ret

.Lret_zero:
    mov     x0, #0
    ret

#endif
