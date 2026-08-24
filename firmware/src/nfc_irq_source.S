/* Direct VC2 vector entry reconstructed from original function 0x1678. */

    .syntax unified
    .cpu cortex-m0plus
    .thumb

    .section .text.VC2_IRQHandler,"ax",%progbits
    .balign 4
    .global VC2_IRQHandler
    .type VC2_IRQHandler,%function
    .thumb_func
VC2_IRQHandler:
    push    {r4, lr}
    ldr     r0, =0x40000080
    ldr     r0, [r0, #0x38]
    movs    r1, #0x40
    bics    r0, r1
    ldr     r1, =0x40000080
    str     r0, [r1, #0x38]
    mov     r0, r1
    ldr     r0, [r0, #0x3c]
    lsrs    r0, r0, #1
    lsls    r0, r0, #1
    str     r0, [r1, #0x3c]

    ldr     r0, =0x20000004
    ldrb    r0, [r0]
    bl      nfc_receive_frame
    mov     r4, r0
    cmp     r4, #0
    beq     .Lirq_cleanup
    ldr     r0, =0x20000004
    ldrb    r0, [r0]
    cmp     r0, #0
    beq     .Lirq_ntag
    movs    r1, #4
    mov     r0, r4
    bl      iso15693_dispatch
    b       .Lirq_cleanup

.Lirq_ntag:
    mov     r0, r4
    bl      ntag_dispatch

.Lirq_cleanup:
    movs    r0, #0
    ldr     r1, =0x40004800
    str     r0, [r1]
    str     r0, [r1, #0x18]
    str     r0, [r1, #0x24]
    ldr     r0, =0x40000080
    ldr     r0, [r0, #0x3c]
    lsrs    r0, r0, #1
    lsls    r0, r0, #1
    ldr     r1, =0x40000080
    str     r0, [r1, #0x3c]
    mov     r0, r1
    ldr     r0, [r0, #0x38]
    movs    r1, #0x40
    orrs    r0, r1
    ldr     r1, =0x40000080
    str     r0, [r1, #0x38]
    pop     {r4, pc}
    .size VC2_IRQHandler, .-VC2_IRQHandler

    .global NFC_IRQHandler
    .type NFC_IRQHandler,%function
    .thumb_func
NFC_IRQHandler:
    b       VC2_IRQHandler
    .size NFC_IRQHandler, .-NFC_IRQHandler

    .section .note.GNU-stack,"",%progbits
