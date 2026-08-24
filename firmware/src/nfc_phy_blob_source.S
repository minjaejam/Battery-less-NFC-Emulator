/* Exact physical-layer bytes recovered from original range 0x1B98..0x229B. */

    .syntax unified
    .cpu cortex-m0plus
    .thumb

    .section .text.nfc_phy_blob,"ax",%progbits
    .balign 4

    .global nfc_phy_original_block
nfc_phy_original_block:

    .global nfc_typea_symbol_1
    .type nfc_typea_symbol_1,%function
    .thumb_func
nfc_typea_symbol_1:
    .incbin "../USER/src/nfc_phy_01_typea_symbol_1.bin"
    .size nfc_typea_symbol_1, .-nfc_typea_symbol_1

    .global nfc_typea_symbol_0
    .type nfc_typea_symbol_0,%function
    .thumb_func
nfc_typea_symbol_0:
    .incbin "../USER/src/nfc_phy_02_typea_symbol_0.bin"
    .size nfc_typea_symbol_0, .-nfc_typea_symbol_0

    .global nfc_typea_tx_finish
    .type nfc_typea_tx_finish,%function
    .thumb_func
nfc_typea_tx_finish:
    .incbin "../USER/src/nfc_phy_03_typea_tx_finish.bin"
    .size nfc_typea_tx_finish, .-nfc_typea_tx_finish

    .global nfc_typea_tx_start
    .type nfc_typea_tx_start,%function
    .thumb_func
nfc_typea_tx_start:
    .incbin "../USER/src/nfc_phy_04_typea_tx_start.bin"
    .size nfc_typea_tx_start, .-nfc_typea_tx_start

    .global nfc_typea_send_short_4bit
    .type nfc_typea_send_short_4bit,%function
    .thumb_func
nfc_typea_send_short_4bit:
    .incbin "../USER/src/nfc_phy_05_typea_short.bin"
    .size nfc_typea_send_short_4bit, .-nfc_typea_send_short_4bit

    .global nfc_typea_send_frame
    .type nfc_typea_send_frame,%function
    .thumb_func
nfc_typea_send_frame:
    .incbin "../USER/src/nfc_phy_06_typea_frame.bin"
    .size nfc_typea_send_frame, .-nfc_typea_send_frame

    .global nfc_tx_edge_sync
    .type nfc_tx_edge_sync,%function
    .thumb_func
nfc_tx_edge_sync:
    .incbin "../USER/src/nfc_phy_07_tx_edge_sync.bin"
    .size nfc_tx_edge_sync, .-nfc_tx_edge_sync

    .global nfc_iso15693_eof
    .type nfc_iso15693_eof,%function
    .thumb_func
nfc_iso15693_eof:
    .incbin "../USER/src/nfc_phy_08_iso_eof.bin"
    .size nfc_iso15693_eof, .-nfc_iso15693_eof

    .global nfc_iso15693_symbol_0
    .type nfc_iso15693_symbol_0,%function
    .thumb_func
nfc_iso15693_symbol_0:
    .incbin "../USER/src/nfc_phy_09_iso_symbol_0.bin"
    .size nfc_iso15693_symbol_0, .-nfc_iso15693_symbol_0

    .global nfc_iso15693_symbol_1
    .type nfc_iso15693_symbol_1,%function
    .thumb_func
nfc_iso15693_symbol_1:
    .incbin "../USER/src/nfc_phy_10_iso_symbol_1.bin"
    .size nfc_iso15693_symbol_1, .-nfc_iso15693_symbol_1

    .global nfc_iso15693_sof
    .type nfc_iso15693_sof,%function
    .thumb_func
nfc_iso15693_sof:
    .incbin "../USER/src/nfc_phy_11_iso_sof.bin"
    .size nfc_iso15693_sof, .-nfc_iso15693_sof

    .global nfc_iso15693_send_frame
    .type nfc_iso15693_send_frame,%function
    .thumb_func
nfc_iso15693_send_frame:
    .incbin "../USER/src/nfc_phy_12_iso_frame.bin"
    .size nfc_iso15693_send_frame, .-nfc_iso15693_send_frame

    .global nfc_receive_frame
    .type nfc_receive_frame,%function
    .thumb_func
nfc_receive_frame:
    .incbin "../USER/src/nfc_phy_13_nfc_receive.bin"
    .size nfc_receive_frame, .-nfc_receive_frame

    .section .note.GNU-stack,"",%progbits
