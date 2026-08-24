#ifndef TAGEMULATOR_NFC_PHY_H
#define TAGEMULATOR_NFC_PHY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These entry points are backed by the exact Thumb bytes recovered from
 * TagEmulator-20251127.hex (original range 0x1B98..0x229B).
 */
uint16_t nfc_receive_frame(uint32_t iso15693_mode);

void nfc_typea_symbol_1(void);
void nfc_typea_symbol_0(void);
void nfc_typea_tx_finish(void);
void nfc_typea_tx_start(void);
void nfc_tx_edge_sync(void);

void nfc_typea_send_short_4bit(uint32_t value);
void nfc_typea_send_frame(uint8_t *frame,
                          uint16_t length,
                          uint32_t use_external_parity,
                          const uint8_t *parity_bits);

/* The caller appends CRC16 before entering this routine. */
void nfc_iso15693_send_frame(uint8_t *frame, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif
