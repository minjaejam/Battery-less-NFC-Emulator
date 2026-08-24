#ifndef TAGEMULATOR_MFC_CRYPTO1_H
#define TAGEMULATOR_MFC_CRYPTO1_H

#include <stdint.h>

typedef struct {
    uint32_t odd;
    uint32_t even;
} MfcCrypto1State;

void mfc_crypto1_init(MfcCrypto1State *state, uint64_t key);
uint8_t mfc_crypto1_bit(MfcCrypto1State *state,
                        uint8_t input,
                        uint32_t input_is_encrypted);
uint8_t mfc_crypto1_byte(MfcCrypto1State *state,
                         uint8_t input,
                         uint32_t input_is_encrypted);
uint32_t mfc_crypto1_word(MfcCrypto1State *state,
                          uint32_t input,
                          uint32_t input_is_encrypted);
uint32_t mfc_prng_successor(uint32_t value, uint32_t clocks);
uint8_t mfc_crypto1_filter(uint32_t odd_state);

#endif
