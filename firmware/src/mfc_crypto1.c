/*
 * Minimal Crypto1 forward implementation for MIFARE Classic emulation.
 *
 * Derived from the Proxmark3 crapto1 implementation:
 * Copyright (C) 2008-2014 bla <blapost@gmail.com>
 * Copyright (C) Proxmark3 contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "../inc/mfc_crypto1.h"

#define BIT(value, bit) (((value) >> (bit)) & 1u)
#define BEBIT(value, bit) BIT((value), ((bit) ^ 24u))
#define LF_POLY_ODD  0x29CE5Cu
#define LF_POLY_EVEN 0x870804u
#define ALWAYS_INLINE static __attribute__((always_inline)) inline

ALWAYS_INLINE uint8_t even_parity32(uint32_t value)
{
    value ^= value >> 16;
    value ^= value >> 8;
    value ^= value >> 4;
    value &= 0x0Fu;
    return (uint8_t)((0x6996u >> value) & 1u);
}

ALWAYS_INLINE uint8_t crypto1_filter_inline(uint32_t x)
{
    uint32_t f;

    f  = (0xF22C0u >> (x        & 0x0Fu)) & 16u;
    f |= (0x6C9C0u >> ((x >> 4) & 0x0Fu)) & 8u;
    f |= (0x3C8B0u >> ((x >> 8) & 0x0Fu)) & 4u;
    f |= (0x1E458u >> ((x >> 12) & 0x0Fu)) & 2u;
    f |= (0x0D938u >> ((x >> 16) & 0x0Fu)) & 1u;
    return (uint8_t)BIT(0xEC57E80Au, f);
}

uint8_t mfc_crypto1_filter(uint32_t x)
{
    return crypto1_filter_inline(x);
}

void mfc_crypto1_init(MfcCrypto1State *state, uint64_t key)
{
    int32_t bit;

    state->odd = 0u;
    state->even = 0u;
    for (bit = 47; bit > 0; bit -= 2) {
        state->odd = (state->odd << 1) |
                     (uint32_t)BIT(key, ((uint32_t)(bit - 1) ^ 7u));
        state->even = (state->even << 1) |
                      (uint32_t)BIT(key, ((uint32_t)bit ^ 7u));
    }
}

ALWAYS_INLINE uint8_t crypto1_bit_inline(MfcCrypto1State *state,
                                         uint8_t input,
                                         uint32_t input_is_encrypted)
{
    uint32_t feedback;
    uint32_t temporary;
    uint8_t output = crypto1_filter_inline(state->odd);

    feedback = output & (input_is_encrypted != 0u);
    feedback ^= (input != 0u);
    feedback ^= LF_POLY_ODD & state->odd;
    feedback ^= LF_POLY_EVEN & state->even;
    state->even = (state->even << 1) | even_parity32(feedback);

    temporary = state->odd;
    state->odd = state->even;
    state->even = temporary;
    return output;
}

uint8_t mfc_crypto1_bit(MfcCrypto1State *state,
                        uint8_t input,
                        uint32_t input_is_encrypted)
{
    return crypto1_bit_inline(state, input, input_is_encrypted);
}

uint8_t mfc_crypto1_byte(MfcCrypto1State *state,
                         uint8_t input,
                         uint32_t input_is_encrypted)
{
    uint8_t output = 0u;
    uint8_t bit;

    for (bit = 0u; bit < 8u; ++bit) {
        output |= (uint8_t)(crypto1_bit_inline(
            state, (uint8_t)BIT(input, bit), input_is_encrypted) << bit);
    }
    return output;
}

uint32_t mfc_crypto1_word(MfcCrypto1State *state,
                          uint32_t input,
                          uint32_t input_is_encrypted)
{
    uint32_t output = 0u;
    uint8_t bit;

    for (bit = 0u; bit < 32u; ++bit) {
        output |= (uint32_t)crypto1_bit_inline(
            state, (uint8_t)BEBIT(input, bit), input_is_encrypted)
            << (24u ^ bit);
    }
    return output;
}

static uint32_t swap_endian32(uint32_t value)
{
    value = ((value >> 8) & 0x00FF00FFu) |
            ((value & 0x00FF00FFu) << 8);
    return (value >> 16) | (value << 16);
}

uint32_t mfc_prng_successor(uint32_t value, uint32_t clocks)
{
    value = swap_endian32(value);
    while (clocks-- != 0u) {
        value = (value >> 1) |
                ((value >> 16 ^ value >> 18 ^
                  value >> 19 ^ value >> 21) << 31);
    }
    return swap_endian32(value);
}
