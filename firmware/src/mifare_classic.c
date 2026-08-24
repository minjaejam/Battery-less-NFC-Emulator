#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../inc/mfc_crypto1.h"
#include "../inc/mifare_classic.h"
#include "../inc/nfc_phy.h"
#include "../inc/tag_emulator.h"

#define TYPEA_SLOT_BASE 0x0000E000u
#define SLOT_SIZE       0x00000400u
#define MFC_BLOCK_SIZE  16u
#define MFC_BLOCK_COUNT 64u
#define MFC_ACK          0x0Au
#define MFC_NAK          0x04u

typedef enum {
    MFC_STATE_IDLE = 0,
    MFC_STATE_SELECTED,
    MFC_STATE_AUTH_WAIT,
    MFC_STATE_AUTHENTICATED,
    MFC_STATE_WRITE_DATA
} MfcProtocolState;

typedef struct {
    MfcCrypto1State crypto;
    MfcProtocolState state;
    uint32_t nonce;
    uint8_t authenticated_sector;
    uint8_t authenticated_key;
    uint8_t write_block;
    uint8_t memory_ready;
} MfcRuntime;

static uint8_t g_mfc_memory[MFC1K_MEMORY_SIZE]
    __attribute__((section(".bss.noinit.g_mfc_memory")));
static MfcRuntime g_mfc
    __attribute__((section(".bss.noinit.g_mfc_runtime")));
static uint32_t g_nonce_state
    __attribute__((section(".bss.noinit.g_mfc_nonce")));

static uint16_t typea_crc16(const uint8_t *data, uint16_t length)
{
    uint16_t crc = 0x6363u;
    uint16_t i;

    for (i = 0u; i < length; ++i) {
        uint16_t x = (uint16_t)((data[i] ^ crc) & 0xFFu);
        x = (uint16_t)(((x << 4) ^ x) & 0xFFu);
        crc = (uint16_t)((x << 8) ^ (x << 3) ^
                         (x >> 4) ^ (crc >> 8));
    }
    return crc;
}

static void append_typea_crc(uint8_t *frame, uint16_t length)
{
    uint16_t crc = typea_crc16(frame, length);
    frame[length] = (uint8_t)crc;
    frame[length + 1u] = (uint8_t)(crc >> 8);
}

static bool typea_crc_is_valid(const uint8_t *frame, uint16_t length)
{
    uint16_t crc;

    if (length < 2u) {
        return false;
    }
    crc = typea_crc16(frame, (uint16_t)(length - 2u));
    return (frame[length - 2u] == (uint8_t)crc) &&
           (frame[length - 1u] == (uint8_t)(crc >> 8));
}

static uint8_t odd_parity_bit(uint8_t value)
{
    value ^= value >> 4;
    value ^= value >> 2;
    value ^= value >> 1;
    return (uint8_t)((value ^ 1u) & 1u);
}

static uint32_t bytes_to_u32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           bytes[3];
}

static void u32_to_bytes(uint32_t value, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static uint64_t key_from_trailer(uint8_t sector, uint8_t key_b)
{
    uint16_t offset = (uint16_t)sector * 64u + 48u;
    uint64_t key = 0u;
    uint8_t i;

    if (key_b != 0u) {
        offset += 10u;
    }
    for (i = 0u; i < 6u; ++i) {
        key = (key << 8) | g_mfc_memory[offset + i];
    }
    return key;
}

static void send_plain(uint8_t *frame, uint16_t length)
{
    nfc_typea_send_frame(frame, length, 0u, frame);
}

static void encrypt_frame(uint8_t *frame,
                          uint16_t length,
                          uint8_t *parity)
{
    uint16_t i;

    memset(parity, 0, (length + 7u) / 8u);
    for (i = 0u; i < length; ++i) {
        uint8_t plain = frame[i];
        uint8_t parity_bit;

        frame[i] ^= mfc_crypto1_byte(&g_mfc.crypto, 0u, 0u);
        parity_bit = (uint8_t)(mfc_crypto1_filter(g_mfc.crypto.odd) ^
                               odd_parity_bit(plain));
        parity[i >> 3] |= (uint8_t)(parity_bit << (7u - (i & 7u)));
    }
}

static void send_encrypted(uint8_t *frame, uint16_t length)
{
    uint8_t parity[3];

    encrypt_frame(frame, length, parity);
    nfc_typea_send_frame(frame, length, 1u, parity);
}

static void decrypt_frame(const volatile uint8_t *encrypted,
                          uint8_t *plain,
                          uint16_t length)
{
    uint16_t i;

    for (i = 0u; i < length; ++i) {
        plain[i] = encrypted[i] ^
                   mfc_crypto1_byte(&g_mfc.crypto, 0u, 0u);
    }
}

static void send_encrypted_nibble(uint8_t value)
{
    uint8_t encrypted = 0u;
    uint8_t bit;

    for (bit = 0u; bit < 4u; ++bit) {
        encrypted |= (uint8_t)(((value >> bit) & 1u) ^
                     mfc_crypto1_bit(&g_mfc.crypto, 0u, 0u)) << bit;
    }
    nfc_typea_send_short_4bit(encrypted);
}

static void reset_session(void)
{
    uint8_t memory_ready = g_mfc.memory_ready;

    memset(&g_mfc, 0, sizeof(g_mfc));
    g_mfc.state = MFC_STATE_IDLE;
    g_mfc.memory_ready = memory_ready;
}

void mifare_classic_memory_prepare(void)
{
    const uint8_t *flash = (const uint8_t *)(uintptr_t)
        (TYPEA_SLOT_BASE + MFC1K_SLOT_INDEX * SLOT_SIZE);

    g_mfc.memory_ready = 0u;
    g_nonce_state = 0x6D3A8B17u;
    reset_session();
    memcpy(g_mfc_memory, flash, MFC_BLOCK_SIZE);
}

void mifare_classic_memory_finish(void)
{
    const uint8_t *flash = (const uint8_t *)(uintptr_t)
        (TYPEA_SLOT_BASE + MFC1K_SLOT_INDEX * SLOT_SIZE);

    memcpy(g_mfc_memory + MFC_BLOCK_SIZE,
           flash + MFC_BLOCK_SIZE,
           sizeof(g_mfc_memory) - MFC_BLOCK_SIZE);
    g_mfc.memory_ready = 1u;
}

static uint32_t next_nonce(void)
{
    g_nonce_state = mfc_prng_successor(g_nonce_state, 32u);
    return g_nonce_state;
}

static void begin_authentication(uint8_t command,
                                 uint8_t block,
                                 bool nested)
{
    uint8_t nonce_bytes[4];
    uint8_t encrypted_nonce[4];
    uint8_t parity[1] = {0u};
    uint8_t sector;
    uint8_t key_b = command & 1u;
    uint8_t i;

    if ((g_mfc.memory_ready == 0u) || (block >= MFC_BLOCK_COUNT)) {
        reset_session();
        return;
    }

    sector = block >> 2;
    g_mfc.nonce = next_nonce();
    g_mfc.authenticated_sector = sector;
    g_mfc.authenticated_key = key_b;
    u32_to_bytes(g_mfc.nonce, nonce_bytes);
    mfc_crypto1_init(&g_mfc.crypto, key_from_trailer(sector, key_b));

    for (i = 0u; i < 4u; ++i) {
        uint8_t stream = mfc_crypto1_byte(
            &g_mfc.crypto, (uint8_t)(g_mfc_memory[i] ^ nonce_bytes[i]), 0u);

        encrypted_nonce[i] = nonce_bytes[i] ^ stream;
        parity[0] |= (uint8_t)((mfc_crypto1_filter(g_mfc.crypto.odd) ^
                      odd_parity_bit(nonce_bytes[i])) << (7u - i));
    }

    g_mfc.state = MFC_STATE_AUTH_WAIT;
    if (nested) {
        nfc_typea_send_frame(encrypted_nonce, 4u, 1u, parity);
    } else {
        send_plain(nonce_bytes, 4u);
    }
}

static void process_auth_answer(uint16_t rx_length)
{
    const volatile uint8_t *rx = g_nfc_state.rx;
    uint32_t reader_nonce_encrypted;
    uint32_t reader_answer;
    uint32_t expected_answer;
    uint8_t card_answer[4];

    if (rx_length != 8u) {
        reset_session();
        return;
    }

    reader_nonce_encrypted =
        ((uint32_t)rx[0] << 24) | ((uint32_t)rx[1] << 16) |
        ((uint32_t)rx[2] << 8) | rx[3];
    (void)mfc_crypto1_word(&g_mfc.crypto,
                           reader_nonce_encrypted, 1u);

    reader_answer =
        (((uint32_t)rx[4] << 24) | ((uint32_t)rx[5] << 16) |
         ((uint32_t)rx[6] << 8) | rx[7]) ^
        mfc_crypto1_word(&g_mfc.crypto, 0u, 0u);
    expected_answer = mfc_prng_successor(g_mfc.nonce, 64u);
    if (reader_answer != expected_answer) {
        reset_session();
        return;
    }

    u32_to_bytes(mfc_prng_successor(g_mfc.nonce, 96u), card_answer);
    send_encrypted(card_answer, 4u);
    g_mfc.state = MFC_STATE_AUTHENTICATED;
}

static bool authenticated_for_block(uint8_t block)
{
    return (block < MFC_BLOCK_COUNT) &&
           ((block >> 2) == g_mfc.authenticated_sector);
}

static void process_encrypted_command(uint16_t rx_length)
{
    uint8_t frame[20];
    uint8_t reply[18];
    uint8_t block;

    if (rx_length > sizeof(frame)) {
        reset_session();
        return;
    }
    decrypt_frame(g_nfc_state.rx, frame, rx_length);

    if (g_mfc.state == MFC_STATE_WRITE_DATA) {
        if ((rx_length == 18u) && typea_crc_is_valid(frame, rx_length)) {
            memcpy(&g_mfc_memory[(uint16_t)g_mfc.write_block * MFC_BLOCK_SIZE],
                   frame, MFC_BLOCK_SIZE);
            send_encrypted_nibble(MFC_ACK);
            g_mfc.state = MFC_STATE_AUTHENTICATED;
        } else {
            send_encrypted_nibble(MFC_NAK);
            g_mfc.state = MFC_STATE_AUTHENTICATED;
        }
        return;
    }

    if (!typea_crc_is_valid(frame, rx_length)) {
        send_encrypted_nibble(MFC_NAK);
        return;
    }

    if ((rx_length == 4u) &&
        ((frame[0] == 0x60u) || (frame[0] == 0x61u))) {
        begin_authentication(frame[0], frame[1], true);
        return;
    }

    if ((rx_length == 4u) && (frame[0] == 0x30u)) {
        block = frame[1];
        if (!authenticated_for_block(block)) {
            send_encrypted_nibble(MFC_NAK);
            return;
        }
        memcpy(reply, &g_mfc_memory[(uint16_t)block * MFC_BLOCK_SIZE],
               MFC_BLOCK_SIZE);
        if ((block & 3u) == 3u) {
            memset(reply, 0, 6u); /* Key A is never readable over RF. */
        }
        append_typea_crc(reply, MFC_BLOCK_SIZE);
        send_encrypted(reply, sizeof(reply));
        return;
    }

    if ((rx_length == 4u) && (frame[0] == 0xA0u)) {
        block = frame[1];
        if (!authenticated_for_block(block) ||
            (block == 0u) || ((block & 3u) == 3u)) {
            send_encrypted_nibble(MFC_NAK);
            return;
        }
        g_mfc.write_block = block;
        g_mfc.state = MFC_STATE_WRITE_DATA;
        send_encrypted_nibble(MFC_ACK);
        return;
    }

    if ((rx_length == 4u) && (frame[0] == 0x50u) &&
        (frame[1] == 0u)) {
        reset_session();
        return;
    }

    send_encrypted_nibble(MFC_NAK);
}

void mifare_classic_dispatch(uint16_t rx_length)
{
    const volatile uint8_t *rx = g_nfc_state.rx;
    uint8_t reply[5];
    uint8_t i;

    if ((rx_length == 1u) && ((rx[0] == 0x26u) || (rx[0] == 0x52u))) {
        reset_session();
        reply[0] = 0x04u;
        reply[1] = 0x00u;
        send_plain(reply, 2u);
        return;
    }

    if ((rx_length == 2u) && (rx[0] == 0x93u) && (rx[1] == 0x20u)) {
        for (i = 0u; i < 4u; ++i) {
            reply[i] = g_mfc_memory[i];
        }
        reply[4] = (uint8_t)(reply[0] ^ reply[1] ^ reply[2] ^ reply[3]);
        send_plain(reply, 5u);
        return;
    }

    if ((rx_length == 9u) && (rx[0] == 0x93u) && (rx[1] == 0x70u)) {
        for (i = 0u; i < 5u; ++i) {
            if (rx[2u + i] !=
                ((i < 4u) ? g_mfc_memory[i] :
                 (uint8_t)(g_mfc_memory[0] ^ g_mfc_memory[1] ^
                           g_mfc_memory[2] ^ g_mfc_memory[3]))) {
                reset_session();
                return;
            }
        }
        reply[0] = 0x08u;
        append_typea_crc(reply, 1u);
        send_plain(reply, 3u);
        g_mfc.state = MFC_STATE_SELECTED;
        return;
    }

    if (g_mfc.state == MFC_STATE_AUTH_WAIT) {
        process_auth_answer(rx_length);
        return;
    }

    if ((g_mfc.state == MFC_STATE_AUTHENTICATED) ||
        (g_mfc.state == MFC_STATE_WRITE_DATA)) {
        process_encrypted_command(rx_length);
        return;
    }

    if ((rx_length == 4u) &&
        ((rx[0] == 0x60u) || (rx[0] == 0x61u)) &&
        typea_crc_is_valid((const uint8_t *)rx, rx_length)) {
        begin_authentication(rx[0], rx[1], false);
        return;
    }

    if ((rx_length == 4u) && (rx[0] == 0x50u) && (rx[1] == 0u) &&
        typea_crc_is_valid((const uint8_t *)rx, rx_length)) {
        reset_session();
        return;
    }

    if (rx_length == 4u) {
        nfc_typea_send_short_4bit(MFC_NAK);
    }
}
