#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../inc/mifare_classic.h"
#include "../inc/nfc_phy.h"
#include "../inc/tag_emulator.h"

#define ISO15693_SLOT_BASE 0x0000C000u
#define NTAG_SLOT_BASE     0x0000E000u
#define SLOT_SIZE          0x00000400u
#define NTAG215_PAGE_COUNT 135u
#define NTAG215_DATA_SIZE  (NTAG215_PAGE_COUNT * 4u)
#define NTAG215_USER_FIRST_PAGE 0x04u
#define NTAG215_USER_LAST_PAGE  0x81u
#define NTAG215_CFG0_OFFSET (0x83u * 4u)
#define NTAG215_CFG1_OFFSET (0x84u * 4u)
#define NTAG215_PWD_OFFSET (0x85u * 4u)
#define NTAG215_PACK_OFFSET (0x86u * 4u)
#define NTAG_NAK_INVALID_ARGUMENT 0x00u
#define NTAG_NAK_CRC_ERROR        0x01u
#define NTAG_NAK_AUTH_REQUIRED    0x04u
#define NTAG_ACK                   0x0Au
#define NTAG_ACCESS_PROT           0x80u
#define NTAG_ACCESS_NFC_CNT_EN     0x10u
#define NTAG_ACCESS_CNT_PWD_PROT   0x08u
#define NTAG_TEARING_FLAG_VALID    0xBDu

enum {
    NTAG_STATE_IDLE = 0,
    NTAG_STATE_READY1,
    NTAG_STATE_READY2,
    NTAG_STATE_ACTIVE,
    NTAG_STATE_COMPAT_WRITE,
    NTAG_STATE_HALT
};

typedef struct {
    uint32_t counter;
    uint8_t state;
    uint8_t from_halt;
    uint8_t authenticated;
    uint8_t compat_page;
    uint8_t counter_incremented;
    uint8_t memory_ready;
} NtagRuntime;

static uint8_t g_ntag_memory[NTAG215_DATA_SIZE]
    __attribute__((section(".bss.noinit.g_ntag_memory")));
static uint8_t g_ntag_reply[NTAG215_DATA_SIZE + 2u]
    __attribute__((section(".bss.noinit.g_ntag_reply")));
static NtagRuntime g_ntag
    __attribute__((section(".bss.noinit.g_ntag_runtime")));

enum {
    ISO15693_CMD_INVENTORY = 0x01,
    ISO15693_CMD_WRITE_SINGLE = 0x21,
    ISO15693_CMD_READ_SINGLE = 0x20,
    ISO15693_CMD_READ_MULTIPLE = 0x23,
    ISO15693_CMD_GET_SYS_INFO = 0x2B,
    ISO15693_CMD_GET_MULT_SEC = 0x2C
};

static const uint8_t *iso15693_tag(void)
{
    return (const uint8_t *)(uintptr_t)
        (ISO15693_SLOT_BASE + ((uint32_t)g_nfc_state.slot * SLOT_SIZE));
}

static const uint8_t *ntag_flash(void)
{
    return (const uint8_t *)(uintptr_t)
        (NTAG_SLOT_BASE + ((uint32_t)g_nfc_state.slot * SLOT_SIZE));
}

static uint8_t ntag_cascade_byte(uint8_t level, uint8_t index)
{
    return g_ntag_memory[((level == 1u) ? 0u : 4u) + index];
}

void ntag_memory_prepare(void)
{
    const uint8_t *flash = ntag_flash();

    g_ntag.memory_ready = 0u;
    memcpy(g_ntag_memory, flash, sizeof(g_ntag_memory));

    g_ntag.counter = 0u;
    g_ntag.state = NTAG_STATE_IDLE;
    g_ntag.from_halt = 0u;
    g_ntag.authenticated = 0u;
    g_ntag.compat_page = 0u;
    g_ntag.counter_incremented = 0u;
    g_ntag.memory_ready = 1u;
}

static uint8_t ntag_read_visible_byte(const uint8_t *tag, uint16_t position)
{
    if ((position >= NTAG215_PWD_OFFSET) &&
        (position < NTAG215_DATA_SIZE)) {
        return 0u;
    }
    return tag[position];
}

static uint16_t iso15693_crc16(const uint8_t *data, uint16_t length)
{
    uint16_t crc = 0xFFFFu;
    uint16_t i;
    uint8_t bit;

    for (i = 0; i < length; ++i) {
        crc ^= data[i];
        for (bit = 0; bit < 8u; ++bit) {
            if ((crc & 1u) != 0u) {
                crc = (uint16_t)((crc >> 1) ^ 0x8408u);
            } else {
                crc >>= 1;
            }
        }
    }

    return (uint16_t)~crc;
}

static void iso15693_send_with_crc(uint8_t *frame, uint16_t payload_length)
{
    uint16_t crc = iso15693_crc16(frame, payload_length);

    frame[payload_length] = (uint8_t)crc;
    frame[payload_length + 1u] = (uint8_t)(crc >> 8);
    nfc_iso15693_send_frame(frame, (uint16_t)(payload_length + 2u));
}

static uint16_t typea_crc_update(uint16_t crc, uint8_t value)
{
    uint16_t x = (uint16_t)((value ^ crc) & 0xFFu);

    x = (uint16_t)(((x << 4) ^ x) & 0xFFu);
    return (uint16_t)((x << 8) ^ (x << 3) ^ (x >> 4) ^ (crc >> 8));
}

static uint16_t typea_crc16(const volatile uint8_t *frame, uint16_t length)
{
    uint16_t crc = 0x6363u;
    uint16_t i;

    for (i = 0; i < length; ++i) {
        crc = typea_crc_update(crc, frame[i]);
    }

    return crc;
}

static void append_typea_crc(uint8_t *frame, uint16_t length)
{
    uint16_t crc = typea_crc16(frame, length);

    frame[length] = (uint8_t)crc;
    frame[length + 1u] = (uint8_t)(crc >> 8);
}

static void typea_send(uint8_t *frame, uint16_t length)
{
    nfc_typea_send_frame(frame, length, 0u, frame);
}

static void typea_stream_byte(uint8_t value)
{
    uint8_t bit;
    uint8_t odd_ones = 0u;

    for (bit = 0u; bit < 8u; ++bit) {
        if ((value & 1u) != 0u) {
            nfc_typea_symbol_1();
            odd_ones ^= 1u;
        } else {
            nfc_typea_symbol_0();
        }
        value >>= 1;
    }
    if (odd_ones != 0u) {
        nfc_typea_symbol_0();
    } else {
        nfc_typea_symbol_1();
    }
}

/* Start FAST_READ inside the n=9 FDT, then calculate CRC while bytes are sent. */
static void ntag_stream_memory_with_crc(uint16_t offset, uint16_t length)
{
    uint16_t crc = 0x6363u;
    uint16_t i;

    nfc_tx_edge_sync();
    nfc_typea_tx_start();
    for (i = 0u; i < length; ++i) {
        uint8_t value = ntag_read_visible_byte(
            g_ntag_memory, (uint16_t)(offset + i));

        crc = typea_crc_update(crc, value);
        typea_stream_byte(value);
    }
    typea_stream_byte((uint8_t)crc);
    typea_stream_byte((uint8_t)(crc >> 8));
    nfc_typea_tx_finish();
}

static bool typea_crc_is_valid(const volatile uint8_t *frame,
                               uint16_t length)
{
    uint16_t crc;

    if (length < 2u) {
        return false;
    }
    crc = typea_crc16(frame, (uint16_t)(length - 2u));
    return (frame[length - 2u] == (uint8_t)crc) &&
           (frame[length - 1u] == (uint8_t)(crc >> 8));
}

static void ntag_return_to_wait_state(void)
{
    g_ntag.state = (g_ntag.from_halt != 0u) ?
                   NTAG_STATE_HALT : NTAG_STATE_IDLE;
    g_ntag.authenticated = 0u;
    g_ntag.compat_page = 0u;
}

static void ntag_begin_selection(uint8_t from_halt)
{
    g_ntag.state = NTAG_STATE_READY1;
    g_ntag.from_halt = from_halt;
    g_ntag.authenticated = 0u;
    g_ntag.compat_page = 0u;
    g_ntag_reply[0] = 0x44u;
    g_ntag_reply[1] = 0x00u;
    typea_send(g_ntag_reply, 2u);
}

static bool ntag_page_requires_auth(uint8_t page)
{
    uint8_t auth0 = g_ntag_memory[NTAG215_CFG0_OFFSET + 3u];

    return (auth0 < NTAG215_PAGE_COUNT) && (page >= auth0);
}

static uint8_t ntag_read_page_limit(void)
{
    uint8_t access = g_ntag_memory[NTAG215_CFG1_OFFSET];
    uint8_t auth0 = g_ntag_memory[NTAG215_CFG0_OFFSET + 3u];

    if (((access & NTAG_ACCESS_PROT) != 0u) &&
        (g_ntag.authenticated == 0u) &&
        (auth0 < NTAG215_PAGE_COUNT)) {
        return auth0;
    }
    return NTAG215_PAGE_COUNT;
}

static void ntag_note_first_read(void)
{
    uint8_t access = g_ntag_memory[NTAG215_CFG1_OFFSET];

    if ((g_ntag.counter_incremented == 0u) &&
        ((access & NTAG_ACCESS_NFC_CNT_EN) != 0u)) {
        if (g_ntag.counter < 0x00FFFFFFu) {
            ++g_ntag.counter;
        }
        g_ntag.counter_incremented = 1u;
    }
}

static bool ntag_write_page_is_valid(uint8_t page)
{
    return (page >= NTAG215_USER_FIRST_PAGE) &&
           (page <= NTAG215_USER_LAST_PAGE);
}

static void ntag_write_page(uint8_t page, const volatile uint8_t *data)
{
    uint16_t offset = (uint16_t)page * 4u;
    uint8_t i;

    for (i = 0u; i < 4u; ++i) {
        g_ntag_memory[offset + i] = data[i];
    }
}

static void ntag_process_active_command(uint16_t rx_length)
{
    const volatile uint8_t *rx = g_nfc_state.rx;
    uint16_t i;

    if (g_ntag.state == NTAG_STATE_COMPAT_WRITE) {
        uint8_t page = g_ntag.compat_page;

        g_ntag.state = NTAG_STATE_ACTIVE;
        g_ntag.compat_page = 0u;
        if ((rx_length != 18u) || !typea_crc_is_valid(rx, rx_length)) {
            nfc_typea_send_short_4bit(NTAG_NAK_CRC_ERROR);
            return;
        }
        ntag_write_page(page, rx);
        nfc_typea_send_short_4bit(NTAG_ACK);
        return;
    }

    if ((rx_length < 3u) || !typea_crc_is_valid(rx, rx_length)) {
        if (rx_length >= 3u) {
            nfc_typea_send_short_4bit(NTAG_NAK_CRC_ERROR);
        } else {
            ntag_return_to_wait_state();
        }
        return;
    }

    if ((rx_length == 4u) && (rx[0] == 0x50u)) {
        if (rx[1] == 0x00u) {
            g_ntag.state = NTAG_STATE_HALT;
            g_ntag.from_halt = 1u;
            g_ntag.authenticated = 0u;
            g_ntag.compat_page = 0u;
        } else {
            nfc_typea_send_short_4bit(NTAG_NAK_INVALID_ARGUMENT);
        }
        return;
    }

    if ((rx_length == 4u) && (rx[0] == 0x30u)) {
        uint8_t page = rx[1];
        uint8_t limit = ntag_read_page_limit();
        uint8_t byte_in_page = 0u;

        if (page >= limit) {
            nfc_typea_send_short_4bit(NTAG_NAK_INVALID_ARGUMENT);
            return;
        }
        ntag_note_first_read();
        for (i = 0u; i < 16u; ++i) {
            uint16_t position = (uint16_t)page * 4u + byte_in_page;

            g_ntag_reply[i] = ntag_read_visible_byte(g_ntag_memory,
                                                      position);
            ++byte_in_page;
            if (byte_in_page == 4u) {
                byte_in_page = 0u;
                ++page;
                if (page == limit) {
                    page = 0u;
                }
            }
        }
        append_typea_crc(g_ntag_reply, 16u);
        typea_send(g_ntag_reply, 18u);
        return;
    }

    if ((rx_length == 3u) && (rx[0] == 0x60u)) {
        static const uint8_t version_reply[8] = {
            0x00u, 0x04u, 0x04u, 0x02u,
            0x01u, 0x00u, 0x11u, 0x03u
        };

        for (i = 0u; i < 8u; ++i) {
            g_ntag_reply[i] = version_reply[i];
        }
        append_typea_crc(g_ntag_reply, 8u);
        typea_send(g_ntag_reply, 10u);
        return;
    }

    if ((rx_length == 4u) && (rx[0] == 0x3Cu)) {
        if (rx[1] != 0u) {
            nfc_typea_send_short_4bit(NTAG_NAK_INVALID_ARGUMENT);
            return;
        }
        for (i = 0u; i < 0x20u; ++i) {
            g_ntag_reply[i] = 0u;
        }
        append_typea_crc(g_ntag_reply, 0x20u);
        typea_send(g_ntag_reply, 0x22u);
        return;
    }

    if ((rx_length == 4u) && (rx[0] == 0x39u)) {
        uint8_t access = g_ntag_memory[NTAG215_CFG1_OFFSET];

        if (rx[1] != 0x02u) {
            nfc_typea_send_short_4bit(NTAG_NAK_INVALID_ARGUMENT);
            return;
        }
        if (((access & NTAG_ACCESS_CNT_PWD_PROT) != 0u) &&
            (g_ntag.authenticated == 0u)) {
            nfc_typea_send_short_4bit(NTAG_NAK_AUTH_REQUIRED);
            return;
        }
        g_ntag_reply[0] = (uint8_t)g_ntag.counter;
        g_ntag_reply[1] = (uint8_t)(g_ntag.counter >> 8);
        g_ntag_reply[2] = (uint8_t)(g_ntag.counter >> 16);
        append_typea_crc(g_ntag_reply, 3u);
        typea_send(g_ntag_reply, 5u);
        return;
    }

    /*
     * Common Ultralight/NTAG discovery tools probe the single NFC counter's
     * tearing flag even though the public NTAG21x command table omits it.
     * Proxmark3 and Flipper both emulate index 2 for NTAG215.
     */
    if ((rx_length == 4u) && (rx[0] == 0x3Eu)) {
        if (rx[1] != 0x02u) {
            nfc_typea_send_short_4bit(NTAG_NAK_INVALID_ARGUMENT);
            return;
        }
        g_ntag_reply[0] = NTAG_TEARING_FLAG_VALID;
        append_typea_crc(g_ntag_reply, 1u);
        typea_send(g_ntag_reply, 3u);
        return;
    }

    if ((rx_length == 7u) && (rx[0] == 0x1Bu)) {
        for (i = 0u; i < 4u; ++i) {
            if (rx[1u + i] != g_ntag_memory[NTAG215_PWD_OFFSET + i]) {
                nfc_typea_send_short_4bit(NTAG_NAK_AUTH_REQUIRED);
                return;
            }
        }
        g_ntag.authenticated = 1u;
        g_ntag_reply[0] = g_ntag_memory[NTAG215_PACK_OFFSET];
        g_ntag_reply[1] = g_ntag_memory[NTAG215_PACK_OFFSET + 1u];
        append_typea_crc(g_ntag_reply, 2u);
        typea_send(g_ntag_reply, 4u);
        return;
    }

    if ((rx_length == 5u) && (rx[0] == 0x3Au)) {
        uint8_t first = rx[1];
        uint8_t last = rx[2];
        uint8_t limit = ntag_read_page_limit();
        uint16_t offset;
        uint16_t data_length;

        if ((last < first) || (first >= limit) || (last >= limit)) {
            nfc_typea_send_short_4bit(NTAG_NAK_INVALID_ARGUMENT);
            return;
        }
        offset = (uint16_t)first * 4u;
        data_length = (uint16_t)((uint16_t)(last - first) + 1u) * 4u;
        ntag_note_first_read();
        ntag_stream_memory_with_crc(offset, data_length);
        return;
    }

    if ((rx_length == 8u) && (rx[0] == 0xA2u)) {
        uint8_t page = rx[1];

        if (!ntag_write_page_is_valid(page)) {
            nfc_typea_send_short_4bit(NTAG_NAK_INVALID_ARGUMENT);
            return;
        }
        if (ntag_page_requires_auth(page) &&
            (g_ntag.authenticated == 0u)) {
            nfc_typea_send_short_4bit(NTAG_NAK_AUTH_REQUIRED);
            return;
        }
        ntag_write_page(page, &rx[2]);
        nfc_typea_send_short_4bit(NTAG_ACK);
        return;
    }

    if ((rx_length == 4u) && (rx[0] == 0xA0u)) {
        uint8_t page = rx[1];

        if (!ntag_write_page_is_valid(page)) {
            nfc_typea_send_short_4bit(NTAG_NAK_INVALID_ARGUMENT);
            return;
        }
        if (ntag_page_requires_auth(page) &&
            (g_ntag.authenticated == 0u)) {
            nfc_typea_send_short_4bit(NTAG_NAK_AUTH_REQUIRED);
            return;
        }
        g_ntag.compat_page = page;
        g_ntag.state = NTAG_STATE_COMPAT_WRITE;
        nfc_typea_send_short_4bit(NTAG_ACK);
        return;
    }

    ntag_return_to_wait_state();
}

void ntag_dispatch(uint16_t rx_length)
{
    const volatile uint8_t *rx = g_nfc_state.rx;
    uint16_t i;

    if (g_nfc_state.selector_valid == 0u) {
        return;
    }

    if (g_nfc_state.slot == MFC1K_SLOT_INDEX) {
        mifare_classic_dispatch(rx_length);
        return;
    }

    if (g_ntag.memory_ready == 0u) {
        return;
    }

    if (rx_length == 1u) {
        if ((rx[0] == 0x26u) && (g_ntag.state != NTAG_STATE_HALT)) {
            ntag_begin_selection(0u);
        } else if (rx[0] == 0x52u) {
            ntag_begin_selection((g_ntag.state == NTAG_STATE_HALT) ? 1u : 0u);
        }
        return;
    }

    if ((g_ntag.state == NTAG_STATE_IDLE) ||
        (g_ntag.state == NTAG_STATE_HALT)) {
        return;
    }

    if (g_ntag.state == NTAG_STATE_READY1) {
        if ((rx_length == 2u) &&
            (rx[0] == 0x93u) && (rx[1] == 0x20u)) {
            g_ntag_reply[0] = 0x88u;
            for (i = 0u; i < 4u; ++i) {
                g_ntag_reply[1u + i] = ntag_cascade_byte(1u, (uint8_t)i);
            }
            typea_send(g_ntag_reply, 5u);
            return;
        }
        if ((rx_length == 9u) &&
            (rx[0] == 0x93u) && (rx[1] == 0x70u) &&
            typea_crc_is_valid(rx, rx_length) &&
            (rx[2] == 0x88u)) {
            for (i = 0u; i < 4u; ++i) {
                if (rx[3u + i] != ntag_cascade_byte(1u, (uint8_t)i)) {
                    ntag_return_to_wait_state();
                    return;
                }
            }
            g_ntag_reply[0] = 0x04u;
            append_typea_crc(g_ntag_reply, 1u);
            typea_send(g_ntag_reply, 3u);
            g_ntag.state = NTAG_STATE_READY2;
            return;
        }
        if ((rx_length == 4u) && (rx[0] == 0x30u) &&
            (rx[1] == 0u) && typea_crc_is_valid(rx, rx_length)) {
            g_ntag.state = NTAG_STATE_ACTIVE;
            ntag_process_active_command(rx_length);
            return;
        }
        ntag_return_to_wait_state();
        return;
    }

    if (g_ntag.state == NTAG_STATE_READY2) {
        if ((rx_length == 2u) &&
            (rx[0] == 0x95u) && (rx[1] == 0x20u)) {
            for (i = 0u; i < 5u; ++i) {
                g_ntag_reply[i] = ntag_cascade_byte(2u, (uint8_t)i);
            }
            typea_send(g_ntag_reply, 5u);
            return;
        }
        if ((rx_length == 9u) &&
            (rx[0] == 0x95u) && (rx[1] == 0x70u) &&
            typea_crc_is_valid(rx, rx_length)) {
            for (i = 0u; i < 5u; ++i) {
                if (rx[2u + i] != ntag_cascade_byte(2u, (uint8_t)i)) {
                    ntag_return_to_wait_state();
                    return;
                }
            }
            g_ntag_reply[0] = 0x00u;
            append_typea_crc(g_ntag_reply, 1u);
            typea_send(g_ntag_reply, 3u);
            g_ntag.state = NTAG_STATE_ACTIVE;
            return;
        }
        if ((rx_length == 4u) && (rx[0] == 0x30u) &&
            (rx[1] == 0u) && typea_crc_is_valid(rx, rx_length)) {
            g_ntag.state = NTAG_STATE_ACTIVE;
            ntag_process_active_command(rx_length);
            return;
        }
        ntag_return_to_wait_state();
        return;
    }

    ntag_process_active_command(rx_length);
}

void iso15693_dispatch(uint16_t rx_length, uint32_t block_size)
{
    uint8_t reply[276];
    const uint8_t *tag = iso15693_tag();
    const uint8_t *block_data = tag + 0x10u;
    const volatile uint8_t *rx = g_nfc_state.rx;
    uint8_t flags;
    uint8_t command;
    uint8_t addressed_offset;

    if ((rx_length < 2u) || (block_size == 0u) || (block_size > 255u)) {
        return;
    }
    if (iso15693_crc16((const uint8_t *)rx, rx_length) != 0x0F47u) {
        return;
    }

    flags = rx[0];
    command = rx[1];
    addressed_offset = ((flags & 0x20u) != 0u) ? 8u : 0u;

    if (command == ISO15693_CMD_INVENTORY) {
        uint8_t i;
        if ((flags & 0x26u) != 0x26u) {
            return;
        }
        reply[0] = 0u;
        reply[1] = 0u;
        for (i = 0; i < 8u; ++i) {
            reply[2u + i] = tag[i];
        }
        iso15693_send_with_crc(reply, 10u);
        return;
    }

    if ((command == ISO15693_CMD_READ_SINGLE) ||
        (command == ISO15693_CMD_READ_MULTIPLE)) {
        uint16_t first;
        uint16_t blocks = 1u;
        uint16_t payload_length;
        uint16_t block;
        bool include_security = (flags & 0x40u) != 0u;

        if (rx_length <= (uint16_t)(addressed_offset + 2u)) {
            return;
        }
        first = rx[addressed_offset + 2u];
        if (command == ISO15693_CMD_READ_MULTIPLE) {
            if (rx_length <= (uint16_t)(addressed_offset + 3u)) {
                return;
            }
            blocks = (uint16_t)rx[addressed_offset + 3u] + 1u;
        }

        payload_length = (uint16_t)(blocks * (block_size +
                           (include_security ? 1u : 0u)) + 1u);
        if ((payload_length + 2u > sizeof(reply)) ||
            (first + blocks >= (uint16_t)g_nfc_state.max_block + 2u)) {
            return;
        }

        reply[0] = 0u;
        for (block = 0; block < blocks; ++block) {
            uint16_t position = (uint16_t)
                (block * (block_size + (include_security ? 1u : 0u)) + 1u);
            uint16_t i;

            if (include_security) {
                reply[position++] = 0u;
            }
            if ((uint16_t)g_nfc_state.max_block < first + block) {
                for (i = 0; i < block_size; ++i) {
                    reply[position + i] = 0x03u;
                }
            } else {
                for (i = 0; i < block_size; ++i) {
                    reply[position + i] =
                        block_data[(first + block) * block_size + i];
                }
            }
        }
        iso15693_send_with_crc(reply, payload_length);
        return;
    }

    if (command == ISO15693_CMD_GET_SYS_INFO) {
        uint8_t i;
        reply[0] = 0u;
        reply[1] = 0x0Fu;
        for (i = 0; i < 8u; ++i) {
            reply[2u + i] = tag[i];
        }
        reply[10] = tag[0x0Bu];
        reply[11] = tag[0x0Au];
        reply[12] = g_nfc_state.max_block;
        reply[13] = (uint8_t)(block_size - 1u);
        reply[14] = 0x50u;
        iso15693_send_with_crc(reply, 15u);
        return;
    }

    if (command == ISO15693_CMD_GET_MULT_SEC) {
        uint8_t first;
        uint8_t count;
        uint8_t i;

        if (rx_length <= (uint16_t)(addressed_offset + 3u)) {
            return;
        }
        first = rx[addressed_offset + 2u];
        count = rx[addressed_offset + 3u];
        if ((int16_t)((uint16_t)g_nfc_state.max_block - first) <= count) {
            count = (uint8_t)(g_nfc_state.max_block - first + 1u);
        }
        reply[0] = 0u;
        for (i = 0; i < count; ++i) {
            reply[1u + i] = 0u;
        }
        iso15693_send_with_crc(reply, (uint16_t)count + 1u);
        return;
    }

    if ((command == ISO15693_CMD_WRITE_SINGLE) && ((flags & 0x20u) == 0u)) {
        /* This is the behavior in the recovered image: success response only. */
        reply[0] = 0u;
        iso15693_send_with_crc(reply, 1u);
    }
}
