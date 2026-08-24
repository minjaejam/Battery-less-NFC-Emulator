#ifndef TAGEMULATOR_HYBRID_H
#define TAGEMULATOR_HYBRID_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    TAG_MODE_NTAG = 0,
    TAG_MODE_ISO15693 = 1
};

/*
 * The machine-code receiver contains the literal address 0x2000000C.
 * Project.sct therefore fixes this object at 0x20000004.
 */
typedef struct {
    volatile uint8_t mode;          /* 0x20000004 */
    volatile uint8_t slot;          /* 0x20000005 */
    volatile uint8_t max_block;     /* 0x20000006 */
    volatile uint8_t selector_valid; /* 0x20000007 */
    volatile uint32_t printf_state; /* 0x20000008 */
    volatile uint8_t rx[256];       /* 0x2000000C */
} NfcRuntime;

extern NfcRuntime g_nfc_state;

void ntag_memory_prepare(void);
void ntag_dispatch(uint16_t rx_length);
void iso15693_dispatch(uint16_t rx_length, uint32_t block_size);

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(offsetof(NfcRuntime, rx) == 8u, "RX offset must stay fixed");
_Static_assert(sizeof(NfcRuntime) == 0x108u, "Runtime layout must stay fixed");
#endif

#ifdef __cplusplus
}
#endif

#endif
