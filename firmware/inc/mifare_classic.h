#ifndef TAGEMULATOR_MIFARE_CLASSIC_H
#define TAGEMULATOR_MIFARE_CLASSIC_H

#include <stdint.h>

#define MFC1K_SLOT_INDEX 7u
#define MFC1K_MEMORY_SIZE 1024u

void mifare_classic_memory_prepare(void);
void mifare_classic_memory_finish(void);
void mifare_classic_dispatch(uint16_t rx_length);

#endif
