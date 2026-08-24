#include <stddef.h>
#include <stdint.h>

#include "../inc/mifare_classic.h"
#include "../inc/tag_emulator.h"
#include "cw32l010.h"

#define REG32(address) (*(volatile uint32_t *)(uintptr_t)(address))

#define VC_DIV_REG          ((uintptr_t)&CW_VCREF->CR)
#define VC2_CR0_REG         ((uintptr_t)&CW_VC2->CR0)
#define VC2_CR1_REG         ((uintptr_t)&CW_VC2->CR1)
#define VC2_SR_REG          ((uintptr_t)&CW_VC2->SR)

#define NVIC_ISER0_REG      0xE000E100u
#define NVIC_ICPR0_REG      0xE000E280u
#define VC2_IRQ_MASK        (1u << 15)

#define SYSCTRL_CR0_REG     ((uintptr_t)&CW_SYSCTRL->CR0)
#define SYSCTRL_CR1_REG     ((uintptr_t)&CW_SYSCTRL->CR1)
#define SYSCTRL_HSE_REG     ((uintptr_t)&CW_SYSCTRL->HSE)
#define SYSCTRL_AHBEN_REG   ((uintptr_t)&CW_SYSCTRL->AHBEN)
#define SYSCTRL_APBEN2_REG  ((uintptr_t)&CW_SYSCTRL->APBEN2)
#define SYSCTRL_APBEN1_REG  ((uintptr_t)&CW_SYSCTRL->APBEN1)
#define SYSCTRL_HSE_STABLE  (1u << 19)
#define HSE_WAIT_FOR_STABLE 0
#define HSE_STARTUP_PDRIVER 7u
#define HSE_FAST_CONFIG     (0x00012605u | (HSE_STARTUP_PDRIVER << 20))


#define BTIM1_CR1_REG       ((uintptr_t)&CW_BTIM1->CR1)
#define BTIM1_ICR_REG       ((uintptr_t)&CW_BTIM1->ICR)
#define BTIM1_CNT_REG       ((uintptr_t)&CW_BTIM1->CNT)

#define GTIM1_CR1_REG       ((uintptr_t)&CW_GTIM1->CR1)
#define GTIM1_CCMR2CMP_REG  ((uintptr_t)&CW_GTIM1->CCMR2CMP)
#define GTIM1_CCER_REG      ((uintptr_t)&CW_GTIM1->CCER)
#define GTIM1_CNT_REG       ((uintptr_t)&CW_GTIM1->CNT)
#define GTIM1_PSC_REG       ((uintptr_t)&CW_GTIM1->PSC)
#define GTIM1_ARR_REG       ((uintptr_t)&CW_GTIM1->ARR)
#define GTIM1_CCR4_REG      ((uintptr_t)&CW_GTIM1->CCR4)

#define GPIOA_DIR_REG       ((uintptr_t)&CW_GPIOA->DIR)
#define GPIOA_OPENDRAIN_REG ((uintptr_t)&CW_GPIOA->OPENDRAIN)
#define GPIOA_PUR_REG       ((uintptr_t)&CW_GPIOA->PUR)
#define GPIOA_AFRL_REG      ((uintptr_t)&CW_GPIOA->AFRL)
#define GPIOA_ANALOG_REG    ((uintptr_t)&CW_GPIOA->ANALOG)
#define GPIOA_IDR_REG       ((uintptr_t)&CW_GPIOA->IDR)
#define GPIOA_BRR_REG       ((uintptr_t)&CW_GPIOA->BRR)

#define GPIOB_DIR_REG       ((uintptr_t)&CW_GPIOB->DIR)
#define GPIOB_OPENDRAIN_REG ((uintptr_t)&CW_GPIOB->OPENDRAIN)
#define GPIOB_AFRL_REG      ((uintptr_t)&CW_GPIOB->AFRL)
#define GPIOB_ANALOG_REG    ((uintptr_t)&CW_GPIOB->ANALOG)
#define GPIOB_BRR_REG       ((uintptr_t)&CW_GPIOB->BRR)

/* The scatter file fixes these objects because the recovered PHY uses them. */
uint32_t SystemCoreClock
    __attribute__((section(".bss.noinit.SystemCoreClock"), used));
NfcRuntime g_nfc_state
    __attribute__((section(".bss.noinit.g_nfc_state"), used));
typedef char nfc_runtime_size_check[(sizeof(NfcRuntime) == 0x108u) ? 1 : -1];
typedef char nfc_rx_offset_check[(offsetof(NfcRuntime, rx) == 8u) ? 1 : -1];

static void system_clock_start_hse(void)
{
    /* Start the crystal first, then do useful initialization while it locks. */
    REG32(SYSCTRL_AHBEN_REG) |= 0x30u;
    REG32(GPIOA_ANALOG_REG) = 3u;
    REG32(SYSCTRL_HSE_REG) = HSE_FAST_CONFIG;
    REG32(SYSCTRL_CR1_REG) |= 0x5A5A0182u;

    /* Make GPIO, GTIM1 and VC registers available during the HSE start-up. */
    REG32(SYSCTRL_AHBEN_REG) = 0x5A5A0032u;
    REG32(SYSCTRL_APBEN1_REG) = 0x5A5A0042u;
    REG32(SYSCTRL_APBEN2_REG) = 0x5A5A0004u;
}

static void system_clock_finish_hse(void)
{
#if HSE_WAIT_FOR_STABLE
    /* 8192 detected HSE clocks are required before the timing-source switch. */
    while ((REG32(SYSCTRL_HSE_REG) & SYSCTRL_HSE_STABLE) == 0u) {
    }
#endif

    REG32(SYSCTRL_CR0_REG) =
        (((REG32(SYSCTRL_CR0_REG) & 0xFFFFu) + 0x5A5A0000u) & ~7u) | 1u;
    SystemCoreClock = 27120000u;
    REG32(SYSCTRL_CR1_REG) =
        (((REG32(SYSCTRL_CR1_REG) & 0xFFFFu) + 0x5A5A0000u) & ~1u);
}

static void io_init(void)
{
    uint32_t selector;

    /* PB5/PB6 are unused analog inputs; do not power the former UART pins. */
    REG32(GPIOB_ANALOG_REG) = 0x60u;
    REG32(GPIOB_DIR_REG) = 0u;
    REG32(GPIOB_OPENDRAIN_REG) = 0u;
    REG32(GPIOB_BRR_REG) |= 0x18u;

    REG32(GPIOA_ANALOG_REG) &= ~0x7Cu;
    REG32(GPIOA_PUR_REG) |= 0x78u;
    REG32(GPIOA_DIR_REG) = (REG32(GPIOA_DIR_REG) & ~0x04u) | 0x78u;
    REG32(GPIOA_OPENDRAIN_REG) &= ~0x04u;
    REG32(GPIOA_BRR_REG) = 0x04u;

    selector = REG32(GPIOA_IDR_REG) & 0x78u;
    REG32((uintptr_t)&g_nfc_state) = 0x01000000u;
    g_nfc_state.printf_state = 0u;

    /* Patterns are written in PA3, PA4, PA5, PA6 order. */
    switch (selector) {
    case 0x70u: /* 0,1,1,1: PA3 low */
        g_nfc_state.slot = 4u;
        break;
    case 0x68u: /* 1,0,1,1: PA4 low */
        g_nfc_state.slot = 5u;
        break;
    case 0x58u: /* 1,1,0,1: PA5 low */
        g_nfc_state.slot = 6u;
        break;
    case 0x38u: /* 1,1,1,0: PA6 low */
        g_nfc_state.slot = 7u;
        break;
    default:
        g_nfc_state.slot = 4u;
        g_nfc_state.selector_valid = 0u;
        break;
    }

    /* The one-hot selector is latched. Remove its static pull-up current. */
    REG32(GPIOA_PUR_REG) &= ~0x78u;
    REG32(GPIOA_ANALOG_REG) |= 0x78u;

    REG32(GPIOB_AFRL_REG) =
        (REG32(GPIOB_AFRL_REG) & 0xFFFFF8FFu) + 0x00000400u;
}

static void nfc_config_typea_timing(void)
{
    REG32(GPIOB_AFRL_REG) =
        (REG32(GPIOB_AFRL_REG) & ~(7u << 12)) | (3u << 13);
    REG32(GTIM1_CR1_REG) = 0x86u;
    REG32(GTIM1_PSC_REG) = 0u;
    REG32(GTIM1_CCMR2CMP_REG) |= ((uint32_t)GTIM1_BASE << 2);
    REG32(GTIM1_ARR_REG) = 0x1Fu;
    REG32(GTIM1_CCR4_REG) = 0x0Fu;
    REG32(GTIM1_CNT_REG) = 0x18u;
    REG32(GTIM1_CCER_REG) |= ((uint32_t)GTIM1_BASE >> 18);
}

static void nfc_clear_timing_state(void)
{
    REG32(BTIM1_CR1_REG) = 0u;
    REG32(BTIM1_ICR_REG) = 0u;
    REG32(BTIM1_CNT_REG) = 0u;
}

static void nfc_enable_typea_receiver(void)
{
    REG32(VC2_CR1_REG) = 0x57u;
    REG32(VC_DIV_REG) = 0x16u;
    REG32(VC2_SR_REG) &= ~1u;
    REG32(NVIC_ICPR0_REG) = VC2_IRQ_MASK;
    REG32(NVIC_ISER0_REG) = VC2_IRQ_MASK;
    REG32(VC2_CR0_REG) = 0x31Fu;
}

int main(void)
{
    uint8_t mfc_selected;
    uint8_t ntag_selected;

    system_clock_start_hse();
    io_init();
    nfc_config_typea_timing();
    nfc_clear_timing_state();

    mfc_selected = (uint8_t)((g_nfc_state.selector_valid != 0u) &&
                            (g_nfc_state.slot == MFC1K_SLOT_INDEX));
    ntag_selected = (uint8_t)((g_nfc_state.selector_valid != 0u) &&
                             (g_nfc_state.slot != MFC1K_SLOT_INDEX));
    if (mfc_selected != 0u) {
        mifare_classic_memory_prepare();
    } else if (ntag_selected != 0u) {
        ntag_memory_prepare();
    }

    system_clock_finish_hse();
    nfc_enable_typea_receiver();

    if (mfc_selected != 0u) {
        mifare_classic_memory_finish();
    }

    for (;;) {
        __WFI();
    }
}

void assert_failed(uint8_t *file, uint32_t line)
{
    (void)file;
    (void)line;
    for (;;) {
    }
}
