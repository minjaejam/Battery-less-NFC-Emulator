; Minimal startup for the NFC emulator. RAM state is initialized explicitly.

Stack_Size      EQU     0x00000400

                AREA    STACK, NOINIT, READWRITE, ALIGN=3
Stack_Mem       SPACE   Stack_Size
__initial_sp

                PRESERVE8
                THUMB

                AREA    RESET, DATA, READONLY
                EXPORT  __Vectors
                EXPORT  __Vectors_End
                EXPORT  __Vectors_Size
                EXPORT  __initial_sp

__Vectors
                DCD     __initial_sp
                DCD     Reset_Handler
                DCD     NMI_Handler
                DCD     HardFault_Handler
                DCD     0
                DCD     0
                DCD     0
                DCD     0
                DCD     0
                DCD     0
                DCD     0
                DCD     SVC_Handler
                DCD     0
                DCD     0
                DCD     PendSV_Handler
                DCD     SysTick_Handler

                DCD     WDT_IRQHandler
                DCD     LVD_IRQHandler
                DCD     RTC_IRQHandler
                DCD     FLASHRAM_IRQHandler
                DCD     SYSCTRL_IRQHandler
                DCD     GPIOA_IRQHandler
                DCD     GPIOB_IRQHandler
                DCD     0
                DCD     0
                DCD     0
                DCD     0
                DCD     0
                DCD     ADC_IRQHandler
                DCD     ATIM_IRQHandler
                DCD     VC1_IRQHandler
                DCD     VC2_IRQHandler
                DCD     GTIM1_IRQHandler
                DCD     0
                DCD     0
                DCD     LPTIM_IRQHandler
                DCD     BTIM1_IRQHandler
                DCD     BTIM2_IRQHandler
                DCD     BTIM3_IRQHandler
                DCD     I2C1_IRQHandler
                DCD     0
                DCD     SPI1_IRQHandler
                DCD     0
                DCD     UART1_IRQHandler
                DCD     UART2_IRQHandler
                DCD     0
                DCD     0
                DCD     CLKFAULT_IRQHandler

__Vectors_End
__Vectors_Size  EQU     __Vectors_End - __Vectors

                AREA    |.text|, CODE, READONLY

Reset_Handler   PROC
                EXPORT  Reset_Handler
                IMPORT  main
                LDR     R0, =main
                BX      R0
                ENDP

NMI_Handler     PROC
                EXPORT  NMI_Handler [WEAK]
                B       .
                ENDP

HardFault_Handler PROC
                EXPORT  HardFault_Handler [WEAK]
                B       .
                ENDP

SVC_Handler     PROC
                EXPORT  SVC_Handler [WEAK]
                B       .
                ENDP

PendSV_Handler  PROC
                EXPORT  PendSV_Handler [WEAK]
                B       .
                ENDP

SysTick_Handler PROC
                EXPORT  SysTick_Handler [WEAK]
                B       .
                ENDP

Default_Handler PROC
                EXPORT  WDT_IRQHandler [WEAK]
                EXPORT  LVD_IRQHandler [WEAK]
                EXPORT  RTC_IRQHandler [WEAK]
                EXPORT  FLASHRAM_IRQHandler [WEAK]
                EXPORT  SYSCTRL_IRQHandler [WEAK]
                EXPORT  GPIOA_IRQHandler [WEAK]
                EXPORT  GPIOB_IRQHandler [WEAK]
                EXPORT  ADC_IRQHandler [WEAK]
                EXPORT  ATIM_IRQHandler [WEAK]
                EXPORT  VC1_IRQHandler [WEAK]
                EXPORT  VC2_IRQHandler [WEAK]
                EXPORT  GTIM1_IRQHandler [WEAK]
                EXPORT  LPTIM_IRQHandler [WEAK]
                EXPORT  BTIM1_IRQHandler [WEAK]
                EXPORT  BTIM2_IRQHandler [WEAK]
                EXPORT  BTIM3_IRQHandler [WEAK]
                EXPORT  I2C1_IRQHandler [WEAK]
                EXPORT  SPI1_IRQHandler [WEAK]
                EXPORT  UART1_IRQHandler [WEAK]
                EXPORT  UART2_IRQHandler [WEAK]
                EXPORT  CLKFAULT_IRQHandler [WEAK]

WDT_IRQHandler
LVD_IRQHandler
RTC_IRQHandler
FLASHRAM_IRQHandler
SYSCTRL_IRQHandler
GPIOA_IRQHandler
GPIOB_IRQHandler
ADC_IRQHandler
ATIM_IRQHandler
VC1_IRQHandler
VC2_IRQHandler
GTIM1_IRQHandler
LPTIM_IRQHandler
BTIM1_IRQHandler
BTIM2_IRQHandler
BTIM3_IRQHandler
I2C1_IRQHandler
SPI1_IRQHandler
UART1_IRQHandler
UART2_IRQHandler
CLKFAULT_IRQHandler
                B       .
                ENDP

                ALIGN
                END
