@echo off
setlocal

set "ARMCLANG=%LOCALAPPDATA%\Keil_v5\ARM\ARMCLANG\Bin\armclang.exe"
if not exist "%ARMCLANG%" (
    echo ARMCLANG not found: "%ARMCLANG%"
    exit /b 1
)

pushd "%~dp0..\..\MDK"
"%ARMCLANG%" --target=arm-arm-none-eabi -mcpu=cortex-m0plus -c ..\USER\src\nfc_phy_blob_source.S -o ..\USER\src\nfc_phy_blob.o
if errorlevel 1 goto :failed

"%ARMCLANG%" --target=arm-arm-none-eabi -mcpu=cortex-m0plus -c ..\USER\src\nfc_irq_source.S -o ..\USER\src\nfc_irq.o
if errorlevel 1 goto :failed

popd
echo NFC physical-layer objects rebuilt successfully.
exit /b 0

:failed
popd
echo Failed to rebuild NFC physical-layer objects.
exit /b 1
