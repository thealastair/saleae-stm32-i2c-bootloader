# STM32 I2C Bootloader Protocol Analyzer

Saleae Logic 2 High Level Analyzer for decoding STM32 I2C bootloader communications per AN4221.

## Supported Commands

- Get (0x00), Get Version (0x01), Get ID (0x02)
- Read Memory (0x11), Write Memory (0x31)
- Erase Memory (0x44)
- Go (0x21)
- Write Protect (0x63), Write Unprotect (0x73)
- Readout Protect (0x82), Readout Unprotect (0x92)
- Special (0x50), Extended Special (0x51)
- No-Stretch variants (0x32, 0x45, 0x64, 0x74, 0x83, 0x93, 0xA1)

## Usage

1. Add an I2C analyzer to your capture
2. Add this HLA on top of the I2C analyzer
3. Set the bootloader's I2C address (default 0x56)

## Settings

- **Device Address**: 7-bit I2C address of the STM32 bootloader (default: 0x62). See AN2606 for the address used by your device.
