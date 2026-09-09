# Hardware

STM32U535CCTX on the **TS13 DevKit**, TrustZone split, TROPIC01 on SPI1. Peripheral pins and clocks are owned by **STM32CubeMX** (`SE_firmware.ioc`). Do not hand-edit `MX_*_Init` or `HAL_*_MspInit`.

How to program option bytes and ELFs: **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

---

## Device

| | |
| --- | --- |
| MCU | STM32U535CCTX (U5, Cortex-M33, TrustZone) |
| Flash | **256 KB**, **32 × 8 KB** pages |
| RAM | **272 KB** total (see split below) |

Linker comments: [Secure/STM32U535CCTX_FLASH.ld](../Secure/STM32U535CCTX_FLASH.ld), [NonSecure/STM32U535CCTX_FLASH.ld](../NonSecure/STM32U535CCTX_FLASH.ld).

---

## Flash map

Non-secure view base `0x08000000`. Secure linker uses alias `0x0C000000` for the same bank.

| Region | NS address | Secure alias | Size | Pages | Source |
| --- | --- | --- | --- | --- | --- |
| Secure code | `0x08000000` | `0x0C000000` | 168 KB | **0–20** | `FLASH` |
| Creds (runtime) | `0x0802A000` | `0x0C02A000` | 8 KB | **21** | `FLASH_CREDS`, SAE CA + device cert |
| MCU NV (runtime) | `0x0802C000` | `0x0C02C000` | 8 KB | **22** | `FLASH_NV`, dwk header + sealed v6 |
| NSC veneers | `0x0802E000` | `0x0C02E000` | 8 KB | **23** | `FLASH_NSC`, `.gnu.sgstubs` |
| NonSecure app | `0x08030000` | — | 64 KB | **24–31** | NS `FLASH` |

Page 21 is Secure data (not part of the Secure ELF load). Page 22 is **not** part of the Secure ELF load. After a linker-map change, rebuild Secure so code still fits pages 0–20.

`SECWM1_PEND` stays `0x17` (page 23): page 21 is Secure-only data, not code.

NV implementation: `SE_NV_FLASH_ADDR = 0x0C02C000`, `SE_NV_FLASH_PAGE = 22`; creds page 21 at `0x0C02A000` in [se_tropic_port_stm32.c](../Secure/Core/Src/se_tropic_port_stm32.c). Record layout: **[TROPIC.md](TROPIC.md)**.

Boot: Secure init then jump to NonSecure `VTOR_TABLE_NS_START_ADDR = 0x08030000`.

---

## RAM

| World | Region | Origin | Size |
| --- | --- | --- | --- |
| Secure | RAM | `0x30000000` | 192 KB |
| Secure | SRAM4 | `0x38000000` | 16 KB |
| NonSecure | RAM | `0x20030000` | 64 KB |
| NonSecure | SRAM4 | `0x28000000` | 16 KB |

Secure heap/stack minima in the linker: heap `0x200`, stack `0x400` (TLS + ML-KEM). NonSecure: heap `0x200` (USBX), stack `0x400`.

---

## Option bytes

TrustZone (`TZEN`) must be enabled.

| Option | Value | Meaning |
| --- | --- | --- |
| `SECWM1_PSTRT` | `0x0` | Secure flash from page 0 |
| `SECWM1_PEND` | `0x17` | Last Secure page = **23** (includes NSC) |
| `NSBOOTADD0` | `0x100600` | NS vectors at `0x08030000` (`addr >> 7`) |
| `HDP1EN` | `0x0` | Hide protection off |

Inspect:

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob displ
```

Set (after a map change, then `-rst`):

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob SECWM1_PSTRT=0x0 SECWM1_PEND=0x17 NSBOOTADD0=0x100600 HDP1EN=0x0 -rst
```

---

## GTZC / SAU

From `SE_firmware.ioc`:

| Peripheral | Attribute |
| --- | --- |
| SPI1 | `GTZC_TZSC_PERIPH_SEC` |
| RNG | Secure |

SAU (CubeMX):

| Region | Start | Size |
| --- | --- | --- |
| SAU0 | `0x0C01E000` | (CubeMX default remainder) |
| SAU1 | `0x08020000` | `0x20000` (128 KB) |

Keep SPI1 and Tropic GPIO **Secure** when regenerating.

---

## Pinout (CubeMX-generated labels)

Generated [main.h](../Secure/Core/Inc/main.h) uses `PWR` / `CS` / `GPO`, not `TR01_*`.

| Pin | Label | Mode | World |
| --- | --- | --- | --- |
| PA0 | `PWR` | GPIO output (Tropic power; firmware sets high in `se_tropic_port_hw_init`) | Secure |
| PA4 | `CS` | GPIO output, initial **high** (software NSS) | Secure |
| PA5 | — | SPI1_SCK, full-duplex master | Secure |
| PA6 | — | SPI1_MISO | Secure |
| PA7 | — | SPI1_MOSI | Secure |
| PB0 | `GPO` | GPIO input (optional Tropic INT) | Secure |
| PA11 | — | USB_DM | NonSecure |
| PA12 | — | USB_DP | NonSecure |

SPI1: master, 8-bit, prescaler **32** (~1.5 Mbit/s). Firmware does **not** call `MX_SPI1_Init()`; libtropic calls `HAL_SPI_Init()` and uses CubeMX `HAL_SPI_MspInit`.

USB: USBX CDC ACM on `USB_DRD_FS` (NonSecure).

---

## CubeMX vs application code

Enable SPI1, GPIO, RNG, GTZC, SAU in the **Secure (M33S)** context, save the `.ioc`, regenerate. Application code only drives the generated symbols (`PWR_Pin`, `CS_Pin`, …).

Do not edit anything under `Secure/Debug/` or `NonSecure/Debug/` (CubeIDE regenerates those trees).
