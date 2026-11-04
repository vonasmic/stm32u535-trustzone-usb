/*
******************************************************************************
**
**  File        : LinkerScript.ld
**
**  Author      : STM32CubeIDE
**
**  Abstract    : Linker script for STM32U535xC Device from STM32U5 series
**                      256Kbytes FLASH
**                      272Kbytes RAM
**
**                Set heap size, stack size and stack location according
**                to application requirements.
**
**                Set memory bank area and size if external memory is used.
**
**  Target      : STMicroelectronics STM32
**
**  Distribution: The file is distributed as is without any warranty
**                of any kind.
**
*****************************************************************************
** @attention
**
** Copyright (c) 2026 STMicroelectronics.
** All rights reserved.
**
** This software is licensed under terms that can be found in the LICENSE file
** in the root directory of this software component.
** If no LICENSE file comes with this software, it is provided AS-IS.
**
*****************************************************************************
*/

/* Entry Point */
ENTRY(Reset_Handler)

/* Highest address of the user mode stack */
_estack = ORIGIN(RAM) + LENGTH(RAM);	/* end of "RAM" Ram type memory */
_sstack = _estack - _Min_Stack_Size;	/* bottom of Secure MSP; Reset_Handler loads it into MSPLIM_S */

_Min_Heap_Size = 0x200;	/* TLS 1.3 + ML-KEM heap */
_Min_Stack_Size = 0x4000;	/* 16 KB: TLS + NSC + libtropic; storage-blob AEAD frames ~8.6 KB; _sbrk stops the heap here */
ASSERT((_sstack % 8) == 0, "_sstack (MSPLIM_S) must be 8-byte aligned")

/* Reset_Handler zeroes these ranges before SystemInit: all Secure RAM
 * (SRAM1 + Secure SRAM2, stack included) and all of SRAM4. */
_swipe_ram   = ORIGIN(RAM);
_ewipe_ram   = ORIGIN(RAM) + LENGTH(RAM);
_swipe_sram4 = ORIGIN(SRAM4);
_ewipe_sram4 = ORIGIN(SRAM4) + LENGTH(SRAM4);
ASSERT(((_ewipe_ram - _swipe_ram) % 16) == 0, "RAM wipe range must be a multiple of 16 bytes")
ASSERT(((_ewipe_sram4 - _swipe_sram4) % 16) == 0, "SRAM4 wipe range must be a multiple of 16 bytes")

/* Memories definition */
MEMORY
{
  RAM	(xrw)	 : ORIGIN = 0x30000000,	LENGTH = 224K     /* SRAM1 192K + low 32K of SRAM2. High 32K of SRAM2 is NonSecure. */
  SRAM4	(xrw)    : ORIGIN = 0x38000000,	LENGTH = 16K
  FLASH	(rx)	 : ORIGIN = 0x0C000000,	LENGTH = 168K    /* pages 0-20, 8KB pages */
  FLASH_CREDS	(r)	 : ORIGIN = 0x0C02A000,	LENGTH = 8K      /* page 21, SAE CA + device cert */
  FLASH_NV	(r)	 : ORIGIN = 0x0C02C000,	LENGTH = 8K      /* page 22, dwk + plaintext NV */
  FLASH_NSC	(rx) : ORIGIN = 0x0C02E000,	LENGTH = 8K      /* page 23, Secure+NSC */
}

/* Sections */
SECTIONS
{
  /* The startup code into "FLASH" Rom type memory */
  .isr_vector :
  {
    KEEP(*(.isr_vector)) /* Startup code */
  } >FLASH

  /* The program code and other data into "FLASH" Rom type memory */
  .text :
  {
    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */
    *(.glue_7)         /* glue arm to thumb code */
    *(.glue_7t)        /* glue thumb to arm code */
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    _etext = .;        /* define a global symbols at end of code */
  } >FLASH

  /* SG veneers first on page 23, then string literals and the newlib ctype
   * table. Must appear before FLASH .rodata so *(.rodata*) does not claim
   * them. -fdata-sections names literals .rodata.<fn>.str1.1, not
   * .rodata.str1.1. _ctype_ is 257 bytes and is what made .data overflow
   * the 168K FLASH region. */
  .gnu.sgstubs :
  {
    . = ALIGN(4);
    KEEP(*(.gnu.sgstubs*))   /* Secure Gateway stubs — NSC entry points */
    . = ALIGN(4);
  } >FLASH_NSC

  .rodata_str (READONLY) :
  {
    *(.rodata.str1.*)
    *(.rodata.*str1.*)
    *(.rodata._ctype_)
  } >FLASH_NSC

  /* Constant data into "FLASH" Rom type memory */
  .rodata :
  {
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
  } >FLASH

  .ARM.extab (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    *(.ARM.extab* .gnu.linkonce.armextab.*)
  } >FLASH
  .ARM (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
  } >FLASH

  .preinit_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
  } >FLASH

  .init_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
  } >FLASH

  .fini_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT(.fini_array.*)))
    KEEP (*(.fini_array*))
    PROVIDE_HIDDEN (__fini_array_end = .);
  } >FLASH

  /* Used by the startup to initialize data */
  _sidata = LOADADDR(.data);

  /* Initialized data sections into "RAM" Ram type memory */
  .data :
  {
    _sdata = .;        /* create a global symbol at data start */
    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */
    *(.RamFunc)        /* .RamFunc sections */
    *(.RamFunc*)       /* .RamFunc* sections */

    _edata = .;        /* define a global symbol at data end */
  } >RAM AT> FLASH

  /* Pages 21 and 22 (FLASH_CREDS, FLASH_NV) are not in the image.
   * The debug launch mass-erases before load, so a download leaves them blank. */

  /* Uninitialized data section into "RAM" Ram type memory */
  .bss :
  {
    /* This is used by the startup in order to initialize the .bss section */
    _sbss = .;         /* define a global symbol at bss start */
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)

    _ebss = .;         /* define a global symbol at bss end */
    __bss_end__ = _ebss;
  } >RAM

  /* Static buffers that do not fit on the TLS stack (SE_SRAM4_BSS).
   * NOLOAD: Reset_Handler zeroes all of SRAM4 (_swipe_sram4.._ewipe_sram4). */
  .sram4_bss (NOLOAD) :
  {
    . = ALIGN(16);
    _ssram4 = .;
    *(.sram4_bss)
    *(.sram4_bss*)
    . = ALIGN(16);
    _esram4 = .;
  } >SRAM4

  /* User_heap_stack section, used to check that there is enough "RAM" Ram  type memory left */
  ._user_heap_stack :
  {
    . = ALIGN(8);
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = . + _Min_Heap_Size;
    . = . + _Min_Stack_Size;
    . = ALIGN(8);
  } >RAM

  /* Remove information from the compiler libraries */
  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }

  .ARM.attributes 0 : { *(.ARM.attributes) }
}
