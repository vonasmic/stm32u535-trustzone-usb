/* Host stand-in for the firmware SRAM4 NOLOAD region.
 * On the device Reset_Handler zeroes all of SRAM4; the host ELF loads this
 * section zero-filled. _ssram4/_esram4 match the device linker script.
 */
SECTIONS
{
  .sram4_bss :
  {
    . = ALIGN(16);
    _ssram4 = .;
    KEEP(*(.sram4_bss))
    KEEP(*(.sram4_bss*))
    . = ALIGN(16);
    _esram4 = .;
  }
}
INSERT AFTER .bss;
