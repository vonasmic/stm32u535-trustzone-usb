/* Host stand-in for the firmware SRAM4 NOLOAD region.
 * se_sram4_bss_init() zeros _ssram4.._esram4. The device linker script
 * provides those symbols; this fragment does the same for the host ELF.
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
