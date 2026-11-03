# How to run (silicon)

Host model / `se_host` is **[host/README.md](../host/README.md)**. This file is the TS13 board.

Command syntax: **[COMMANDS.md](COMMANDS.md)**. Flash map and option bytes: **[HARDWARE.md](HARDWARE.md)**.

---

## Prerequisites


| Tool                                                                              | Purpose                                       |
| --------------------------------------------------------------------------------- | --------------------------------------------- |
| [STM32CubeIDE](https://www.st.com/en/development-tools/stm32cubeide.html)         | Build Secure + NonSecure                      |
| [STM32CubeProgrammer](https://www.st.com/en/development-tools/stm32cubeprog.html) | Flash + option bytes (`STM32_Programmer_CLI`) |
| ST-LINK (SWD)                                                                     | Connect to the MCU                            |


Hardware: **TS13 DevKit** (or equivalent) with TROPIC01 on SPI1.

Irreversible Tropic sequences (MANAGE PAIRING, PIN setup) must pass host model groups **A–E and H** first. Restarting the model restores a fresh chip; silicon does not.

---

## First run (new board or after a flash-map change)

### 1. Build

1. Open this repo root in STM32CubeIDE.
2. Build `SE_firmware_Secure` **first**, then `SE_firmware_NonSecure` (NonSecure needs `secure_nsclib.o` from Secure).
3. Expected outputs:
  - `Secure/Debug/SE_firmware_Secure.elf`
  - `NonSecure/Debug/SE_firmware_NonSecure.elf`

Enroll TLS credentials **at runtime**: unsigned USB `OWNER SET` (owner + optional SAE CA), on-chip ML-DSA, `CLIENT CSR`, then `MANAGE` TLS for KEYGEN / KEM INIT / INSERT SIGNED CSR / PEER.

### 2. Option bytes (new board, or after the linker map changes)

Set these, in order. Values: **[HARDWARE.md](HARDWARE.md)**. Unplug power between the two `-ob` commands. `-rst` does not apply `TZEN` or `DBANK`.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -e all

STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob DBANK=0x0 SWAP_BANK=0x0 TZEN=0x1 -rst
```

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob SECBOOTADD0=0x180000 NSBOOTADD0=0x100600 SECWM1_PSTRT=0x0 SECWM1_PEND=0x17 HDP1EN=0x0 BOOT_LOCK=0x0 -rst
```

Confirm with `-ob displ`:


| Option         | Value                                          |
| -------------- | ---------------------------------------------- |
| `TZEN`         | `0x1`                                          |
| `DBANK`        | `0x0` (single bank, 8 KB pages)                |
| `SWAP_BANK`    | `0x0`                                          |
| `SECBOOTADD0`  | `0x180000` (Secure vectors at `0x0C000000`)    |
| `NSBOOTADD0`   | `0x100600` (NonSecure vectors at `0x08030000`) |
| `SECWM1_PSTRT` | `0x0`                                          |
| `SECWM1_PEND`  | `0x17`                                         |
| `HDP1EN`       | `0x0`                                          |
| `SRAM_RST`     | `0x1` (production: `0x0`, set at lock)         |
| `SRAM2_RST`    | `0x1` (production: `0x0`, set at lock)         |
| `BOOT_LOCK`    | `0x0`                                          |
| `RDP`          | `0xAA` (level 0)                               |


After a linker-map change, rerun only the second `-ob` command. SRAM split and SAU are programmed by Secure startup, not by these option bytes.

Readout protection, `BOOT_LOCK`, the SRAM erase on reset, and the OEM regression keys are set last: [Lockdown and reverting](#lockdown-and-reverting). Leave `RDP` at `0xAA` on a board you still reflash.

The map command writes `BOOT_LOCK=0x0`. Boot then follows the BOOT0 pin, and `SECBOOTADD0` / `NSBOOTADD0` stay writable, so a lab board can still change the flash map or enter the system bootloader.

### 3. Program both images

Erase the whole flash, then program both images. Pages 21 and 22 (creds and NV) are not in the ELFs, so they stay blank. `-e all` does not change option bytes.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -e all

STM32_Programmer_CLI.exe -c port=SWD mode=UR -w "Secure\Debug\SE_firmware_Secure.elf" -v

STM32_Programmer_CLI.exe -c port=SWD mode=UR -w "NonSecure\Debug\SE_firmware_NonSecure.elf" -v -rst
```

### 4. Open the console

Reset or power-cycle. USB re-enumerates as CDC ACM. Do not open a raw serial terminal: every CDC byte is a frame (`0x6767` / type `0x00` command / type `0x01` Secure). Use UserApp or SaeNode (`fel.cvut.usb`). Command payloads are at most **160** bytes. `HELP` lists names. Wire format: **[COMMUNICATION.md](COMMUNICATION.md)**.

### 5. Tropic bring-up

```text
TROPIC PING
TROPIC INFO
```

Default pairing is factory **SH0** (production `prod0` keys unless the firmware was built with `SE_TROPIC_SH0_ENG`).

### 6. One-time chip state

`KEYGEN` and `KEM INIT` run over MANAGE TLS. KEYGEN replaces an occupied ECC slot. KEM INIT takes the unsigned PIN and refuses an occupied slot 510. Occupancy of ECC slot 0 is visible with `TROPIC PUB` dump status empty vs ok.

```text
OWNER SET
MANAGE <unix>    # KEYGEN (empty body)
MANAGE <unix>    # KEM INIT (unsigned PIN + empty body)
```

This creates the owner key, on-chip device ML-DSA, PIN, and ML-KEM key. `CLIENT CSR` dumps the device public key; a client-CA-signed cert is installed with MANAGE INSERT SIGNED CSR. The 1184-byte ML-KEM-768 public key is stored in NV.

To replace an occupied P-256 key:

```text
MANAGE <unix>    # KEYGEN
```

Optional, **irreversible** on silicon (MANAGE cmd 8). The pairing private key is returned once over that TLS session; UserApp writes `pairing-key.hex` and does not print it. After an MCU erase, `OWNER SET` then MANAGE cmd 9 (`PAIRING LOAD`) restores L3 only:

```text
MANAGE <unix>    # PAIRING, body = slot 1–3
MANAGE <unix>    # PAIRING LOAD, body = slot | priv | pub (after reflash)
```

### 7. First USER peers, then first SAE provision

`PEER ADD` is optional and runs over **USER** MANAGE TLS (unsigned), not SAE.
Need a live UserApp for that step. Then a live SaeNode on the same CDC for `PROVISION`.

```text
MANAGE <unix>    # PEER ADD
PROVISION <unix>             # SAE
```

With an empty NV peer list the uplink has 7 items (no peer pairs). Peer hash is SHA384 of the peer SPKI (96 hex digits), the same hash SAE already receives as uplink items 7+. Cap 8 nicknames; see [COMMANDS.md](COMMANDS.md).

`<unix>` is decimal Unix UTC seconds, non-zero. Secure also requires it in `[2024-01-01, 2038-01-01]`. If it is behind the stored TIME floor, firmware keeps the floor. PIN is **not** a console argument; ENCRYPT/DECRYPT take it inside mTLS, and MANAGE takes it only on KEM INIT.

After a successful arm, type `0x01` frames carry TLS until the session ends. A type `0x00` command sent in that window is queued and runs after IDLE. A host that does not frame (plain `socat`) is not a peer.

---

## Lockdown and reverting

A production board ends at RDP level 2 with both OEM keys set. Level 2 is the strongest readout protection on the U535: debug and the system bootloader are off and the option bytes are frozen. The two OEM keys keep every step reversible for the key holder. Without `OEM2KEY`, level 2 is permanent. Do this after [step 7](#7-first-user-peers-then-first-sae-provision), on a board that runs both images.

| Level | `RDP`  | What it does |
| ----- | ------ | ------------ |
| 0     | `0xAA` | Lab default. SWD can read and rewrite flash and option bytes. |
| 0.5   | `0x55` | Secure flash, Secure SRAM, and Secure debug are closed. NonSecure flash and NonSecure debug stay open. |
| 1     | `0xBB` | Debugger cannot read or write flash or SRAM. SWD connects only while the CPU runs NonSecure code (`mode=HOTPLUG`). Option bytes stay writable. |
| 2     | `0xCC` | SWD and the system bootloader are off. Boot only from flash. Option bytes are frozen. With `OEM2KEY` set, SWD answers under reset only, to take the key. |

| Key       | Size | Gates | Can be rewritten |
| --------- | ---- | ----- | ---------------- |
| `OEM1KEY` | 64 bit, two 32-bit words | Level 1 → 0 (mass erase) | At level 0 |
| `OEM2KEY` | 64 bit, two 32-bit words | Level 2 → 1 and level 1 → 0.5 | At level 0 or 0.5 |

The keys are write-only. Once set, `OEM1LOCK` and `OEM2LOCK` in `FLASH_NSSR` read 1. Without `OEM1KEY`, anyone with SWD can mass-erase a level 1 board. Without `OEM2KEY`, anyone with SWD can take a level 1 board to 0.5 and replace the NonSecure image.

### Keys

- Generate both keys fresh for each board from a random source. Four words, one per command: `openssl rand -hex 4`. Never use `0xFFFFFFFF 0xFFFFFFFF`; that value clears a key.
- Store them offline or in a password vault, labelled with the board serial. They never go into the repo, a script, a `.env` file, or shell history.
- The commands below read them from environment variables set for one shell session, for example `$env:OEM1_W0 = Read-Host` in PowerShell. Close the shell afterwards.
- Pass the words in the same order to lock and unlock (`W0` is key bits 31:0, `W1` is bits 63:32).
- Losing `OEM2KEY` makes level 2 permanent. Losing `OEM1KEY` makes level 0 unreachable, so the Secure image can never be replaced.
- Whoever holds `OEM2KEY` can regress the board to level 1 and then to 0.5, which erases and replaces the NonSecure image while Secure flash and pages 21–22 stay. Whoever holds `OEM1KEY` can mass-erase the board. Guard both like the owner key.

### Lock

1. Set both keys at level 0:

```text
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -lockrdp1 $env:OEM1_W0 $env:OEM1_W1
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -lockrdp2 $env:OEM2_W0 $env:OEM2_W1
```

2. Read `FLASH_NSSR` and check that bits 19:18 (`OEM2LOCK`, `OEM1LOCK`) are both 1, for example `0x000C0000`. Stop if either is 0.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -r32 0x40022020 4
```

3. Optional `BOOT_LOCK=0x1` (see [BOOT_LOCK](#boot_lock)).

4. SRAM erase on every system reset. `SRAM_RST=0x0` erases SRAM1 and SRAM4, `SRAM2_RST=0x0` erases SRAM2. Level 2 freezes these bits, so set them now. Power-cycle and check `-ob displ`:

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob SRAM_RST=0x0 SRAM2_RST=0x0 -rst
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob displ
```

5. Level 1. Power-cycle, check that the firmware runs, and check that a hot-plug connection works (`-ob displ` shows `RDP: 0xBB`):

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob RDP=0xBB -rst
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -ob displ
```

6. Level 2. The probe loses the connection; that is expected. Power-cycle.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -ob RDP=0xCC
```

At level 1, a debug access while the CPU is Secure counts as an intrusion. Connect only in `mode=HOTPLUG` while the firmware runs. An ST-LINK whose mass-storage interface probes the target on plug-in triggers this too.

The Secure image arms the TAMP internal tampers at every boot: backup-domain voltage and temperature (ITAMP1, ITAMP2), crypto peripheral fault (ITAMP9), and, at level 2 only, debug access (ITAMP6). Each event erases SRAM2, the backup registers, and BKPSRAM, and the Secure image then resets. ITAMP6 stays off at levels 0 to 1, so the hot-plug steps above keep working.

### BOOT_LOCK

`BOOT_LOCK=0x1` ignores BOOT0, so the system bootloader, SRAM boot, and the RSS boot cannot be selected. At level 2 the bootloader and SRAM boot are already off, so it only removes the RSS. Writing `BOOT_LOCK=0x0` afterwards does not clear it; a regression to level 0 does.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob BOOT_LOCK=0x1 -rst
```

With `BOOT_LOCK=0x1` and Secure boot in Secure flash (`SECBOOTADD0`), a regression works only through a hot-plug connection into the running NonSecure image. Such a board can go 2 → 1 → 0, but not to 0.5, because 0.5 erases the NonSecure image. Leave `BOOT_LOCK=0x0` on a board that may need the 0.5 path.

### Reverting

A key unlock works once per power cycle. Power-cycle before each attempt.

**Level 2 → 1 with `OEM2KEY`.** Flash, credentials, and NV are kept and the firmware runs as before. A debugger still cannot read or write flash, so a new image needs one of the next two paths. To lock again, repeat Lock step 6.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -unlockrdp2 $env:OEM2_W0 $env:OEM2_W1
```

The CLI then reports that it cannot connect; that is expected. Power-cycle, then:

```text
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -ob RDP=0xBB
```

**Level 1 → 0.5 with `OEM2KEY`: new NonSecure image.** NonSecure flash is erased. Secure flash, pages 21–22, and the enrolment are kept. Only on a board with `BOOT_LOCK=0x0`: with no NonSecure code the CPU stays Secure, so set BOOT0 high (boot from the RSS) before you program. Do not run `-e all` here.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -unlockrdp1 $env:OEM2_W0 $env:OEM2_W1
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -ob RDP=0x55
STM32_Programmer_CLI.exe -c port=SWD mode=UR -w "NonSecure\Debug\SE_firmware_NonSecure.elf" -v
```

Set BOOT0 low and raise the level with `-ob RDP=0xBB`, then Lock step 6. Level 0.5 cannot go to level 0 directly; go through level 1.

**Level 1 → 0 with `OEM1KEY`: full mass erase.** All flash is erased, including Secure pages 21–22 (SAE CA, device cert, `secure_dwk`, ML-DSA secret, pairing private key, NV state), SRAM2, and the backup registers. `TZEN` stays 1 and the flash map stays.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -unlockrdp1 $env:OEM1_W0 $env:OEM1_W1
STM32_Programmer_CLI.exe -c port=SWD mode=HOTPLUG -ob RDP=0xAA
```

Check `-ob displ` (`RDP: 0xAA`, `BOOT_LOCK`). The board is now new to the system. Run [First run](#first-run-new-board-or-after-a-flash-map-change) steps [3](#3-program-both-images) to 7 again. TROPIC01 keeps its pairing slot, so after `OWNER SET` restore L3 with `PAIRING LOAD` from `pairing-key.hex` ([step 6](#6-one-time-chip-state)). Then lock again.

**Clearing the keys.** At level 0, write `0xFFFFFFFF 0xFFFFFFFF` with `-lockrdp1` and `-lockrdp2`. `OEM2KEY` can also be cleared at level 0.5.

References: ST AN5347 (RDP with OEM keys, regression steps), ST AN5156 (RDP levels), STM32CubeProgrammer user manual (`-lockrdp1`, `-lockrdp2`, `-unlockrdp1`, `-unlockrdp2`).

---

## Subsequent runs

No option-byte rewrite unless the flash map changed. Re-flash with the same erase-all, then program both images, when firmware changed. That blanks creds and NV. A reset does not.

1. Power-cycle or reopen the serial port.
2. Skip `KEYGEN` / `KEM INIT` if ECC slot 0 and R-MEM slot 510 already hold keys (`TROPIC PUB` succeeds / occupied 510). Replace the P-256 key with MANAGE KEYGEN.
3. Arm one TLS session (only one host owns CDC):

```text
PROVISION <unix>    # SAE
ENCRYPT <unix>      # USER
DECRYPT <unix>      # USER
MANAGE <unix>       # USER
```


| Command     | Peer | When                                                                                                                                      |
| ----------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `PROVISION` | SAE  | New QKD fill. Wipes R-MEM slots **0–509**, commits `fill_id`, arms encrypt/decrypt pad halves. Keeps PIN NVM (511) and ML-KEM seed (510). |
| `ENCRYPT`   | USER | XOR-consume the **encrypt** pad half; UserApp sends PIN + plaintext on TLS.                                                               |
| `DECRYPT`   | USER | XOR-consume the **decrypt** pad half; UserApp sends PIN + the encrypt reply.                                                              |
| `MANAGE`    | USER | Unsigned enroll / peer / creds / owner-replace command. PIN only on KEM INIT.                                                             |


Pads are one-shot. When a half is exhausted (every pad the last fill wrote into it is used, which after a partial fill can be well before the half's last slot), ENCRYPT/DECRYPT reply with OTP error code **1** (`EXHAUSTED`) until a new `PROVISION`. `TROPIC OTP STATUS` shows the bytes left and written per half. Cursor mismatch or fill_id mismatch returns `DEVICE_TAMPERED`.

Disconnect, DTR off, TLS error, or session end returns to command mode.

---

## Lab extras (not a USER or SAE TLS session)

- `CLIENT CSR` — dump on-chip ML-DSA-44 public key.
- `TROPIC PUB` / `CLIENT HASH` / `TROPIC KEM PUB` / `TROPIC PAD LEN` — dump P-256 pub, device `client_hash`, ML-KEM public key, or plaintext pad ceiling.

---

## Host vs silicon (same command names)


|              | Silicon USB                        | `se_host` PTY + stdin                               |
| ------------ | ---------------------------------- | --------------------------------------------------- |
| Line limit   | 160 chars                          | 160 chars (same `tls_usb_io.c`)                     |
| Unix time    | Sets Secure RTC + TIME floor       | Same `se_time_set_unix`; wolfSSL uses process clock |
| After TLS    | Stays armed until the session ends | Same firmware state machine                         |
| Stop process | Unplug / reset                     | Ctrl-C (unlinks `/tmp/ttyACM0`)                     |


