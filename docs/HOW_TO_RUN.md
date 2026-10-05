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
| `BOOT_LOCK`    | `0x0`                                          |
| `RDP`          | `0xAA` (level 0)                               |


After a linker-map change, rerun only the second `-ob` command. SRAM split and SAU are programmed by Secure startup, not by these option bytes.

Optional readout protection, after both images are programmed. Leave `RDP` at `0xAA` on a board you still reflash.


| Level | Value  | What it does                                                                                                                                                       |
| ----- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0     | `0xAA` | Lab default. SWD can read and rewrite flash and option bytes.                                                                                                      |
| 1     | `0xBB` | Debugger cannot read flash or SRAM. The firmware still runs. SWD can still change option bytes. Writing `RDP=0xAA` mass-erases the chip and returns it to level 0. |
| 2     | `0xCC` | Permanent. SWD is disabled and option bytes are frozen. There is no regression and no reflash. A bad image cannot be replaced.                                     |


Level 1:

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob RDP=0xBB -rst
```

Level 2:

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob RDP=0xCC -rst
```

The map command writes `BOOT_LOCK=0x0`. Boot then follows the BOOT0 pin, and `SECBOOTADD0` / `NSBOOTADD0` stay writable, so a lab board can still change the flash map or enter the system bootloader.

Set `BOOT_LOCK` only on a device that must always boot the image in flash. BOOT0 is ignored. The system bootloader and SRAM boot cannot be selected. Writing `BOOT_LOCK=0x0` afterwards does not clear it. Clearing it takes an RDP regression to `0xAA`, which mass-erases the chip.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob BOOT_LOCK=0x1 -rst
```

### 3. Program both images

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -w "Secure\Debug\SE_firmware_Secure.elf" -v

STM32_Programmer_CLI.exe -c port=SWD mode=UR -w "NonSecure\Debug\SE_firmware_NonSecure.elf" -v -rst
```

### 4. Open the console

Reset or power-cycle. USB re-enumerates as CDC ACM. Open the serial port (any terminal). Idle prompt:

```text
waiting PROVISION|ENCRYPT|DECRYPT|MANAGE <unix>
```

USB command lines are at most **160** characters. `HELP` lists names.

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
Need a live UserApp for that step. Then a live SAE TLS server (TerminalBridge USB
relay) for `PROVISION`.

```text
MANAGE <unix>    # PEER ADD
PROVISION <unix>             # SAE
```

With an empty NV peer list the uplink has 7 items (no peer pairs). Peer hash is SHA384 of the peer SPKI (96 hex digits), the same hash SAE already receives as uplink items 7+. Cap 8 nicknames; see [COMMANDS.md](COMMANDS.md).

`<unix>` is decimal Unix UTC seconds, non-zero. Secure also requires it in `[2024-01-01, 2038-01-01]`. If it is behind the stored TIME floor, firmware keeps the floor. PIN is **not** a console argument; ENCRYPT/DECRYPT take it inside mTLS, and MANAGE takes it only on KEM INIT.

CDC RX then becomes an opaque TLS pipe until the session ends.

---

## Subsequent runs

No option-byte rewrite unless the flash map changed. Re-flash ELFs only when firmware changed.

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


Pads are one-shot. When a half is exhausted, ENCRYPT/DECRYPT reply with OTP error code **1** (`EXHAUSTED`) until a new `PROVISION`. Cursor mismatch or fill_id mismatch returns `DEVICE_TAMPERED`.

Disconnect, DTR off, TLS error, or session end returns to command mode.

---

## Lab extras (not a USER or SAE TLS session)

- `CLIENT CSR` — dump on-chip ML-DSA-44 public key.
- `TROPIC PUB` / `CLIENT HASH` / `TROPIC KEM PUB` — dump P-256 pub, device `client_hash`, or ML-KEM public key.

---

## Host vs silicon (same command names)


|              | Silicon USB                        | `se_host` PTY + stdin                               |
| ------------ | ---------------------------------- | --------------------------------------------------- |
| Line limit   | 160 chars                          | 160 chars (same `tls_usb_io.c`)                     |
| Unix time    | Sets Secure RTC + TIME floor       | Same `se_time_set_unix`; wolfSSL uses process clock |
| After TLS    | Stays armed until the session ends | Same firmware state machine                         |
| Stop process | Unplug / reset                     | Ctrl-C (unlinks `/tmp/ttyACM0`)                     |


