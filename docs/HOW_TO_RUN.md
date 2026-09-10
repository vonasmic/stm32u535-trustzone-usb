# How to run (silicon)

Host model / `se_host` is **[host/README.md](../host/README.md)**. This file is the TS13 board.

Command syntax: **[COMMANDS.md](COMMANDS.md)**. Flash map and option bytes: **[HARDWARE.md](HARDWARE.md)**.

---

## Prerequisites


| Tool                                                                              | Purpose                                                            |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| [STM32CubeIDE](https://www.st.com/en/development-tools/stm32cubeide.html)         | Build Secure + NonSecure                                           |
| [STM32CubeProgrammer](https://www.st.com/en/development-tools/stm32cubeprog.html) | Flash + option bytes (`STM32_Programmer_CLI`)                      |
| ST-LINK (SWD)                                                                     | Connect to the MCU                                                 |


Hardware: **TS13 DevKit** (or equivalent) with TROPIC01 on SPI1.

Irreversible Tropic sequences (`TROPIC PAIRING`, PIN setup) must pass host model groups **A–E and H** first. Restarting the model restores a fresh chip; silicon does not.

---



## First run (new board or after a flash-map change)



### 1. Build

1. Open this repo root in STM32CubeIDE.
2. Build `SE_firmware_Secure` **first**, then `SE_firmware_NonSecure` (NonSecure needs `secure_nsclib.o` from Secure).
3. Expected outputs:
  - `Secure/Debug/SE_firmware_Secure.elf`
  - `NonSecure/Debug/SE_firmware_NonSecure.elf`

Enroll TLS credentials **at runtime**: unsigned USB `OWNER SET` (owner + optional device cert/key + SAE CA), then `MANAGE` TLS for KEM INIT / CREDS / PEER.

### 2. Option bytes (once, or after the linker map changes)

TrustZone (`TZEN`) must be enabled. Values and meaning: **[HARDWARE.md](HARDWARE.md)**.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -ob SECWM1_PSTRT=0x0 SECWM1_PEND=0x17 NSBOOTADD0=0x100600 HDP1EN=0x0 -rst
```



### 3. Program both images

CubeIDE often downloads only one project. Flash **Secure first, then NonSecure**.

```text
STM32_Programmer_CLI.exe -c port=SWD mode=UR -w "Secure\Debug\SE_firmware_Secure.elf" -v

STM32_Programmer_CLI.exe -c port=SWD mode=UR -w "NonSecure\Debug\SE_firmware_NonSecure.elf" -v -rst
```

After NonSecure download, the vector table at `0x08030000` must **not** be `0xFFFFFFFF`. If Secure boots then HardFaults into NS, re-flash the NonSecure ELF.

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

Default pairing is factory **SH0** (engineering-sample keys unless the firmware was built with `SE_TROPIC_SH0_PROD`).

### 6. One-time chip state

`KEYGEN` is one-shot when the ECC slot is empty. Occupied `KEYGEN` and `KEM INIT` print `use MANAGE <unix>` then take an unsigned PIN on MANAGE TLS. Occupied KEM slot 510 refuses a second write.

```text
OWNER SET
TROPIC KEYGEN
MANAGE <unix>    # KEM INIT (unsigned PIN + empty body)
```

This is how the **user** creates the owner key, device TLS creds (inside the OWNER SET blob or a later MANAGE CREDS DEVICE), PIN, and ML-KEM key (no factory PIN). The 1184-byte ML-KEM-768 public key is stored in NV and survives reboot without reflash.

To replace an occupied P-256 key (unsigned PIN on MANAGE):

```text
TROPIC KEYGEN
MANAGE <unix>
```

Optional, **irreversible** on silicon:

```text
TROPIC PAIRING 1
TROPIC PAIRING 1 y
```

That writes a new X25519 host key to pairing slot 1–3, stores the private half in MCU NV, **invalidates factory SH0**, and prints `TROPIC PAIRING KEY` so the host can save `pairing.key`. After an MCU reflash:

```text
TROPIC PAIRING 1 LOAD <64-hex-priv> <64-hex-pub>
```

### 7. First SAE session

Need a live Java SAE TLS server. Then:

```text
PEER ADD <name> <96-hex>
PROVISION <unix>
```

`PEER ADD` is optional and runs over MANAGE TLS (unsigned). With an empty NV peer list the uplink has 7 items (no peer pairs). `<96-hex>` is SHA384 of the peer SPKI (96 hex digits), the same hash SAE already receives as uplink items 7+. Cap 8 nicknames; see [COMMANDS.md](COMMANDS.md).

`<unix>` is decimal Unix UTC seconds, non-zero. Secure also requires it in `[2024-01-01, 2038-01-01]`. If it is behind the stored TIME floor, firmware keeps the floor. PIN is **not** a console argument; ENCRYPT/DECRYPT take it inside mTLS, MANAGE takes it in the unsigned request when the command is PIN-gated.

CDC RX then becomes an opaque TLS pipe until the session ends.

---



## Subsequent runs

No option-byte rewrite unless the flash map changed. Re-flash ELFs only when firmware changed.

1. Power-cycle or reopen the serial port.
2. Skip `KEYGEN` / `KEM INIT` if ECC slot 0 and R-MEM slot 510 already hold keys (`TROPIC slot occupied` / occupied 510). Replace the P-256 key with `TROPIC KEYGEN` then unsigned PIN on MANAGE.
3. Arm one TLS session:

```text
PROVISION <unix>
ENCRYPT <unix>
DECRYPT <unix>
```


| Command     | When                                                                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `PROVISION` | New QKD fill from the SAE. Wipes R-MEM slots **0–509**, commits `fill_id`, arms encrypt/decrypt pad halves. Keeps PIN NVM (511) and ML-KEM seed (510). |
| `ENCRYPT`   | XOR-consume the **encrypt** pad half; SAE sends PIN + plaintext on TLS.                                                                                |
| `DECRYPT`   | XOR-consume the **decrypt** pad half; SAE sends PIN + the encrypt reply.                                                                               |


Pads are one-shot. When a half is exhausted, ENCRYPT/DECRYPT reply with OTP error code **1** (`EXHAUSTED`) until a new `PROVISION`. Cursor mismatch or fill_id mismatch returns `DEVICE_TAMPERED`.

There is no `TIME=` command. Disconnect, DTR off, TLS error, or session end returns to command mode.

---



## Lab extras (not the SAE path)

- `TROPIC SIGN <64-hex>` — ECDSA over a 32-byte hash.
- `TROPIC PUB` / `CLIENT HASH` / `TROPIC KEM PUB` — dump P-256 pub, device `client_hash`, or ML-KEM public key.

---



## Host vs silicon (same command names)


|                 | Silicon USB                        | `se_host` PTY + stdin                             |
| --------------- | ---------------------------------- | ------------------------------------------------- |
| Line limit      | 160 chars                          | 160 chars (same `tls_usb_io.c`)                   |
| Unix time       | Sets Secure RTC + TIME floor       | Same `se_time_set_unix`; wolfSSL uses process clock |
| After TLS       | Stays armed until the session ends | Same firmware state machine                       |
| Stop process    | Unplug / reset                     | Ctrl-C (unlinks `/tmp/ttyACM0`)                   |


