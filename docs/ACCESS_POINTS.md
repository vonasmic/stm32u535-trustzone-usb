# Access points (SAE and SE)

Inventory of every interface that can reach **SAE** (SaeNode) or **SE** (this board: STM32U535 + TROPIC01). Use it to decide which doors to analyze. It does not restate the protocol; wire formats stay in [COMMUNICATION.md](COMMUNICATION.md), command bytes in [COMMANDS.md](COMMANDS.md), pins and option bytes in [HARDWARE.md](HARDWARE.md), and what each door can actually break in [SECURITY.md](SECURITY.md).

**SE** is the TS13 DevKit running this firmware. **SAE** is the provisioning peer. SaeNode source is not in this tree; SAE rows below are the contract this firmware implements and the assets [SECURITY.md](SECURITY.md) assigns to SAE. USER (UserApp) is a third role. Its process is not inventoried, but every SE command USER can send is listed under SE, because those commands are doors into the secure element.

Lab default (`RDP = 0xAA`, `BOOT_LOCK = 0`, `HDP1EN = 0`) leaves SWD and the bootloader open. A locked production board drops SE-P1 and SE-P2.

```text
SAE (SaeNode) --USB CDC host--> SE MCU (NonSecure CDC)
                                  | NSC
                                  v
                                Secure (TLS, NV, SPI1) --> TROPIC01
```

Only one host process owns the CDC port. SAE uses it for `PROVISION`. USER uses the same port for `ENCRYPT` / `DECRYPT` / `MANAGE`.

---

## What to analyze

| Priority | IDs | Why |
| --- | --- | --- |
| **First** | SE-P1, SE-L1, SE-L3, SE-T1, SE-T2 | SWD reads `secure_dwk`, the ML-DSA secret, and the pairing private key. Unsigned USB enrolls the owner and the SAE CA. `PROVISION` is how pads enter the chip. SPI before pairing speaks Tropic L3 with the factory key. |
| **Next** | SE-T3, SE-T4, SE-L2, SAE-1, SAE-2, SAE-3 | Encrypt/decrypt and MANAGE move the PIN and identity. A compromised SAE holds the CA key and the pad plaintext before it is sealed. |
| **Later** | SE-L4, SE-N1, SE-P3 | Read-only USB dumps and the NSC veneers. They leak occupancy and public keys. They do not hold pad plaintext by themselves. |
| **Skip on this board** | — | No UART, Ethernet, BLE, Wi-Fi, or TCP listener. USB is CDC ACM only (no DFU class in the application). `se_host` is a lab stand-in, not a target ([SECURITY.md](SECURITY.md) §9). |

---

## SE — physical

MCU `STM32U535CCT6`, TrustZone on. Pins from `SE_firmware.ioc`. USB is NonSecure. SPI1, RNG, and the Tropic GPIO are Secure.

| ID | Access point | Where | Who can use it | Gate today | What it reaches |
| --- | --- | --- | --- | --- | --- |
| SE-P1 | SWD / ST-LINK | Debug port | Anyone with the probe | None at RDP 0. RDP 1 blocks readout. RDP 2 disables SWD | Flash, SRAM, option bytes. Pages 21–22 hold the SAE CA, device cert, `secure_dwk`, ML-DSA secret, pairing private key |
| SE-P2 | BOOT0 → ROM bootloader | BOOT0 pin | Anyone who can strap the pin | `BOOT_LOCK = 0` (lab). `BOOT_LOCK = 1` ignores BOOT0 until an RDP regression | System bootloader. Option bytes and the flash map stay writable. This image does not expose a UART |
| SE-P3 | USB full-speed | PA11 `USB_DM`, PA12 `USB_DP` | The host that opens CDC | Cable plus enumeration. No USB login | The whole logical surface below. VID `1155` (`0x0483`), PID `22288` (`0x5710`), CDC ACM, bulk OUT `0x03`, bulk IN `0x82`, interrupt IN `0x81` |
| SE-P4 | SPI1 to TROPIC01 | PA4 `CS`, PA5 SCK, PA6 MISO, PA7 MOSI | Probe on the board, or Secure firmware | Pins are Secure GPIO/SPI. No application authentication on the wires | Tropic L2/L3, R-MEM, ECC slot 0, pairing, M&D. Factory SH0 private key is in the SDK until MANAGE PAIRING burns it |
| SE-P5 | Tropic power | PA0 `PWR`, GPIO out, Secure | Secure firmware; a probe can force the rail | Driven high in `se_tropic_port_hw_init` | Power-cut and glitch on the secure element. Not a data API |
| SE-P6 | Tropic GPO | PB0 `GPO`, GPIO in, Secure | Tropic chip | Optional interrupt input | Level from TROPIC01. Firmware does not take host commands from this pin |
| SE-P7 | Reset and power | NRST, VDD | Anyone with the board | None | Reboot. Does not erase pages 21–22. A power cut during pad consume burns that pad (advance-then-erase) |

Not bonded in this CubeMX project: USART, LPUART, I2C, extra SPI, Ethernet, tamper pin. RTC is initialized and is not a host interface. Wall time comes from the USB `<unix>` argument.

---

## SE — USB logical

Every CDC byte is a frame: `u16le magic 0x6767 | u8 type | u16le length | payload`. A raw serial terminal is not a peer.

| ID | Access point | Type | Gate | What it reaches |
| --- | --- | --- | --- | --- |
| SE-L1 | Console commands | `0x00`, max 160 bytes | **None.** Unknown lines return `failed` | Table below. A command that arrives during TLS is queued (4 deep) and runs after idle |
| SE-L2 | Secure pipe | `0x01`, host splits at 1024 bytes | Open only after `OWNER SET` begin or a successful TLS arm. Idle `0x01` is dropped | OWNER SET blob, or the TLS byte stream (RX ring 16 KiB, TX ring 8 KiB) |
| SE-L3 | `PROVISION <unix>` then TLS | `0x00` arms mode 1, then `0x01` | Unsigned arm. Then mTLS: SAE CA from flash page 21, device cert, exporter-bound uplink | SAE session. Device sends uplink v5, erases R-MEM 0–509, stores downlink v3 |
| SE-L4 | Read-only console | `0x00` | None | Public or occupancy data only. See the read-only rows |

DTR off, CDC deactivate, RX overflow, or TLS end returns the parser to command mode.

### Commands on SE-L1

| Command | Peer after arm | Auth on the USB line | Mutates | Review |
| --- | --- | --- | --- | --- |
| `HELP`, `?` | — | none | no | Low. Lists the surface |
| `OWNER SET` + `0x01` blob | — | **none, first empty slot wins** | owner SPKI, reset-password hash, optional SAE CA; device ML-DSA key is generated on-chip | **High.** Unsigned enrollment |
| `PROVISION <unix>` | SAE | none to arm; mTLS after | pads, `fill_id`, `kem_ct`, cursors | **High.** SAE door |
| `ENCRYPT <unix>` | USER | none to arm; mTLS + owner SPKI pin; PIN inside TLS | burns encrypt-half pads | **High.** OTP consume |
| `DECRYPT <unix>` | USER | same as ENCRYPT | burns decrypt-half pads; skip-ahead burns intermediates | **High.** OTP consume |
| `MANAGE <unix>` | USER | none to arm; owner-pinned TLS, **no device client cert** | one unsigned command (table below) | **High.** Identity and PIN setup |
| `PEER LIST` | — | none | no | Medium. Names, SPKI hashes, pad sizes |
| `CLIENT HASH` | — | none | no | Medium. 48-byte `SHA384(device_cert_spki \|\| ecc_pub)` |
| `CLIENT CSR` | — | none | no | Medium. Raw ML-DSA-44 public key (1312 bytes) |
| `TROPIC PING` | — | none | no | Low. Liveness |
| `TROPIC INFO` | — | none | no | Low. Chip id / firmware string |
| `TROPIC PUB` | — | none | no | Low. P-256 public key, or `empty` |
| `TROPIC KEM PUB` | — | none | no | Medium. ML-KEM-768 public key, or `empty` |
| `TROPIC OTP STATUS` | — | none | no | Medium. Remaining pad kilobytes per half |
| `TROPIC PAD LEN` | — | none | no | Low. Plaintext bytes per pad |

`<unix>` is decimal UTC, accepted range 1704067200–2145916800. A value behind the NV time floor does not move the clock backward. The PIN is never a console argument.

### MANAGE commands (inside SE-L2 after `MANAGE`)

One request per session: `u8 cmd | u8 pin_len | pin | u16le body_len | body`. PIN length is 0 except on KEM INIT. Reply status bytes are in [COMMANDS.md](COMMANDS.md).

| Cmd | Name | What an accepted call changes | Review |
| --- | --- | --- | --- |
| 1 | KEM INIT | PIN setup (8 silicon tries), ML-KEM seed in R-MEM 510, public key in NV. PIN is on this TLS channel | **High** |
| 2 | KEYGEN | P-256 key in Tropic ECC slot 0 (generate, or replace if occupied) | **High.** Uplink signatures |
| 3 | PEER ADD | Nickname + SPKI hash + pad length in NV (max 8) | Medium |
| 4 | PEER REMOVE | Deletes that peer | Medium |
| 5 | CREDS SAE | Replaces the SAE CA on flash page 21 | **High.** Chooses who `PROVISION` trusts |
| 6 | INSERT SIGNED CSR | Device cert, must match the on-chip ML-DSA key | High |
| 7 | OWNER REPLACE | New owner SPKI if the reset password matches. Pairing key survives; pads and creds do not | **High** |
| 8 | PAIRING | X25519 in slot 1–3, factory SH0 burned, private key returned **once** on this TLS session | **High.** Irreversible on silicon |
| 9 | PAIRING LOAD | Restores an exported pairing private key into NV. No Tropic write | **High.** Reopens L3 after reflash |

---

## SE — inside the chip

These are reachable only after NonSecure or the debug probe is already on the device. They matter once SE-P1 or a malicious NonSecure image is in scope.

| ID | Access point | Caller | Gate | What it reaches |
| --- | --- | --- | --- | --- |
| SE-N1 | NSC veneers (`SECURE_*_nsc_call` in [se_tls_nsc.h](../Secure_nsclib/se_tls_nsc.h)) | NonSecure | CMSE entry, 64-byte packets | Arm TLS mode and Unix time, USB RX/TX, OWNER SET begin, read-only Tropic/peer dumps, console TX. KEYGEN / KEM INIT / PEER ADD are not NSC entries |
| SE-N2 | Secure flash page 21 | Secure code; SWD | TrustZone. Not in the ELF | SAE CA, device certificate |
| SE-N3 | Secure flash page 22 | Secure code; SWD | TrustZone. Plaintext record | `secure_dwk`, `fill_id`, cursors, owner SPKI, password hash, pairing private key, ML-DSA secret, ML-KEM public key |
| SE-N4 | Secure RAM | Secure code; SWD at RDP 0 | TrustZone | Live TLS keys, PIN `final_key`, session exporter. Wiped after use on the paths that copy them |

NonSecure cannot read Secure RAM or those two pages. It can still point `PROVISION` at the wrong time and proxy USB bytes.

### TROPIC01 (behind SE-P4)

| ID | Access point | Gate | What it reaches |
| --- | --- | --- | --- |
| SE-T1 | L3 session | X25519. Factory SH0 until PAIRING, then the host key in NV | R-MEM read/write as the paired host. Published SH0 private keys are in the SDK |
| SE-T2 | R-MEM slots 0–511 | L3 plus per-slot AEAD | 0–2 `kem_ct`, 3–509 pad blobs, 510 ML-KEM seed, 511 PIN NVM. Blobs are ciphertext. Plaintext still needs the MCU key and, for the seed, the PIN |
| SE-T3 | ECC slot 0 | L3 | P-256 private key used for the uplink signature |
| SE-T4 | MAC-and-Destroy slots | Live Tropic + MCU pepper | 8 PIN tries on silicon (16 hardware slots). Each miss destroys a pair. Not an offline hash |
| SE-T5 | Mcounters 0 and 1 | L3 | Encrypt and decrypt cursors. Mismatch with MCU NV returns `DEVICE_TAMPERED` |

---

## SAE

SaeNode opens the SE CDC port and is the TLS server for mode 1 only. It does not see the OTP PIN. ENCRYPT, DECRYPT, and MANAGE are USER sessions on the same USB connector.

| ID | Access point | Where | Gate | What it reaches |
| --- | --- | --- | --- | --- |
| SAE-1 | USB host CDC | The cable to SE-P3. Lab: the PTY named by `USB_SERIAL_PORT` | Process that opens the port. One owner at a time | SE-L1 and SE-L2. SAE’s command is `PROVISION <unix>` |
| SAE-2 | TLS 1.3 server on that byte stream | After `PROVISION` | ML-KEM-768, `TLS13-AES256-GCM-SHA384`, peer cert checked against the SAE CA stored on the SE | Uplink v5 in, downlink v3 out |
| SAE-3 | Downlink v3 | SAE → SE inside SAE-2 | SE checks version, lengths, and AEAD under the ML-KEM shared secret. It does not have a second signature on each pad image | `kem_ct` (1088 B), `decrypt_half`, `pad_plain`, up to 507 pad images. This is how keystream enters R-MEM |
| SAE-4 | Uplink v5 | SE → SAE inside SAE-2 | SAE recomputes the client hash from the mTLS client cert and checks the P-256 signature over `SHA384(client_hash \|\| exporter)` | Session signature, Tropic P-256 pub, client hash, slot size, pad count 507, pending `fill_id`, ML-KEM public key (1184 B), peer table |
| SAE-5 | SAE CA private key | On the SAE host (the SE stores only the CA certificate) | Host protection. Not visible on the SE USB console | Whoever holds it can sign a leaf the SE will accept on `PROVISION`, until CREDS SAE or OWNER SET replaces the CA |
| SAE-6 | Pad plaintext and encapsulation | SAE memory before SAE-3 is sent | Host protection | The keystream SAE seals into the downlink. The SE will not release it later without PIN + mTLS |

Progress lines (`TROPIC_WIPE_FINISHED`, integer KiB, `SE_OK`) travel on SAE-2 and are not a second API.

This tree does not list SaeNode files, admin sockets, or QKD links to other SAE nodes. Those exist only in the Java application.

---

## Review checklist

Copy this and mark each row when the review is done.

| ID | Question |
| --- | --- |
| SE-P1 | Can SWD or a firmware image dump page 21 and page 22? |
| SE-P2 | Can BOOT0 enter the ROM bootloader and rewrite flash or option bytes? |
| SE-P3 | Is USB the only external data port, and is CDC ACM the only class? |
| SE-P4 | Who can observe or inject SPI before and after PAIRING? |
| SE-L1 | Which unsigned commands still run with no prior enrollment? |
| SE-L3 | Can a non-SAE peer complete `PROVISION`, or substitute a downlink? |
| SE-L2 | What does one MANAGE session change, and is the PIN only on KEM INIT? |
| SE-N1 | If NonSecure is replaced, which NSC calls does it gain, and which keys does it still not see? |
| SE-T1 | Is factory SH0 still valid on the chip under test? |
| SE-T4 | Is the live PIN budget still 8, and can tries be made without the MCU? |
| SAE-1 | Who else can open the CDC port while SaeNode is running? |
| SAE-2 | Does the SAE leaf chain to the CA currently on flash page 21? |
| SAE-3 | Is pad plaintext present on the SAE host, and who can read it there? |
| SAE-5 | Where is the SAE CA private key stored, and who can replace the cert on the SE (`OWNER SET`, CREDS SAE)? |
