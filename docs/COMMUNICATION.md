# Communication

How the host, USB console, Secure TLS client, **USER** (UserApp), and **SAE**
(SaeNode) talk. The device is a TLS client and connects to **two** applications:
SAE for `PROVISION`, USER for `ENCRYPT` / `DECRYPT` / `MANAGE`. Tropic slot
contents: **[TROPIC.md](TROPIC.md)**. Console commands that *arm* these paths:
**[COMMANDS.md](COMMANDS.md)**.

```text
USB ASCII commands  →  NonSecure parser  →  NSC  →  Secure
USB TLS bytes       →  16 KiB RX / 8 KiB TX rings →  wolfSSL 1.3 client  →  SAE (provision) or USER (encrypt / decrypt / manage)
SPI                 →  TROPIC01 L2/L3
```

Mode is chosen **off the TLS wire** by `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE`. After handshake the peer infers the role from what the device sends (uplink vs silence) and from its own request.

---

## USB / NSC pipe

NonSecure ([tls_usb_io.c](../NonSecure/Core/Src/tls_usb_io.c)):

- **Command mode** — `\n`-terminated ASCII, max 160 chars.
- After a successful `SECURE_TlsStart_nsc_call` or `SECURE_OwnerBegin_nsc_call`, **binary/TLS mode** — every RX byte goes to `SECURE_UsbRx_nsc_call`. Poll `SECURE_UsbService_nsc_call` until `SECURE_USB_IDLE` or `SECURE_USB_ERR`.
- TX drains Secure in **64-byte** NSC packets (`SECURE_USB_PKT_MAX`). After each TLS RX packet, NonSecure runs `SECURE_UsbService_nsc_call` so wolfSSL drains the ring before the next push (a PQC ServerHello is ~12 KiB; dumping it first overflowed the old 8 KiB ring).
- DTR off, CDC deactivate, overflow, or TLS end → command mode again.

Secure rings ([se_usb_tls.h](../Secure/Core/Inc/se_usb_tls.h)): RX **16384** bytes, TX **8192** bytes.

Framed `DEBUG:<text>:DEBUG` status lines (handshake progress, Tropic logs) go on the CDC TX ring **only before the first TLS record byte**. After that, TX is TLS only. The closer `:DEBUG` is the ASCII/TLS boundary, so a ClientHello (`0x16`) glued onto the same USB read is still unambiguous. ClientHello waits until the current DEBUG frame has left the Secure TX ring.

PIN is never on the ASCII pipe for the TLS modes. Occupied KEYGEN / KEM INIT / PEER ADD/REMOVE / CREDS / OWNER REPLACE stream unsigned bodies over MANAGE TLS (no ML-DSA). ENCRYPT/DECRYPT stay mTLS.

---



## TLS 1.3 (device is client)

[se_tls_client.c](../Secure/Core/Src/se_tls_client.c) (same source on `se_host` over a PTY):


| Setting            | Value                                                            |
| ------------------ | ---------------------------------------------------------------- |
| Version            | TLS 1.3 only                                                     |
| Cipher             | `TLS13-AES256-GCM-SHA384`                                        |
| Group              | **ML-KEM-768** (`WOLFSSL_ML_KEM_768`)                            |
| Client cert        | ENCRYPT/DECRYPT/PROVISION: device cert from FLASH_CREDS. MANAGE: none (not mTLS) |
| Client private key | ENCRYPT/DECRYPT/PROVISION: NV device SK DER (loaded only for mTLS). MANAGE: none |
| Peer verify        | `WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT`      |




### CA per mode


| Mode      | Peer | Constant                        | Verify blob                           |
| --------- | ---- | ------------------------------- | ------------------------------------- |
| Provision | SAE  | `SECURE_TLS_MODE_PROVISION` = 1 | SAE CA from FLASH_CREDS                          |
| Encrypt   | USER | `SECURE_TLS_MODE_ENCRYPT` = 2   | no CA; pin peer leaf SPKI to enrolled owner key  |
| Decrypt   | USER | `SECURE_TLS_MODE_DECRYPT` = 3   | no CA; pin peer leaf SPKI to enrolled owner key  |
| Manage    | USER | `SECURE_TLS_MODE_MANAGE` = 4    | no CA; pin peer leaf SPKI to enrolled owner key; no device client cert |


TLS refuses until ready: ENCRYPT/DECRYPT need owner SPKI + device cert + device SK; PROVISION needs those plus SAE CA and NV ML-KEM pk; MANAGE needs owner SPKI only.

### Exporter (session binding)

After handshake:

- RFC 9266 `tls-exporter`: label `EXPORTER-Channel-Binding`, empty context, 32 bytes
  (same value BC JSSE returns from `getChannelBinding("tls-exporter")`)

Used only on **provision**: hashed into the uplink signature so a MitM that terminates TLS cannot forward a valid uplink.

### Post-handshake


| Mode      | Peer | Device sends              | Device reads                            |
| --------- | ---- | ------------------------- | --------------------------------------- |
| Provision | SAE  | LV **uplink v4**, then `SE_OK\n` | LV **downlink v2** (QKD ingest)         |
| Encrypt   | USER | nothing until USER request | PIN + plaintext; replies OTP ciphertext |
| Decrypt   | USER | nothing until USER request | PIN + encrypt reply; replies plaintext  |
| Manage    | USER | nothing until request     | unsigned cmd + optional PIN + body; replies status |


Then bidirectional TLS shutdown: the device sends {@code close_notify} and stays in TLS until the peer (SAE on provision, USER otherwise) close_notify arrives, then returns to ASCII. A 3 s timeout still disarms if the peer never closes.

---



## LV envelope (uplink and downlink)

[secure_lv.h](../Secure/Core/Inc/secure_lv.h). Little-endian. Items are **positional**: absent fields are **zero-length items**, never omitted.

```text
u8  version
u16 count
repeat count times:
  u16 len
  u8  value[len]
```

Unknown `version` is a hard error (`SECURE_QKD_WRONG_VERSION` on downlink). Uplink and downlink versions are independent.


| Message                    | Version                              |
| -------------------------- | ------------------------------------ |
| Session uplink (provision) | **4** (`SECURE_LV_UPLINK_VERSION`)   |
| QKD downlink (provision)   | **2** (`SECURE_LV_DOWNLINK_VERSION`) |


---



## Uplink v4 (Secure → SAE, provision only)

Built in [se_tropic_session.c](../Secure/Core/Src/se_tropic_session.c).

`count = 7 + 2 × NV peer_count` (`se_nv_peer_count()`, from `PEER ADD`). An empty list is valid → **7** items.


| Index | Item                    | Size         | Notes                                           |
| ----- | ----------------------- | ------------ | ----------------------------------------------- |
| 0     | Session signature       | 64 B         | TROPIC P-256 ECDSA                              |
| 1     | TROPIC P-256 public key | 64 B         | XY from ECC slot 0                              |
| 2     | Client hash             | 48 B         | `SHA384(device_cert_spki || ecc_pub)`           |
| 3     | R-MEM slot size         | 2 B          | u16 LE, chip `r_mem_udata_slot_size_max`        |
| 4     | Pad slot count          | 2 B          | u16 LE = **507**                                |
| 5     | Pending `fill_id`       | 32 B         | RNG; committed when `kem_ct` is written         |
| 6     | ML-KEM-768 public key   | **1184 B**   | Encapsulate from **this item**, not from a file |
| 7+    | Per peer: hash, name    | 48 B + UTF-8 | MCU NV (`PEER ADD`); hash is SHA384 of the peer SPKI |


Signature digest:

```text
client_hash = SHA384(device_cert_spki || ecc_pub)
to_sign     = SHA384(client_hash || exporter)
sig         = ECDSA_P256(Tropic slot 0, to_sign[0..31])
```

TROPIC01 takes exactly a 32-byte digest, so it signs the leftmost half of `to_sign`. That is
plain ECDSA-with-SHA-384 on P-256: a verifier handed all 48 bytes derives the same `e` from the
leftmost 256 bits (FIPS 186-4 §6.4).

The exporter is wiped after hashing. Device-cert SPKI bits are hashed, never sent: SAE
recomputes them from the mTLS client certificate (raw `subjectPublicKey` BIT STRING payload,
not the whole SPKI DER). USB command `CLIENT HASH` prints this same `client_hash` (96 hex digits).

Encrypt/decrypt modes send **no** uplink.

---



## Downlink v2 (SAE → Secure, provision only)

Parsed on the fly by [secure_qkd_ingest.c](../Secure/Core/Src/secure_qkd_ingest.c) (no full-message buffer).


| Index | Item           | Size                | Action                                                                                |
| ----- | -------------- | ------------------- | ------------------------------------------------------------------------------------- |
| 0     | `kem_ct`       | **1088 B**          | `se_tropic_kem_ct_write` — new `fill_id`, wipe slots **0–509**, store ct in slots 0–2 |
| 1     | `decrypt_half` | **1 B**, `0` or `1` | `se_tropic_qkd_arm_halves` — which pad half is decrypt vs encrypt                     |
| 2…    | Pad images     | 29–475 B            | Logical pad index = item index − 2; `se_tropic_qkd_store`                             |


- Empty item 0 or 1 is a parse error.
- Zero-length **pad** items are skipped but still consume the index.
- Payload cap `SECURE_QKD_MAX_BYTES` = 1088 + 507×475 = **241 913** bytes (framing not counted).

`decrypt_half = 0`: decrypt uses physical pads 3–255, encrypt 256–509. `1` swaps the halves. Details: **[TROPIC.md](TROPIC.md)**.

---



## OTP over TLS (encrypt / decrypt)

Not an LV envelope. Device ↔ **USER** (UserApp), not SAE. [secure_otp.h](../Secure/Core/Inc/secure_otp.h).

PIN length **4–8** bytes (`SE_TROPIC_PIN_SIZE_MIN` / `MAX`).

### ENCRYPT (USER → SE)

```text
u8  pin_len
u8  pin[pin_len]
u32 msg_len LE
u8  plaintext[msg_len]
```



### ENCRYPT reply (SE → USER)

```text
u32 n_pads LE
repeat n_pads times:
  u16 logical_slot LE
  u16 chunk_len LE
  u8  chunk[chunk_len]
```

Last chunk may be short. Cap is remaining pads in the **encrypt** half. `logical_slot` is the logical pad index (0 = first pad), not the physical R-MEM index.

If the request needs more pads than remain, the device replies with an error instead of ciphertext:

```text
u32 n_pads LE = 0
u32 err_code LE
```

UserApp prints `OTP error <code> (<name>): …`. Codes: **1** exhausted, **3** parse, **4** PIN, **5** tampered, **255** fail.

### DECRYPT (USER → SE)

```text
u8  pin_len
u8  pin[pin_len]
<ENCRYPT reply unchanged>
```

If the requested logical slot is ahead of the decrypt cursor, intermediate pads are **burned** (erased, no XOR). Rewind is refused.

### DECRYPT reply (SE → USER)

```text
u32 n_pads LE
repeat n_pads times:
  u16 chunk_len LE
  u8  chunk[chunk_len]
```

No slot IDs. UserApp concatenates chunks. Non-last pads must be full `se_tropic_otp_xor_pad_max()` (plaintext max, typically 446 on FW ≥ 2.0.0); last may be short. Exhausted / parse / PIN / tamper use the same `n_pads = 0` error reply as encrypt.

OTP consume is **TLS only** (`ENCRYPT` / `DECRYPT`). Remaining/capacity pad kilobytes (no PIN, no consume) are `TROPIC OTP LEFT` on the USB console.

### Parser codes


| Code                          | Meaning                       |
| ----------------------------- | ----------------------------- |
| `SECURE_OTP_REQ_OK` (0)       | Need more bytes               |
| `SECURE_OTP_REQ_PARSE` (3)    | Bad framing; abort            |
| `SECURE_OTP_REQ_COMPLETE` (5) | PIN + length parsed; open XOR |
| `SECURE_OTP_PAD_READY` (6)    | One pad ready to XOR and send |

Error reply `err_code` when `n_pads = 0`: `SECURE_OTP_ERR_EXHAUSTED` (1), `PARSE` (3), `PIN` (4), `TAMPERED` (5), `FAIL` (255).


