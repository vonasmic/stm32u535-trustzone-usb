# Communication

How the host, USB console, Secure TLS client, and SAE talk. Tropic slot contents: **[TROPIC.md](TROPIC.md)**. Console commands that *arm* these paths: **[COMMANDS.md](COMMANDS.md)**.

```text
USB ASCII commands  →  NonSecure parser  →  NSC  →  Secure
USB TLS bytes       →  8 KiB rings       →  wolfSSL 1.3 client  →  Java SAE
SPI                 →  TROPIC01 L2/L3
```

Mode is chosen **off the TLS wire** by `PROVISION` / `ENCRYPT` / `DECRYPT`. After handshake the SAE infers the role from what the device sends (uplink vs silence) and from its own request.

---

## USB / NSC pipe

NonSecure ([tls_usb_io.c](../NonSecure/Core/Src/tls_usb_io.c)):

- **Command mode** — `\n`-terminated ASCII, max 96 chars.
- After a successful `SECURE_TlsStart_nsc_call`, **TLS mode** — every RX byte goes to `SECURE_UsbRx_nsc_call`. Poll `SECURE_UsbService_nsc_call` until `SECURE_USB_IDLE` or `SECURE_USB_ERR`.
- TX drains Secure in **64-byte** NSC packets (`SECURE_USB_PKT_MAX`).
- DTR off, CDC deactivate, overflow, or TLS end → command mode again.

Secure rings ([se_usb_tls.h](../Secure/Core/Inc/se_usb_tls.h)): RX and TX **8192** bytes each.

`DEBUG:` status lines (handshake progress, Tropic logs) go on the CDC TX ring **only before the first TLS record byte**. After that, TX is TLS only, so records do not glue onto ASCII (BouncyCastle). ClientHello waits until DEBUG is drained.

PIN is never on this pipe for the three TLS modes.

---



## TLS 1.3 (device is client)

[se_tls_client.c](../Secure/Core/Src/se_tls_client.c) (host mirror: [se_host_tls.c](../host/tropic_model/se_host_tls.c)):


| Setting            | Value                                                            |
| ------------------ | ---------------------------------------------------------------- |
| Version            | TLS 1.3 only                                                     |
| Cipher             | `TLS13-AES256-GCM-SHA384`                                        |
| Group              | **ML-KEM-768** (`WOLFSSL_ML_KEM_768`)                            |
| Client cert        | `fw_client_cert_der`                                             |
| Client private key | wrapped`wrapped_client_key.h`using device AES key (`secure_dwk`) |
| Peer verify        | `WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT`      |




### CA per mode


| Mode      | Constant                        | Verify blob                           |
| --------- | ------------------------------- | ------------------------------------- |
| Provision | `SECURE_TLS_MODE_PROVISION` = 1 | `fw_root_ca_der` (SAE application CA) |
| Encrypt   | `SECURE_TLS_MODE_ENCRYPT` = 2   | `fw_client_ca_der` + pin `fw_user_spki` |
| Decrypt   | `SECURE_TLS_MODE_DECRYPT` = 3   | `fw_client_ca_der` + pin `fw_user_spki` |


If `fw_client_ca_der_len` is 0, ENCRYPT/DECRYPT fail at CA load until `scripts/embed_fw_creds.py` is re-run. If `fw_user_spki_len` is 0, they fail at setup (`embed user-cert.pem`). After handshake, ENCRYPT/DECRYPT also require the TLS peer SPKI to match `fw_user_spki` (home-PC `certs/user/user-cert.pem`). SAE/terminal identity is not accepted for those modes.

### Exporter (session binding)

After handshake:

- Label: `EXPORTER-tropic-binding` (23 bytes)
- Length: 32 bytes

Used only on **provision**: hashed into the uplink signature so a MitM that terminates TLS cannot forward a valid uplink.

### Post-handshake


| Mode      | Device sends              | Device reads                            |
| --------- | ------------------------- | --------------------------------------- |
| Provision | LV **uplink v3**          | LV **downlink v2** (QKD ingest)         |
| Encrypt   | nothing until SAE request | PIN + plaintext; replies OTP ciphertext |
| Decrypt   | nothing until SAE request | PIN + encrypt reply; replies plaintext  |


Then TLS shutdown.

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
| Session uplink (provision) | **3** (`SECURE_LV_UPLINK_VERSION`)   |
| QKD downlink (provision)   | **2** (`SECURE_LV_DOWNLINK_VERSION`) |


---



## Uplink v3 (Secure → SAE, provision only)

Built in [se_tropic_session.c](../Secure/Core/Src/se_tropic_session.c).

`count = 7 + 2 × fw_peer_count` (currently one peer “Alice” → **9** items).


| Index | Item                    | Size         | Notes                                           |
| ----- | ----------------------- | ------------ | ----------------------------------------------- |
| 0     | Session signature       | 64 B         | TROPIC P-256 ECDSA                              |
| 1     | TROPIC P-256 public key | 64 B         | XY from ECC slot 0                              |
| 2     | Client hash             | 32 B         | `SHA256(fw_client_spki || ecc_pub)`             |
| 3     | R-MEM slot size         | 2 B          | u16 LE, chip `r_mem_udata_slot_size_max`        |
| 4     | Pad slot count          | 2 B          | u16 LE = **507**                                |
| 5     | Pending `fill_id`       | 32 B         | RNG; committed when `kem_ct` is written         |
| 6     | ML-KEM-768 public key   | **1184 B**   | Encapsulate from **this item**, not from a file |
| 7+    | Per peer: hash, name    | 32 B + UTF-8 | From `fw_peers[]` in `fw_creds.h`               |


Signature digest:

```text
client_hash = SHA256(fw_client_spki || ecc_pub)
to_sign     = SHA256(client_hash || exporter)
sig         = ECDSA_P256(Tropic slot 0, to_sign)
```

The exporter is wiped after hashing. `fw_client_spki` is hashed, never sent.

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

Not an LV envelope. [secure_otp.h](../Secure/Core/Inc/secure_otp.h).

PIN length **4–8** bytes (`SE_TROPIC_PIN_SIZE_MIN` / `MAX`).

### ENCRYPT (SAE → SE)

```text
u8  pin_len
u8  pin[pin_len]
u32 msg_len LE
u8  plaintext[msg_len]
```



### ENCRYPT reply (SE → SAE)

```text
u32 n_pads LE
repeat n_pads times:
  u16 logical_slot LE
  u16 chunk_len LE
  u8  chunk[chunk_len]
```

Last chunk may be short. Cap is remaining pads in the **encrypt** half. `logical_slot` is SAE pad index (0 = first pad), not the physical R-MEM index.

### DECRYPT (SAE → SE)

```text
u8  pin_len
u8  pin[pin_len]
<ENCRYPT reply unchanged>
```

If the requested logical slot is ahead of the decrypt cursor, intermediate pads are **burned** (erased, no XOR). Rewind is refused.

### DECRYPT reply (SE → SAE)

```text
u32 n_pads LE
repeat n_pads times:
  u16 chunk_len LE
  u8  chunk[chunk_len]
```

No slot IDs. SAE concatenates chunks. Non-last pads must be full `se_tropic_otp_xor_pad_max()` (plaintext max, typically 446 on FW ≥ 2.0.0); last may be short.

OTP consume is **TLS only** (`ENCRYPT` / `DECRYPT`). There is no USB console OTP command.

### Parser codes


| Code                          | Meaning                       |
| ----------------------------- | ----------------------------- |
| `SECURE_OTP_REQ_OK` (0)       | Need more bytes               |
| `SECURE_OTP_REQ_PARSE` (3)    | Bad framing; abort            |
| `SECURE_OTP_REQ_COMPLETE` (5) | PIN + length parsed; open XOR |
| `SECURE_OTP_PAD_READY` (6)    | One pad ready to XOR and send |


