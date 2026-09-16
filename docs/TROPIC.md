# TROPIC01 usage

How this firmware uses the chip: R-MEM map, OTP cursors, MCU NV, MAC-and-Destroy, pairing, and what a classical vs PQC attacker can actually get.

Console: **[COMMANDS.md](COMMANDS.md)**. TLS/QKD wire: **[COMMUNICATION.md](COMMUNICATION.md)**. MCU flash page for NV: **[HARDWARE.md](HARDWARE.md)**.

Sources: [se_tropic_rmem.h](../Secure/Core/Inc/se_tropic_rmem.h), [se_nv.h](../Secure/Core/Inc/se_nv.h), [se_tropic_pin.h](../Secure/Core/Inc/se_tropic_pin.h).

Tropic L3 (X25519 + AES-GCM + HMAC) is **classical**. Pad confidentiality is **ML-KEM-768 + MCU `secure_dwk`**. Do not treat a Tropic dump as equivalent to pad plaintext.

PQ attack surfaces (TLS, USB, NSC, SPI, flash dump, PIN): **[SECURITY.md](SECURITY.md)**.

---

## R-MEM user slots 0–511

TROPIC01 has 512 user-data slots. This project:

| Physical | Purpose | Key / binding |
| --- | --- | --- |
| **0–2** | ML-KEM-768 `kem_ct` (1088 B split across 3 slots) | MCU device AEAD; AAD = `slot LE \|\| fill_id` |
| **3–255** | Keystream pads, logical **0–252** (253 pads) | `HKDF-SHA384(ML-KEM ss, "SE_tropic_qkd_slot_v3" \|\| fill_id \|\| slot_index LE)`; blob binding = `slot_index LE` |
| **256–509** | Keystream pads, logical **253–506** (254 pads) | Same. Odd pad count → extra pad in the second half |
| **510** | ML-KEM generation **seed** (64 B, KEK-wrapped) | `KEK = HKDF-SHA384(PIN final_key 48 B, salt=device_key, "SE_tropic_mlkem_kek_v4")`; AAD = `"SE_tropic_mlkem_seed_v2"` |
| **511** | MAC-and-Destroy **PIN NVM** | MCU device AEAD; binding = `511 LE` |

Constants: `SE_TROPIC_PAD_FIRST = 3`, `SE_TROPIC_PAD_COUNT = 507`, `SE_TROPIC_PAD_HALF = 253`, `SE_TROPIC_QKD_SLOT_LAST = 509`.

`PROVISION` ingest and HKDF use **logical** pad index (0 = first pad). OTP cursors stay **physical**.

A new `kem_ct` write (`PROVISION` downlink item 0) commits `fill_id`, **erases slots 0–509**, and clears OTP-armed flags. Slots **510 and 511 are kept**.

### Blob format (all encrypted payloads)

```text
version(1) || nonce(12) || ciphertext || tag(16)
```

Overhead **29** bytes. Max slot **475** B (FW ≥ 2.0.0) → plaintext max **446**. Older Tropic FW reports 444; always use `se_tropic_get_rmem_slot_plaintext_max_size()`.

### Other Tropic namespaces (not R-MEM)

| Resource | Slot | Use |
| --- | --- | --- |
| ECC P-256 | `TR01_ECC_SLOT_0` | Session uplink signature, `TROPIC SIGN` |
| Pairing X25519 | 0 = factory **SH0**; **1–3** = host | L3 session keys |
| MAC-and-Destroy | hardware slots `0 .. 2*PIN_ROUNDS-1` | PIN attempt budget (chip has 128; this firmware uses 16 slots / 8 tries) |
| Mcounters | index 0 = encrypt cursor, index 1 = decrypt | Mirror of MCU OTP pointers |

---

## OTP cursors (slot pointers)

MCU NV is the **source of truth**. Tropic mcounters **mirror** the two physical pad pointers. They are not a second copy of the NV page.

On consume, firmware reads MCU cursor and Tropic mcounter. **Mismatch → `DEVICE_TAMPERED`**.

### Halves (`decrypt_half` from downlink item 1)

| `decrypt_half` | Decrypt base (physical) | Encrypt base (physical) |
| --- | --- | --- |
| 0 | 3 (logical 0–252) | 256 (logical 253–506) |
| 1 | 256 | 3 |

Each direction stays inside `[base, last]` (`last` is the other base − 1, or 509). Crossing halves is refused.

### Consume order (erase-before-reuse)

```text
match MCU vs Tropic cursor
→ read pad blob
→ decrypt (ML-KEM ss + fill_id)
→ advance Tropic mcounter, then MCU NV
→ erase R-MEM slot
→ XOR
```

Advance **before** erase: a power cut loses that pad and never rewinds it.

- Decrypt **rewind** (`target < cursor`) is refused.
- Decrypt **skip-ahead**: intermediate pads are burned (`erase + advance`, no XOR).
- Exhausted: Tropic mcounter `0xFFFFFFFE`; MCU cursor **510** (not a keystream slot). TLS replies with `SECURE_OTP_ERR_EXHAUSTED`. `TROPIC OTP LEFT` prints remaining/capacity kilobytes per half (`enc=A/B kb dec=C/D kb`). No fill yet is `0/capacity`, not an error.

---

## MCU NV (not duplicated in Tropic)

Plaintext record on Secure flash **page 22** (`0x0C02C000`). The page is **8 KB** (same size in the host RAM model). Bytes `[0,32)` are generate-once `secure_dwk` (Tropic AEAD / PIN pepper / pw hash only — **not** an NV seal). The record starts at offset 32 (`SE_NV_REC_OFF`).

Magic `SENV` (`0x53454E56`) + version **7**. Erased page or unknown magic → empty (`flags` 0, `LT_OK`). Sealed v3–v6 blobs are **not** migrated; re-enroll. Wrong version with a valid magic → `DEVICE_TAMPERED`. Length overflow on owner/SK/ML-KEM/peer fields → `DEVICE_TAMPERED`. There is no NV GCM MAC; OTP rewind is still caught by MCU vs Tropic mcounter mismatch.

Reads copy only the fields the caller needs. Pairing priv and the device ML-DSA SK are not loaded on fill/OTP/peer/KEM-PUB paths. Writes erase the whole 8 KB page (RMW work buffer, then `ForceZero`).

Operational fields sit first; `pw_hash`, pairing **priv**, and the device SK DER sit at the end of the record.

| Field | Size | Meaning |
| --- | --- | --- |
| `fill_id` | 32 B | Committed fill; binds kem_ct and pad keys |
| `cursor_encrypt` / `cursor_decrypt` | u16 × 2 | Current physical pad index |
| `base_encrypt` / `base_decrypt` | u16 × 2 | Half starts |
| `time_floor` | u32 | Monotonic Unix floor for wolfSSL |
| `flags` | u32 | `FILL`, `TIME`, `PAIRING`, `OTP` |
| `pairing_slot` | 1 B | Tropic pairing slot 1–3 |
| `pairing_pub` | 32 B | X25519 host public |
| `peer_count` | 1 B | Occupied peers, 0–8 |
| 8 × `{name_len, name[16], hash[48]}` | 65 B × 8 | Compact slots `0..count-1`; `PEER ADD` / `REMOVE` / `LIST` |
| `owner_len` + owner SPKI | u16 + 1312 B | Enrolled owner (`OWNER SET`) |
| `mlkem_len` + ML-KEM pk | u16 + 1184 B | NV copy from `KEM INIT` |
| `pw_hash` | 48 B | `SHA-384(secure_dwk \|\| password)` |
| `pairing_priv` | 32 B | X25519 host private (also printed once on USB for `pairing.key`) |
| `sk_len` + device SK DER | u16 + 3072 B | ML-DSA-44 PKCS#8/SEC1 (`CREDS DEVICE`); loaded only for mTLS |

RAM-only until `kem_ct` write: `pending_fill_id` from the uplink (item 5).

Flags: `SE_NV_FLAG_FILL 0x1`, `TIME 0x2`, `PAIRING 0x4`, `OTP 0x8`.

---

## MAC-and-Destroy PIN

Silicon: **8** tries (`SE_TROPIC_PIN_ROUNDS`) using **16** hardware M&D slots (`2i` and `2i+1` per try). Host model: **4** tries / 8 slots (`host_libtropic_config.h`). Chip maximum is 128; this firmware does not use the rest.

PIN length **4–8** bytes.

MCU KDF is **HMAC-SHA384**. Each try concatenates two independent 32-byte M&D outputs as a 64-byte HMAC key so the MAC is a 192-bit PQ primitive (NIST SHA-384). `master_secret`, wrap blocks `ci[]`, tag `t`, and `final_key` are 48 bytes.

**Pepper** (MCU-only): `HKDF-SHA384(device_key, "SE_tropic_pin_pepper_v2")`. Tropic never sees it. `kdf_in = PIN || add || pepper`. Changing `secure_dwk` invalidates PIN NVM — re-run `KEM INIT`.

NVM blob in slot **511** (MCU-sealed): remaining attempts `i` (1 B), wrapped `ci[ROUNDS][48]`, auth tag `t` (48 B). Silicon size `1 + 8*48 + 48 = 433` B (fits FW ≥ 2.0.0 plaintext max 446).

### Setup (`MANAGE` KEM INIT)

This is the **user** path to create the PIN and wrap the ML-KEM seed (slot 510). There is no factory PIN. USB `TROPIC KEM INIT` only prints `use MANAGE <unix>`. The unsigned MANAGE request carries the ASCII PIN and runs setup in one step:

1. Random 48-byte `master_secret`.
2. Init chip M&D slot pairs `0&1, 2&3, …, 14&15` (host: `0&1 … 6&7`).
3. For each try `i`: `S1,S2 = M&D(2i), M&D(2i+1)`; `K = S1||S2`; `ci[i] = master XOR HMAC-SHA384(K, kdf_in)`.
4. Store wrapped `ci` and tag `t = HMAC-SHA384(master, 0x00)` in slot 511.
5. `final_key = HMAC-SHA384(master, "2")` → ML-KEM KEK input (48 B).

### Check (OTP / later KEM use)

1. Decrypt slot 511. `i == 0` → exhausted; seed 510 is unrecoverable without re-provision.
2. **Decrement `i` and persist** before verify (attempt spent even if the rest fails).
3. `lt_mac_and_destroy` on slots `2i` and `2i+1` **destroys that hardware pair**.
4. Unwrap with `HMAC-SHA384(S1||S2, kdf_in)`; compare `HMAC-SHA384(s, 0x00)` to `t`.
5. Success: restore `i = ROUNDS`, re-init remaining M&D slots `[2i, 2*ROUNDS)`, return `final_key`.
6. Wrong PIN: both slots of the pair stay consumed, no `final_key`.

Eight wrong PINs on silicon (four on the host model) lock ML-KEM forever until a new `KEM INIT` (slot 510 must be empty first — it will not be).

---

## Pairing / SH0

Until paired, L3 uses factory **SH0** (pairing slot 0). Firmware default is **eng-sample** SH0 unless `SE_TROPIC_SH0_PROD` (host model always prod0).

`TROPIC PAIRING n y` (`n` = 1–3):

1. Generate X25519 (priv from MCU RNG).
2. Write **public** to Tropic pairing slot `n`.
3. Persist priv+pub in MCU NV.
4. `lt_pairing_key_invalidate(slot 0)` — factory SH0 **burned**.
5. Re-open L3 with the new slot.
6. Print `TROPIC PAIRING KEY n <priv-hex> <pub-hex>` on USB so UserApp can save `pairing.key` next to the device cert.

Irreversible on silicon. The pairing **private** key is in MCU NV (and, after INIT, in the host `pairing.key`) so a Tropic-only dump cannot impersonate L3 after SH0 is gone.

After an MCU reflash NV is empty and SH0 is already invalid, so L3 cannot start from factory keys. `TROPIC PAIRING n LOAD <priv> <pub>` writes the saved key back into MCU NV (no Tropic write) and re-opens L3. UserApp INIT does this automatically when `pairing.key` is present.

---

## Device-seal key (`secure_dwk`)

32-byte generate-once RNG value at the start of the NV page (bytes `[0,32)`). `0xFF…` means uninitialized. It is **not** AEAD'd with itself and never appears on USB or in the ELF.

| Derived | HKDF | Used for |
| --- | --- | --- |
| Device AEAD (silicon) | SHA-384(`secure_dwk`, `"SE_tropic_rmem_aes_v1"`) | kem_ct, PIN NVM |
| PIN pepper | SHA-384(device AEAD, `"SE_tropic_pin_pepper_v2"`) | M&D `kdf_in` |
| ML-KEM KEK | SHA-384(PIN `final_key` 48 B, salt=device AEAD, `"SE_tropic_mlkem_kek_v4"`) | Slot 510 |

Host model **does not** use `secure_dwk` for Tropic AEAD: [port_posix.c](../host/tropic_model/port_posix.c) has a fixed 32-byte test key. Host still stores dwk in the NV header for the password hash. `OWNER REPLACE` does not rotate dwk. Pairing slots survive that wipe. MCU NV itself is plaintext.

Opened ML-KEM public key must match the NV copy when present (`mlkem_check_pk`). `KEM INIT` writes that copy; no reflash.

---

## Tamper / consume precautions (in code)

| Mechanism | Effect |
| --- | --- |
| MCU-authoritative `fill_id` and cursors | Tropic R-MEM is not trusted alone if L3 ECC is broken |
| Dual cursor check | MCU vs mcounter mismatch → tamper |
| `fill_id` in kem_ct and pad HKDF | Restored old blobs fail decrypt |
| Advance-before-erase | Power-cut loses a pad; never reuse |
| No decrypt rewind; skip-ahead burns | Holes are consumed |
| Half isolation | Encrypt/decrypt cannot cross |
| Occupied pad refuse | `qkd_store` will not overwrite |
| New `kem_ct` wipes 0–509 | Fresh fill cannot mix with old pads |
| PIN pepper | SPI/L3 cannot offline-hash the PIN |
| M&D budget | Wrong PIN destroys a chip slot pair |
| KEK salt = MCU device key | PIN-only HKDF cannot open slot 510 |
| TIME floor in NV | Wall clock will not go backwards |
| SH0 invalidate + pairing priv on MCU | Factory L3 key gone; dump of Tropic pub is not enough |

---

## Classical Tropic vs PQC

| Function | Algorithm | Where |
| --- | --- | --- |
| L3 session | **X25519** | Tropic pairing slots; **priv in MCU NV** after pairing (host `pairing.key` backup) |
| Session attest | **P-256 ECDSA** | Tropic ECC slot 0 (classical) |
| R-MEM at rest | AES-256-GCM | Ciphertext on Tropic |
| M&D | HMAC-SHA384 (MCU KDF, 64-byte key from two M&D outputs) + KMAC M&D (chip) | Tropic hardware slots + slot 511 NVM |
| Pad keys | **ML-KEM-768** SS + `fill_id` HKDF | SS from decapsulation; sk never stored — seed in 510 |
| Anti-rollback | `fill_id`, dual cursors | **MCU NV only** |
| Device seal / pepper | `secure_dwk` HKDF | **MCU flash only** |

### If the attacker dumps **Tropic only** (no MCU)

Readable: ciphertext of kem_ct, pads, wrapped seed, PIN NVM, consumed M&D state, ECC **public** (and the **classical P-256 private** in ECC slot 0), pairing **publics**.

Not decryptable without MCU secrets: kem_ct and PIN NVM (`secure_dwk`), slot 510 (PIN + MCU salt), pads (ML-KEM SS **and** `fill_id` from MCU NV).

Post-pairing L3: pairing **private** is in MCU NV (and the host `pairing.key` backup); SH0 is invalid. Dump + broken X25519 still does not yield pad plaintext.

A PQC attacker who “gets Tropic contents” therefore gets **classical chip state and AES-GCM blobs**, not the QKD pads. Pads need ML-KEM sk (PIN path) plus MCU `fill_id`.

### If the attacker dumps **Tropic + MCU flash** (including `secure_dwk` and page 22)

Gains: device AEAD → kem_ct bytes, PIN NVM structure, `fill_id`, cursors, pairing **priv**, ML-DSA SK in the clear.

Still needs the **PIN** (and surviving M&D slots) to unwrap slot 510 and decapsulate. Erased pads are gone.

### If Tropic + MCU + PIN

Pads, seed, and OTP order are available. That is the intended “all secrets” failure.

**Bottom line:** Tropic is a classical SE used as tamper-evident storage and M&D. Confidentiality of keystream is ML-KEM + MCU binding. Do not claim Tropic L3 is PQC.
