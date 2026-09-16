# Security (PQ attacker)

Attack surfaces and what this firmware actually hardens. Slot map and consume rules: **[TROPIC.md](TROPIC.md)**. TLS/USB framing: **[COMMUNICATION.md](COMMUNICATION.md)**. Pins / option bytes: **[HARDWARE.md](HARDWARE.md)**.

This is a threat model of the **current code**, not a claim that the product is PQ-complete.

---

## Attacker

Assume a **cryptanalytically relevant quantum computer** plus ordinary physical/logical access. They can:

- Break **X25519** and **P-256 ECDSA** (Tropic L3, session uplink signature, factory SH0).
- **Not** break **ML-KEM-768**, **ML-DSA-44**, or AES-256-GCM / SHA-384 used as specified here.
- Read buses (USB, SPI), dump Tropic R-MEM, dump MCU flash if they get SWD / a firmware image, and talk to the CDC console.

They cannot skip **PIN + M&D** (8 live attempts on silicon; each miss burns two M&D slots).

---

## Scope

This document analyses **protocol, TrustZone layout, Tropic binding, and PQ algorithm choice**. It does **not** claim lab-grade implementation security (DPA, fault injection, or CVE-free crypto stack).

### In scope


| Area                           | What we analyse                                                                                                                             |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **PQ cryptography**            | ML-KEM-768 TLS, ML-DSA-44 mTLS, AES-256-GCM / SHA-384 at the **algorithm** level (assume correct implementations).                          |
| **Pad / seed confidentiality** | Pads and ML-KEM seed require ML-KEM sk + `fill_id` + PIN + MCU `secure_dwk`; kem_ct and PIN NVM are MCU-sealed.                             |
| **OTP integrity**              | No rewind, no half-mixing, cursor/mcounter binding, advance-then-erase consume.                                                             |
| **TLS binding**                | SAE on `PROVISION` (CA + mTLS + exporter-bound uplink); USER on `ENCRYPT` / `DECRYPT` / `MANAGE` (owner SPKI pin; mTLS on encrypt/decrypt). |
| **USB / NS policy**            | Unsigned enrollment surface, first-wins owner, DEBUG leakage, NS as API caller (documented residuals).                                      |
| **Tropic / L3 (classical)**    | SH0, pairing, mcounters, R-MEM ciphertext, M&D budget, uplink P-256 vs PQ TLS identity.                                                     |
| **MCU flash / SWD**            | `secure_dwk`, NV page 22, creds page 21, plaintext ML-DSA SK and pairing priv in flash dump.                                                |
| **PIN online guessing**        | M&D throttle (8 tries); weak PIN on a live device.                                                                                           |


### Out of scope


| Area | What is excluded | Why it is not analysed here | Residual in this tree |
| ---- | ---------------- | --------------------------- | --------------------- |
| **Side channels — power / EM** | Attacker places a scope or EM probe on the MCU and records power or emissions while crypto runs, then correlates traces with key material (DPA/EMA). | Not evaluated in this document; firmware is not DPA-tested. | Software wolfCrypt on U535 (no HW AES): full AES T-tables, full ML-DSA; `WOLFSSL_MLKEM_SMALL` still on. `GCM_TABLE_4BIT` and `ECC_TIMING_RESISTANT` are compile-time choices only. |
| **Side channels — timing** | Secret-dependent branches and table lookups make crypto take longer or shorter (e.g. AES S-box index, ML-KEM `*_SMALL` paths). An attacker who can **measure execution time** on the device — debugger, cycle counter, or how long a USB/TLS operation takes to complete — may recover bits statistically. | Same: implementation leakage, not part of this threat model; no constant-time claim for AES or PQ software paths. | `WOLFSSL_MLKEM_SMALL` remains for flash; AES and ML-DSA use full table paths in `user_settings.h`. |
| **Fault injection** | Voltage/glitch/EM fault to skip checks (e.g. OTP cursor advance, GCM reject, NV commit). | No redundant verification, glitch detectors, or secure-boot rollback. PIN guessing is in scope via M&D (§7), not via faults. | No countermeasures in this tree. |
| **wolfSSL / wolfCrypt implementation** | Memory corruption, parser bugs, unknown CVEs in the vendored stack. | Not FIPS-validated or independently audited; assume algorithms work, not every line of wolfSSL. | Full TLS 1.3 client + ML-KEM + ML-DSA + AES-GCM in Secure during handshake. |

---

## What is PQ vs what is not


| Asset                   | Algorithm                      | PQ?                                  |
| ----------------------- | ------------------------------ | ------------------------------------ |
| TLS key exchange        | ML-KEM-768 only                | yes                                  |
| TLS client identity     | ML-DSA-44 cert + SK in NV      | yes                                  |
| Pad encryption keys     | ML-KEM-768 SS + `fill_id` HKDF | yes (needs MCU `fill_id`)            |
| Tropic L3 session       | X25519                         | **no**                               |
|                         |                                |                                      |
| R-MEM blobs at rest     | AES-256-GCM                    | yes (key secrecy is the issue)       |
| PIN / M&D               | HMAC-SHA384 (MCU KDF, 512-bit key) + KMAC M&D (chip) | **yes** at the MAC (NIST 192-bit SHA-384); online guess limit is still 8 silicon tries (16 M&D slots) |
| Factory SH0 in firmware | X25519 (eng-sample by default) | **no**                               |


Tropic is a **classical** SE: tamper-evident storage, M&D, and (until pairing) L3. It is **not** the confidentiality root for pads.

---

## Compromise ladders


| What the attacker has              | Pads / ML-KEM sk                                                           | L3 to Tropic                                                 | Impersonate TLS client           |
| ---------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------- |
| Recorded TLS (no keys)             | no (ML-KEM)                                                                | n/a                                                          | no (ML-DSA)                      |
| USB CDC, no PIN                    | cannot consume pads (need TLS + PIN); first-fill KEYGEN; can brick pairing | yes, as the MCU                                              | no (key in Secure)               |
| Tropic dump only                   | ciphertext only                                                            | pub keys; P-256 **sk** is on chip (classical attest)         | no                               |
| Tropic dump + break X25519         | still no pads (`fill_id` + dwk + PIN)                                      | **yes if SH0 still valid** (pre-pairing / leaked eng-sample) | no                               |
| MCU flash (`secure_dwk` + page 22) | kem_ct and PIN NVM decrypt; pads still need PIN                            | pairing **priv** after `PAIRING y`                           | **yes** (ML-DSA SK in the clear) |
| MCU flash + Tropic + PIN           | **yes**                                                                    | yes                                                          | yes                              |


---

## Surfaces

### 1. TLS to SAE and USER

The device is a TLS client. **SAE** is the peer for `PROVISION` only. **USER**
(UserApp) is the peer for `ENCRYPT` / `DECRYPT` / `MANAGE`. UserApp is not an SAE.

**Attack:** MitM, harvest-now-decrypt-later, fake SAE, fake UserApp, replay an old provision.

**Hardening:**

- TLS 1.3 only, cipher `TLS13-AES256-GCM-SHA384`, group **ML-KEM-768** only.
- mTLS on provision / encrypt / decrypt; `WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT`. MANAGE is owner-pinned without a device client cert.
- Provision verifies SAE CA from FLASH_CREDS; encrypt/decrypt/manage load **no client CA** and pin the peer SPKI to the enrolled owner ML-DSA key (same key as UserApp). A CDC attacker presenting any other leaf is rejected.
- Client cert is **ML-DSA-44**; private key is plaintext DER in NV, copied into Secure RAM only when wolfSSL starts mTLS, then wiped.
- Provision uplink is bound to this TLS session: `to_sign = SHA384(SHA384(spki||ecc_pub) || exporter)` using RFC 9266 `tls-exporter` (`EXPORTER-Channel-Binding`, empty context, 32 bytes — the RFC fixes that length). TROPIC01 signs the leftmost 32 bytes of `to_sign`, which is ECDSA-with-SHA-384 on P-256. A TLS MitM gets a different exporter; forwarding a captured uplink fails.
- Wall clock from `PROVISION|ENCRYPT|DECRYPT|MANAGE <unix>` with a **TIME floor** in MCU NV (no rewind). Rejects certs that are not-yet-valid / expired against that clock.

**Residual:**

- USER sees PIN on the TLS application channel (encrypt / decrypt, and PIN-gated MANAGE). Compromise of UserApp ⇒ PIN. SAE does not see the OTP PIN; provision has no PIN on the wire.

### 2. USB CDC console

**Attack:** Plug in, send commands; sniff the enrollment PIN on USB; irreversible Tropic ops.

**Hardening:**

- `PROVISION` / `ENCRYPT` / `DECRYPT` never take a PIN; PIN is only inside TLS.
- `OWNER SET` is first USB wins (unsigned blob). `OWNER REPLACE` is reset-password only over MANAGE (not M&D); pairing survives; owner/creds/pads/ML-KEM pk do not.
- Occupied ECC slot 0 and `KEM INIT` / `PEER ADD`/`REMOVE` require a Tropic PIN on unsigned MANAGE TLS. Empty-slot `KEYGEN` stays unsigned USB. R-MEM 510 refuses a second `KEM INIT`.
- USB line cap 160 chars; unsigned OWNER SET and MANAGE bodies use the 16 KiB RX ring. RX overflow aborts.
- DEBUG ASCII only **before** the first TLS record, framed as `DEBUG:<text>:DEBUG` so a glued ClientHello is still split at `:DEBUG`.

**Residual:**

- **No USB authentication** for ping, info, list, empty-slot keygen, or TLS arm. First USB `OWNER SET` wins. The reset password is dumpable with MCU flash (`SHA-384(dwk || password)`). Pairing survives owner wipe.
- Occupied `KEYGEN` / `KEM INIT` / `PEER *` PIN is on MANAGE TLS (owner-pinned, not mTLS). After slot 510 is occupied, pad consume PIN is only inside ENCRYPT/DECRYPT mTLS.
- DEBUG lines leak handshake/Tropic status to the USB host.

### 3. NonSecure world and NSC

**Attack:** Malicious or buggy NonSecure calls `SECURE_Tropic*_nsc_call` / `SECURE_TlsStart_nsc_call`.

**Hardening:**

- Crypto, Tropic SPI, `secure_dwk`, NV, and wolfSSL live in **Secure**.
- GTZC: SPI1 and RNG are Secure; USB is NonSecure.
- NSC packets 64 B. Unsigned OWNER SET bytes still cross NS→S on the USB ring after `OwnerBegin`.

**Residual:**

- **TrustZone:** Compromising NS does **not** compromise Secure. NS cannot read or modify Secure RAM, `secure_dwk`, ML-DSA SK, kem seals, or PIN NVM — that isolation is hardware-enforced.
- **NSC calling surface:** NS still chooses TLS mode and Unix time and forwards every USB/Tropic request into Secure. A buggy or malicious NS image can abuse that interface (proxy records, arm the wrong session, invoke destructive Tropic ops) without ever obtaining Secure key material.
- NS can set a clock at the floor (not behind it). It cannot roll time backward.

### 4. SPI and Tropic L3 (classical)

**Attack:** PQ break of X25519 → open an L3 session; replay/replace R-MEM; rewind mcounters.

**Hardening:**

- After `TROPIC PAIRING n y`, factory **SH0 is invalidated** and the X25519 **private** key is in MCU NV **and** printed once on USB for host backup (`pairing.key`). Tropic dump of pairing *pub* is not enough to speak L3 as this host.
- MCU NV (`fill_id`, OTP cursors) is authoritative. Tropic mcounters must **match**; mismatch → `DEVICE_TAMPERED`.
- kem_ct and PIN NVM are MCU-sealed (device AEAD + `fill_id` / slot binding). Pads are sealed under ML-KEM SS, not under L3.
- PIN pepper never leaves the MCU; M&D inputs on SPI are not a PIN hash.
- Pad consume: match → read → decrypt → **advance then erase**. No rewind; skip-ahead burns pads.

**Residual:**

- **Before pairing**, L3 uses factory SH0. Default firmware is **eng-sample** SH0 (`libtropic_user_config.h`) unless `SE_TROPIC_SH0_PROD`. Those private keys are in the SDK. A PQ attacker (or anyone with the published sample key) who can SPI the chip **before** pairing owns L3.
- Even with broken L3, pads still need ML-KEM sk + `fill_id`. L3 break alone ≠ pad plaintext.
- Tropic ECC slot 0 **private** key is on the chip (classical). Dump or L3 as host ⇒ forge uplink signatures.
- `HDP1EN = 0` (hide protection off). SWD/debug is an assumed lab surface unless you lock it in production.

### 5. Tropic dump (no MCU)

**Attack:** Read R-MEM / pairing pubs / ECC.

**Hardening:** pads, kem_ct, seed 510, PIN NVM are ciphertext. `fill_id` and pairing **priv** are not on Tropic. Pepper and `secure_dwk` are not on Tropic.

**Residual:** attacker gets classical P-256 sk (slot 0), pairing pubs, AES-GCM blobs, consumed M&D state. They still cannot decapsulate `kem_ct` without slot 510 + PIN + MCU salt.

### 6. MCU flash / firmware image (`secure_dwk`)

**Attack:** Read Secure flash (SWD / dump). `secure_dwk` is a generate-once 32-byte value in the NV page header, not an STM32 HUK and not compiled into the ELF.

**Hardening:**

- ML-KEM **seed** still needs PIN `final_key` and M&D (slot 510 KEK salt = device key, but the PIN path is required).
- Erased pads stay gone.
- OTP/peer reads do not copy the ML-DSA SK or pairing priv into RAM. A flash dump still contains both in the clear.

**Residual (important):**


| From a Secure-flash dump | Consequence                                                                     |
| ------------------------ | ------------------------------------------------------------------------------- |
| `secure_dwk`             | Device AEAD (kem_ct, PIN NVM), PIN pepper                                       |
| NV page 22               | `fill_id`, cursors, pairing **priv**, owner SPKI, pw hash, ML-DSA SK, ML-KEM pk |
| FLASH_CREDS page 21      | SAE CA, device cert                                                             |


A PQ attacker who dumps the MCU does **not** need quantum for TLS impersonation. Pads still need the PIN (8 M&D tries on silicon, two hardware slots each). This tree does not put `secure_dwk` in a hardware unique key.

### 7. PIN and MAC-and-Destroy

**Attack:** Brute-force a 4–8 byte PIN; replay M&D; offline hash.

**Hardening:**

- MCU runs the PIN protocol KDF (**HMAC-SHA384** on `PIN || add || pepper`). Each check concatenates two 32-byte **`lt_mac_and_destroy`** outputs as a 64-byte HMAC key (`K = S1 || S2`), then `t = HMAC-SHA384(master, 0x00)` (48-byte tag). Chip **KMAC** still runs in one-time hardware slots (two slots per try).
- Key entropy up to 512 bits (independent 256-bit M&D outputs). HMAC-SHA384 output 384 bits. Generic quantum key-search on the 512-bit key ~2²⁵⁶; generic quantum attack on a 384-bit MAC value ~2¹⁹². NIST lists SHA-384 as a 192-bit hash-strength primitive.
- Attempt spent **before** verify; each miss **destroys** one M&D slot pair (not a software counter).
- Silicon budget **8** tries / **16** slots (host model 4 tries / 8 slots). Exhaustion makes slot 510 unrecoverable (`KEM INIT` will also refuse: slot occupied).
- Pepper binds PIN to this MCU’s `secure_dwk`.

**Residual:**

- Entropy is small; M&D is the only throttle. 8 guesses of a 4-digit PIN is not enough if the PIN is weak **and** the attacker can run checks (they need live Tropic + MCU). HMAC-SHA384 does not add PIN entropy; a PQ break of Tropic L3 can still observe M&D outputs on the wire.
- Correct PIN on TLS is visible to USER (encrypt / decrypt / PIN-gated MANAGE), not to SAE.
- Changing `secure_dwk` (new firmware blob) invalidates PIN NVM — re-run `KEM INIT` (slot 510 must be empty, so this is a brick unless you wipe Tropic).

### 8. QKD fill / OTP protocol

**Attack:** Mix two fills; reuse a pad; decrypt from the encrypt half; replay old `kem_ct`.

**Hardening:**

- New `kem_ct` commits `fill_id`, wipes slots **0–509**, re-arms halves. 510/511 kept.
- Pad HKDF includes `fill_id` and logical slot. Old images fail AEAD.
- Occupied pad store refused. Encrypt/decrypt halves isolated.
- LV version checked first (`SECURE_QKD_WRONG_VERSION`).
- Decrypt rewind refused.

**Residual:** SAE can load pads on `PROVISION`. Device does not authenticate pad images beyond AEAD under the ML-KEM SS it will only get after PIN. A provisioning MitM is stopped by ML-KEM TLS + exporter-bound uplink, not by Tropic.

### 9. Host model (`se_host`)

**Not a security target.** Fixed Tropic AEAD test key, PIN rounds 4, RAM NV, SH0 prod0, Unix time not applied. Use it to gate irreversible sequences, not to evaluate PQ strength. Details: **[host/README.md](../host/README.md)**.

---

## Operator checklist (PQ-relevant)

1. Do not leave factory **SH0** on a field device; run `TROPIC PAIRING n y` after model gates A–E/H. Build with `SE_TROPIC_SH0_PROD` for production chips, not eng-sample keys.
2. Enroll unsigned USB `OWNER SET` (owner + device cert/key + SAE CA), then **USER** `MANAGE` `KEM INIT` (unsigned PIN). TLS refuses ENCRYPT until owner + cert + device SK are present. ML-KEM pk lives in NV (no reflash).
3. After enrollment, do not send the Tropic PIN on the ASCII line; encrypt/decrypt take it only inside mTLS. Occupied `KEYGEN` is identity replace over MANAGE, not enrollment.
4. Lock SWD / enable hide protection if you ship; this project leaves `HDP1EN = 0`.
5. SAE (`PROVISION`) must require **ML-KEM TLS + ML-DSA client cert**; do not accept a P-256 uplink signature as the device’s PQ identity. USER (`ENCRYPT` / `DECRYPT`) pins the peer to the enrolled owner key, not to SAE CA.
6. Assume anyone with the **firmware image** or the host `pairing.key` can speak L3 after pairing. Pads remain PIN-gated. Keep `pairing.key` with the device cert; without it an MCU reflash cannot reopen L3.

