# Security (PQ attacker)

Attack surfaces and what this firmware actually hardens. Slot map and consume rules: **[TROPIC.md](TROPIC.md)**. TLS/USB framing: **[COMMUNICATION.md](COMMUNICATION.md)**. Pins / option bytes: **[HARDWARE.md](HARDWARE.md)**.

This is a threat model of the **current code**, not a claim that the product is PQ-complete.

---

## Attacker

Assume a **cryptanalytically relevant quantum computer** plus ordinary physical/logical access. They can:

- Break **X25519** and **P-256 ECDSA** (Tropic L3, session uplink signature, factory SH0).
- **Not** break **ML-KEM-768**, **ML-DSA-44**, or AES-256-GCM / SHA-384 used as specified here.
- Read buses (USB, SPI), dump Tropic R-MEM, dump MCU flash if they get SWD / a firmware image, and talk to the CDC console.

They cannot skip **PIN + M&D** or invent `fill_id` / `secure_dwk` they do not have.

**In scope:** confidentiality of QKD pads and ML-KEM seed; integrity of OTP consume; TLS to the SAE.

**Out of scope:** side channels (power, EM, timing), fault injection, USB stack bugs, wolfSSL implementation bugs, a malicious SAE that already has the PIN.

---

## What is PQ vs what is not

| Asset | Algorithm | PQ? |
| --- | --- | --- |
| TLS key exchange | ML-KEM-768 only | yes |
| TLS client identity | ML-DSA-44 cert + wrapped key | yes |
| Pad encryption keys | ML-KEM-768 SS + `fill_id` HKDF | yes (needs MCU `fill_id`) |
| Tropic L3 session | X25519 | **no** |
| Uplink “device attest” | P-256 ECDSA on Tropic ECC slot 0 | **no** |
| R-MEM / NV blobs at rest | AES-256-GCM | yes (key secrecy is the issue) |
| PIN / M&D | HMAC-SHA256 + chip destroy | classical MAC; budget is the control |
| Factory SH0 in firmware | X25519 (eng-sample by default) | **no** |

Tropic is a **classical** SE: tamper-evident storage, M&D, and (until pairing) L3. It is **not** the confidentiality root for pads.

---

## Compromise ladders

| What the attacker has | Pads / ML-KEM sk | L3 to Tropic | Impersonate TLS client |
| --- | --- | --- | --- |
| Recorded TLS (no keys) | no (ML-KEM) | n/a | no (ML-DSA) |
| USB CDC, no PIN | cannot consume pads (need TLS + PIN); first-fill KEYGEN; can brick pairing | yes, as the MCU | no (key in Secure) |
| Tropic dump only | ciphertext only | pub keys; P-256 **sk** is on chip (classical attest) | no |
| Tropic dump + break X25519 | still no pads (`fill_id` + dwk + PIN) | **yes if SH0 still valid** (pre-pairing / leaked eng-sample) | no |
| MCU flash (`secure_dwk` + page 22) | kem_ct and PIN NVM decrypt; pads still need PIN | pairing **priv** after `PAIRING y` | **yes** (unwrap ML-DSA) |
| MCU flash + Tropic + PIN | **yes** | yes | yes |

---

## Surfaces

### 1. TLS to the SAE

**Attack:** MitM, harvest-now-decrypt-later, fake SAE, replay an old provision.

**Hardening:**

- TLS 1.3 only, cipher `TLS13-AES256-GCM-SHA384`, group **ML-KEM-768** only.
- mTLS; `WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT`.
- Provision verifies SAE CA from FLASH_CREDS; encrypt/decrypt load **no client CA** and pin the peer SPKI to the enrolled owner ML-DSA key (same key as UserApp). A CDC attacker presenting any other leaf is rejected.
- Client cert is **ML-DSA-44**; private key is AES-GCM wrapped under HKDF(`secure_dwk`) and unwrapped only in Secure.
- Provision uplink is bound to this TLS session: `to_sign = SHA384(SHA384(spki||ecc_pub) || exporter)` using RFC 9266 `tls-exporter` (`EXPORTER-Channel-Binding`, empty context, 32 bytes — the RFC fixes that length). TROPIC01 signs the leftmost 32 bytes of `to_sign`, which is ECDSA-with-SHA-384 on P-256. A TLS MitM gets a different exporter; forwarding a captured uplink fails.
- Wall clock from `PROVISION|ENCRYPT|DECRYPT <unix>` with a **TIME floor** in MCU NV (no rewind). Rejects certs that are not-yet-valid / expired against that clock.

**Residual:**

- Uplink **signature** is still P-256. A PQ attacker who can use Tropic ECC slot 0 can forge item 0 for a *chosen* exporter. They still cannot join a real SAE session without ML-KEM TLS and the ML-DSA client key. SAE must treat item 0 as **classical device binding**, not PQ identity. PQ identity is the TLS cert + item 6 (ML-KEM pk).
- TLS refuses until owner + device cert + wrapped SK are enrolled (PROVISION also needs SAE CA + NV ML-KEM pk). There is no compiled-in client CA.
- SAE sees PIN on the TLS application channel (encrypt/decrypt). Compromise of SAE ⇒ PIN.

### 2. USB CDC console

**Attack:** Plug in, send commands; sniff the enrollment PIN on USB; irreversible Tropic ops.

**Hardening:**

- `PROVISION` / `ENCRYPT` / `DECRYPT` never take a PIN; PIN is only inside TLS.
- `OWNER SET` is first USB wins (unsigned blob). `OWNER REPLACE` is reset-password only over MANAGE (not M&D); pairing survives; owner/creds/pads/ML-KEM pk do not.
- Occupied ECC slot 0 and `KEM INIT` / `PEER ADD`/`REMOVE` require a Tropic PIN on unsigned MANAGE TLS. Empty-slot `KEYGEN` stays unsigned USB. R-MEM 510 refuses a second `KEM INIT`.
- USB line cap 144 chars; unsigned OWNER SET and MANAGE bodies use the 16 KiB RX ring. RX overflow aborts.
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

- NonSecure **is not a security boundary** for Tropic. It chooses TLS mode and Unix time, and can invoke every Tropic command. TrustZone stops NS from *reading* Secure keys; it does not stop NS from *using* the APIs.
- NS can set a clock at the floor (not behind it). It cannot roll time backward.

### 4. SPI and Tropic L3 (classical)

**Attack:** PQ break of X25519 → open an L3 session; replay/replace R-MEM; rewind mcounters.

**Hardening:**

- After `TROPIC PAIRING n y`, factory **SH0 is invalidated** and the X25519 **private** key is only in MCU NV (AES-GCM under `secure_dwk`). Tropic dump of pairing *pub* is not enough to speak L3 as this host.
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

**Attack:** Read Secure flash or the ELF. `secure_dwk` is a **compiled-in** 32-byte blob, not an STM32 HUK.

**Hardening:**

- ML-KEM **seed** still needs PIN `final_key` and M&D (slot 510 KEK salt = device key, but the PIN path is required).
- Erased pads stay gone.
- Wrapped ML-DSA key is still wrapped — but the wrap key **is** HKDF(`secure_dwk`), so a flash dump **unwraps the TLS client key**.

**Residual (important):**

| From a Secure-flash dump | Consequence |
| --- | --- |
| `secure_dwk` | Device AEAD, PIN pepper, TLS client **private** key |
| NV page 22 | `fill_id`, cursors, pairing **priv**, owner SPKI, pw hash, wrap, ML-KEM pk |
| FLASH_CREDS page 21 | SAE CA, device cert |

A PQ attacker who dumps the MCU does **not** need quantum for TLS impersonation. Pads still need the PIN (8 M&D tries on silicon). Production hardening would move `secure_dwk` to a hardware unique key; this tree does not.

### 7. PIN and MAC-and-Destroy

**Attack:** Brute-force a 4–8 byte PIN; replay M&D; offline hash.

**Hardening:**

- Attempt spent **before** verify; each miss **destroys** one Tropic M&D slot.
- Silicon budget **8** (host model 4). Exhaustion makes slot 510 unrecoverable (`KEM INIT` will also refuse: slot occupied).
- Pepper binds PIN to this MCU’s `secure_dwk`.

**Residual:**

- Entropy is small; M&D is the only throttle. 8 guesses of a 4-digit PIN is not enough if the PIN is weak **and** the attacker can run checks (they need live Tropic + MCU).
- Correct PIN on TLS is visible to the SAE.
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
2. Enroll unsigned USB `OWNER SET` (owner + device cert/key + SAE CA), then `MANAGE` `KEM INIT` (unsigned PIN). TLS refuses ENCRYPT until owner + cert + wrap are present. ML-KEM pk lives in NV (no reflash).
3. After enrollment, do not send the Tropic PIN on the ASCII line; encrypt/decrypt take it only inside mTLS. Occupied `KEYGEN` is identity replace over MANAGE, not enrollment.
4. Lock SWD / enable hide protection if you ship; this project leaves `HDP1EN = 0`.
5. SAE must require **ML-KEM TLS + ML-DSA client cert**; do not accept a P-256 uplink signature as the device’s PQ identity.
6. Assume anyone with the **firmware image** can impersonate TLS and speak L3 after pairing (pairing priv in NV). Pads remain PIN-gated.
