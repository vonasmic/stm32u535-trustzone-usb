# USB console commands

Authoritative tables live in [NonSecure/Core/Src/tls_usb_io.c](../NonSecure/Core/Src/tls_usb_io.c). Host `se_host` compiles that same file over a PTY.

TLS framing after arming: **[COMMUNICATION.md](COMMUNICATION.md)**. Tropic slots: **[TROPIC.md](TROPIC.md)**. How to run: **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

The device is a TLS client. **SAE** is the peer for `PROVISION`. **USER** (UserApp) is the peer for `ENCRYPT` / `DECRYPT` / `MANAGE`. UserApp is not an SAE.

---

## Parsing

| Rule | USB CDC | Host `se_host` |
| --- | --- | --- |
| Line end | `\n` (`\r` ignored) | Same (PTY + stdin) |
| Max line | **160** chars | **160** chars (same parser) |
| Whitespace | Trim spaces/tabs | Same |
| Match | Case-sensitive prefix; optional spaces/tabs/`=` after the name | Same |
| Empty line | Ignored | Ignored |
| Unknown | `failed` | `failed` |

`HELP` prints every `usage` string. `?` is an alias (not listed in HELP). Stop `se_host` with Ctrl-C (unlinks the PTY).

Clock + TLS arm happen together on `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE <unix>`.

---

## PIN / owner policy

| Context | On the 160-char ASCII line? |
| --- | --- |
| `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE` | **Never** — PIN (when used) is only inside TLS |
| `HELP` / `PING` / `INFO` / `PUB` / `CLIENT HASH` / `CLIENT CSR` / `KEM PUB` / `PEER LIST` | **No PIN** (unsigned, read-only) |
| MANAGE KEYGEN / KEM INIT / PEER ADD / REMOVE / CREDS / OWNER REPLACE / PAIRING | Unsigned request over owner-pinned TLS. PIN when the command is PIN-gated. **No ML-DSA.** |
| `OWNER SET` | Unsigned USB blob (password + SPKI + optional SAE CA). First-wins. Device ML-DSA is generated on-chip. |

Tropic PIN (KEM / KEYGEN replace / PEER / ENCRYPT / PAIRING): **8–16** printable ASCII (`0x20–0x7E`). The same bytes are used on MANAGE and on ENCRYPT/DECRYPT.

Reset password: ASCII printable `0x20–0x7E`, **min 8, max 64**. Hash is `SHA-384(secure_dwk || password)`. Only this password can `OWNER REPLACE` (over MANAGE).

MANAGE TLS request (one per session, unsigned):

```text
u8 cmd | u8 pin_len | pin[pin_len] | u16le body_len | body[body_len]
```

Reply: `u8 status | u16le msg_len | msg`. Cmd 1=KEM INIT, 2=KEYGEN, 3=PEER ADD, 4=PEER REMOVE, 5=CREDS SAE, 6=CREDS DEVICE (cert DER only), 7=OWNER REPLACE, 8=PAIRING (body: one slot byte 1–3). PIN length is 0 for CREDS and OWNER REPLACE. PAIRING never prints the X25519 private key.

---

## Top-level commands

| Syntax | USB | Host | Parameters | What it does |
| --- | --- | --- | --- | --- |
| `HELP` | yes | yes | — | Print `commands:` plus all usage lines |
| `?` | alias | alias | — | Same as HELP |
| `PROVISION <unix>` | yes | yes | decimal Unix UTC, ≠ 0 | Arm TLS mode **1** (**SAE** peer). Refuses until owner + device cert + device SK + SAE CA + NV ML-KEM pk are present. Verify SAE CA from FLASH_CREDS. After handshake: signed uplink v4, then QKD downlink v2 into R-MEM. **mTLS** (device cert). |
| `ENCRYPT <unix>` | yes | yes | same | Arm TLS mode **2** (**USER** peer). Refuses until owner + device cert + device SK. **mTLS**; pin the TLS peer leaf SPKI to the enrolled **owner** key. Wait TLS: PIN + plaintext; reply XOR ciphertext with pad slots. |
| `DECRYPT <unix>` | yes | yes | same | Arm TLS mode **3** (**USER** peer). Same mTLS + owner pin as ENCRYPT. Wait TLS: PIN + encrypt reply; reply plaintext chunks (no slots). |
| `MANAGE <unix>` | yes | yes | same | Arm TLS mode **4** (**USER** peer). Refuses until owner SPKI is present. Owner-pinned TLS **without** a device client cert. After handshake: one unsigned command (see above), status reply, shutdown. |
| `OWNER SET` | yes | yes | then unsigned blob | First USB wins if the owner slot is empty; else dump status **refused**. Two dump frames: begin, then apply. Blob is password + owner SPKI + optional SAE CA. Device ML-DSA is generated on-chip. |
| `PEER LIST` | yes | yes | — | Dump: `u8 count \| (u8 nlen \| name \| 48 hash)*` |
| `CLIENT HASH` | yes | yes | — | Dump 48-byte `SHA384(device_cert_spki \|\| ecc_pub)` |
| `CLIENT CSR` | yes | yes | — | Dump raw ML-DSA-44 pub (1312 B) |
| `TROPIC …` | yes | yes | subcommand | Flat table: PING/INFO/PUB/KEM PUB/OTP LEFT |

### `<unix>`

- Decimal (`strtoul` base 10), **must be non-zero**, no extra tokens. Else `failed`.
- Silicon and `se_host`: `SECURE_TlsStart_nsc_call` → `se_time_set_unix` then `se_tls_arm`. Accepted range **1704067200–2145916800** (2024-01-01 … 2038-01-01). If the value is behind the TIME floor, firmware keeps the floor (no USB notice). Host wolfSSL still uses the **process clock** (no `TIME_OVERRIDES`).

On USB (silicon or PTY), success sets `s_tls_armed`: further RX is opaque TLS until `SECURE_USB_IDLE`, error, disconnect, DTR off, or RX overflow.

TLS arm failure: ASCII line `failed` (no Tropic/TLS/auth taxonomy).

Typed USB replies (PUB, CSR, HASH, KEM PUB, OTP LEFT, PEER LIST, OWNER SET) are dump frames:

```text
0xB1 | u8 status | u16le body_len | body
```

Status: **0** ok, **1** err, **2** empty, **3** refused. ASCII errors elsewhere are only `failed`.

---

## `PEER` commands

Runtime nickname + `SHA384(peer SPKI)` list in MCU NV. Provision uplink items 7+ are this table (hash then name per peer). Cap **8**. Nickname unique (case-sensitive). The same hash under two names is allowed. Duplicate nickname is refused — to change a hash, `REMOVE` then `ADD`. An empty list is valid (uplink then has **7** items).

Certs and PIN-gated commands use MANAGE TLS application data, not the ASCII line.

| Syntax | Success | Errors |
| --- | --- | --- |
| `PEER ADD` (MANAGE cmd 3) | status 0, `PEER ADD ok` | PIN fail, nickname exists, list full |
| `PEER REMOVE` (MANAGE cmd 4) | status 0, `PEER REMOVE ok` | PIN fail, not found |
| `PEER LIST` | dump `u8 count | records` | dump status **err** |

- Tropic PIN is 8–16 printable ASCII inside the unsigned MANAGE request
- `<name>`: 1–16 bytes, printable ASCII `[A-Za-z0-9_.-]`
- Hash: 48-byte SHA-384 of the peer SPKI

`PEER LIST` goes through `SECURE_PeerGet_nsc_call`.

---

## `TROPIC` subcommands

| Syntax | Parameters | Firmware |
| --- | --- | --- |
| `TROPIC PING` | — | `lt_ping("hello")`. Success ASCII: `TROPIC ping ok` |
| `TROPIC INFO` | — | Chip ID / FW ASCII (success only) |
| `TROPIC PUB` | — | Dump 64-byte P-256 pub, or status **empty** |
| `TROPIC KEM PUB` | — | Dump NV ML-KEM pk, or status **empty** |
| `TROPIC OTP LEFT` | — | Dump 4×u32le: enc left, enc cap, dec left, dec cap. Unprovisioned is `0/capacity` |

Unknown USB lines: `failed`. NSC Tropic results are only ok / err (plus dump empty for unoccupied PUB / KEM PUB). MANAGE TLS still returns typed `u8 status` (PIN_FAIL, TAMPERED, …) on the owner-pinned channel, not on USB.

MANAGE Tropic ops (unsigned request after `MANAGE <unix>`):

| Cmd | Name | Firmware |
| --- | --- | --- |
| 1 | KEM INIT | Occupied R-MEM **510** refused. Else M&D PIN setup, wrap seed, persist 1184-byte pk in NV |
| 2 | KEYGEN | Empty or occupied ECC slot 0: generate / PIN-replace P-256. Empty-slot KEYGEN still requires a well-formed PIN (owner-pinned TLS is the first-enroll gate; Tropic verifies the PIN only when replacing an occupied ECC slot). |
| 8 | PAIRING | PIN + body slot 1–3. Success: `PAIRING ok`. Factory SH0 invalidation is irreversible on silicon. Pairing private key stays in MCU NV. |

---

## USB dump status

| Status | Meaning |
| --- | --- |
| 0 ok | Body is the typed payload |
| 1 err | Command failed (no Tropic/TLS/auth subtype) |
| 2 empty | Slot / table unoccupied (PUB / KEM PUB) |
| 3 refused | `OWNER SET` begin when already enrolled |

ASCII errors are only `failed`. PING/INFO/HELP stay ASCII on success.

---

## Status strings (MANAGE TLS only)

USB does not print Tropic `SLOT_OCC` / `NOT_READY` / `TAMPERED` / `DEVICE_TAMPERED`. Those exist only as MANAGE reply codes (`SeManage`) after owner-pinned TLS.

PEER ADD/REMOVE status strings are MANAGE TLS `msg` fields, not USB.

---

## HELP output (silicon)

```text
HELP
PROVISION <unix>
ENCRYPT <unix>
DECRYPT <unix>
MANAGE <unix>
OWNER SET
PEER LIST
CLIENT HASH
CLIENT CSR
TROPIC PING
TROPIC INFO
TROPIC PUB
TROPIC KEM PUB
TROPIC OTP LEFT
```

Host adds `QUIT`.

---

## NSC map

Console handlers call these entries ([se_tls_nsc.h](../Secure_nsclib/se_tls_nsc.h)):

| Console | NSC |
| --- | --- |
| `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE` | `SECURE_TlsStart_nsc_call(mode, unix)` |
| `OWNER SET` | `SECURE_OwnerBegin_nsc_call` then unsigned USB blob |
| `PEER LIST` | `SECURE_PeerGet_nsc_call` |
| `CLIENT HASH` | `SECURE_TropicClientHash_nsc_call` |
| `CLIENT CSR` | `SECURE_ClientCsr_nsc_call` |
| `TROPIC OTP LEFT` | `SECURE_TropicOtpLeft_nsc_call` |
| `TROPIC PING` … | `SECURE_TropicPing/Info/Pub/KemPub/OtpLeft_nsc_call`. Failures collapse to ERR; empty PUB / KEM PUB is dump empty. |
| Armed USB RX/TX | `SECURE_UsbRx_nsc_call` / `SECURE_UsbTx_nsc_call` / `SECURE_UsbService_nsc_call` |
| Debug / dump | `SECURE_UsbLog_nsc_call` / `SECURE_UsbDump_nsc_call` |
