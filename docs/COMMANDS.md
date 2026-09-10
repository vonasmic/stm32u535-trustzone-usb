# USB console commands

Authoritative tables live in [NonSecure/Core/Src/tls_usb_io.c](../NonSecure/Core/Src/tls_usb_io.c). Host `se_host` compiles that same file over a PTY.

TLS framing after arming: **[COMMUNICATION.md](COMMUNICATION.md)**. Tropic slots: **[TROPIC.md](TROPIC.md)**. How to run: **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

---

## Parsing

| Rule | USB CDC | Host `se_host` |
| --- | --- | --- |
| Line end | `\n` (`\r` ignored) | Same (PTY + stdin) |
| Max line | **160** chars | **160** chars (same parser) |
| Whitespace | Trim spaces/tabs | Same |
| Match | Case-sensitive prefix; optional spaces/tabs/`=` after the name | Same |
| Empty line | Ignored | Ignored |
| Unknown | `unknown command` | `unknown command` |

`HELP` prints every `usage` string. `?` is an alias (not listed in HELP). Stop `se_host` with Ctrl-C (unlinks the PTY).

There is **no** `TIME=` command. `SECURE_SetUnixTime_nsc_call` exists on the NSC API but the console never calls it. Clock + TLS arm happen together on `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE <unix>`.

---

## PIN / owner policy

| Context | On the 160-char ASCII line? |
| --- | --- |
| `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE` | **Never** — PIN (when used) is only inside TLS |
| `HELP` / `PING` / `INFO` / `PUB` / `CLIENT HASH` / `KEM PUB` / `PEER LIST` / `SIGN` / `PAIRING` / empty-slot `KEYGEN` | **No PIN** (unsigned). `PAIRING y` prints the host X25519 priv+pub; `PAIRING LOAD` puts that backup on the line |
| Occupied `TROPIC KEYGEN`, `TROPIC KEM INIT`, `PEER ADD` / `REMOVE`, `CREDS *`, `OWNER REPLACE` | USB prints `use MANAGE <unix>`. Command + PIN (ASCII digits, same bytes as ENCRYPT) + body stream over owner-pinned TLS. **No ML-DSA.** |
| `OWNER SET` | Unsigned USB blob (password + SPKI + optional device cert/key + SAE CA). First-wins |

Tropic PIN (KEM / KEYGEN replace / PEER / ENCRYPT): **4–8** ASCII digits. The same bytes are used on MANAGE and on ENCRYPT/DECRYPT (`'9','8','7','6'`, not nibble values).

Reset password: ASCII printable `0x20–0x7E`, **min 8, max 64**. Hash is `SHA-384(secure_dwk || password)`. Only this password can `OWNER REPLACE` (over MANAGE).

MANAGE TLS request (one per session, unsigned):

```text
u8 cmd | u8 pin_len | pin[pin_len] | u16le body_len | body[body_len]
```

Reply: `u8 status | u16le msg_len | msg`. Cmd 1=KEM INIT, 2=KEYGEN, 3=PEER ADD, 4=PEER REMOVE, 5=CREDS SAE, 6=CREDS DEVICE, 7=OWNER REPLACE. PIN length is 0 for CREDS and OWNER REPLACE.

---

## Top-level commands

| Syntax | USB | Host | Parameters | What it does |
| --- | --- | --- | --- | --- |
| `HELP` | yes | yes | — | Print `commands:` plus all usage lines |
| `?` | alias | alias | — | Same as HELP |
| `PROVISION <unix>` | yes | yes | decimal Unix UTC, ≠ 0 | Arm TLS mode **1**. Refuses until owner + device cert + wrapped SK + SAE CA + NV ML-KEM pk are present. Verify SAE CA from FLASH_CREDS. After handshake: signed uplink v4, then QKD downlink v2 into R-MEM. **mTLS** (device cert). |
| `ENCRYPT <unix>` | yes | yes | same | Arm TLS mode **2**. Refuses until owner + device cert + wrapped SK. **mTLS**; pin the TLS peer leaf SPKI to the enrolled **owner** key. Wait TLS: PIN + plaintext; reply XOR ciphertext with pad slots. |
| `DECRYPT <unix>` | yes | yes | same | Arm TLS mode **3**. Same mTLS + owner pin as ENCRYPT. Wait TLS: PIN + encrypt reply; reply plaintext chunks (no slots). |
| `MANAGE <unix>` | yes | yes | same | Arm TLS mode **4**. Refuses until owner SPKI is present. Owner-pinned TLS **without** a device client cert. After handshake: one unsigned command (see above), status reply, shutdown. |
| `OWNER SET` | yes | yes | then unsigned blob | First USB wins if the owner slot is empty; else refuse. Blob may include device cert/key and SAE CA. |
| `PEER LIST` | yes | yes | — | Print each NV peer, or `PEER list empty` |
| `CLIENT HASH` | yes | yes | — | Print `client hash:` + 96 hex digits: `SHA384(device_cert_spki \|\| ecc_pub)`, same as provision uplink item 2 |
| `TROPIC …` | yes | yes | subcommand | Dispatch to the TROPIC table |

### `<unix>`

- Decimal (`strtoul` base 10), **must be non-zero**, no extra tokens. Else `bad unix time`.
- Silicon and `se_host`: `SECURE_TlsStart_nsc_call` → `se_time_set_unix` then `se_tls_arm`. Accepted range **1704067200–2145916800** (2024-01-01 … 2038-01-01). If the value is behind the TIME floor, firmware keeps the floor (`TIME behind floor, using unix=…`). Host wolfSSL still uses the **process clock** (no `TIME_OVERRIDES`).

On USB (silicon or PTY), success sets `s_tls_armed`: further RX is opaque TLS until `SECURE_USB_IDLE`, error, disconnect, DTR off, or RX overflow.

TLS arm failure: `TLS start failed`.

---

## `PEER` commands

Runtime nickname + `SHA384(peer SPKI)` list in sealed MCU NV. Provision uplink items 7+ are this table (hash then name per peer). Cap **8**. Nickname unique (case-sensitive). The same hash under two names is allowed. Duplicate nickname is refused — to change a hash, `REMOVE` then `ADD`. An empty list is valid (uplink then has **7** items).

USB line max is **144** chars. Certs and PIN-gated commands use MANAGE TLS application data, not the ASCII line.

| Syntax | Success | Errors |
| --- | --- | --- |
| `PEER ADD` (MANAGE cmd 3) | status 0, `PEER ADD ok` | PIN fail, nickname exists, list full |
| `PEER REMOVE` (MANAGE cmd 4) | status 0, `PEER REMOVE ok` | PIN fail, not found |
| `PEER LIST` | one line per peer: `<name> <96-hex-lowercase>`, or `PEER list empty` | `DEVICE_TAMPERED` / `PEER command failed` |

- Tropic PIN is ASCII digits inside the unsigned MANAGE request
- `<name>`: 1–16 bytes, printable ASCII `[A-Za-z0-9_.-]`
- Hash: 48-byte SHA-384 of the peer SPKI
- USB `PEER ADD` / `REMOVE`: `unknown PEER command` (dumb serial cannot add peers)

`PEER LIST` goes through `SECURE_PeerGet_nsc_call`.

---

## `TROPIC` subcommands

Two-step commands: `PAIRING` still probes then `y` (or `LOAD` after a reflash). Occupied `KEYGEN` and `KEM INIT` print `use MANAGE <unix>`. Empty-slot `KEYGEN` is one-shot and unsigned.

| Syntax | Two-step | Parameters | Firmware |
| --- | --- | --- | --- |
| `TROPIC PING` | no | — | `lt_ping("hello")`. Success: `TROPIC ping ok` |
| `TROPIC INFO` | no | — | Chip ID, RISC-V/SPECT FW versions, cert-store lengths |
| `TROPIC PUB` | no | — | Read P-256 public key from ECC slot 0; hex-dump 64 bytes |
| `TROPIC KEYGEN` | no / MANAGE | none | If ECC slot 0 empty: generate P-256. If occupied: `use MANAGE <unix>` then unsigned PIN on MANAGE |
| `TROPIC SIGN <64-hex>` | no | exactly **64 hex chars** (32-byte hash) | ECDSA; hex-dump 64-byte `r\|\|s`. Bad length/hex: `bad TROPIC SIGN hash` |
| `TROPIC PAIRING <1-3>` | **probe** | slot decimal **1–3** | Warnings only; no Tropic write. Prints `TROPIC PAIRING n y` |
| `TROPIC PAIRING <1-3> y` | **confirm** | slot + `y` or `Y` | Generate X25519, write pub to pairing slot, persist priv in MCU NV, invalidate factory SH0, re-session. Prints `TROPIC PAIRING KEY n <64-hex-priv> <64-hex-pub>` for host backup |
| `TROPIC PAIRING <1-3> LOAD <64-hex-priv> <64-hex-pub>` | no | slot + priv + pub | Restore MCU NV after a reflash. No Tropic write / no SH0 invalidate. Verifies X25519(pub)=priv, then L3 with that slot |
| `TROPIC KEM INIT` | **MANAGE** | USB prints `use MANAGE <unix>` | **User enrollment** over unsigned MANAGE. Occupied R-MEM **510** refused. Else M&D PIN setup, wrap seed, persist 1184-byte pk in NV |
| `TROPIC KEM PUB` | no | — | Dump NV ML-KEM pk (or RAM cache). Else `ML-KEM pk missing…` / `TROPIC not ready` |
| `TROPIC OTP LEFT` | no | — | Remaining / half-capacity pad kilobytes (floor, 1024). No PIN. Prints `OTP left enc=A/B kb dec=C/D kb`. Unprovisioned is `0/capacity`, not `TROPIC not ready`. Tamper as usual |

Unknown TROPIC: `unknown TROPIC command`. Unknown KEM sub: `unknown TROPIC KEM command`.

### PAIRING warnings (probe)

```text
WARNING: PAIRING writes a new X25519 access key to pairing slot N
WARNING: factory SH0 (pairing slot 0) will be INVALIDATED
WARNING: irreversible on real silicon; resend with y to continue
TROPIC PAIRING N y
```

Slot outside 1–3: `TROPIC PAIRING slot must be 1-3`. Confirm token not `y`/`Y`/`LOAD`: `bad TROPIC PAIRING (expected y or LOAD)`. Bad LOAD hex: `bad TROPIC PAIRING LOAD key`. Success: `TROPIC PAIRING LOAD ok`.

---

## Status strings (after a TROPIC command)

Mapped in NonSecure / `se_host` from NSC codes (`SECURE_TROPIC_*` in [se_tls_nsc.h](../Secure_nsclib/se_tls_nsc.h)):

| Code | Console |
| --- | --- |
| `OK` (0) | Silent at the parser; Secure may log details |
| `SLOT_OCC` (3) | `TROPIC slot occupied` |
| `NOT_READY` (4) | `TROPIC not ready` |
| `TAMPERED` (5) | `DEVICE_TAMPERED` |
| other | `TROPIC command failed` |

Parser errors (examples): `bad unix time`, `bad TROPIC KEYGEN`, `bad TROPIC KEM INIT`, `OWNER SET refused`, `use MANAGE <unix>`, `bad TROPIC PAIRING slot`, `bad TROPIC PAIRING LOAD key`.

### PEER status strings

Mapped from `SECURE_PEER_*` (USB) / `se_nv_peer_*` (host). These codes do **not** reuse TROPIC slot values:

| Code | Console |
| --- | --- |
| `OK` (0) | `PEER ADD ok` / `PEER REMOVE ok` |
| `EXISTS` (6) | `PEER nickname exists` |
| `NOT_FOUND` (7) | `PEER not found` |
| `FULL` (8) | `PEER list full` |
| `PIN_FAIL` (9) | `PEER PIN fail` |
| `TAMPERED` (5) | `DEVICE_TAMPERED` |
| other | `PEER command failed` |

Secure detail lines (USB debug, before the first TLS record): `TROPIC session ok (pairing slot N)`, `TROPIC factory SH0 invalidated`, …

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
TROPIC PING
TROPIC INFO
TROPIC PUB
TROPIC KEYGEN
TROPIC SIGN <64-hex>
TROPIC PAIRING <1-3> [y|LOAD <priv> <pub>]
TROPIC KEM INIT
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
| `TROPIC OTP LEFT` | `SECURE_TropicOtpLeft_nsc_call` |
| `TROPIC PING` … `PAIRING` | `SECURE_Tropic*_nsc_call` |
| `TROPIC PAIRING … LOAD` | `SECURE_TropicPairingLoad_nsc_call` |
| Armed USB RX/TX | `SECURE_UsbRx_nsc_call` / `SECURE_UsbTx_nsc_call` / `SECURE_UsbService_nsc_call` |
| Debug log | `SECURE_UsbLog_nsc_call` |
