# USB console commands

Authoritative tables live in [NonSecure/Core/Src/tls_usb_io.c](../NonSecure/Core/Src/tls_usb_io.c). Host `se_host` uses the same names ([host/tropic_model/se_host_main.c](../host/tropic_model/se_host_main.c)).

TLS framing after arming: **[COMMUNICATION.md](COMMUNICATION.md)**. Tropic slots: **[TROPIC.md](TROPIC.md)**. How to run: **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

---

## Parsing

| Rule | USB CDC | Host `se_host` |
| --- | --- | --- |
| Line end | `\n` (`\r` ignored) | `\n` / `\r` stripped |
| Max line | **96** chars | **4096** chars |
| Whitespace | Trim spaces/tabs | Same |
| Match | Case-sensitive prefix; optional spaces/tabs/`=` after the name | Same |
| Empty line | Ignored | Ignored |
| Unknown | `unknown command` | `unknown command` |

`HELP` prints every `usage` string. `?` is an alias (not listed in HELP). Host also has `QUIT` / `EXIT`.

There is **no** `TIME=` command. `SECURE_SetUnixTime_nsc_call` exists on the NSC API but the console never calls it. Clock + TLS arm happen together on `PROVISION` / `ENCRYPT` / `DECRYPT <unix>`.

---

## PIN policy

| Context | PIN on USB/console? |
| --- | --- |
| `PROVISION` / `ENCRYPT` / `DECRYPT` | **Never** — PIN is only inside TLS after mTLS (4–8 bytes) |
| `TROPIC KEYGEN <pin>` | **Yes** (`<pin>` decimal digits) — occupied-slot replace only |
| `TROPIC KEYGEN` (empty slot) | **No** |
| `TROPIC KEM INIT … CONFIRM` | **Yes** (`<pin>` decimal digits, converted to bytes) |
| `TROPIC KEM INIT` (probe) | Token required by syntax but **not used** |

`<pin>` (KEM INIT / KEYGEN replace): **4–8** digits `0-9` only. Each digit becomes one PIN byte (`9876` → `09 08 07 06`).

---

## Top-level commands

| Syntax | USB | Host | Parameters | What it does |
| --- | --- | --- | --- | --- |
| `HELP` | yes | yes | — | Print `commands:` plus all usage lines |
| `?` | alias | alias | — | Same as HELP |
| `PROVISION <unix>` | yes | yes | decimal Unix UTC, ≠ 0 | Arm TLS mode **1**. Verify SAE application CA (`fw_root_ca_der`). After handshake: signed uplink v3, then QKD downlink v2 into R-MEM. |
| `ENCRYPT <unix>` | yes | yes | same | Arm TLS mode **2**. Verify client CA (`fw_client_ca_der`) and pin the peer to `fw_user_spki` (home-PC user cert). Wait TLS: PIN + plaintext; reply XOR ciphertext with pad slots. |
| `DECRYPT <unix>` | yes | yes | same | Arm TLS mode **3**. Same CA + user-key pin as ENCRYPT. Wait TLS: PIN + encrypt reply; reply plaintext chunks (no slots). |
| `TROPIC …` | yes | yes | subcommand | Dispatch to the TROPIC table |
| `QUIT` | no | yes | — | Exit `se_host` |
| `EXIT` | no | alias | — | Same as QUIT |

### `<unix>`

- Decimal (`strtoul` base 10), **must be non-zero**, no extra tokens. Else `bad unix time`.
- Silicon: `SECURE_TlsStart_nsc_call` → `se_time_set_unix` then `se_tls_arm`. Accepted range **1704067200–2145916800** (2024-01-01 … 2038-01-01). If the value is behind the MCU TIME floor, firmware keeps the floor (`TIME behind floor, using unix=…`).
- Host: parsed and logged; wolfSSL uses the **process clock**.

On USB, success sets `s_tls_armed`: further RX is opaque TLS until `SECURE_USB_IDLE`, error, disconnect, DTR off, or RX overflow. Host runs one blocking session then returns to the prompt.

TLS arm failure: `TLS start failed`.

---

## `TROPIC` subcommands

Two-step commands: send the probe first. Confirm only when the probe says the slot is empty (`KEM INIT`) or after the pairing warnings (`PAIRING`). `KEYGEN` is one-shot.

| Syntax | Two-step | Parameters | Firmware |
| --- | --- | --- | --- |
| `TROPIC PING` | no | — | `lt_ping("hello")`. Success: `TROPIC ping ok` |
| `TROPIC INFO` | no | — | Chip ID, RISC-V/SPECT FW versions, cert-store lengths |
| `TROPIC PUB` | no | — | Read P-256 public key from ECC slot 0; hex-dump 64 bytes |
| `TROPIC KEYGEN` | no | none | If ECC slot 0 empty: generate P-256. If occupied: `TROPIC slot occupied` (send `KEYGEN <pin>`) |
| `TROPIC KEYGEN <pin>` | no | 4–8 decimal digits | Occupied: PIN check, erase slot 0, generate. Empty: generate (PIN unused). Wrong PIN: `TROPIC command failed` |
| `TROPIC SIGN <64-hex>` | no | exactly **64 hex chars** (32-byte hash) | ECDSA; hex-dump 64-byte `r\|\|s`. Bad length/hex: `bad TROPIC SIGN hash` |
| `TROPIC PAIRING <1-3>` | **probe** | slot decimal **1–3** | Warnings only; no Tropic write. Prints `TROPIC PAIRING n y` |
| `TROPIC PAIRING <1-3> y` | **confirm** | slot + `y` or `Y` | Generate X25519, write pub to pairing slot, persist priv in MCU NV, invalidate factory SH0, re-session |
| `TROPIC KEM INIT <pin>` | **probe** | pin required in syntax | If R-MEM **510** empty: `slot 510 empty; send KEM INIT <pin> CONFIRM`. Occupied: `TROPIC slot occupied`. Pin is **not** used on probe |
| `TROPIC KEM INIT <pin> CONFIRM` | **confirm** | pin + `CONFIRM` | Decimal digits `0-9` converted to PIN bytes; MAC-and-Destroy PIN setup, wrap 64-byte ML-KEM seed in slot 510, dump 1184-byte pk. `KEM INIT ok; embed fw_mlkem_pk and reflash` |
| `TROPIC KEM PUB` | no | — | Dump embedded `fw_mlkem_pk` or the RAM cache from this boot. Else `ML-KEM pk not embedded…` / `TROPIC not ready` |

Unknown TROPIC: `unknown TROPIC command`. Unknown KEM sub: `unknown TROPIC KEM command`.

### PAIRING warnings (probe)

```text
WARNING: PAIRING writes a new X25519 access key to pairing slot N
WARNING: factory SH0 (pairing slot 0) will be INVALIDATED
WARNING: irreversible on real silicon; resend with y to continue
TROPIC PAIRING N y
```

Slot outside 1–3: `TROPIC PAIRING slot must be 1-3`. Confirm token not `y`/`Y`: `bad TROPIC PAIRING (expected y)`.

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

Parser errors (examples): `bad unix time`, `bad TROPIC KEYGEN`, `bad TROPIC KEYGEN pin`, `bad TROPIC KEM INIT pin`, `bad TROPIC KEM INIT (expected CONFIRM)`, `bad TROPIC PAIRING slot`.

Secure detail lines (USB debug, before the first TLS record): `TROPIC session ok (pairing slot N)`, `TROPIC factory SH0 invalidated`, …

---

## HELP output (silicon)

```text
HELP
PROVISION <unix>
ENCRYPT <unix>
DECRYPT <unix>
TROPIC PING
TROPIC INFO
TROPIC PUB
TROPIC KEYGEN [<pin>]
TROPIC SIGN <64-hex>
TROPIC PAIRING <1-3> [y]
TROPIC KEM INIT <pin> [CONFIRM]
TROPIC KEM PUB
```

Host adds `QUIT`.

---

## NSC map

Console handlers call these entries ([se_tls_nsc.h](../Secure_nsclib/se_tls_nsc.h)):

| Console | NSC |
| --- | --- |
| `PROVISION` / `ENCRYPT` / `DECRYPT` | `SECURE_TlsStart_nsc_call(mode, unix)` |
| `TROPIC PING` … `PAIRING` | `SECURE_Tropic*_nsc_call` |
| Armed USB RX/TX | `SECURE_UsbRx_nsc_call` / `SECURE_UsbTx_nsc_call` / `SECURE_UsbService_nsc_call` |
| Debug log | `SECURE_UsbLog_nsc_call` |
