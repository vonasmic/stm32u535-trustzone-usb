# USB console commands

Authoritative tables live in [NonSecure/Core/Src/tls_usb_io.c](../NonSecure/Core/Src/tls_usb_io.c). Host `se_host` compiles that same file over a PTY.

USB frames and TLS after arming: **[COMMUNICATION.md](COMMUNICATION.md)**. Tropic slots: **[TROPIC.md](TROPIC.md)**. How to run: **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

The device is a TLS client. **SAE** is the peer for `PROVISION`. **USER** (UserApp) is the peer for `ENCRYPT` / `DECRYPT` / `MANAGE`. UserApp is not an SAE.

---

## Parsing

CDC is framed. Command text is the payload of a type `0x00` frame, not a raw `\n` line. Wire format: **[COMMUNICATION.md](COMMUNICATION.md)**. Host `se_host` compiles the same NonSecure parser over a PTY, so the PTY also carries frames.


| Rule       | USB CDC / PTY                                                  | Meaning                     |
| ---------- | -------------------------------------------------------------- | --------------------------- |
| Frame      | magic `0x6767`, type `0x00`, length, payload                   | Console command or reply    |
| Max command | **160** bytes in the `0x00` payload                           | Same parser on `se_host`    |
| Whitespace | Trim spaces/tabs                                               | Same                        |
| Match      | Case-sensitive prefix; optional spaces/tabs/`=` after the name | Same                        |
| Empty payload | Ignored                                                     | Ignored                     |
| Unknown    | `failed` (type `0x00`)                                         | `failed`                    |
| During TLS / OWNER SET | type `0x00` is queued (4 deep) and run after IDLE | `CLIENT CSR` after MANAGE   |
| Type `0x01` | Secure payload: TLS, or the OWNER SET blob after begin `ok`  | Not parsed as a command     |


`HELP` prints every `usage` string. `?` is an alias (not listed in HELP). Stop `se_host` with Ctrl-C (unlinks the PTY).

Clock + TLS arm happen together on `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE <unix>`.

---



## PIN / owner policy


| Context                                                                                   | On the 160-char ASCII line?                                                                            |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE`                                            | **Never** — PIN (when used) is only inside TLS                                                         |
| `HELP` / `PING` / `INFO` / `PUB` / `CLIENT HASH` / `CLIENT CSR` / `KEM PUB` / `PEER LIST` | Unsigned, read-only                                                                                    |
| MANAGE KEYGEN / KEM INIT / PEER ADD / REMOVE / CREDS / OWNER REPLACE / PAIRING / PAIRING LOAD | Unsigned request over owner-pinned TLS. PIN only on KEM INIT. **No ML-DSA.** |
| `OWNER SET`                                                                               | Unsigned USB blob (password + SPKI + optional SAE CA). First-wins. Device ML-DSA is generated on-chip. |


Tropic PIN (KEM INIT / ENCRYPT / DECRYPT): **8–16** printable ASCII (`0x20–0x7E`). The same bytes are used on MANAGE KEM INIT and on ENCRYPT/DECRYPT.

Reset password: ASCII printable `0x20–0x7E`, **min 8, max 64**. Hash is `SHA-384(secure_dwk || password)`. Only this password can `OWNER REPLACE` (over MANAGE).

MANAGE TLS request (one per session, unsigned). Commands and bodies: **[MANAGE commands](#manage-commands)**.

```text
u8 cmd | u8 pin_len | pin[pin_len] | u16le body_len | body[body_len]
```

Reply: `u8 status | u16le msg_len | msg` (ASCII, no NUL on the wire, max 160). PIN length is 0 except on KEM INIT.

---



## Top-level commands


| Syntax             | USB   | Host  | Parameters            | What it does                                                                                                                                                                                                                                      |
| ------------------ | ----- | ----- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HELP`             | yes   | yes   | —                     | Print `commands:` plus all usage lines                                                                                                                                                                                                            |
| `?`                | alias | alias | —                     | Same as HELP                                                                                                                                                                                                                                      |
| `PROVISION <unix>` | yes   | yes   | decimal Unix UTC, ≠ 0 | Arm TLS mode **1** (**SAE** peer). Refuses until owner + device cert + device SK + SAE CA + NV ML-KEM pk are present. Verify SAE CA from FLASH_CREDS. After handshake: signed uplink v4, then QKD downlink v2 into R-MEM. **mTLS** (device cert). |
| `ENCRYPT <unix>`   | yes   | yes   | same                  | Arm TLS mode **2** (**USER** peer). Refuses until owner + device cert + device SK. **mTLS**; pin the TLS peer leaf SPKI to the enrolled **owner** key. Wait TLS: PIN + plaintext; reply XOR ciphertext with pad slots.                            |
| `DECRYPT <unix>`   | yes   | yes   | same                  | Arm TLS mode **3** (**USER** peer). Same mTLS + owner pin as ENCRYPT. Wait TLS: PIN + encrypt reply; reply plaintext chunks (no slots).                                                                                                           |
| `MANAGE <unix>`    | yes   | yes   | same                  | Arm TLS mode **4** (**USER** peer). Refuses until owner SPKI is present. Owner-pinned TLS **without** a device client cert. After handshake: one unsigned command ([MANAGE commands](#manage-commands)), status reply, shutdown.                  |
| `OWNER SET`        | yes   | yes   | then type `0x01` blob | First USB wins if the owner slot is empty; else type `0x00` `refused`. Begin and apply `ok`/`failed` are type `0x00` ASCII. The blob is type `0x01`. Blob is password + owner SPKI + optional SAE CA. Device ML-DSA is generated on-chip. |
| `PEER LIST`        | yes   | yes   | —                     | Dump: `u8 count | (u8 nlen | name | 48 hash)*`                                                                                                                                                                                                    |
| `CLIENT HASH`      | yes   | yes   | —                     | Dump 48-byte `SHA384(device_cert_spki || ecc_pub)`                                                                                                                                                                                                |
| `CLIENT CSR`       | yes   | yes   | —                     | Dump raw ML-DSA-44 pub (1312 B)                                                                                                                                                                                                                   |
| `TROPIC …`         | yes   | yes   | subcommand            | Flat table: PING/INFO/PUB/KEM PUB/OTP STATUS                                                                                                                                                                                                      |




### `<unix>`

- Decimal (`strtoul` base 10), **must be non-zero**, no extra tokens. Else `failed`.
- Silicon and `se_host`: `SECURE_TlsStart_nsc_call` → `se_time_set_unix` then `se_tls_arm`. Accepted range **1704067200–2145916800** (2024-01-01 … 2038-01-01). If the value is behind the TIME floor, firmware keeps the floor (no USB notice). Host wolfSSL still uses the **process clock** (no `TIME_OVERRIDES`).

On USB (silicon or PTY), success sets `s_tls_armed`: further type `0x01` is the TLS byte stream until `SECURE_USB_IDLE`, error, disconnect, DTR off, or RX overflow. A type `0x00` command that arrives in that window is queued.

TLS arm failure: type `0x00` line `failed` (no Tropic/TLS/auth taxonomy).

---



## MANAGE commands

Not USB lines. `HELP` prints only `MANAGE <unix>`. After that arms TLS mode **4**, the owner peer sends **one** request from the framing above, the device replies, and TLS shuts down. Codec: [se_manage.h](../Secure/Core/Inc/se_manage.h) and Java `fel.cvut.se.SeManage`. UserApp sends these from `INIT LAB` / `INIT PROD` / `PEER` / `INSERT SIGNED CSR` / `REPLACE` ([UserApp README](../../JAVA_APPS/src/UserApp/README.md)); a raw `MANAGE` line at that prompt is refused.

Tropic PIN is only cmd 1 (KEM INIT): **8–16** printable ASCII (`0x20–0x7E`). A missing or ill-formed PIN is status **11** (`PIN required` / `bad PIN`) before Tropic runs. Every other command rejects a non-zero PIN length (`bad KEYGEN`, `bad PEER ADD`, `bad PAIRING`, …).


| Cmd | Name              | Body                                                          | Success `msg`          |
| --- | ----------------- | ------------------------------------------------------------- | ---------------------- |
| 1   | KEM INIT          | empty                                                         | `KEM INIT ok`          |
| 2   | KEYGEN            | empty                                                         | `KEYGEN ok`            |
| 3   | PEER ADD          | `u8 nlen | name | 48-byte hash`                               | `PEER ADD ok`          |
| 4   | PEER REMOVE       | `u8 nlen | name`                                              | `PEER REMOVE ok`       |
| 5   | CREDS SAE         | SAE CA DER (1–4000 bytes)                                     | `CREDS SAE ok`         |
| 6   | INSERT SIGNED CSR | `u16le cert_len | cert DER`                                   | `INSERT SIGNED CSR ok` |
| 7   | OWNER REPLACE     | `u8 old_len | old | u8 new_len | new | u16le spki_len | spki` | `OWNER REPLACE ok`     |
| 8   | PAIRING           | one byte, slot **1–3**                                        | `PAIRING ok <slot> <64 hex priv> <64 hex pub>` |
| 9   | PAIRING LOAD      | `u8 slot | 32-byte priv | 32-byte pub`                        | `PAIRING LOAD ok`      |


Unknown `cmd` is status **10**, `bad command`. A non-empty body on KEM INIT or KEYGEN is status **11** (`bad KEM INIT` / `bad KEYGEN`).


| Cmd               | What it does                                                                                                                                                                                       | Notable failures                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| KEM INIT          | Occupied R-MEM **510** is refused. Else M&D PIN setup, wrap the seed, persist the 1184-byte ML-KEM pk in NV.                                                                                       | **3** `slot occupied`. **1** `KEM INIT failed`.                                                |
| KEYGEN            | ECC slot 0. Empty: generate P-256. Occupied: erase and generate.                                                                                                                                   | **1** `KEYGEN failed`. **11** `bad KEYGEN`.                                                    |
| PEER ADD          | Nickname + `SHA384(peer SPKI)` into MCU NV. Name rules are under [PEER](#peer-commands).                                                                                                           | **6** `PEER nickname exists`. **8** `PEER list full`. **11** `bad PEER ADD`.                   |
| PEER REMOVE       | Delete by nickname.                                                                                                                                                                                | **7** `PEER not found`. **11** `bad PEER REMOVE`.                                              |
| CREDS SAE         | Store the SAE CA DER in FLASH_CREDS.                                                                                                                                                               | **11** `bad CREDS SAE`. **1** `CREDS SAE failed`.                                              |
| INSERT SIGNED CSR | Cert DER only. Requires the on-chip device SK. The leaf must match the on-chip ML-DSA public key.                                                                                                  | **4** `no device key`. **11** `bad INSERT SIGNED CSR`. **1** `INSERT SIGNED CSR failed`.       |
| OWNER REPLACE     | Reset password (not the Tropic PIN): **8–64** printable ASCII, same hash as [PIN / owner policy](#pin--owner-policy). Replaces the enrolled owner SPKI.                                            | Wrong current password: **12** `OWNER REPLACE failed`. **11** `bad OWNER REPLACE`.             |
| PAIRING           | X25519 into pairing slot 1–3. The private key is stored in MCU NV and returned once in the MANAGE reply (UserApp writes `pairing-key.hex`, does not print it). On silicon, factory SH0 invalidation is irreversible. An occupied slot is refused. | **3** `slot occupied`. **11** `bad PAIRING`. **1** `PAIRING failed`. |
| PAIRING LOAD      | Restore a previously exported host pairing key into MCU NV (no Tropic write). Refused if NV already has a pairing key. After a reflash: `OWNER SET`, then this command. Restores L3 only; pads and device identity stay lost. | **11** `bad PAIRING LOAD`. **1** `pairing present` / `PAIRING LOAD failed`. |




### Reply status

`msg` is the device string (max 160). USB never prints these codes.


| Status | Name           | Typical `msg`                 |
| ------ | -------------- | ----------------------------- |
| 0      | OK             | command `… ok`                |
| 1      | ERR            | `… failed` / `command failed` |
| 3      | SLOT_OCC       | `slot occupied`               |
| 4      | NOT_READY      | `no device key` / `not ready` |
| 5      | TAMPERED       | `DEVICE_TAMPERED`             |
| 6      | PEER_EXISTS    | `PEER nickname exists`        |
| 7      | PEER_NOT_FOUND | `PEER not found`              |
| 8      | PEER_FULL      | `PEER list full`              |
| 9      | PIN_FAIL       | `PIN fail`                    |
| 10     | BAD_CMD        | `bad command`                 |
| 11     | PARSE          | `bad …` / `PIN required`      |
| 12     | PW_FAIL        | `OWNER REPLACE failed`        |


There is no status **2**.

---

Console replies (PUB, CSR, HASH, KEM PUB, OTP STATUS, PEER LIST, OWNER SET)
are **ASCII in type `0x00` frames**. The host drains until idle and prints.
Binary payloads are hex lines; occupancy / refuse use the words `empty` /
`refused`; hard errors are `failed`. The OWNER SET blob is type `0x01`; begin
and apply status stay type `0x00`.

---



## `PEER` commands

Runtime nickname + `SHA384(peer SPKI)` list in MCU NV. Provision uplink items 7+ are this table (hash then name per peer). Cap **8**. Nickname unique (case-sensitive). The same hash under two names is allowed. Duplicate nickname is refused — to change a hash, `REMOVE` then `ADD`. An empty list is valid (uplink then has **7** items).

PEER ADD/REMOVE use MANAGE TLS application data, not the ASCII line. Bodies are in [MANAGE commands](#manage-commands).


| Syntax                       | Success                                   | Errors                               |
| ---------------------------- | ----------------------------------------- | ------------------------------------ |
| `PEER ADD` (MANAGE cmd 3)    | status 0, `PEER ADD ok`                   | nickname exists, list full |
| `PEER REMOVE` (MANAGE cmd 4) | status 0, `PEER REMOVE ok`                | not found                  |
| `PEER LIST`                  | ASCII lines `name` + hex hash, or `empty` | `failed`                             |


- `<name>`: 1–16 bytes, printable ASCII `[A-Za-z0-9_.-]`
- Hash: 48-byte SHA-384 of the peer SPKI

`PEER LIST` goes through `SECURE_PeerGet_nsc_call`.

---



## `TROPIC` subcommands


| Syntax              | Parameters | Firmware                                               |
| ------------------- | ---------- | ------------------------------------------------------ |
| `TROPIC PING`       | —          | `lt_ping("hello")`. Success ASCII: `TROPIC ping ok`    |
| `TROPIC INFO`       | —          | Chip ID / FW ASCII (success only)                      |
| `TROPIC PUB`        | —          | Hex P-256 pub, or `empty`                              |
| `TROPIC KEM PUB`    | —          | Hex NV ML-KEM pk, or `empty`                           |
| `TROPIC OTP STATUS` | —          | `enc=A/B kb dec=C/D kb`. Unprovisioned is `0/capacity` |


Unknown USB lines: `failed`. NSC Tropic results are only ok / err (plus empty for unoccupied PUB / KEM PUB). KEM INIT, KEYGEN, PAIRING, and PAIRING LOAD run as MANAGE cmds 1, 2, 8, and 9 — see [MANAGE commands](#manage-commands).

---



## Console status words


| Word        | Meaning                                             |
| ----------- | --------------------------------------------------- |
| (hex lines) | ok body for PUB / CSR / HASH / KEM PUB              |
| `ok`        | OWNER SET begin/apply with no body                  |
| `empty`     | Slot / table unoccupied (PUB / KEM PUB / PEER LIST) |
| `refused`   | `OWNER SET` begin when already enrolled             |
| `failed`    | Command failed (no Tropic/TLS/auth subtype)         |


PING/INFO/HELP stay multi-line ASCII on success.

---



## Status strings (MANAGE TLS only)

USB does not print Tropic `SLOT_OCC` / `NOT_READY` / `TAMPERED` / `DEVICE_TAMPERED`. Those exist only as MANAGE reply codes after owner-pinned TLS. The byte and `msg` table is under [MANAGE commands](#manage-commands).

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
TROPIC OTP STATUS
```

Host adds `QUIT`.

---



## NSC map

Console handlers call these entries ([se_tls_nsc.h](../Secure_nsclib/se_tls_nsc.h)):


| Console                                        | NSC                                                                                                                   |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `PROVISION` / `ENCRYPT` / `DECRYPT` / `MANAGE` | `SECURE_TlsStart_nsc_call(mode, unix)`                                                                                |
| `OWNER SET`                                    | `SECURE_OwnerBegin_nsc_call` then type `0x01` blob                                                                    |
| Armed USB RX/TX                                | type `0x01` payload → `SECURE_UsbRx_nsc_call` / `SECURE_UsbTx_nsc_call` / `SECURE_UsbService_nsc_call`              |
| `PEER LIST`                                    | `SECURE_PeerGet_nsc_call`                                                                                             |
| `CLIENT HASH`                                  | `SECURE_TropicClientHash_nsc_call`                                                                                    |
| `CLIENT CSR`                                   | `SECURE_ClientCsr_nsc_call`                                                                                           |
| `TROPIC OTP STATUS`                            | `SECURE_TropicOtpLeft_nsc_call`                                                                                       |
| `TROPIC PING` …                                | `SECURE_TropicPing/Info/Pub/KemPub/OtpLeft_nsc_call`. Failures collapse to ERR; empty PUB / KEM PUB is ASCII `empty`. |
| Console ASCII                                  | `SECURE_UsbLog_nsc_call` (TX wrapped as type `0x00` when idle)                                                      |


