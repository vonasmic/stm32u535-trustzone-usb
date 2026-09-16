# Host TROPIC01 model and `se_host`

Linux (**WSL2**) only. This tree compiles the Secure Tropic/OTP/TLS sources against Tropic Square’s `model_server` instead of SPI silicon.

Two things live in `host/tropic_model/`:

| Binary | What it is | How you run it |
| --- | --- | --- |
| `test_a_session` … `test_k_owner`, `brick_lab` | Unit gates A–K (+ brick lab). Default CTest suite. | `ctest` or `./run_all.sh` |
| `se_host` | Simulated CDC device: firmware console + TLS over a PTY (`--tty`, default `/tmp/ttyACM0`). **Not** a CTest. | Start `model_server`, start Java, then `./se_host` |

Restarting the model restores a fresh chip. A real TROPIC01 does not.

---

## 1. Prepare (once)

From this firmware tree (`stm32u535-trustzone-usb/`; CubeIDE project name `SE_firmware`):

```bash
# TROPIC01 model_server + Python venv (tvl wheel)
bash libtropic/scripts/tropic01_model/install_linux.sh
source libtropic/scripts/tropic01_model/.venv/bin/activate

# wolfSSL 5.8.4 + ed25519 into host/tropic_model/_deps/
bash host/tropic_model/download_deps.sh
```

Needs `python3`, `curl` or `wget`, `sha256sum`, `cmake`, a C compiler, and `make`. CMake fails until `_deps/wolfssl` exists.

TLS credentials are enrolled at runtime (unsigned USB `OWNER SET`, then unsigned MANAGE TLS for KEM INIT / CREDS / PEER).

---

## 2. Build

```bash
cd host/tropic_model
mkdir -p build && cd build
cmake ..
make -j"$(nproc)"
```

Optional: after a Secure CubeIDE build, gate brick APIs out of the ELF:

```bash
cmake .. -DFIRMWARE_ELF=/path/to/SE_firmware_Secure.elf
# then ctest will also run firmware_nm_gate
# or:
bash ../check_firmware_nm.sh /path/to/SE_firmware_Secure.elf
```

---

## 3. Run the model tests (A–K)

Each test gets a **fresh** `model_server` on `127.0.0.1:28992` (`libtropic/scripts/tropic01_model/model_cfg.yml`). Run them serial:

```bash
cd host/tropic_model/build
source ../../libtropic/scripts/tropic01_model/.venv/bin/activate
ctest --output-on-failure -j1
```

Or from `host/tropic_model/build` after `make`:

```bash
bash ../run_all.sh
```

`run_all.sh` (and `run_one.sh` / `run_direct.sh` / `run_cd.sh`) resolve the firmware tree from the script location. `run_all.sh` rebuilds and runs groups A–K plus `brick_lab`.

| Group | Binary | What it gates |
| --- | --- | --- |
| A | `test_a_session` | Session / ping / info |
| B | `test_b_ecc` | ECC store, occupied-slot KEYGEN refuse, generate, PIN reroll, sign+verify |
| C | `test_c_rmem` | R-MEM erase-before-write keystream |
| D | `test_d_pin` | PIN setup/check, wrong-PIN consume, PIN-gated XOR, exhaustion |
| E | `test_e_mcounter` | Monotonic cursor advance-before-use |
| F | `test_f_mlkem` | ML-KEM provision / kem_ct / PIN-gated XOR |
| G | `test_g_ingest` | QKD ingest / pad store |
| H | `test_h_pairing` | Pairing-key install, SH0 invalidate, session uses new key, LOAD after NV wipe |
| I | `test_i_post_tls` | Encrypt TLS body / OTP reply with slot IDs, 100 KiB encrypt, remaining bytes, decrypt skip-ahead, almost-empty refuse |
| J | `test_j_peers` | PEER NV add/remove/list, uplink item count `7+2n` |
| K | `test_k_owner` | First-wins owner, REPLACE, unsigned MANAGE CREDS stream, NV ML-KEM |
| brick | `brick_lab` | Config writes + occupied SH0 (**model only**) |

Do **not** run `TROPIC KEYGEN`, `TROPIC PAIRING … y`, PIN setup, or R-MEM writes on physical silicon until A–E and H are green.

One test with a live model (same helper CTest uses):

```bash
bash ../run_with_model.sh ./test_a_session \
  ../../../libtropic/scripts/tropic01_model/model_cfg.yml
```

---

## 4. Run `se_host` (simulated ttyACM)

`se_host` is the host stand-in for the Secure firmware **device**. It talks to:

- TROPIC01 **model** at `127.0.0.1:28992` (hardcoded in `port_posix.c`)
- Host apps over a PTY, same console + TLS pipe as USB CDC on silicon

It does **not** open TCP to SAE or USER. Lab cable ownership is a JSON file plus
`scripts/lab-run.py` in the existing tmux `terminal` / `userapp` panes (restart
with new `USB_SERIAL_PORT` / `NODE_*`). Silicon uses one `/dev/ttyACM0`. The lab
stack runs **two** `se_host` processes:

| Path | Tropic model | Lab client |
| --- | --- | --- |
| `--tty /tmp/ttyACM-se1 --tropic-port 28992` | `model_server -p 28992` | CL 1 |
| `--tty /tmp/ttyACM-se2 --tropic-port 28993` | `model_server -p 28993` | CL 2 |

`--tty-sae none` disables the optional second symlink (default in `scripts/host.sh`).
UserApp and Terminal open whichever PTY their process env `USB_SERIAL_PORT` names.

### 4.1 Start the chip model

In a terminal with the model venv:

```bash
source libtropic/scripts/tropic01_model/.venv/bin/activate
model_server tcp -c libtropic/scripts/tropic01_model/model_cfg.yml -p 28992
# second chip:
model_server tcp -c libtropic/scripts/tropic01_model/model_cfg.yml -p 28993
```

Leave it running. Restart it to wipe Tropic + host RAM NV.

### 4.2 Start the Java Node

Start `JAVA_TLS_TEST` listening on `NODE_NATIVE_PORT` (default **11111**) when you are ready to provision.

### 4.3 Start the host device

```bash
cd host/tropic_model/build
./se_host --tty /tmp/ttyACM-se1 --tty-sae none --tropic-port 28992
./se_host --tty /tmp/ttyACM-se2 --tty-sae none --tropic-port 28993
```

Creates a PTY and the symlink. Stdin is mirrored onto the same RX path when no
slave is attached (bring-up). Ctrl-C unlinks the path.

Console commands match USB CDC on silicon (`HELP` lists names):

```text
HELP
TROPIC PING
TROPIC INFO
TROPIC PUB
CLIENT HASH
TROPIC KEYGEN
TROPIC SIGN <64-hex>
TROPIC KEM INIT
TROPIC KEM PUB
TROPIC PAIRING <1-3> [y|LOAD <priv> <pub>]
OWNER SET
PROVISION <unix>
ENCRYPT <unix>
DECRYPT <unix>
MANAGE <unix>
PEER LIST
TROPIC OTP LEFT
```

Typical bring-up (same order as silicon). `OWNER SET` waits for an unsigned USB blob. PIN-gated and identity-changing commands stream unsigned over `MANAGE <unix>` (no ML-DSA):

```text
OWNER SET
TROPIC KEYGEN
MANAGE <unix>    # KEM INIT
MANAGE <unix>    # PEER ADD
```

Leave TerminalBridge running with `USB_BRIDGE=1` and `USB_SERIAL_PORT` pointing
at the device PTY. In `./run-all.sh` the terminal pane wrapper starts that only
while lab owner is SAE.

Do not use plain `socat` (it forwards `DEBUG:<text>:DEBUG` into the TLS server). **Encrypt/decrypt**
is UserApp on the selected client PTY (`USER` in LabSwitchApp). PIN is
never a console argument for PROVISION/ENCRYPT/DECRYPT — it arrives on TLS.

On host, `TROPIC KEM INIT` persists the ML-KEM pub into NV. Tests may also fill `host_fw_mlkem_pk` as a fallback when NV is empty.

---

## 5. TLS framing (what Java must speak)

Uplink is **v4**. Item 6 (0-based) is the 1184-byte ML-KEM-768 public key. Java encapsulates from that item.

QKD downlink is **v2**: item 0 is `kem_ct` (1088 B), item 1 is `decrypt_half` (1 byte: 0 = first pad half for decrypt, 1 = second), then pad images.

After mTLS:

- **Provision** — host sends the signed session uplink, then stores the QKD downlink into R-MEM.
- **Encrypt** — UserApp writes PIN + `u32 msg_len` + plaintext. Reply is `u32 n_pads` then `u16 slot | u16 len | chunk` per pad.
- **Decrypt** — UserApp writes PIN plus that encrypt reply. Reply is `u32 n_pads` then `u16 len | chunk` (plaintext only, no slots).

---

## 6. What is firmware vs what the host substitutes

Shared Secure + NonSecure sources (linked into `se_host`):

`se_tropic.c`, `se_tropic_pin.c`, `se_tropic_rmem.c`, `se_tropic_mlkem.c`, `se_tropic_session.c`, `se_nv.c`, `se_creds.c`, `se_owner.c`, `se_auth.c`, `se_manage.c`, `se_cert_spki.c`, `se_tls_user.c`, `secure_qkd_ingest.c`, `secure_otp.c`, `secure_client_key.c`, `se_usb_tls.c`, `se_tls_client.c`, `se_tls_nsc_callable.c`, `wc_port_time.c`, `tls_usb_io.c`.

Host-only (do not exist on silicon):

| Piece | Firmware | Host |
| --- | --- | --- |
| Tropic transport | SPI1 (`se_tropic_port_stm32.c`) | TCP `127.0.0.1` (`port_posix.c`, `--tropic-port`) |
| Device AEAD key | HKDF from `secure_dwk` | Fixed 32-byte test key |
| ML-KEM pub | NV (KEM INIT) | NV first, else RAM `host_fw_mlkem_pk[]` |
| NV page | Secure flash page 22 (8 KB, dwk + plaintext) | 8 KB RAM |
| Creds page | Secure flash page 21 | 8 KB RAM |
| CDC bytes | USBX CDC ACM | PTY `--tty` (lab: `/tmp/ttyACM-se1` / `se2`) |
| SH0 | eng-sample unless `SE_TROPIC_SH0_PROD` | Forced prod0 (`host_libtropic_config.h`) |
| PIN rounds | silicon default 8 tries / 16 M&D slots | 4 tries / 8 slots (`SE_TROPIC_PIN_ROUNDS`) |

TLS I/O, console parsing, NSC veneers, and wall-clock floor are the firmware sources. Host wolfSSL still uses the process clock (`TIME_OVERRIDES` is firmware-only).

TLS certs/keys/CA come from NV + FLASH_CREDS after unsigned `OWNER SET` / MANAGE CREDS. Provision uplink peers are runtime NV (MANAGE PEER ADD/REMOVE, USB LIST). ENCRYPT/DECRYPT are mTLS and pin the peer to the enrolled owner key. MANAGE is owner-pinned TLS without a device client cert. There is no client CA in firmware.

---

## Layout

```text
host/
  README.md               This file
  tropic_model/
    CMakeLists.txt        Shared runtime + tests + se_host
    download_deps.sh      Fetch wolfSSL / ed25519 into _deps/
    run_with_model.sh     CTest helper: model_server + one exe
    run_all.sh            Rebuild + A–K + brick (script-relative firmware tree)
    port_posix.c          Platform hooks (TCP, RAM NV, test AEAD key)
    host_fw_mlkem.c       RAM stand-in for fw_mlkem_pk
    host_usb_debug_stub.c stdout DEBUG for A–K tests
    host_cdc/             USBX stubs + PTY CDC for se_host
    se_host_main.c        Device main (`--tty`)
    test_a_session.c …    Groups A–K
    brick_lab.c           Irreversible config writes (model only)
    sae_qkd.c             SAE-side pad seal helper for tests
```
