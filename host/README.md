# Host TROPIC01 model and `se_host`

Linux (**WSL2**) only. This tree compiles the Secure Tropic/OTP/TLS sources against Tropic Square’s `model_server` instead of SPI silicon.

Two things live in `host/tropic_model/`:

| Binary | What it is | How you run it |
| --- | --- | --- |
| `test_a_session` … `test_j_peers`, `brick_lab` | Unit gates A–J (+ brick lab). Default CTest suite. | `ctest` or `./run_all.sh` |
| `se_host` | Interactive SE process: firmware-style console + TLS 1.3 client to a live Java SAE. **Not** a CTest. | Start `model_server`, start Java, then `./se_host` |

Restarting the model restores a fresh chip. A real TROPIC01 does not.

---

## 1. Prepare (once)

From the **repo root** (`SE_firmware/`):

```bash
# TROPIC01 model_server + Python venv (tvl wheel)
bash libtropic/scripts/tropic01_model/install_linux.sh
source libtropic/scripts/tropic01_model/.venv/bin/activate

# wolfSSL 5.8.4 + ed25519 into host/tropic_model/_deps/
bash host/tropic_model/download_deps.sh
```

Needs `python3`, `curl` or `wget`, `sha256sum`, `cmake`, a C compiler, and `make`. CMake fails until `_deps/wolfssl` exists.

Firmware TLS blobs are already in `Secure/Core/Inc/fw_creds.h` and `wrapped_client_key.h`. Rebuild them only if the certs directory changed:

```bash
python scripts/embed_fw_creds.py <certs_dir> \
  Secure/Core/Inc/fw_creds.h \
  Secure/Core/Inc/wrapped_client_key.h
```

`<certs_dir>` uses the CertGenerator layout (`ca/root-ca.pem`, `ca/client_ca.pem`, `client/`, `user/user-cert.pem`, `Alice.pem`). `ENCRYPT` / `DECRYPT` load `fw_client_ca_der` and pin the peer to `fw_user_spki`. If either array is empty (`len = 0`), re-run the embed script before those modes.

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

## 3. Run the model tests (A–J)

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

`run_all.sh` (and `run_one.sh` / `run_direct.sh` / `run_cd.sh`) currently hardcode `/mnt/c/tmp/SE_firmware`. Prefer `cmake` + `ctest` if your checkout is elsewhere.

| Group | Binary | What it gates |
| --- | --- | --- |
| A | `test_a_session` | Session / ping / info |
| B | `test_b_ecc` | ECC store, occupied-slot KEYGEN refuse, generate, PIN reroll, sign+verify |
| C | `test_c_rmem` | R-MEM erase-before-write keystream |
| D | `test_d_pin` | PIN setup/check, wrong-PIN consume, PIN-gated XOR, exhaustion |
| E | `test_e_mcounter` | Monotonic cursor advance-before-use |
| F | `test_f_mlkem` | ML-KEM provision / kem_ct / PIN-gated XOR |
| G | `test_g_ingest` | QKD ingest / pad store |
| H | `test_h_pairing` | Pairing-key install, SH0 invalidate, session uses new key |
| I | `test_i_post_tls` | Encrypt TLS body / OTP reply with slot IDs |
| J | `test_j_peers` | PEER NV add/remove/list, v3→v4 migrate, uplink item count `7+2n` |
| brick | `brick_lab` | Config writes + occupied SH0 (**model only**) |

Do **not** run `TROPIC KEYGEN`, `TROPIC PAIRING … y`, PIN setup, or R-MEM writes on physical silicon until A–E and H are green.

One test with a live model (same helper CTest uses):

```bash
bash ../run_with_model.sh ./test_a_session \
  ../../../libtropic/scripts/tropic01_model/model_cfg.yml
```

---

## 4. Run `se_host` (Java SAE)

`se_host` is the host stand-in for the Secure firmware TLS client. It talks to:

- TROPIC01 **model** at `127.0.0.1:28992` (hardcoded in `port_posix.c`)
- Java SAE TLS server (`--host` / `--port`, default `127.0.0.1:11111`)

### 4.1 Start the chip model

In a terminal with the model venv:

```bash
source libtropic/scripts/tropic01_model/.venv/bin/activate
model_server tcp -c libtropic/scripts/tropic01_model/model_cfg.yml
```

Leave it running. Restart it to wipe Tropic + host RAM NV.

### 4.2 Start the Java Node

Start `JAVA_TLS_TEST` listening on `NODE_NATIVE_PORT` (default **11111**) when you are ready to TLS. This binary does not encapsulate or seal pads; the Java SAE does.

### 4.3 Start the host console

```bash
cd host/tropic_model/build
./se_host --host 127.0.0.1 --port 11111
```

Stdin matches USB CDC on silicon (`HELP` lists names):

```text
HELP
TROPIC PING
TROPIC INFO
TROPIC PUB
TROPIC KEYGEN
TROPIC SIGN <64-hex>
TROPIC KEM INIT <pin>
TROPIC KEM INIT <pin> CONFIRM
TROPIC KEM PUB
TROPIC PAIRING <1-3> [y]
PROVISION <unix>
ENCRYPT <unix>
DECRYPT <unix>
PEER ADD <name> <64-hex>
PEER REMOVE <name>
PEER LIST
QUIT
```

Typical bring-up (same order as silicon), then one TLS session per arm:

```text
TROPIC KEYGEN
TROPIC KEM INIT 9876
TROPIC KEM INIT 9876 CONFIRM
PEER ADD Alice <64-hex-of-SHA256-peer-SPKI>
PROVISION 1756380000
ENCRYPT 1756380000
DECRYPT 1756380000
```

`PROVISION` / `ENCRYPT` / `DECRYPT` take a Unix timestamp so the command line matches firmware. Host wolfSSL uses the **process clock**; the number is parsed and logged, then one TLS session runs and the prompt returns. PIN is never a console argument for those three — it arrives on TLS.

On host, `TROPIC KEM INIT … CONFIRM` fills an in-process ML-KEM pub cache for this run. Tests copy that into `host_fw_mlkem_pk`. Silicon embeds `fw_mlkem_pk` via `embed_fw_creds.py` and reflashes.

---

## 5. TLS framing (what Java must speak)

Uplink is **v3**. Item 6 (0-based) is the 1184-byte ML-KEM-768 public key. Java should encapsulate from that item, not from a file such as `SE_MLKEM_PK_PATH`.

QKD downlink is **v2**: item 0 is `kem_ct` (1088 B), item 1 is `decrypt_half` (1 byte: 0 = first pad half for decrypt, 1 = second), then pad images.

After mTLS:

- **Provision** — host sends the signed session uplink, then stores the QKD downlink into R-MEM.
- **Encrypt** — SAE writes PIN + `u32 msg_len` + plaintext. Reply is `u32 n_pads` then `u16 slot | u16 len | chunk` per pad.
- **Decrypt** — SAE writes PIN plus that encrypt reply. Reply is `u32 n_pads` then `u16 len | chunk` (plaintext only, no slots).

---

## 6. What is firmware vs what the host substitutes

Shared Secure sources (linked into `libse_tropic_host.a` / `se_host`):

`se_tropic.c`, `se_tropic_pin.c`, `se_tropic_rmem.c`, `se_tropic_mlkem.c`, `se_tropic_session.c`, `se_nv.c`, `secure_qkd_ingest.c`, `secure_otp.c`, plus `secure_client_key.c` / `secure_wrap.c` for `se_host`.

Host-only (do not exist on silicon):

| Piece | Firmware | Host |
| --- | --- | --- |
| Transport | SPI1 (`se_tropic_port_stm32.c`) | TCP `127.0.0.1:28992` (`port_posix.c`) |
| Device AEAD key | HKDF from `secure_dwk` | Fixed 32-byte test key |
| ML-KEM pub | `fw_mlkem_pk` in `fw_creds.h` | RAM `host_fw_mlkem_pk[]` (empty until filled) |
| NV page | Secure flash page 22 | 1024-byte RAM |
| Time | `se_time_set_unix()` + SysTick | Process clock; unix arg logged only |
| TLS I/O | `se_tls_client.c` over USB/NSC | `se_host_tls.c` over blocking TCP |
| Console | NonSecure USB CDC | `se_host_main.c` stdin |
| SH0 | eng-sample unless `SE_TROPIC_SH0_PROD` | Forced prod0 (`host_libtropic_config.h`) |
| PIN rounds | silicon default | 4 (`SE_TROPIC_PIN_ROUNDS`) |

Still consumed from firmware headers: `fw_client_cert_der`, `fw_root_ca_der`, `fw_client_spki`, and the wrapped ML-DSA key (`secure_dwk`). Provision uplink peers are runtime NV (`PEER ADD` / `REMOVE` / `LIST`), not `fw_creds.h`.

---

## Layout

```text
host/
  README.md               This file
  tropic_model/
    CMakeLists.txt        Shared runtime + tests + se_host
    download_deps.sh      Fetch wolfSSL / ed25519 into _deps/
    run_with_model.sh     CTest helper: model_server + one exe
    run_all.sh            Lab: rebuild + A–J + brick (hardcoded checkout path)
    port_posix.c          Platform hooks (TCP, RAM NV, test AEAD key)
    host_fw_mlkem.c       RAM stand-in for fw_mlkem_pk
    se_host_main.c        Console
    se_host_tls.c         POSIX TLS client (mirrors se_tls_client.c)
    test_a_session.c …    Groups A–J
    brick_lab.c           Irreversible config writes (model only)
    sae_qkd.c             SAE-side pad seal helper for tests
```
