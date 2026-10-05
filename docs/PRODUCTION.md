# Production profile (silicon)

Lab UserApp and this firmware tree stay open for bring-up. Production is the
**same ELF** with operator steps that lab `INIT LAB` must not perform.

Use **INIT PROD** in UserApp only when you intend a field device. The app prints
which profile it is using and warns before PROD continues.

## What production does differently

- Device ML-DSA is generated **on-chip**. The host never injects a device private key.
- `CLIENT CSR` is written to the client folder. **Do not** sign it with the lab
  `client_ca.p12`. A production client CA (offline) signs the CSR; the operator
  then runs UserApp **INSERT SIGNED CSR** (MANAGE cmd 6, cert DER only). INIT PROD
  itself does **not** install. ENCRYPT / DECRYPT / PROVISION stay down until that
  cert matches the on-chip public key.
- Pairing (MANAGE cmd 8 + PIN, slots 1–3) **invalidates factory SH0**. The pairing
  private key stays in MCU NV. An MCU reflash after pairing cannot reopen L3
  from factory SH0.
- PIN is **8–16 printable ASCII**. Losing it loses ML-KEM unwrap.

## STM32 lock (operator, outside this repo)

Lab firmware leaves debug open. For a field unit, after bring-up and pairing:

1. Enable **RDP** (and **HDP** if the product policy requires hiding Secure flash).
2. Disable SWD on the production image you ship.
3. Treat a dump of Secure NV as full impersonation of TLS identity and pairing
   priv — pads still need the PIN.

This document does not give fuse bit recipes; follow ST’s RDP/HDP application
notes for STM32U535.

## What not to copy from lab

- Lab factory SH0 (eng-sample) private keys from the Tropic SDK.
- Lab `certs/ca/client_ca.p12` as a production signer.
