# Hardware Wallet Signing

Zipher CLI signs Zcash transactions via external hardware wallets using the [zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk) and the PCZT (ZIP-320) standard.

The spending key never leaves the device — only the Orchard full viewing key (FVK) is exported for address derivation and blockchain scanning. Both **Orchard shielded actions** and **transparent inputs** can be signed by the hardware, with independent on-device verification of the ZIP-244 sighash.

## What the device signs

| Pool | Signature | Key | On-device verification |
|---|---|---|---|
| Orchard | RedPallas (spend auth) | `ask` — ZIP-32 `m/32'/coin'/account'` | ZIP-244 shielded sighash (HWP v2) |
| Transparent | ECDSA secp256k1 | `tsk` — BIP-32 `m/44'/coin'/0'/0/0` | ZIP-244 transparent digest + per-input sighash (HWP v3) |

Before signing, the SDK streams transaction metadata and input/output data to the device, which **independently recomputes** the ZIP-244 digests and refuses to sign on any mismatch. A compromised host cannot forge a sighash the device will sign.

Consensus branches currently accepted: **Nu5**, **Nu6**, **Nu6.1**.

## Prerequisites

- A device speaking the HWP v2/v3 protocol (ESP32-S3 reference firmware, or any microcontroller using `libzcash-orchard-c`), **or** a Ledger running the Zcash Orchard app.
- Transport: USB CDC serial (`/dev/ttyACM0`), Ledger USB HID, or the Speculos emulator over TCP.

## Commands

### 1. Pair a hardware device

Exports the Orchard FVK and creates a watch-only wallet:

```bash
# USB serial device
zipher-cli hw-wallet pair --device /dev/ttyACM0 --birthday 2600000

# Ledger hardware wallet (PCZT + HWP flow — Zcash Orchard app)
zipher-cli hw-wallet pair --device ledger --birthday 2600000

# Speculos emulator
zipher-cli hw-wallet pair --device speculos:127.0.0.1:9999 --birthday 2600000
```

Options:
- `--device` — serial port path, `ledger`, or `speculos[:host:port]`
- `--birthday` — block height for faster sync (default: 1)

The coin type passed to the device is derived from `--testnet` (`coin_type=1`) vs mainnet (`coin_type=133`). The SDK validates that the `consensus_branch_id` in the PCZT matches the signer's network before kicking off proof generation.

Sync after pairing:

```bash
zipher-cli sync start
```

### 2. Query a Ledger running Hanh's native app

For Ledgers flashed with Hanh's native `zcash-ledger` (APDU builder) app, use:

```bash
zipher-cli hw-wallet info
```

This reports the app version and exports the Orchard FVK via direct APDU commands (parallel to HWP — does not create a wallet). Pairing/signing against Hanh's app is not wired to the PCZT pipeline; use the Zcash Orchard app for transaction signing.

### 3. Propose a transaction

Same as a normal send — no device needed at this step:

```bash
zipher-cli send propose --to <ADDRESS> --amount 100000
```

The proposal may include transparent inputs (e.g. from shielding flows); they will be signed by the device in step 4.

### 4. Sign and broadcast via hardware wallet

Instead of `send confirm` (which requires a seed phrase), use `confirm-hw`:

```bash
zipher-cli send confirm-hw --device /dev/ttyACM0
# or: zipher-cli send confirm-hw --device ledger
# or: zipher-cli send confirm-hw --device speculos:127.0.0.1:9999
```

Per-action flow on the device:

1. **Metadata** — 129-byte `TxMeta` (header fields + pre-computed transparent/sapling sub-digests + `coin_type`) is streamed via `TxOutput(index=0xFFFF)`.
2. **Orchard action data** — each action's 820-byte ZIP-244 payload (`cv_net || nullifier || rk || cmx || epk || enc_ct || out_ct`) is streamed; the device folds it into three BLAKE2b digesters (compact / memos / non-compact).
3. **Sighash verify** — SDK sends the expected sighash; device compares against its own and returns `SighashMismatch` on divergence.
4. **Transparent digest verify (v3)** — raw transparent inputs (prevout, sequence, amount, scriptPubKey) and outputs are streamed; the device recomputes the transparent txid digest and compares with the value from `TxMeta`.
5. **Sign** — Orchard actions are signed (RedPallas, `sighash + alpha` → `(sig, rk)`), then each transparent input is signed (ECDSA secp256k1 via RFC 6979, per-input sighash computed on-device, DER-encoded).
6. The CLI verifies the RedPallas signatures + rk binding, injects signatures into the PCZT, extracts the transaction, and broadcasts via lightwalletd.

The engine logs the counts on success:

```
[HW-CONFIRM] Hardware signed OK: 2 orchard action(s), 1 transparent input(s)
```

## Device selector cheatsheet

| `--device` value | Transport | Typical use |
|---|---|---|
| `/dev/ttyACM0`, `/dev/ttyUSB0`, ... | USB CDC serial (HWP) | ESP32-S3, STM32, custom firmware |
| `ledger` | Ledger USB HID (HWP) | Nano S+/X/Stax/Flex with Zcash Orchard app |
| `speculos[:host:port]` | TCP (HWP over Speculos) | Ledger emulator for CI/dev |

`hw-wallet info` is a fixed-transport command (Ledger-HID only).

## How it works

```
propose_send()                 → unsigned proposal (FVK only)
create_pczt_from_proposal()    → PCZT (Partially Created Zcash Transaction)
                                       │
                 zcash-hw-wallet-sdk — PcztHardwareSigning::sign_with_details
                 ├── Halo2 Orchard proof
                 ├── Extract ZIP-244 tx metadata + action data + transparent i/o
                 ├── Device verifies shielded sighash (v2) + transparent digest (v3)
                 ├── Device signs each Orchard action (RedPallas) + each t-input (ECDSA)
                 ├── SDK verifies rk + RedPallas signatures
                 └── Signatures injected back into the PCZT
                                       │
extract_and_store_transaction_from_pczt() → raw Zcash tx
broadcast via lightwalletd
```

## Further reading

- `zcash-hw-wallet-sdk` README — full HWP v2/v3 protocol spec, security model, trait reference
- `libzcash-orchard-c` — C11 device-side implementation (ZIP-32/44, Pallas/RedPallas, secp256k1/ECDSA, ZIP-244)
- ZIP-320 (PCZT) — the wire format used between host and wallet backends
