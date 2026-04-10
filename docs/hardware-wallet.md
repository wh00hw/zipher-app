# Hardware Wallet Signing

Zipher CLI supports signing Zcash Orchard shielded transactions via external hardware wallets using the [zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk).

The spending key never leaves the device. Only the full viewing key (FVK) is exported for address derivation and blockchain scanning.

## Prerequisites

- A hardware device running the HWP protocol (e.g. Flipper Zero with FlipZ, or any compatible microcontroller), or a Ledger with the Zcash Orchard app
- Device connected via USB serial (`/dev/ttyACM0`), Ledger USB HID, or Speculos emulator

## Commands

### 1. Pair a hardware device

Exports the Orchard FVK from the device and creates a watch-only wallet:

```bash
# USB serial device
zipher-cli hw-wallet pair --device /dev/ttyACM0 --birthday 2600000

# Ledger hardware wallet
zipher-cli hw-wallet pair --device ledger --birthday 2600000

# Speculos emulator
zipher-cli hw-wallet pair --device speculos:127.0.0.1:9999 --birthday 2600000
```

Options:
- `--device` — serial port path, `ledger`, or `speculos:host:port`
- `--birthday` — block height for faster sync (default: 1)

After pairing, sync the blockchain:

```bash
zipher-cli sync start
```

### 2. Propose a transaction

Same as a normal send — no device needed at this step:

```bash
zipher-cli send propose --to <ADDRESS> --amount 100000
```

### 3. Sign and broadcast via hardware wallet

Instead of `send confirm` (which requires a seed phrase), use `confirm-hw`:

```bash
zipher-cli send confirm-hw --device /dev/ttyACM0
# or: zipher-cli send confirm-hw --device ledger
# or: zipher-cli send confirm-hw --device speculos:127.0.0.1:9999
```

The device will:
1. Receive the sighash and alpha randomizer for each Orchard action
2. Compute the RedPallas spend authorization signature
3. Return the signature for injection into the PCZT

The CLI verifies each signature before broadcasting.

### Ledger

```bash
zipher-cli hw-wallet pair --device ledger --birthday 2600000
zipher-cli send confirm-hw --device ledger
```

The Zcash Orchard app must be open on the Ledger. For testing with the Speculos emulator:

```bash
zipher-cli hw-wallet pair --device speculos:127.0.0.1:9999 --birthday 2600000
zipher-cli send confirm-hw --device speculos:127.0.0.1:9999
```

## How it works

```
propose_send()          -> creates unsigned proposal (FVK only)
create_pczt_from_proposal() -> PCZT (Partially Created Zcash Transaction)
                            |
                    Hardware Signer SDK
                    ├── Orchard proof generation (Halo2)
                    ├── Sighash computation
                    ├── For each action: send to device, verify signature
                    └── Inject signatures into PCZT
                            |
extract_and_store_transaction_from_pczt() -> signed transaction
broadcast via lightwalletd
```
