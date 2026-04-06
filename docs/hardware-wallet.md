# Hardware Wallet Signing

Zipher CLI supports signing Zcash Orchard shielded transactions via external hardware wallets using the [zcash-hw-signer-sdk](https://github.com/wh00hw/zcash-hw-signer).

The spending key never leaves the device. Only the full viewing key (FVK) is exported for address derivation and blockchain scanning.

## Prerequisites

- A hardware device running the HWP protocol (e.g. Flipper Zero with FlipZ, or any compatible microcontroller)
- Device connected via USB serial (`/dev/ttyACM0`) or TCP (`tcp://host:port`)

## Commands

### 1. Pair a hardware device

Exports the Orchard FVK from the device and creates a watch-only wallet:

```bash
zipher-cli hw-wallet pair --device /dev/ttyACM0 --birthday 2600000
```

Options:
- `--device` — serial port path or `tcp://host:port`
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
```

The device will:
1. Receive the sighash and alpha randomizer for each Orchard action
2. Compute the RedPallas spend authorization signature
3. Return the signature for injection into the PCZT

The CLI verifies each signature before broadcasting.

### TCP mode (for networked HSMs or testing)

```bash
zipher-cli hw-wallet pair --device tcp://192.168.1.100:9000 --birthday 2600000
zipher-cli send confirm-hw --device tcp://192.168.1.100:9000
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
