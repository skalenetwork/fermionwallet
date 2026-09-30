# Driving a real Ledger from the demo

The demo can sign with a real FermionGuard Ledger instead of the Python stand-in. Which device it uses is `LEDGER_TRANSPORT`:

| `LEDGER_TRANSPORT` | Device | Screens shown in |
|---|---|---|
| `simulator` (default) | `demo/ledger_sim.py`, a Python stand-in | the demo's own device window (`/ledger`) |
| `speculos` | the real app in [Speculos](https://github.com/LedgerHQ/speculos), Ledger's emulator | Speculos at http://localhost:5001, and mirrored into the demo's device window |
| `usb` | a physical Ledger over USB | the device itself |

`demo/ledger_device.py` speaks the APDU protocol of [ledger-xmss-app.md](../ledger-xmss-app.md) over either transport; nothing above it changes, so the Safe App and the standalone dashboard behave the same.

## With the emulator

Build the app first — `ledger-app/build.sh` puts the ELF at
`ledger-app/build/nanos2/bin/app.elf`, which is where the compose profile looks:

```sh
./ledger-app/build.sh            # docker is all it needs
cd demo/wallet
LEDGER_TRANSPORT=speculos docker compose --profile ledger up -d --wait
```

The emulator runs with anvil's mnemonic, so the device's ECDSA key at `m/44'/60'/0'/0/4` is the Quantum Administrator address the demo registers on-chain. Point it at a different build with `LEDGER_APP_ELF`.

The XMSS key is a different matter: it is generated on the device, so the demo cannot
invent it. With `speculos` or `usb` the setup asks the device for its public key
(`GET_XMSS_ROOT`) before deploying and registers *that* root and SEED, via
`DEVICE_XMSS_ROOT` / `DEVICE_XMSS_SEED` (`demo/entrypoint.sh`, `Demo.s.sol`). Without
a device it registers the reference key as before. Registering one key and signing
with another is the failure this prevents: the Guard would refuse every approval with
`InvalidXmssSignature`, after the device had already spent the leaf.

## With a physical Ledger

Install the FermionGuard app, unlock the device, open the app, then:

`demo/server.py` is only the web layer: it needs a chain and a deployment that already
registered the device's key. Inside the image `demo/entrypoint.sh` does that; from a
source checkout, do the same three steps by hand (this is `entrypoint.sh` with the
container paths removed):

```sh
pip install hidapi                                  # the USB transport needs it
anvil --port 8545 --chain-id 31337 --silent &        # the chain server.py expects
cd contracts && mkdir -p demo-state
eval "$(python3 ../demo/ledger_device.py key)"       # sets DEVICE_XMSS_ROOT / _SEED
export DEVICE_XMSS_ROOT DEVICE_XMSS_SEED
forge script script/Demo.s.sol:Demo -s "deploy()" \
  --rpc-url http://127.0.0.1:8545 --broadcast        # writes demo-state/deployment.json
cd .. && LEDGER_TRANSPORT=usb CONTRACTS_DIR="$PWD/contracts" python3 demo/server.py
```

Two of those are easy to skip and fail confusingly. `CONTRACTS_DIR` defaults to the
in-container `/app/contracts`, so without it every `/api/*` call fails looking for
`demo-state/deployment.json`. And the device's key must be read *before* deploying:
register the reference key and sign with the device's, and the Guard rejects every
approval with `InvalidXmssSignature` after the device has already spent the leaf.

Review and confirm on the device itself; the demo's device window says so rather than pretending to drive it.

## The wire protocol

The spec's command table lists the commands but not their framing, because an APDU carries at most 255 bytes while a signature is about 2.3 KB. The concrete framing, implemented by `ledger_device.py` and documented in full in its module docstring:

- **CLA** `0xE0`, key slot in **P2**. The instruction numbers are the Ethereum app's: a command with an Ethereum analogue keeps that app's own number, and the FermionGuard-specific ones start at `0x40`, above its highest assignment.
- `0x02` `GET_ADMIN_ADDRESS` → 20 bytes (the Ethereum app's GET ETH PUBLIC ADDRESS).
- `0x04` `SIGN_PREAPPROVAL` streams the **fields**, never a hash: P1 is `0x00` first chunk, `0x80` more follow, `0x81` last. The response to the last chunk arrives only when the human decides: `0x9000` with leaf ‖ digest ‖ total length, or `0x6985` for a rejection.
- `0x06` `GET_APP_CONFIG` → what the ceremony preflight checks the device against.
- `0x44` `GET_XMSS_ROOT` → root ‖ seed ‖ treeHeight ‖ parameterSet.
- `0x46` `GET_LEAF_INDEX` → next unused leaf, 4 bytes.
- `0x50` `GET_SIGNATURE_CHUNK` with P1 `0x00` for the first chunk and `0x80` for each next one, until the whole `r(32) ‖ wotsSig(67×32) ‖ auth(h×32) ‖ ecdsa(65)` blob has arrived. The ECDSA half is last, so a host that reads only the first chunk holds neither half whole.

The two halves keep their own lengths if they swap places, so a blob in the wrong order is the right size and only fails on-chain, as `InvalidEcdsaSignature` — which reads like a wrong `quantumAdmin` key, after a one-time leaf has already been spent. `ledger_device.py` therefore checks the split itself: the ECDSA half must carry a real recovery id and must recover to the Administrator address the device reports, or the host refuses to relay and says the blob is not in the order it expects.

The device recomputes the EIP-712 digest from the fields it displayed, so a host that lies about what it is asking for gets a signature the Guard rejects.

## What is checked

`python3 demo/test_ledger_transport.py` checks the payload encoding offline, and the wire framing against a real Ledger app when `SPECULOS_APDU_URL` is set:

```sh
docker run -d --name ledger-check -v "$PWD/ledger-app/build/nanos2/bin":/app -p 15000:5000 -p 19999:9999 \
  ghcr.io/ledgerhq/speculos:latest --model nanosp --display headless \
  --api-port 5000 --apdu-port 9999 --seed "test test test test test test test test test test test junk" /app/app.elf
SPECULOS_APDU_URL=tcp://127.0.0.1:19999 SPECULOS_API_URL=http://127.0.0.1:15000 python3 demo/test_ledger_transport.py
```

The framing checks pass against any Ledger app, since the framing belongs to the device rather than to FermionGuard.

What the FermionGuard app itself produces is checked by `ledger-app/test/test_app.py`:
the device's digest against the contracts' EIP-712 encoding, its XMSS half against the
RFC 8391 reference implementation, and its ECDSA half against the address it publishes
as `quantumAdmin`. See [`ledger-app/README.md`](../ledger-app/README.md).
