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

```sh
pip install hidapi     # the USB transport needs it
LEDGER_TRANSPORT=usb python3 demo/server.py
```

Review and confirm on the device itself; the demo's device window says so rather than pretending to drive it.

## The wire protocol

The spec's command table lists the commands but not their framing, because an APDU carries at most 255 bytes while a signature is about 2.3 KB. The concrete framing, implemented by `ledger_device.py` and documented in full in its module docstring:

- **CLA** `0xE0`, key slot in **P2**.
- `0x02` `GET_XMSS_ROOT` → root ‖ seed ‖ treeHeight ‖ parameterSet.
- `0x04` `GET_LEAF_INDEX` → next unused leaf, 4 bytes.
- `0x0E` `GET_ADMIN_ADDRESS` → 20 bytes.
- `0x06` `SIGN_PREAPPROVAL` streams the **fields**, never a hash: P1 is `0x00` first chunk, `0x80` more follow, `0x81` last. The response to the last chunk arrives only when the human decides: `0x9000` with leaf ‖ digest ‖ total length, or `0x6985` for a rejection.
- `0x18` `GET_SIGNATURE_CHUNK` with P1 the chunk index, until the whole `ecdsa(65) ‖ r(32) ‖ wotsSig(67×32) ‖ auth(h×32)` blob has arrived.

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
