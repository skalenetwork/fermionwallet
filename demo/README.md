# The demos

Two of them, sharing one chain-and-contracts setup. Both are real: a real Safe, a real
FermionGuard deployed on a real chain, and a device that really produces a hybrid
ECDSA + XMSS signature. What is simulated is named wherever it is simulated.

| | `demo/` — standalone | `demo/wallet/` — Safe{Wallet} |
|---|---|---|
| What you drive | a dashboard written for the demo | the **real, open-source Safe{Wallet}**, with FermionGuard as a Safe App |
| Safe | v1.5.0, 2-of-3 | canonical v1.4.1 SafeL2, 1-of-1 (what the Safe services index) |
| Runs as | one container | a Compose stack: chain, Client Gateway, Config Service, Transaction Service, UI, nginx |
| Start | `docker run --rm -p 8080:8080 -p 8545:8545 ghcr.io/skalenetwork/fermionguard-demo:latest` | `cd demo/wallet && docker compose up -d --wait`, then http://localhost:8000 |
| Read next | this file | [`wallet/README.md`](./wallet/README.md) |

Both show the same thing: an owner signs a transfer, it **will not execute**, the Quantum
Administrator approves it on the device, and only then does the money move.

## What is in here

- **`server.py`** — the standalone demo's HTTP API and dashboard host. `/api/blocked`,
  `/api/approve`, `/api/execute` drive one cycle; `/api/screen` and `/api/button` are the
  device's screen and buttons.
- **`app_api.py`** — the Safe App's API, per Safe rather than per demo:
  `/api/v1/safes/<safe>/status|queue|approvals`, and `relayPreApproval`, which submits a
  pre-approval the device signed for *any* Safe, token, recipient, amount and window.
- **`ui/`** — the dashboard (`ui/index.html`), the FermionGuard Safe App
  (`ui/safe-app/index.html`) and the device window (`ui/ledger/index.html`).
- **`ledger_sim.py`** — the simulated device. It holds the XMSS key and its own leaf
  counter, renders every field on a screen, and commits the counter to disk *before* it
  computes either signature. It is a stand-in for the device, not a mock of one.
- **`ledger_device.py`** — the same interface against a **real** Ledger: APDUs over USB,
  or over TCP to the app running in Ledger's Speculos emulator. See [`LEDGER.md`](./LEDGER.md).
- **`ledger-proof/`** — the device's signing flow as a state machine, model-checked
  exhaustively, with `ledger_sim.py` proven to refine it. See its
  [`README.md`](./ledger-proof/README.md).
- **`entrypoint.sh`** — starts anvil, asks the device for its key when one is attached,
  deploys and registers, then serves.
- **`test_ledger_transport.py`** — 14 checks over the transport layer, four of which need
  a real app in Speculos.

## Which device signs

Set `LEDGER_TRANSPORT`:

- **`simulator`** (default) — `ledger_sim.py`, in the same container. No build, no
  emulator, and the demo registers the reference key.
- **`speculos`** — the real Rust app from [`../ledger-app/`](../ledger-app/) running in
  Ledger's emulator. Build it first (`./ledger-app/build.sh`); the Compose profile mounts
  `ledger-app/build/nanos2/bin/app.elf`, and the service refuses to start with a clear
  message if it is not there.
- **`usb`** — a physical Ledger with the app sideloaded. Needs `pip install hidapi`.

With a real device the key that signs is the one **generated on the device**, so
`entrypoint.sh` reads its root and SEED over `GET_XMSS_ROOT` *before* deploying and
registers those. Registering the reference key and then signing with a different one is
the mistake this ordering exists to prevent.

The host also recomputes the EIP-712 digest from the fields it sent and refuses the
signatures if the device reports a different one, and it checks that the signature blob is
split the way it expects — by recovering the ECDSA half to the device's own Administrator
address, which is the check the Guard itself would fail. Both exist because a device that
signs something other than what it displayed, or a host that mis-splits the two halves,
otherwise surfaces on-chain as a confusing revert *after* a one-time leaf is spent.

## The keys are public

Every key in these demos is published: the Safe owners and the Quantum Administrator are
anvil's, and the XMSS key is generated deterministically from a fixed string. They exist
so a stranger can run this in one command. Never use them for anything.

## Running from a source checkout

Until the images are published with a release:

```shell
git submodule update --init --recursive
docker build -f demo/Dockerfile -t fermionguard-demo .      # from the repository root
docker run --rm -p 8080:8080 -p 8545:8545 fermionguard-demo
```

For the Safe{Wallet} stack, use the build command in [`wallet/README.md`](./wallet/README.md#run-it).
