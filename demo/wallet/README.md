# FermionWallet demo on the real Safe{Wallet}

This runs the open-source Safe stack locally with FermionWallet installed as a Safe App:
- the Safe{Wallet} web UI;
- the Client Gateway;
- the Config Service;
- the Transaction Service.

Everything runs against a local chain. You use the ordinary Safe{Wallet} screens to try to pay a vendor from a Safe protected by the FermionWalletGuard. Then you approve the payment on a simulated FermionWallet Ledger and pay again.

## Run it

You need Docker with Compose v2. The images total about 3 GB.

```sh
docker compose up -d --wait
```

Open http://localhost:8000. To stop the demo and reset it to a fresh chain, run `docker compose down -v`.

| Port | What |
|---|---|
| 8000 | Safe{Wallet}, its backend services, and the chain RPC at `/rpc` |
| 8001 | The FermionWallet Safe App and its simulated Ledger |

To build the two FermionWallet images from a source checkout instead of pulling them:

```sh
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build --wait
```

## Walk through it

1. **Connect the owner.** Click **Connect wallet**, choose **Private key**, and paste the demo owner's key. This is anvil's public test account #1, so never use it anywhere else:
   `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d`
2. **Open the demo Safe.** Go to http://localhost:8000/home?safe=fwdemo:0x8E3fd7B315486ce7Ea44A6E5129046148f807D49. This 1-of-1 Safe holds 10 ETH and 1,000,000 dUSD.
3. **Open FermionWallet.** Go to **Apps** and open **FermionWallet**.
4. **Pay without approval.** Click **Propose payout in Safe{Wallet}**. Safe{Wallet} opens its normal review. Trust the Safe when asked, then click **Continue**.
   - Safe{Wallet} warns *"This transaction will most likely fail"*.
   - If you press **Execute** anyway, execution fails. The owner's signature is valid, but the Guard reverts the transfer because no quantum pre-approval exists.
5. **Approve on the Ledger.** Click **Send to Ledger for approval**. On the simulated device, page through all eight screens with ▶, then press **Approve**.
   - The device signs the exact payment twice over one EIP-712 digest: once with ECDSA and once with XMSS. This uses one of its 16 one-time leaves.
   - The pre-approval is then stored in the Guard.
6. **Pay again.** Click the second **Propose payout in Safe{Wallet}**. The failure warning is gone, **Execute** succeeds, and the payment appears in Safe{Wallet}'s transaction history.

## What's inside

| Service | Image | Role |
|---|---|---|
| `chain` | `fermionwallet-demo` (`DEMO_MODE=wallet`) | Runs the anvil chain for chain 31337, the Safe contracts, the demo Safe and Guard, the simulated Ledger, and the Safe App on port 8001 |
| `nginx` | `fermionwallet-demo-wallet` | Serves the Safe{Wallet} static build and proxies the Safe services and `/rpc` |
| `cfg-*` | `safe-config-service` v2.96.1 | Holds chain 31337's settings and lists the FermionWallet Safe App (seeded by `bootstrap_cfg.py`) |
| `cgw-*` | `safe-client-gateway` v1.115.0 | The API that Safe{Wallet} talks to |
| `txs-*` | `safe-transaction-service` v6.5.0 | Indexes the Safe: balances, history and the queue |

How the stack is put together:

- **Safe contracts.** Safe v1.4.1 is installed at its canonical addresses by `install_safe_contracts.py`. It uses the exact mainnet bytecode, and every contract's hash matches safe-deployments. This lets the unmodified Safe services recognise the Safe.
- **Safe{Wallet} build.** It is built from the official `safe-wallet-web` image. There is one source change: small balances are shown by default, because a local chain has no prices and every token would otherwise be hidden as dust.
- **No events service.** The stack leaves out the Safe events service. The gateway's caches are simply kept to a few seconds instead.
- **Gateway version.** The gateway is pinned to v1.115.0, the newest release published for linux/amd64. The other services are pinned to releases from the same weeks.

## End-to-end test

`e2e/e2e.js` drives headless Chrome through the whole walk-through above against a running stack. It fails unless:
- the unapproved payout is blocked and pays nothing;
- the approved payout executes and pays the vendor exactly the approved amount.

```sh
cd e2e && npm ci && node e2e.js   # CHROME=/path/to/chrome if not /usr/bin/google-chrome
```
