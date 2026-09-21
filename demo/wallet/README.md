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

It takes about a minute: `--wait` returns once Safe{Wallet} can load the demo Safe. Then open http://localhost:8000.

Nothing is kept between runs. Any restart, including `docker compose restart`, starts a fresh chain. To stop the demo, run `docker compose down -v`.

| Port | What |
|---|---|
| 8000 | Safe{Wallet}, its backend services, and the chain RPC at `/rpc` |
| 8001 | The FermionWallet Safe App and its simulated Ledger |

`docker compose up -d --wait` pulls the two FermionWallet images from ghcr.io. The copy of this README in a release bundle pins them to that release. To run your own changes, or before the first release that includes this demo, build them from a source checkout of [demo/wallet](https://github.com/skalenetwork/fermionwallet/tree/main/demo/wallet) instead:

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
   - If you press **Execute** anyway, Safe{Wallet} shows *"Error submitting the transaction"* and sends nothing. The owner's signature is valid, but the Guard reverts the transfer because no quantum pre-approval exists. Under **Details**, the revert data starts with `0x95828945`, the selector of `NoMatchingPreApproval`.
   - To go back to the app, close the review with ✕ and confirm. Close the red notification first if it covers the ✕.
5. **Approve on the Ledger.** Click **Send to Ledger for approval**. On the simulated device, page through all eight screens with ▶, then press **Approve**.
   - The device signs the exact payment twice over one EIP-712 digest: once with ECDSA and once with XMSS. This uses one of its 16 one-time leaves.
   - The pre-approval is then stored in the Guard.
6. **Pay again.** Click the second **Propose payout in Safe{Wallet}**. The failure warning is gone, **Execute** succeeds, and the payment appears in Safe{Wallet}'s transaction history.

## Good to know

- **16 approvals per run.** Each Ledger approval uses one of the demo key's 16 one-time XMSS leaves. When they are all used, the app says so and disables approving. Run `docker compose down -v`, then `docker compose up -d --wait`, to start again with a fresh key.
- **Other ways to pay.** An approval covers one dUSD payment to the vendor for exactly the approved amount. The payment can also be made with Safe{Wallet}'s own **Send** flow, for the same token, recipient and amount. ETH transfers, batches (Safe{Wallet} sends them through MultiSendCallOnly) and Safe settings changes need kinds of approval this demo's Ledger does not sign, so the Guard always blocks them.
- **Sign instead of Execute.** If you only sign a payout, it waits in **Transactions → Queue** and holds its nonce. Later payouts queue behind it and cannot execute. Rejecting it in Safe{Wallet} does not work either, because the rejection is itself a Safe transaction that the Guard blocks. To clear it, approve exactly its amount in the app, then execute it from the queue. The app shows this when it sees such a payout.
- **Demo Safe only.** The app only works on the demo Safe, because that is the Safe with the Guard and the Ledger key. On any other Safe it shows a notice and its buttons stay disabled.

## What's inside

| Service | Image | Role |
|---|---|---|
| `chain` | `fermionwallet-demo` (`DEMO_MODE=wallet`) | Runs the anvil chain for chain 31337, the Safe contracts, the demo Safe and Guard, the simulated Ledger, and the Safe App on port 8001 |
| `nginx` | `fermionwallet-demo-wallet` | Serves the Safe{Wallet} static build and proxies the Safe services and `/rpc` |
| `cfg-*` | `safe-config-service` v2.96.1 | Holds chain 31337's settings and lists the FermionWallet Safe App (seeded by `bootstrap_cfg.py`) |
| `cgw-*` | `safe-client-gateway` v1.115.0 | The API that Safe{Wallet} talks to |
| `txs-*` | `safe-transaction-service` v6.5.0 | Indexes the Safe: balances, history and the queue |

How the stack is put together:

- **Safe contracts.** Safe v1.4.1 is installed at its canonical addresses by `install_safe_contracts.py` (in the source tree, run inside the chain image). It uses the exact mainnet bytecode, and every contract's hash matches safe-deployments. This lets the unmodified Safe services recognise the Safe.
- **Safe{Wallet} build.** It is built from the official `safe-wallet-web` image. There is one source change: small balances are shown by default, because a local chain has no prices and every token would otherwise be hidden as dust.
- **No events service.** The stack leaves out the Safe events service. The gateway's caches are simply kept to a few seconds instead.
- **Gateway version.** The gateway is pinned to v1.115.0, the newest release published for linux/amd64. The other services are pinned to releases from the same weeks.

## End-to-end test

`e2e/e2e.js` (in the source tree) drives headless Chrome through the whole walk-through above against a running stack. It fails unless:
- the unapproved payout is blocked and pays nothing;
- the approved payout executes and pays the vendor exactly the approved amount.

```sh
cd e2e && npm ci && node e2e.js   # CHROME=/path/to/chrome if not /usr/bin/google-chrome
```

Each run uses one of the 16 XMSS leaves, so reset the stack after 16 runs.
