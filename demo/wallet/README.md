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

You play two roles: a Safe **owner**, who creates and executes transactions in Safe{Wallet}, and the **Quantum Administrator**, who approves them in the FermionWallet app on a Ledger.

1. **Connect the owner.** Open http://localhost:8000/home?safe=fwdemo:0x8E3fd7B315486ce7Ea44A6E5129046148f807D49 (a 1-of-1 Safe holding 10 ETH and 1,000,000 dUSD). Click **Connect wallet**, choose **Private key**, and paste the demo owner's key. It is anvil's public test account #1, so never use it anywhere else:
   `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d`
2. **Create a payment and sign it.** Click **Send**, pick **Demo USD**, enter any recipient and amount, then **Next** → **Continue**. Open the menu next to **Execute**, choose **Sign**, and click **Sign**. Trust the Safe when asked (any name). The payment now waits in **Transactions → Queue**.
3. **Try to execute it.** In **Transactions → Queue**, click **Execute**. Safe{Wallet} warns *"This transaction will most likely fail"*, and executing it fails: the owner's signature is valid, but the Guard reverts the payment because it has no quantum pre-approval. Close the dialog.
4. **Connect the Ledger.** Open http://localhost:8001/ledger in a second window. It stands in for the Quantum Administrator's Ledger running the FermionWallet XMSS app, which is not released yet.
5. **Approve it in FermionWallet.** In Safe{Wallet}, go to **Apps**, click the **FermionWallet** card, then **Open Safe App** (accept the Safe Apps disclaimer the first time). The **Queue** tab lists the payment as *Quantum approval required*. Click **Review**, check the decoded fields, pick how long the approval stays valid, and click **Sign on Ledger**.
   - On the Ledger window, page through every screen with ▶ and press **Approve** on the last one. The device signs the exact payment, pinned to this Safe transaction, with ECDSA and XMSS over one EIP-712 digest. This uses one of the key's 16 one-time signatures.
   - The app relays the signatures to the Guard, and the row turns *Ready to execute*.
6. **Execute it.** Back in **Transactions → Queue**, click **Execute**. The failure warning is gone, the payment goes through, and it appears in the history. In FermionWallet, the **Approvals** tab shows the approval as *used*.

## Good to know

- **16 approvals per run.** The demo key has 16 one-time XMSS signatures; the app's key card shows how many are left. When they run out, run `docker compose down -v`, then `docker compose up -d --wait`, to start again with a fresh key.
- **What the app approves.** Single ERC-20 transfers. ETH transfers, batches and Safe settings changes need approval classes this version of the app does not sign, so they stay listed as *Not supported* and the Guard blocks them.
- **Revoking.** An approved payment shows a **Revoke** button. Revoking is itself a Safe transaction, which the Guard always lets through; execute it in Safe{Wallet} to take effect.
- **Order matters.** A Safe executes transactions in nonce order. An approved payment behind an unapproved one waits; the app shows *Approved · waiting for earlier nonce*.
- **"Recipient analysis failed" and "Cannot estimate".** Both are expected on an unapproved payment. Safe Shield's recipient check needs Safe's transaction decoder service, which this stack leaves out, and the fee estimate simulates the payment, which the Guard reverts.
- **Any Safe.** The app works for whichever Safe it is opened in. A Safe without the FermionWallet Guard is shown as *Not protected*.

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
