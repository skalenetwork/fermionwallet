# Fermion user guide

How to use Fermion: create a wallet, back it up, send from it, use it as a Safe owner, protect a
Safe with Fermion Guard, approve transactions, and get out in an emergency.

**Before anything else:** Fermion v2 is in development. It is **unaudited**, it is not deployed on
any public network, and the apps described here are being built. Do not put real funds into it.
This guide describes how v2 is meant to work, so you can try it on a local demo and tell us what
is unclear.

## Contents

1. [What Fermion is](#what-fermion-is)
2. [Before you start](#before-you-start)
3. [Creating a wallet](#creating-a-wallet)
4. [Choosing ML-DSA-44 or ML-DSA-65](#choosing-ml-dsa-44-or-ml-dsa-65)
5. [Backup and restore](#backup-and-restore)
6. [Sending](#sending)
7. [Using your wallet as a Safe owner](#using-your-wallet-as-a-safe-owner)
8. [Protecting a Safe with Fermion Guard](#protecting-a-safe-with-fermion-guard)
9. [Approving Safe transactions](#approving-safe-transactions)
10. [Changing the Guard key](#changing-the-guard-key)
11. [Emergency removal and rescue](#emergency-removal-and-rescue)
12. [Warnings and what they mean](#warnings-and-what-they-mean)
13. [If something goes wrong](#if-something-goes-wrong)

---

## What Fermion is

Ordinary Ethereum accounts are protected by one kind of signature (ECDSA). A large enough quantum
computer could forge those. Fermion adds a second, post-quantum signature (ML-DSA) and requires
**both**. Your Ledger makes both signatures at once, after you check the details on its screen.

There are two products:

- **Fermion Wallet** is a cold vault. It can receive anything. It sends ETH, tokens and NFTs only
  when your Ledger signs. It does not connect to DeFi apps, and it cannot approve spending.
- **Fermion Guard** protects a Safe. Your Safe keeps its owners and threshold. On top of that,
  every Safe transaction needs one more approval from the Safe's **Quantum Administrator**, made
  on a Ledger.

One Ledger app, called **Fermion**, signs for both.

## Before you start

You need:

- A Ledger Nano S Plus, Nano X, Stax or Flex.
- The **Fermion** app, installed from **Ledger Live's app catalog**. Never install it any other way.
- Your Ledger's recovery phrase, written down and stored safely.

Three rules that protect everything else:

1. **Your recovery phrase is the key to everything.** Both of Fermion's signatures for every
   wallet and every Safe come from it. Whoever has it can take your funds.
2. **Never type your recovery phrase anywhere except on the Ledger itself.** No Fermion website,
   Safe App, Ledger Live app or support person will ever ask for it. If something asks, it is an
   attack.
3. **Use a passphrase if you can.** A Ledger passphrase (sometimes called the "25th word") means a
   stolen copy of your phrase is not enough on its own. But if you forget the passphrase, your
   keys are gone just as if you lost the phrase. Store it somewhere different from the phrase.

## Creating a wallet

1. Open the Fermion web app or the Fermion app in Ledger Live and connect your Ledger.
2. Choose **Create wallet**. Pick ML-DSA-44 (the default) or ML-DSA-65 ([below](#choosing-ml-dsa-44-or-ml-dsa-65)).
   You cannot change this later.
3. The app asks your Ledger for a new key. Each wallet gets its own key; Fermion never reuses one.
4. The app shows your new wallet's address and sends one setup transaction, paid from your
   ordinary browser wallet or by a relayer. After it confirms, the wallet exists and can receive.

Your wallet has **the same address on Ethereum, Base, Arbitrum and Optimism**. Send to it like any
other address. Receiving needs no signature from you.

## Choosing ML-DSA-44 or ML-DSA-65

Both are NIST-standard post-quantum signatures. ML-DSA-65 has a larger security margin and costs
more gas. Most people should keep the default.

| | ML-DSA-44 (default) | ML-DSA-65 |
|---|---|---|
| Setup (gas) | 5.55M | 9.53M |
| First send (gas) | 5.90M | 9.56M |
| Every later send (gas) | 2.82M | 3.83M |

Gas figures are from the project's measurements and will change when Ethereum reprices gas.
Verifying a post-quantum signature is expensive on Ethereum mainnet and much cheaper on L2s such as
Base, Arbitrum and Optimism.

The contracts also accept ML-DSA-87, but the Ledger app does not offer it.

## Backup and restore

Your backup is your recovery phrase (and passphrase, if you set one). There is nothing else to back
up.

- **Restoring works.** If you restore your phrase on another Ledger and install the Fermion app,
  you get exactly the same keys for every wallet and Safe. The app finds your wallets again.
- **Uninstalling the Fermion app is safe.** Reinstall it and your keys come back.
- **Losing your Ledger is not losing your funds**, as long as your phrase is safe. Restore it on a
  new device.

What cannot be recovered: a Fermion Wallet whose phrase (or passphrase) is lost **and** whose
Ledger is gone. Nobody can move those funds, including us. For a Safe, the owners can still remove
the Guard ([below](#emergency-removal-and-rescue)).

## Sending

1. In the Fermion app, choose **Send**. Pick ETH, a token or an NFT, the recipient and the amount.
   You can put up to 8 sends in one batch; either all of them happen or none.
2. Choose how long the signature stays valid. It can be at most 24 hours.
3. Your Ledger shows every detail: the wallet, the chain, each recipient and amount, and the
   validity times in UTC. **Check them on the Ledger screen**, not on your computer, then approve.
4. The app submits the transaction from your browser wallet or a relayer.

The **first** send from a new wallet costs more, because it stores some data the later sends
reuse. If the transaction is not included before the validity window ends, it expires; sign again.

## Using your wallet as a Safe owner

A Fermion Wallet can be an owner of a Safe. When the Safe wants your signature:

1. Open the transaction in the Fermion app or the Safe App and choose **Sign as owner**.
2. Your Ledger shows **Sign as Safe OWNER**, the Safe's address, the chain, the Safe's nonce and
   what the transaction does: a token transfer, an ETH send, a named Safe setting change, or a
   contract call it can describe.
3. Approve on the Ledger.

Your Ledger will refuse some Safe transactions outright, whatever you press
([warnings](#warnings-and-what-they-mean)). Your wallet can also sign plain-text messages, such as
"Sign in with Ethereum" or a proof that you own the address; the Ledger shows the whole text.

## Protecting a Safe with Fermion Guard

Use the Fermion Safe App (open it in Safe{Wallet} under *Apps → My custom apps*). The Safe App's
official address will be published with the release; only ever take it from this repository.

1. **Choose the Quantum Administrator.** One person holds the Ledger that approves. It works best
   when this person is not also the one who controls the owners' keys.
2. **Create the Guard key** on that Ledger: ML-DSA-44 (default) or ML-DSA-65. Each Safe gets its
   own key.
3. **Register the key.** The Safe App sends the transactions that store the key's data.
4. **Enroll and turn on the Guard.** The owners sign a Safe transaction that sets Fermion Guard.
   On Safe 1.5.0 it is also set as the module guard. Safe versions 1.3.0, 1.4.1 and 1.5.0 are
   supported; modules are allowed only on 1.5.0.

From then on, **every** Safe transaction needs a quantum approval, except the emergency-removal
steps.

## Approving Safe transactions

When a Safe transaction is proposed:

1. The Quantum Administrator opens it in the Safe App and chooses **Approve**.
2. The Ledger shows **Quantum APPROVAL**, the Safe, the chain, the Safe's nonce, what the
   transaction does, and the validity times (at most 24 hours apart). Check, then approve.
3. Choose how the approval travels:
   - **Inline:** attached to the owners' signatures and checked when the transaction executes.
   - **Stored:** saved on chain first, so any Safe interface's Execute button works. It is used once.

**Batches.** A Safe batch (several transfers or calls in one transaction, through Safe's standard
MultiSendCallOnly contract) gets one approval. The Ledger shows **every step** of the batch, and
checks each step as strictly as a single transaction: if any step would be refused on its own,
the whole batch is refused. Module transactions cannot be batched this way.

The owners still have to reach the threshold as usual. An approval does nothing for a different
transaction, a different Safe or a different chain.

**Taking back a stored approval:** the Quantum Administrator can revoke it from the Ledger, or the
Safe can revoke it with an ordinary Safe transaction. Changing the Guard key also cancels every
stored approval made with the old key.

**Enabling a module** (Safe 1.5.0 only) has its own Ledger screen. After that, every transaction
the module makes needs its own quantum approval too.

## Changing the Guard key

To move the Guard to a new key (a new Ledger, a new phrase, or ML-DSA-65):

1. Create and register the new key.
2. Approve the change with the **old** key on its Ledger.

If the old key is lost or stolen, use emergency removal and then enroll again with the new key.

## Emergency removal and rescue

Emergency removal lets the Safe's owners take the Guard off without the Quantum Administrator, for
example if the Ledger is lost and the phrase with it.

1. **Request.** The owners sign a Safe transaction requesting removal. A **14-day** waiting period
   starts.
2. **While it waits, the Safe is frozen.** Only three things work:
   - **Cancel**, by the owners.
   - **Rescue transfers:** moving ETH, tokens or NFTs out, with the normal quantum approval and the
     owners' threshold.
   - After 14 days, the **final removal**.
3. **Finish.** After 14 days the owners remove the Guard. The Safe works as an ordinary Safe again.

Only owners can cancel. The Quantum Administrator cannot block a removal.

**If you did not request it, cancel it.** A removal request you did not expect means some owner keys
may be compromised. Cancel it, then consider moving funds to a new Safe with rescue transfers. Run
the event watcher, or use the Safe App's alerts, so you hear about a request in time.

**Limit:** this protects you while honest owners still have working keys. If an attacker holds
enough owner keys and the honest owners do not, 14 days later the Guard comes off. See
[security](./security.md#residual-risks).

## Warnings and what they mean

**Refused, whatever you press.** Your Ledger will not sign these:

| Refusal | Why |
|---|---|
| Delegate call | A Safe transaction that runs another contract's code inside the Safe. It can do anything to the Safe. The only exception is a Safe batch through Safe's standard MultiSendCallOnly contract, where each step is checked and shown on its own |
| Gas refund | The Safe would pay someone for gas. This has been used to drain Safes |
| Unlimited approval | Lets someone spend any amount of your tokens forever |
| Validity window too long | The two times are more than 24 hours apart |
| Unsupported Safe action | A change to the Safe's own settings that is not on the list the Ledger can show |

**Strong warning: cannot decode this call.** The Ledger does not know this contract call, so it
shows the target address, the function code, the value and the raw data instead of a plain
description. Treat this as a stop sign. Approve only if you expected exactly this call and you can
check the data some other way.

**Descriptor fetch failed.** The app could not download the description of a contract. You will see
the warning above instead of a plain description.

**A page asks for your recovery phrase.** It is an attack. Close it.

**Key not registered (slower verification).** The key's stored data is missing, so verification
costs more gas. It still works.

**Removal requested.** Someone asked to remove the Guard. If it was not your owners, cancel it.

## If something goes wrong

| What happened | What to do |
|---|---|
| Lost or broken Ledger, phrase safe | Restore the phrase on a new Ledger, install Fermion from Ledger Live. Everything comes back |
| Ledger stolen, PIN not known | The Ledger wipes itself after three wrong PINs. Restore on a new device |
| Ledger stolen with its PIN, or phrase exposed | **Wallet:** restore on another device and move everything to a new wallet under a new phrase, now. **Guard:** change the Guard key to one from a new phrase, or use emergency removal |
| Phrase lost, Ledger still works | Move funds to a new wallet under a new phrase while the device still works |
| Phrase and Ledger both lost | **Wallet:** the funds cannot be moved. **Guard:** owners use emergency removal |
| A send never arrived | It expired. Check the chain, then sign again |
| The Safe is frozen | A removal is pending. Cancel it or wait it out; rescue transfers still work |
