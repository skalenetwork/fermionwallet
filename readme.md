# FermionWallet

<p align="center">
  <img src="./assets/fermionwallet-logo.svg?v=2" alt="FermionWallet logo — a fermion holding a quantum" width="420"/>
</p>

**The quantum-ready second authorization layer for institutional digital-asset custody.**

<p align="center"><a href="https://skalenetwork.github.io/fermionwallet/"><b>🌐 skalenetwork.github.io/fermionwallet</b></a> — product site</p>

Banks, qualified custodians, and enterprise treasuries already run the gold-standard stack: Gnosis Safe, policy engines, hardware keys, and regulated operations. FermionWallet does not replace that stack. It **hardens it** — adding a cryptographically independent second gate that sits in the execution path of every high-value transfer.

If a signer is compromised, a policy is misconfigured, or classical signatures eventually fall to quantum computers, the transfer still does not move. Not until a separate, domain-bound, post-quantum authorization says yes.

That is the product: **keep the wallets you already trust. Make the next decade of cryptographic risk irrelevant.**

## About the author

**Stan (Konstantin) Kladko** — the rare builder who has worked on both sides of the quantum threat: the physics that creates it and the cryptography that must survive it.

- **Quantum physicist by training** — Ph.D. from the Max Planck Institute, M.S. from Kharkov University; Otto Hahn Research Fellow at Stanford University, where he worked with Nobel laureate Robert B. Laughlin on strongly correlated quantum systems; Director's Fellow in the Theoretical Division at Los Alamos National Laboratory, conducting national-security research in quantum materials.
- **Production cryptographer by trade** — Core Cryptography Lead at Ingrian Networks (enterprise data-privacy infrastructure later absorbed into SafeNet/Thales HSM lineage) and core computer-science team member at Sun Microsystems.
- **Ran the lab that certifies the world's crypto** — Director of Aspect Labs / BKP Security, a Silicon Valley cryptographic-module testing laboratory operating under NIST's Cryptographic Module Validation Program (CMVP), delivering FIPS 140-2 validations, Common Criteria evaluations, and FISMA assessments for government-grade cryptography. His lab work included side-channel security — presenting SPA/DPA (power-analysis) testing methodology to the NIST community. He hasn't just built secure cryptography; he has been the examiner that governments trust to certify it.
- **Proven at blockchain scale** — Co-founder and CTO of SKALE, an Ethereum-aligned blockchain network securing real value in production with BLS threshold cryptography his team took from paper to mainnet.
- **Serial infrastructure founder** — previously co-founded Galactic Exchange (big-data container clusters) and Cloudessa (cloud network-access security).

Few people on earth have run quantum-materials research at a national lab, directed a NIST-accredited cryptographic validation laboratory, shipped enterprise-grade cryptography, and operated a live blockchain network. That intersection is exactly what post-quantum custody requires — and it is why institutions evaluating their PQ migration path start the conversation with Stan.

FermionWallet is his answer to the question every custody board is now asking: *what protects the vault the day classical signatures stop being enough?*

---

## Why this exists

Institutional custody is already excellent at *who* can sign. It is not yet excellent at *what happens when those signatures are no longer enough*.

- Multisig is governance. It is not a quantum hedge.
- Hardware isolation is operational security. It is not a second cryptographic domain.
- Off-chain policy is useful. It is not an on-chain veto.

FermionWallet closes that gap. It installs as a **Safe Guard** — the official Gnosis Safe pre-execution hook — and refuses any ERC-20 movement that lacks a matching, time-bound, nonce-protected, quantum-signed pre-approval.

Owners still sign. Governance still governs. The Guard is the last word.

---

## The 2-of-2 model institutions actually need

| Layer | What it is | Who it protects against |
|---|---|---|
| **First authorization** | Existing Safe owners, thresholds, and treasury workflow | Rogue operators, lost devices, internal process failure |
| **Second authorization** | FermionWallet quantum key + policy-bound pre-approval, enforced on-chain | Compromised signers, replay, allowance drains, future quantum attacks on classical keys |

Two independent cryptographic domains. One execution path. Zero silent bypasses.

This is the control model regulated custodians already describe to examiners — dual control, independent verification, fail-closed enforcement — expressed as a smart-contract primitive rather than a slide in a SOC 2 appendix.

---

## Built for the desks that move real AUM

FermionWallet is designed for teams that cannot afford a “move fast and hope” wallet:

- **Qualified custodians and digital-asset banks** that must prove dual control to regulators, not just to themselves
- **Corporate and protocol treasuries** sitting on Safe vaults that already hold eight- and nine-figure balances
- **Asset managers and funds** that need policy-bound transfers, immutable audit trails, and a credible post-quantum roadmap
- **Prime brokers and settlement platforms** that want a drop-in enforcement layer without ripping out Safe, HSM, or existing ops tooling

If your mandate is *client assets, bank-grade controls, and a 10-year cryptographic horizon*, this is the add-on that belongs in the architecture review.

---

## What investors are looking at

**Category.** Post-quantum security for on-chain institutional custody — not a new wallet, not a new chain, not another consumer seed-phrase app.

**Wedge.** The Gnosis Safe Guard is a standard, audited integration point already in production at the institutions that matter. FermionWallet rides that rail. Sales cycle starts with “install a Guard,” not “migrate the vault.”

**Moat.**
- On-chain enforcement, not a backend promise
- Domain-separated, chain-bound, single-use quantum authorizations
- Policy as a hard cap (token, amount, recipient, expiry) — never a suggestion
- Explicit denial of the classic drain paths: `approve`, `permit`, `transferFrom`, `delegatecall`, module bypass, refund abuse, guard removal

**Why now.** NIST has standardized post-quantum signatures. Institutional boards are asking about cryptographic agility. The wallets that hold the assets have not yet answered. FermionWallet is that answer, shipped as an add-on rather than a rip-and-replace.

**Why this shape of product.** We did not invent a fake “contract signer.” We implemented the real Safe execution model: `ITransactionGuard.checkTransaction` as a veto, `setGuard` as the install path, and a hardening program that treats module bypass, nonce quirks, reentrancy, and refund drains as first-class threats.

---

## Product, in one sentence

A Safe Guard that will not let the vault move a token unless a quantum-safe second key has already authorized *that exact* transfer, on *that* chain, to *that* recipient, for *that* amount, once.

---

## Architecture at a glance

```text
Treasury / Ops / Custody UI
            |
            v
FermionWallet Add-on Service
  - generate PQ / hybrid keys
  - create time-bound pre-approvals
  - bind policyHash + chain + Safe
            |
            v
Quantum Key Registry          Pre-approval Engine
  - public-key metadata         - nonce, expiry, revoke
  - rotation / status           - single-use consumption
            |
            v
        Safe Guard  <—— last on-chain veto
            |
            v
     Gnosis Safe Wallet
  - existing owners & threshold
  - executes only if Guard returns
```

Full design: [`fermionwalletspec.md`](./fermionwalletspec.md)

---

## Security posture (what we refuse to hand-wave)

- Real post-quantum or hybrid signatures — HMAC demos are not production claims
- Exact calldata matching, not “a pre-approval ID exists”
- Chain ID + Safe address + nonce + policyHash domain separation
- Transaction-guard *and* module-guard coverage so `execTransactionFromModule` cannot walk around the gate
- Fail-closed pause, time-locked unpause, time-locked emergency de-guard (so a bug cannot brick client funds)
- Non-upgradeable Guard; new code ships as a new Guard set by Safe governance
- Selector allowlist: `transfer` and documented wrap/unwrap only

Details live in [`fermionwallet-guard-module.md`](./fermionwallet-guard-module.md).

---

## Status

MVP specification and a JavaScript prototype of key, policy, and pre-approval flows. The Guard contract is specified against the official Safe `ITransactionGuard` interface.

This is early. The category is not.

---

## Prototype

```js
import { ERC20Token, FermionWallet } from './src/index.js';

const token = new ERC20Token('Fermion', 'FERM');
const wallet = new FermionWallet('0xOwner');

token.mint('0xOwner', 1000n);
const quantumKey = wallet.generateQuantumKeyPair();

const approval = wallet.createPreApproval({
  token,
  spender: '0xVault',
  amount: 200n,
  validFrom: Date.now() - 1000,
  validTo: Date.now() + 60000,
  nonce: 'n-1',
  quantumKeyId: quantumKey.quantumKeyId,
  policyHash: 'treasury-policy-v1'
});

console.log(wallet.validatePreApproval(approval.preApprovalId));
console.log(wallet.executePreApprovedTransfer(approval.preApprovalId, '0xRecipient', 200n));
```

```bash
npm test
```

---

## For operators, risk, and investment committees

If you already custody on Safe, FermionWallet is the smallest possible change with the largest possible security delta: one Guard, one second key domain, one on-chain veto.

If you are allocating to the infrastructure that will still be standing when classical signatures are a footnote, this is the layer to underwrite.

---

**Keep the vault. Add the future.**
