# FermionWallet Add-on Service

## Programming language

- JavaScript
- TypeScript-compatible SDK style

## Open-source libraries / tooling used

- Node.js runtime
- ethers.js or viem
- `@ledgerhq/hw-app-eth` + `@ledgerhq/hw-transport-node-hid` (backend) / `@ledgerhq/hw-transport-webhid` (Safe App key ceremony) for Ledger EIP-712 signing
- `@safe-global/safe-apps-sdk` for the Safe App UI, including submitting the `registerQuantumKey` Safe transaction
- crypto module for key generation and HMAC signing
- express or similar HTTP server framework
- zod or Joi for validation if used in a backend implementation

## Role in the FermionWallet MVP

The FermionWallet add-on service is the policy and validation layer that sits between the Safe and the quantum key system.

## Responsibilities

- generates quantum keys in JavaScript
- creates pre-approvals for transfers
- validates quantum signatures and policy metadata
- checks whether a proposed transfer meets policy constraints
- confirms whether a transfer is eligible for second authorization
- coordinates the interaction between the Safe workflow and the quantum approval flow

## Core responsibilities in practice

- create a quantum key pair in JavaScript
- register the public key hash and token binding
- create a time-bound, nonce-protected pre-approval
- validate expiry, nonce, and policyHash
- return authorization status to the Safe Guard
- orchestrate the Quantum Administrator's Ledger flow: compose the EIP-712 pre-approval payload, obtain on-device confirmation, and release the XMSS signature only against a matching, fresh Ledger signature (see `pre-approval-engine.md`)

## User experience / UI integration

The Safe{Wallet} UI does not natively understand Guard requirements, so quantum-authorization visibility is delivered in three layers.

### 1. FermionWallet Safe App (primary UX)

A Safe App — an iframe dApp running inside the Safe{Wallet} interface, built with `@safe-global/safe-apps-sdk` — reads the transaction queue via the Safe Transaction Service API and overlays quantum status on every pending transaction:

- 🟡 **Quantum authorization required** — Safe owners have signed, but no matching pre-approval exists yet. The row shows an **"Authorize with quantum key"** action that opens the add-on flow and creates the signed, time-bound pre-approval.
- 🟢 **Ready to execute** — a valid, unexpired, unused pre-approval matches the exact transaction payload (token, recipient, amount, nonce, policyHash, chain).
- 🔴 **Blocked** — pre-approval expired, revoked, consumed, or policy-mismatched, with the specific reason displayed.

Status is computed by comparing the queued Safe transaction hash and decoded calldata against the pre-approval registry — the same matching rules the Guard enforces on-chain, so the UI never shows green for a transaction the Guard would revert.

### 2. Simulation as a safety net

Safe{Wallet} simulates `execTransaction` before enabling the Execute button. Without a valid pre-approval, the Guard reverts with a descriptive custom error such as `FermionApprovalMissing(safeTxHash)`, `FermionApprovalExpired(id)`, or `FermionPolicyViolation(reason)`. The Safe UI surfaces the failed simulation and its revert reason, so even a user who has never installed the FermionWallet Safe App:

- cannot execute a transaction the Guard will reject,
- sees a human-readable explanation of what is missing.

This is why the Guard spec mandates explicit custom errors on every revert path — they are the fallback UI.

### 3. Add-on service dashboard and notifications

The add-on service polls the Safe Transaction Service for the enrolled Safes and pushes notifications (email, Slack, webhook) when a transaction enters the queue without quantum authorization:

> "Tx #42 — 500,000 USDC → 0xabc…def — awaiting quantum authorization. Pre-approval window closes in 6 h."

The dashboard mirrors the Safe App's traffic-light view for treasury operators and risk teams who work outside Safe{Wallet}, and records an audit log of who authorized what and when.

### 4. Quantum key ceremony (Quantum Administrator onboarding)

A dedicated **"Quantum key" tab** in the FermionWallet Safe App runs the key ceremony. Design goals: **one on-chain transaction, no opaque IDs ever signed, every hash verified on two independent surfaces, resumable at every step, under 10 minutes end to end.** The same wizard is reused for rotation.

The ceremony replaces a two-transaction propose/approve state machine with a **single-shot registration co-signed off-chain by the Safe owners over the root itself** — structurally eliminating the UI-swap attack (a malicious frontend cannot substitute a root without invalidating every owner signature).

**Stage A — Preflight (Administrator).**
The app checks everything that could fail later, before anything is generated: Ledger connected over WebHID (`@ledgerhq/hw-transport-webhid`), correct app open (Ethereum app in Phase 1; the [Ledger XMSS app](./ledger-xmss-app.md) in Phase 2), device address == registered `quantumAdmin`, registry contract reachable, current `registryNonce` fetched, owner list and threshold read from the Safe. A green checklist is shown; the "Generate key" button stays disabled until all checks pass.

**Stage B — Generate (Administrator).**
- *Phase 2 (target):* `GET_XMSS_ROOT` — seed generated inside the secure element; only root, tree height, parameter set returned.
- *Phase 1 (MVP):* the add-on service generates the XMSS keypair in the HSM; the Ledger clear-signs an EIP-712 `QuantumKeyAttestation { xmssRoot, treeHeight, parameterSet, safe, chainId, registryNonce }` on-device. Never derived from the Ledger seed (restore would reset XMSS state → leaf reuse).

The app derives a **ceremony code** from the root: 6 BIP-39 words (e.g. `orbit-velvet-canyon-lemon-tiger-frost`) plus the first/last 4 hex bytes. The Administrator confirms the code matches the device/HSM display before continuing. Words beat hex: they are readable over a phone call and mis-verification is an order of magnitude less likely than hex skimming.

**Stage C — Collect owner signatures (owners, parallel).**
The app opens a **ceremony session** (add-on service, expiring `validUntil`, default 72 h) and notifies every Safe owner (email/Slack/push, links into the Safe App). Each owner sees one screen:

- the ceremony code in large type, with the instruction to verify it **out-of-band with the Administrator** (call, video, in person — not the same channel as the notification),
- full root hex, tree height (≈ lifetime pre-approvals), parameter set, Safe address, expiry,
- one action: **"Sign quantum key"** — a clear-signed EIP-712 `ApproveQuantumKey { safe, xmssRoot, treeHeight, parameterSet, registryNonce, validUntil }` on the owner's own hardware wallet. **The owner's device screen shows the root itself** — the second independent verification surface; the ceremony is exactly as trustworthy as this comparison, so the UI never abbreviates the root on this screen.

A live quorum tracker (`2 of 3 signed · expires in 41 h`) is visible to all participants and the Administrator. Signatures are EIP-712-bound to the registry contract, chain, Safe, and `registryNonce` — unusable on any other chain, Safe, ceremony, or after expiry. Any participant can **abort**; abort bumps a session flag, and completing any ceremony bumps `registryNonce` on-chain, so stale signatures can never activate.

**Stage D — Activate (Administrator, the only on-chain transaction).**
When the threshold is reached, the app **simulates first** (`eth_call`), showing the decoded result; then the Administrator submits
`registerQuantumKey(root, treeHeight, parameterSet, ledgerAttestation, ownerSigs[])`.
The contract verifies the owner threshold via the Safe's own `checkSignatures`, verifies the attestation, bumps `registryNonce`, and atomically sets the key **`Active`** (prior key → `Rotated`). Neither side can act alone: no owner quorum → no activation; no hardware-attested root → owner signatures verify nothing.

**Stage E — Proof of life.**
Before declaring success, the app performs an end-to-end check: (1) reads the root back from the chain and compares it to the locally held value — detecting any RPC/frontend tampering after the fact; (2) signs a **test pre-approval with leaf index 0** for a zero-value marker payload and verifies it via `eth_call` against the on-chain XMSS verifier. One leaf out of ~1M is spent proving the whole chain — Ledger → signature → verifier → registry — actually works, before real funds depend on it. The success screen shows: active ceremony code, activation tx hash, leaves remaining, and a printable **ceremony record** (root, code, participants, timestamps) for the compliance file.

**Ongoing health panel.** Active root fingerprint, leaf usage bar from the on-chain bitmap with warnings at 80/90/95% exhaustion, registration date, and a "Rotate key" action that re-runs Stages A–E with the additional old-key XMSS signature proof required by `rotateQuantumKey`.

**Resumability and failure handling.** Every stage is idempotent and resumable: Ledger disconnect → reconnect and continue; browser crash → session restored from the add-on service; owner signs twice → deduplicated; expiry reached → ceremony void, restart from Stage B (a fresh key costs nothing). All contract reverts are decoded to their custom errors (`RootAlreadyRegistered`, `StaleRegistryNonce`, `CeremonyExpired`, `InsufficientOwnerSignatures`, `AttestationMismatch`) with a one-line remedy for each.

**Definition of done for this UI** (acceptance criteria):
- [ ] exactly one on-chain transaction per registration or rotation
- [ ] no participant ever signs an identifier — only structs containing the full root
- [ ] the root is verified on ≥2 independent surfaces (Administrator's device + each owner's device) plus one out-of-band human check
- [ ] every step resumable after disconnect/crash without restarting the ceremony
- [ ] stale/aborted ceremonies provably unusable (nonce bump) — test-covered
- [ ] proof-of-life pre-approval verified before success is shown
- [ ] full ceremony ≤ 10 minutes with 3 owners online

### 5. Quantum transaction approval (the pre-approval flow)

The core recurring workflow: the Quantum Administrator reviews a queued Safe transaction and produces the XMSS pre-approval that lets it execute. Design goals: **the Administrator approves only what two independent surfaces agree on, one leaf per approval reserved atomically, every denial is as auditable as every approval, nothing blind-signed — ever.**

**Stage A — Triage queue.**
The "Approvals" tab lists every Safe transaction in 🟡 state across the enrolled Safes, sorted by pre-approval-window urgency. Each row shows decoded essentials (token, amount, recipient, Safe nonce) plus **risk flags** computed by the add-on service:

- 🆕 first-time recipient (never before received from this Safe)
- 📈 amount above the Safe's rolling 30-day median by >N×
- ⛔ selector the Guard will deny anyway (`approve`, `transferFrom`, delegatecall `MultiSend`) — shown as unapprovable, with the reason, so the Administrator never wastes a leaf on a doomed transaction
- ⏱️ Safe owner signatures incomplete (approving now is premature; the payload could still be replaced in the queue)

**Stage B — Independent payload verification.**
Opening a row shows the transaction reconstructed from **two independent sources**: the Safe Transaction Service record and a local decode of the on-chain queue data fetched via the app's own RPC. If they disagree, the flow hard-stops with a tamper warning. The screen shows: token (symbol + contract address), amount (decimals-adjusted + raw), recipient (checksummed, address-book label if known, 🆕 badge if not), Safe address and nonce, computed `safeTxHash`, and the validity window the Administrator is about to grant (picker, ≥15-minute granularity, policy-bounded maximum). For 🆕 recipients the UI requires an explicit "recipient verified out-of-band" checkbox before the sign button enables.

**Stage C — Hardware review and sign.**
The leaf index is **reserved atomically** in the add-on service before signing (crash between reserve and sign wastes one leaf; the reverse order would risk reuse — same invariant as the [Ledger XMSS app](./ledger-xmss-app.md)).

- *Phase 2 (target):* `SIGN_PREAPPROVAL` — the Ledger screen renders token, recipient, amount, window, Safe nonce, and leaf index; physical confirmation releases the XMSS signature from the secure element.
- *Phase 1 (MVP):* the Ledger clear-signs the EIP-712 `PreApproval` struct (same fields) on-device; the HSM releases the matching XMSS half only against that fresh signature.

The device screen is the second verification surface: what the Administrator confirms on hardware is exactly what the Guard will enforce. There is no raw-hash path in either phase.

**Stage D — Submit, simulate, confirm.**
The app simulates `createPreApproval` via `eth_call` (surfacing decoded custom errors — `LeafAlreadyUsed`, `PolicyViolation`, `WindowTooLong` — before gas is spent), submits, and waits for confirmation. On inclusion the queue row flips 🟡→🟢, Safe{Wallet} simulation starts passing, and operators are notified: *"Tx #42 quantum-authorized — executable until 18:40 UTC."* If the Safe transaction is edited or replaced after approval, its hash changes, the pre-approval no longer matches, and the row drops back to 🟡 with an explanation — approvals bind to exact payloads, never to intents.

**Stage E — Deny, with the same weight as approve.**
A **"Deny"** action records a Ledger-signed denial (off-chain, no leaf spent), notifies the operators with the Administrator's stated reason, and pins the row 🔴 in every dashboard. Denials enter the same audit log as approvals — a second-authorization system where refusals are invisible trains operators to route around the Administrator.

**Batching.** Separate transactions can be reviewed in one session, but each is signed individually — one leaf, one device confirmation, one payload per signature; never a "sign all" button. A genuine batch (`MultiSendCallOnly`, e.g. payroll) is **one** transaction and one signature: the UI decodes and displays every leg (target, amount, risk flags per leg), verifies the batch calldata from two independent sources, shows the batch `dataHash`, per-token totals, and leg count that will appear on the Ledger, and requires an explicit "I compared the hash" confirmation. The on-chain Guard re-decodes every leg regardless — a lying UI cannot smuggle an admin call or off-policy recipient inside a batch (see the Guard spec, "Batching (MultiSend)").

**Admin and payload approvals (non-transfer classes).** Native ETH sends and administrative self-calls (guard/module/owner changes) use the `PAYLOAD`/`ADMIN` pre-approval classes and get **visually distinct treatment**: a red "ADMINISTRATIVE" banner, the decoded self-call (e.g., `setGuard(0x0000…0000) — REMOVES THE GUARD`), and for `ADMIN` class a **timelock countdown** ("executable in 47 h 12 m") with a one-click **Revoke** available to the Administrator and highlighted to all owners for the full delay. The dashboard pushes an immediate notification to every owner when an `AdminPreApprovalCreated` event fires — the timelock only protects people who hear about the pending change.

**Audit trail.** Every approval/denial stores: safeTxHash, decoded payload, leaf index (or none), device confirmation timestamp, validity window, risk flags shown at decision time, and the outcome (executed / expired unused / superseded). Exportable for the compliance file.

**Definition of done for this UI** (acceptance criteria):
- [ ] approve button unreachable until both payload sources agree and (for 🆕 recipients) out-of-band verification is confirmed
- [ ] leaf reserved atomically before signature release — crash-tested; no path releases a signature for an unreserved leaf
- [ ] device screen shows all Guard-enforced fields; no blind-signing path exists in either phase
- [ ] unapprovable transactions (Guard-denied selectors) are flagged before a leaf can be spent
- [ ] payload replacement after approval demotes status automatically within one polling interval
- [ ] denials are Ledger-signed, logged, and visible to operators
- [ ] simulation runs before every submission; all custom errors decoded with remedies

### Authorization flow, end to end

1. Operator queues a transfer in Safe{Wallet}; owners sign as usual.
2. Safe App / dashboard flags the transaction 🟡 "quantum authorization required".
3. An authorized key holder opens the FermionWallet flow, reviews the exact payload, and approves with the quantum key — creating the on-chain pre-approval.
4. Status flips to 🟢; simulation now passes.
5. Anyone executes; the Guard validates and consumes the pre-approval atomically.

## Design intent

This service is the operational layer that makes the governance layer and the cryptographic layer work together. It does not replace the Gnosis Safe; it adds the quantum-safe second authorization to the workflow.
