# Pre-approval Engine

## Programming language

- JavaScript
- Solidity if the approval logic is enforced on-chain

## Open-source libraries / tooling used

- Node.js crypto APIs
- ethers.js or viem
- OpenZeppelin library patterns for safe arithmetic and validation
- optional JSON schema or validation libraries for request validation

## Role in the FermionWallet MVP

The pre-approval engine creates and validates time-bound, nonce-protected approvals for ERC-20 transfers. (Wrap/unwrap flows were removed from the MVP — see the security note in [fermionwalletspec.md](./fermionwalletspec.md) §7.1.)

## The Quantum Administrator

Every pre-approval must be signed by the **Quantum Administrator** — a designated role holding a **permanent XMSS key** (RFC 8391 / NIST SP 800-208).

- The Administrator's XMSS public root is registered once in the quantum key registry (`quantumKeyId` → root hash).
- Each pre-approval consumes exactly one XMSS leaf index; a `XMSS-SHA2_20_256`-class key covers ~1M approvals before rotation.
- The on-chain engine records used leaf indices in a bitmap and **reverts on any index reuse** — statefulness is enforced on-chain, not just in the service.
- The signing service must persist its leaf-index counter atomically *before* releasing a signature; a crash-recovery gap that reuses an index is a critical incident.

### Leaf-index synchronization discipline

Three counters exist (service counter, device/HSM counter in Phase 2, on-chain bitmap) and they **will** drift — reorgs, dropped transactions, crashes, restores. The rules that make drift safe:

1. **The on-chain bitmap is the single source of truth.** All other counters are advisory optimizations.
2. **Fail toward waste, never toward reuse.** Any ambiguity about whether an index was used (crash mid-release, tx dropped, RPC timeout) resolves by *skipping* that index permanently. Leaves are cheap (~1M per key); reuse is a forgery.
3. **Resync before every signature.** The service reads the highest used index and bitmap state from chain before releasing a signature, and refuses to sign at an index ≤ the highest on-chain used index.
4. **Monotonicity is local per counter.** The device counter (Phase 2) never decrements, even if the chain shows gaps; the service counter never resets from a backup — a restored-from-backup service must resync from chain and skip forward past its own recorded maximum plus a safety margin.
5. **Desync alarms.** If the service observes an on-chain used index it did not release, that is a key-compromise indicator: page the Administrator, pause the engine (fail-closed), and initiate rotation.
- When the index space nears exhaustion, the Administrator rotates to a new XMSS root with old-key + new-key signature proofs.

## Quantum Administrator hardware: Ledger

The Quantum Administrator operates from a **Ledger hardware wallet**. Since no production Ledger app signs XMSS today, the spec defines two phases.

### Phase 1 (MVP): Ledger anchors the hybrid signature

The pre-approval is valid only when **both** halves verify, and the Ledger provides the classical half:

1. The Administrator's Ledger holds a dedicated secp256k1 key (standard Ethereum app; no custom firmware).
2. The add-on service composes the exact pre-approval payload (token, recipient, amount, validFrom/validTo, nonce, `xmssLeafIndex`, policyHash, Safe address, chain ID) as a typed **EIP-712** message.
3. The Administrator reviews the human-readable fields **on the Ledger screen** and physically confirms — this is the hardware-enforced human-in-the-loop for every pre-approval.
4. The XMSS half is produced by the add-on service's keystore (encrypted at rest, ideally inside an HSM or secure enclave), releasing a signature **only when presented with the matching, fresh Ledger EIP-712 signature** over the same payload.
5. On-chain, `createPreApproval` verifies both: the ECDSA signature against the registered Administrator address (OpenZeppelin `SignatureChecker` + `EIP712`) and the XMSS signature against the registered root.

Threat model consequence: compromising the XMSS keystore alone cannot create a pre-approval (no Ledger confirmation); compromising the Ledger alone cannot either (no XMSS signature). Quantum exposure is limited to the ECDSA half, which is never the sole gate.

### Phase 2 (target): XMSS on the Ledger secure element

A custom Ledger app — specified in [`ledger-xmss-app.md`](./ledger-xmss-app.md) — implementing XMSS signing with the **leaf-index counter kept as a monotonic counter inside the secure element**:

- index reuse becomes impossible even with a fully compromised host machine,
- the XMSS secret never leaves the device,
- the on-chain bitmap remains as defense in depth.

Constraints to engineer for: secure-element NVRAM wear limits on counter updates, XMSS signing time on the device's MCU, and Ledger app review/audit. Until Phase 2 ships, Phase 1 is the normative deployment.

### Forbidden shortcuts

- Deriving the XMSS key from the Ledger seed and re-deriving on a host: a device restore resets no state and invites leaf reuse — prohibited.
- Using the Ledger ECDSA signature *alone* as the "quantum" authorization — it is classical; it is only the hybrid anchor.

## Responsibilities

- creates pre-approvals for token actions
- stores approval metadata, including amount and expiry
- ensures approvals are nonce-protected to prevent replay attacks
- rejects expired or revoked approvals
- enforces policyHash validation
- ensures the quantum signature matches the approved key

## Standard pre-approval data

Every pre-approval carries an `approvalClass` — `TRANSFER`, `PAYLOAD`, or `ADMIN` (defined in [fermionwallet-guard-module.md → Pre-approval classes](./fermionwallet-guard-module.md#pre-approval-classes)) — plus:

- approvalClass (TRANSFER | PAYLOAD | ADMIN)
- token, spender or recipient, amount (TRANSFER class)
- target, value, dataHash = keccak256(exact calldata) (PAYLOAD and ADMIN classes — this is how native ETH sends and administrative self-calls such as `setGuard(address(0))` are representable at all; without these fields the Guard could never be removed and the Safe would brick)
- validFrom (ADMIN class: must be ≥ creation time + `ADMIN_TIMELOCK`, enforced on-chain)
- validTo
- nonce
- quantumKeyId (the Quantum Administrator's registered XMSS root)
- xmssLeafIndex (single-use, tracked on-chain)
- policyHash
- signature (XMSS, verified fully on-chain at creation)

## Validation rules

- the approval must still be active
- the approval must not be expired
- the approval must not be revoked
- the nonce must not have been reused
- the XMSS leaf index must not have been used before (on-chain bitmap check)
- the XMSS signature must verify against the Administrator's registered root
- the transfer amount must remain within the approved amount

## Design intent

The pre-approval engine is the policy gate that converts a quantum key into a usable second authorization for a specific transfer.
