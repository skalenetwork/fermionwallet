# Quantum Key Registry

## Programming language

- Solidity for the on-chain registry implementation
- JavaScript for the read-only backend cache/indexer

## Open-source libraries / tooling used

- OpenZeppelin upgradeable patterns if used in a contract registry
- ethers.js or viem for contract interaction
- Node.js crypto APIs for hashing and validation

## Role in the FermionWallet MVP

The quantum key registry stores the metadata and state of registered quantum keys used for second authorization.

The primary registered key is the **Quantum Administrator's permanent XMSS root** (RFC 8391 / NIST SP 800-208): one long-lived public root hash covering up to 2^h pre-approval signatures, with per-leaf-index usage tracked on-chain to prevent the catastrophic reuse of a one-time WOTS+ leaf.

## Responsibilities

- stores public key metadata
- stores key usage status
- tracks active, rotated, and revoked keys
- enforces the **co-signed one-shot registration** lifecycle described below: activation requires owner-threshold signatures over the root itself plus the Administrator's hardware attestation, in a single transaction
- binds a quantum key to a Safe and supported token context
- supports registration and rotation

## Key activation lifecycle (co-signed one-shot registration)

A key becomes **the quantum approval key** for a Safe in a single on-chain transaction, jointly authorized off-chain:

1. **Generate.** The Quantum Administrator generates the XMSS key with Ledger (see the key ceremony in [fermionwallet-add-on-service.md](./fermionwallet-add-on-service.md)); only the public root leaves the hardware boundary, attested by a Ledger-signed EIP-712 `QuantumKeyAttestation`.
2. **Owners co-sign the root itself, off-chain.** Each Safe owner clear-signs EIP-712 `ApproveQuantumKey { safe, quantumAdmin, xmssRoot, xmssSeed, treeHeight, parameterSet, registryNonce, validUntil }` on their own hardware wallet (the public `xmssSeed` is a mandatory RFC 8391 verification input and is registered alongside the root). No opaque key IDs are ever signed — a compromised frontend cannot substitute a root (or swap in an attacker's Administrator address) without invalidating every signature.
3. **Activate.** The Administrator submits `registerQuantumKey(safe, quantumAdmin, root, xmssSeed, treeHeight, parameterSet, validUntil, ledgerAttestation, ownerSigs)` — `quantumAdmin` is the Administrator's Ledger EOA, stored as the classical verifier address for every hybrid pre-approval. The contract verifies the owner threshold via the Safe's `checkSignatures`, verifies the attestation is signed by `quantumAdmin`, bumps `registryNonce`, and atomically sets the key **`Active`**. Any previously active key transitions to `Rotated`.

Rules:
- exactly **one `Active` key per Safe** at any time
- owner signatures are bound to registry contract, chain, Safe, `registryNonce`, and `validUntil` — stale or aborted ceremonies are provably unusable once the nonce advances
- the Guard rejects pre-approvals signed by keys in any status other than `Active`
- rotation follows the same one-shot path, additionally requiring the old-key XMSS signature proof per the Guard's `rotateQuantumKey` rules

Neither side can act alone: the Administrator cannot activate a key without an owner-threshold set of signatures over the root, and the Safe owners cannot activate a root that was not generated and attested by the Administrator's hardware.

## Key rotation procedure (Quantum Administrator)

Rotation is the same one-shot co-signed path as registration, plus **proof of possession of the old key**. It is the only way forward at exhaustion and the standard response to device replacement.

### When to rotate

| Trigger | Urgency |
|---|---|
| Leaf usage ≥ 80% (device shows amber bar) | Schedule within the quarter |
| Leaf usage ≥ 95% ("Rotation overdue" interstitial) | Rotate now — at 100% the app refuses to sign |
| Planned device replacement / Administrator handover | Before decommissioning the old device |
| Suspected key or device compromise | **Do not use this procedure** — revoke first, then use the emergency path below |

### Routine rotation — step by step

1. **Settle the queue.** Pre-approvals already created on-chain were fully verified at creation and **remain valid** under the old key until consumed, expired, or revoked — rotation only stops *new* creations. Still, drain or revoke anything pending to keep the audit trail clean.
2. **Generate the new key.** On the new Ledger (or via the old device's explicit *Reset* flow if reusing hardware): `GEN_XMSS_KEY` → `GET_XMSS_ROOT`. Record the new ceremony code (6 BIP-39 words). The new device clear-signs the EIP-712 `QuantumKeyAttestation` for the new root (`ledgerAttestation`).
3. **Prove possession of the old key.** On the **old** device, run the rotation flow (`SIGN_ROTATION`): the screen shows the red **ROTATE QUANTUM KEY** header, old-root vs new-root ceremony words, and the abandoned-leaf count. Physical confirmation releases an XMSS signature by the old key over `RotateQuantumKey { safe, oldQuantumKeyId, newQuantumAdmin, newXmssRoot, treeHeight, parameterSet, registryNonce }` — consuming one final leaf of the old key (`oldKeyXmssProof`).
4. **Collect owner co-signatures.** Each Safe owner clear-signs the same `RotateQuantumKey` struct on their own hardware wallet, verifying the **new** root's ceremony words against the Administrator's out-of-band readout — same threshold and same anti-substitution property as registration.
5. **Submit.** The Administrator (via the relayer) calls `rotateQuantumKey(safe, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, validUntil, oldKeyXmssProof, ledgerAttestation, ownerSignatures)`. Atomically: old key → `Rotated`, new key → `Active`, `registryNonce` bumped. Missing any of the three proofs (old-key XMSS, new-key attestation, owner threshold) reverts.
6. **Verify and decommission.** Create and execute one dust-value pre-approval with the new key end-to-end. Only after it executes, wipe the old device (its remaining leaves are dead — the Guard rejects non-`Active` keys).

If the Administrator's address changes (`newQuantumAdmin ≠ quantumAdmin`), owners are co-signing the handover too — the struct binds the new address, so a frontend cannot swap Administrators covertly.

### Emergency rotation — old key unavailable (lost / destroyed / compromised device)

The old-key possession proof is impossible, so the path is Safe governance with a time lock:

1. **If compromise is suspected:** an owner or the Administrator immediately calls `revokePreApproval` on anything pending and the Guard's pause path (fail-closed).
2. Owners create an **ADMIN-class pre-approval–independent** governance action per the Guard's emergency rules (`ADMIN_TIMELOCK` applies; watchers can cancel during the delay) that revokes the old key (`Active` → `Revoked`).
3. Once revoked, a **fresh registration** (not rotation) runs on a new device: full ceremony, owner co-signatures, new `registerQuantumKey` — the one-Active-key rule is satisfied because the old key is `Revoked`, not `Active`.
4. The time lock is the security boundary: a thief holding only the stolen Ledger cannot beat the owners to a quiet key swap, and owners alone cannot instantly bypass the quantum layer.

### Invariants (all enforced on-chain)

- Exactly one `Active` key per Safe before and after; the switch is atomic — there is no window with zero or two active keys.
- Old-key pre-approvals created before rotation remain executable; the old key can create nothing new.
- `registryNonce` bump invalidates any concurrently-running stale ceremony.
- Rotation never touches Safe ownership, the Guard, or funds — it is key-layer only.

## Key states

| Status | Meaning |
|---|---|
| `Active` | co-signed and registered; the one key the Guard verifies against |
| `Rotated` | superseded by a newer registered key; kept for audit |
| `Revoked` | emergency-disabled per the Guard's access-control rules |

(No on-chain `Proposed` state: the pending phase lives entirely in the off-chain ceremony session, keeping the contract state machine minimal and spam-free.)


## Implementation requirement: on-chain only

The registry **must be a smart contract**. An earlier draft allowed a backend registry as an MVP option; that is withdrawn as a security contradiction: the used-leaf-index bitmap is consensus-critical (XMSS leaf reuse enables forgery), and the Guard can only enforce what it can read on-chain at execution time. A backend that "verifies through the Guard" would make the Guard trust off-chain state — exactly the oracle-of-approval anti-pattern the spec forbids.

The backend may keep a **read-only cache/index** of registry state for UI and notifications. On any divergence, the chain wins; the service must resync from chain before releasing any signature.

## Key metadata stored

- quantumKeyId
- xmssRoot (the XMSS public root)
- xmssTreeHeight and used-leaf-index bitmap
- status
- createdAt
- rotatedAt
- useCounter
- associated Safe address
- associated ERC-20 token address

## Design intent

The registry is required so that the Safe Guard can verify a quantum signature against a known and trusted key state before allowing the transaction to proceed.
