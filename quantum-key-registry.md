# Quantum Key Registry

## Programming language

- Solidity for the on-chain registry implementation
- JavaScript for the read-only backend cache/indexer

## Open-source libraries / tooling used

- OpenZeppelin Contracts (non-upgradeable): `EIP712`, `Nonces`, `BitMaps`, `SignatureChecker`, `SafeCast`
- The registry is `contracts/src/QuantumKeyRegistry.sol`, an abstract base compiled into the one deployed `FermionWalletGuard` contract (one address, one storage)
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
- binds a quantum key to one Safe (the key covers all assets; there is no per-token binding)
- supports registration and rotation

## Key activation lifecycle (co-signed one-shot registration)

A key becomes **the quantum approval key** for a Safe in a single on-chain transaction, jointly authorized off-chain:

1. **Generate.** The Quantum Administrator generates the XMSS key with Ledger (see the key ceremony in [fermionwallet-add-on-service.md](./fermionwallet-add-on-service.md)); only the public root leaves the hardware boundary, attested by a Ledger-signed EIP-712 `QuantumKeyAttestation`.
2. **Owners co-sign the root itself, off-chain.** Each Safe owner clear-signs EIP-712 `ApproveQuantumKey { safe, quantumAdmin, xmssRoot, xmssSeed, treeHeight, parameterSet, registryNonce, validUntil }` on their own hardware wallet (the public `xmssSeed` is a mandatory RFC 8391 verification input and is registered alongside the root). No opaque key IDs are ever signed — a compromised frontend cannot substitute a root (or swap in an attacker's Administrator address) without invalidating every signature.
3. **Activate.** The Administrator submits `registerQuantumKey(safe, quantumAdmin, root, xmssSeed, treeHeight, parameterSet, validUntil, ledgerAttestation, ownerSigs)` — `quantumAdmin` is the Administrator's Ledger EOA, stored as the classical verifier address for every hybrid pre-approval. The contract verifies the owner threshold via the Safe's legacy `checkSignatures(bytes32 dataHash, bytes data, bytes signatures)` entry point (with the EIP-712 message itself as `data` — see below), verifies the attestation is signed by `quantumAdmin`, consumes the Safe's `registryNonce`, and sets the key **`Active`**. Registration is refused if the Safe already has an Active key (`SafeAlreadyEnrolled` — a replacement key goes through rotation), if this Safe registered the same root before (`RootAlreadyRegistered`), if `validUntil` has passed, or if the Safe has a fallback handler or unguarded enabled modules (the Guard's enrollment posture check). The Guard initialises the Safe's selector permit-list to `{transfer}` only at the Safe's **first** registration; registering a new key after an emergency revocation keeps the permit-list the owners have governed into place.

Rules:
- exactly **one `Active` key per Safe** at any time
- XMSS root uniqueness is scoped **per Safe**: reusing a root on another Safe is harmless and allowed, but reusing the same root for the same Safe rejects
- owner signatures are bound to the Guard contract (EIP-712 verifying contract), chain, Safe, `registryNonce`, and `validUntil` — stale or aborted ceremonies are provably unusable once the nonce advances
- new pre-approvals can only be created with the Safe's `Active` key; approvals already created under a key that was later `Rotated` stay executable, while a `Revoked` key's approvals do not
- rotation follows the same one-shot path, additionally requiring the old-key XMSS signature proof per the Guard's `rotateQuantumKey` rules

Neither side can act alone: the Administrator cannot activate a key without an owner-threshold set of signatures over the root, and the Safe owners cannot activate a root that was not generated and attested by the Administrator's hardware.

### Owner-signature compatibility

The registry uses Safe's legacy `checkSignatures(bytes32 dataHash, bytes data, bytes signatures)` form because it exists on Safe 1.3.0, 1.4.1, and 1.5.0. The v1.5-only overload must not be used for registration or rotation. Its selector is absent on older Safes, which either makes onboarding revert through the default fallback handler or, with no handler, can silently skip owner verification. The legacy form's `msg.sender`-as-executor caveat is harmless here because `msg.sender` is the registry contract, never a Safe owner.

Owner signatures are checked with the EIP-712 message as `data`: `dataHash` is the registry digest and `data` is its exact preimage, `0x1901 ‖ domainSeparator ‖ structHash`. This is what lets contract owners (a nested Safe, a smart-contract wallet) co-sign on Safe 1.3.0 and 1.4.1, which pass `data` — not the hash — to the owner's legacy `isValidSignature(bytes data, bytes signature)`; Safe 1.4.1 additionally requires `keccak256(data) == dataHash` for contract signatures (`GS027`). Safe 1.5.0 ignores `data` and asks contract owners `isValidSignature(bytes32 digest, bytes signature)`. A contract owner therefore approves the preimage (legacy) or the digest (1.5.0) of the same message; EOA owners sign the digest in every version.

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
2. **Generate the new key.** On the same Ledger — the app holds up to four keys, so `GEN_XMSS_KEY` puts the new key in a free slot and keeps the old one — or on a new Ledger for a device replacement or handover. Record the new ceremony code (6 BIP-39 words). The device holding the new key clear-signs the EIP-712 `QuantumKeyAttestation` for it (`SIGN_KEY_ATTESTATION`, `ledgerAttestation`).
3. **Prove possession of the old key.** With the **old** key's slot — on the same device, or on the old device — run the rotation flow (`SIGN_ROTATION`): the screen shows the red **ROTATE QUANTUM KEY** header, old-root vs new-root ceremony words, and the abandoned-leaf count. Physical confirmation releases an XMSS signature by the old key over `RotateQuantumKey { safe, oldQuantumKeyId, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, registryNonce, validUntil }` — consuming one final leaf of the old key (`oldKeyXmssProof`).
4. **Collect owner co-signatures.** Each Safe owner clear-signs the same `RotateQuantumKey` struct on their own hardware wallet, verifying the **new** root's ceremony words against the Administrator's out-of-band readout — same threshold and same anti-substitution property as registration.
5. **Submit.** The Administrator (via the relayer) calls `rotateQuantumKey(safe, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, validUntil, oldKeyXmssProof, ledgerAttestation, ownerSignatures)`. Atomically: old key → `Rotated`, new key → `Active`, `registryNonce` consumed, and any pending key revocation cancelled. Missing any of the three proofs (old-key XMSS, new-key attestation, owner threshold) reverts.
6. **Verify and retire.** Create and execute one dust-value pre-approval with the new key end-to-end. Only after it executes, retire the old key: *Settings → Retire key* on its slot (same device), or wipe the old device. Its unused leaves are dead either way — the registry accepts new pre-approvals only from the `Active` key.

If the Administrator's address changes (`newQuantumAdmin ≠ quantumAdmin`), owners are co-signing the handover too — the struct binds the new address, so a frontend cannot swap Administrators covertly.

### Emergency rotation — old key unavailable (lost / destroyed / compromised device)

The old-key possession proof is impossible, so the path is Safe governance with a time lock:

1. **If compromise is suspected:** any owner immediately calls `pauseSafe(safe)` (fail-closed) and `revokePreApproval` on pending transfer/payload approvals; pending ADMIN approvals are revoked by the Safe (owner threshold) or the Administrator.
2. The owner threshold signs EIP-712 `RequestKeyRevocation { safe, quantumKeyId, registryNonce, validUntil }` — no quantum signature is needed. Anyone submits `requestKeyRevocation(safe, validUntil, ownerSignatures)`, which records the exact `keyId` and starts `EMERGENCY_ROTATION_TIMELOCK` (set to the same value as the emergency de-guard timelock, e.g. 14 days). The request consumes the registry nonce, so the signatures work exactly once and cannot be replayed to re-arm a cancelled request; this also invalidates any ceremony signatures in flight. During the delay **only the Safe itself** can cancel (`cancelKeyRevocation`, an owner-threshold Safe transaction that the Guard never blocks) — the Administrator's key alone cannot, so a stolen Ledger cannot block the owners' remedy. After the delay, anyone calls `executeKeyRevocation(safe)`.
3. At execution, the registry revokes only that recorded key. If the Safe's active key changed in the meantime, `executeKeyRevocation` reverts with `RevocationSuperseded`; an owner-co-signed rotation cancels the pending revocation because the rotation itself resolves the compromise.
4. Once revoked, a **fresh registration** (not rotation) runs on a new device: full ceremony, owner co-signatures, new `registerQuantumKey` — the one-Active-key rule is satisfied because the old key is `Revoked`, not `Active`.
5. The time lock is the security boundary: a thief holding only the stolen Ledger cannot beat the owners to a quiet key swap, and owners alone cannot instantly bypass the quantum layer. The registration that follows is protected only by classical signatures (owner threshold plus the new Administrator's attestation). An adversary that can forge the owners' ECDSA keys can race it and register its own key the moment the revocation matures. See [threat-model.md §2.1](./threat-model.md#21-quantum-capable-attacker-the-headline-adversary).

### Invariants (all enforced on-chain)

- Exactly one `Active` key per Safe before and after; the switch is atomic — there is no window with zero or two active keys.
- Old-key pre-approvals created before rotation remain executable; the old key can create nothing new.
- `registryNonce` (OpenZeppelin `Nonces`) is consumed by every registration, rotation, revocation request and revocation, so every owner-signed registry message is single-use and any concurrently-running stale ceremony dies.
- A stale revocation request can never destroy the successor key; it is bound to the key that was active when requested.
- Rotation never touches Safe ownership, the Guard, or funds — it is key-layer only.

## Key states

| Status | Meaning |
|---|---|
| `Active` | co-signed and registered; the one key the Guard verifies against |
| `Rotated` | superseded by a newer registered key; kept for audit |
| `Revoked` | emergency-disabled via `requestKeyRevocation` → timelock → `executeKeyRevocation`; its approvals stop working |

(No on-chain `Proposed` state: the pending phase lives entirely in the off-chain ceremony session, keeping the contract state machine minimal and spam-free.)


## Implementation requirement: on-chain only

The registry **must be a smart contract**. An earlier draft allowed a backend registry as an MVP option; that is withdrawn as a security contradiction: the used-leaf-index bitmap is consensus-critical (XMSS leaf reuse enables forgery), and the Guard can only enforce what it can read on-chain at execution time. A backend that "verifies through the Guard" would make the Guard trust off-chain state — exactly the oracle-of-approval anti-pattern the spec forbids.

The backend may keep a **read-only cache/index** of registry state for UI and notifications. On any divergence, the chain wins; the service must resync from chain before releasing any signature.

## Key metadata stored

`KeyRegistration` (see the Guard spec's ABI):

- quantumKeyId (`keccak256(abi.encodePacked(safe, xmssRoot, registryNonce))`)
- safe
- quantumAdmin (the Ledger EOA that the ECDSA half is verified against)
- xmssRoot and xmssSeed (the XMSS public key)
- treeHeight (1..20) and parameterSet
- status
- createdAt, rotatedAt
- useCounter

Alongside: the used-leaf bitmap per key (`isLeafUsed`), the Safe's Active key (`safeToQuantumKey`), the sticky `enrolledSafe` flag, `registryNonce`, per-Safe `rootRegistered`, and the pending revocation (`keyRevocationExecutableAt`, `keyRevocationKeyId`).

## Design intent

The registry is required so that the Safe Guard can verify a quantum signature against a known and trusted key state before allowing the transaction to proceed.
