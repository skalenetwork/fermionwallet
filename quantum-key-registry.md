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
2. **Owners co-sign the root itself, off-chain.** Each Safe owner clear-signs EIP-712 `ApproveQuantumKey { safe, xmssRoot, treeHeight, parameterSet, registryNonce, validUntil }` on their own hardware wallet. No opaque key IDs are ever signed — a compromised frontend cannot substitute a root without invalidating every signature.
3. **Activate.** The Administrator submits `registerQuantumKey(root, treeHeight, parameterSet, ledgerAttestation, ownerSigs[])`. The contract verifies the owner threshold via the Safe's `checkSignatures`, verifies the attestation, bumps `registryNonce`, and atomically sets the key **`Active`**. Any previously active key transitions to `Rotated`.

Rules:
- exactly **one `Active` key per Safe** at any time
- owner signatures are bound to registry contract, chain, Safe, `registryNonce`, and `validUntil` — stale or aborted ceremonies are provably unusable once the nonce advances
- the Guard rejects pre-approvals signed by keys in any status other than `Active`
- rotation follows the same one-shot path, additionally requiring the old-key XMSS signature proof per the Guard's `rotateQuantumKey` rules

Neither side can act alone: the Administrator cannot activate a key without an owner-threshold set of signatures over the root, and the Safe owners cannot activate a root that was not generated and attested by the Administrator's hardware.

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
