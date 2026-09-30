# On-chain Enforcement Layer

## Programming language

- Solidity

## Open-source libraries / tooling used

The enforcement layer is the Guard. It must not grow a parallel stack. See `fermionguard-module.md` for the pinned set:

- `@safe-global/safe-contracts` v1.5.0 — `BaseTransactionGuard`, `BaseModuleGuard`, `ITransactionGuard`, `IModuleGuard`, `Enum`, `ISafe` (`getTransactionHash`, `getModulesPaginated`, `getStorageAt`, `isOwner`), `MultiSendCallOnly`
- OpenZeppelin Contracts v5.2.0 — `EIP712`, `SignatureChecker`, `Nonces`, `BitMaps`, `DoubleEndedQueue`, `Bytes`, `SlotDerivation`, `TransientSlot`, `SafeCast`, `IERC20`, `IERC20Permit`
- PQ: FermionGuard's own clean-room XMSS verifier ([skalenetwork/xmss-solidity](https://github.com/skalenetwork/xmss-solidity), RFC 8391, with its primitives and input-validation rejections proven against the RFC in Halmos, and the root comparison that decides a well-formed signature resting on a hand composition argument plus vectors at h = 4, 10 and 20 — see its `PROOF.md`), verified fully on-chain when a pre-approval is created (`createPreApproval`, `createPayloadPreApproval`, `createAdminPreApproval`) and when a key is rotated (`rotateQuantumKey`); only `signatureHash` is stored
- Foundry for tests and proofs (`forge test`, plus Halmos on the executable specification under `contracts/test/registry-proof/`); Slither is a release gate, not yet wired into CI

No local copies of Guard/ERC165/hasher/signature code. The per-Safe pause and per-Safe nested-call depth counter are the only hand-written state guards (a global lock or pause would be a power over every Safe).

## Role in the FermionGuard MVP

The on-chain enforcement layer is the Safe Guard contract that validates the second authorization before execution.

## Responsibilities

- validates the second authorization before Safe execution (and, on Safe ≥ 1.5, before module execution)
- checks that the transaction matches a live pre-approval
- verifies both hybrid signature halves once, at pre-approval creation
- enforces the Safe's selector permit-list, the fixed deny-list, and fallback-handler / module posture
- rejects unauthorized or replayed transactions

## Implementation model

For the MVP, the enforcement layer is implemented as a Safe Guard. This is the recommended integration path because it acts at the Safe execution boundary and can revert a transaction before it reaches the target call.

## Required checks

- the owner threshold already approved the transaction (the Safe checks this before calling the Guard)
- the Safe has an Active key and is not paused
- the transaction matches a live pre-approval exactly: by `safeTxHash` pin, or by token + recipient + **exact** amount (TRANSFER) / target + value + calldata hash (PAYLOAD, ADMIN)
- the approval is unused, unrevoked and inside its validity window; its key is not revoked
- the quantum signature was verified at creation (both halves, one-time XMSS leaf consumed)
- `policyHash` is bound into the signed approval; it is not checked against an on-chain policy (amount caps and recipient allowlists are not yet enforced on-chain)

## Design intent

This is the final on-chain gate. It is the component that enforces the second authorization model and prevents unauthorized Safe activity.
