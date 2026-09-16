# On-chain Enforcement Layer

## Programming language

- Solidity

## Open-source libraries / tooling used

The enforcement layer is the Guard. It must not grow a parallel stack. See `fermionwallet-guard-module.md` for the pinned set:

- `@safe-global/safe-contracts` — `BaseTransactionGuard`, `ITransactionGuard`, `IModuleGuard`, `Enum`, `ISafe.getTransactionHash`
- OpenZeppelin Contracts — `Pausable`, `ReentrancyGuardTransient`, `AccessControl`, `EIP712`, `SignatureChecker`, `BitMaps`, `EnumerableSet`, `IERC20`, `Address`, `SafeCast`, `Time`
- PQ: pinned audited verifier on-chain, or `liboqs` / `@noble/post-quantum` at `createPreApproval` with on-chain `signatureHash` only
- Foundry + Slither for tests and static analysis

No local copies of Guard/ERC165/hasher/pause/reentrancy/signature code.

## Role in the FermionWallet MVP

The on-chain enforcement layer is the Safe Guard contract that validates the second authorization before execution.

## Responsibilities

- validates the second authorization before Safe execution
- checks that the transfer matches a valid pre-approval
- verifies quantum signature integrity
- enforces policy constraints
- rejects unauthorized or replayed transactions

## Implementation model

For the MVP, the enforcement layer is implemented as a Safe Guard. This is the recommended integration path because it acts at the Safe execution boundary and can revert a transaction before it reaches the target call.

## Required checks

- Safe approval exists
- transaction matches the pre-approved transfer parameters
- quantum signature is valid
- key is active and registered
- nonce is valid and unused
- expiry is valid
- policyHash matches
- amount and recipient are within approved bounds

## Design intent

This is the final on-chain gate. It is the component that enforces the second authorization model and prevents unauthorized Safe activity.
