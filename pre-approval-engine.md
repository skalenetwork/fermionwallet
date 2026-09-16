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

The pre-approval engine creates and validates time-bound, nonce-protected approvals for transfers and wrap/unwrap operations.

## Responsibilities

- creates pre-approvals for token actions
- stores approval metadata, including amount and expiry
- ensures approvals are nonce-protected to prevent replay attacks
- rejects expired or revoked approvals
- enforces policyHash validation
- ensures the quantum signature matches the approved key

## Standard pre-approval data

- token
- spender or recipient
- amount
- validFrom
- validTo
- nonce
- quantumKeyId
- policyHash
- signature

## Validation rules

- the approval must still be active
- the approval must not be expired
- the approval must not be revoked
- the nonce must not have been reused
- the quantum signature must match the registered key
- the transfer amount must remain within the approved amount

## Design intent

The pre-approval engine is the policy gate that converts a quantum key into a usable second authorization for a specific transfer.
