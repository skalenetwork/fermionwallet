# Gnosis Safe Wallet

## Programming language

- Solidity for the Safe contracts themselves
- JavaScript/TypeScript for the surrounding client integration and tooling

## Open-source libraries / tooling used

- Gnosis Safe contracts
- OpenZeppelin libraries for standard security patterns
- ethers.js or viem for client-side interaction
- Safe SDK libraries for transaction construction and validation

## Role in the FermionWallet MVP

The Gnosis Safe wallet is the existing multisig wallet used by treasury and enterprise operations. It remains the primary governance and execution layer for the organization.

## Responsibilities

- handles standard signer approvals
- manages treasury governance and transaction policy
- provides the base multisig safety controls for the organization
- executes validated transactions after Safe approval has been obtained
- is not replaced by FermionWallet; it remains the primary wallet structure

## How it works with FermionWallet

The Safe performs the first authorization in the 2-of-2 model. A transaction must still satisfy the standard Safe approval flow before the FermionWallet Guard checks the second authorization.

This means the Safe continues to enforce multisig governance, while FermionWallet adds a quantum-safe second gate for sensitive transfers.

## Expected behavior

- Safe owners approve a transaction as they normally would.
- The transaction is passed to the FermionWallet Guard.
- The Guard validates quantum-safe authorization and policy compliance.
- If valid, the Safe continues execution.
- If invalid, the Safe transaction reverts.

## Design intent

The Gnosis Safe remains the operational wallet for teams. FermionWallet augments the Safe with a second, cryptographically stronger approval mechanism for high-value, policy-sensitive transfers.
