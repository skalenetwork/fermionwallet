# Quantum Key Registry

## Programming language

- Solidity for on-chain registry implementation
- JavaScript for backend registry implementation (MVP option)

## Open-source libraries / tooling used

- OpenZeppelin upgradeable patterns if used in a contract registry
- ethers.js or viem for contract interaction
- Node.js crypto APIs for hashing and validation

## Role in the FermionWallet MVP

The quantum key registry stores the metadata and state of registered quantum keys used for second authorization.

## Responsibilities

- stores public key metadata
- stores key usage status
- tracks active, rotated, and revoked keys
- binds a quantum key to a Safe and supported token context
- supports registration and rotation

## MVP implementation options

For the MVP, the registry can be implemented either as:
- a smart contract registry, or
- a backend registry that stores key metadata and verifies it through the Safe Guard

## Key metadata stored

- quantumKeyId
- publicKeyHash
- status
- createdAt
- rotatedAt
- useCounter
- associated Safe address
- associated ERC-20 token address

## Design intent

The registry is required so that the Safe Guard can verify a quantum signature against a known and trusted key state before allowing the transaction to proceed.
