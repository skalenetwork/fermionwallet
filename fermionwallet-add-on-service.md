# FermionWallet Add-on Service

## Programming language

- JavaScript
- TypeScript-compatible SDK style

## Open-source libraries / tooling used

- Node.js runtime
- ethers.js or viem
- crypto module for key generation and HMAC signing
- express or similar HTTP server framework
- zod or Joi for validation if used in a backend implementation

## Role in the FermionWallet MVP

The FermionWallet add-on service is the policy and validation layer that sits between the Safe and the quantum key system.

## Responsibilities

- generates quantum keys in JavaScript
- creates pre-approvals for transfers or wrapped token actions
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

## Design intent

This service is the operational layer that makes the governance layer and the cryptographic layer work together. It does not replace the Gnosis Safe; it adds the quantum-safe second authorization to the workflow.
