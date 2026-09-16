# FermionWallet MVP Spec

## Component design files

- [Gnosis Safe Wallet](./gnosis-safe-wallet.md)
- [FermionWallet Guard Contract](./fermionwallet-guard-module.md)
- [FermionWallet Add-on Service](./fermionwallet-add-on-service.md)
- [Quantum Key Registry](./quantum-key-registry.md)
- [Pre-approval Engine](./pre-approval-engine.md)
- [On-chain Enforcement Layer](./on-chain-enforcement-layer.md)

## Architecture diagram

```text
+---------------------+       +---------------------------+
| Treasury / Ops      |       | FermionWallet Add-on     |
| UI / Backend        | ----> | Service                   |
+---------------------+       | - key generation         |
                                | - pre-approval creation  |
                                | - policy validation      |
                                +------------+------------+
                                             |
                                             v
                              +---------------------------+
                              | Quantum Key Registry      |
                              | - public key metadata     |
                              | - key status/rotation     |
                              +------------+------------+
                                           |
                                           v
                              +---------------------------+
                              | Safe Guard                |
                              | - validates tx metadata   |
                              | - checks quantum sig      |
                              | - checks policyHash       |
                              | - reverts if invalid      |
                              +------------+------------+
                                           |
                                           v
                              +---------------------------+
                              | Gnosis Safe Wallet        |
                              | - standard signer approval|
                              | - normal multisig flow    |
                              | - executes tx if guard   |
                              |   allows it               |
                              +---------------------------+
```

## 1. Product summary

FermionWallet is a security add-on for a standard Gnosis Safe wallet. It adds a second authorization step for high-value token transfers by validating a JavaScript-generated quantum key before the transfer is executed.

The MVP is intentionally narrow:
- it plugs into an existing Gnosis Safe using the standard Safe Guard pattern,
- it requires a second approval using a quantum key,
- it supports a low-friction approval flow for ERC-20 transfers,
- it keeps the Safe as the main governance and execution layer.

In practice, FermionWallet behaves like a Gnosis Safe with a 2-of-2 approval model:
- first authorization: standard Safe signer approval,
- second authorization: FermionWallet quantum-key approval validated by a Safe Guard.

The quantum key is not a replacement for the Safe. It is an additional security checkpoint for sensitive transfers.

Important implementation note: a smart contract does not act as a normal EOA signer in Gnosis Safe. The correct integration pattern is to deploy a Safe Guard that intercepts Safe transactions and enforces the FermionWallet second authorization before the Safe executes the transaction.

## 2. Problem to solve

Enterprise wallets and treasury teams need stronger defense against future cryptographic risk while preserving their existing Safe workflows. Standard Gnosis Safe protection is excellent for multisig governance, but it does not provide a future-proof quantum-security layer.

FermionWallet adds a second approval path that is tied to a quantum-safe signing key generated in JavaScript and validated against a registry and policy engine.

## 3. MVP goal

Build an MVP add-on that:
- integrates with normal Gnosis Safe wallets,
- generates and manages a quantum-safe signing key in JavaScript,
- creates a pre-approval for a transfer,
- requires the quantum key as second authorization before execution,
- supports standard ERC-20 token transfer flows,
- supports optional ERC-20 wrap/unwrap flows under the same approval model.

## 4. MVP architecture

### 4.1 Components

1. Gnosis Safe wallet
   - existing multisig wallet used by treasury or enterprise ops
   - handles standard approval and governance workflow

2. FermionWallet Guard contract
   - standard Safe integration point used to intercept transaction execution
   - validates that the transaction has a valid FermionWallet quantum authorization before allowing execution
   - is the on-chain enforcement layer for the second authorization

3. FermionWallet add-on service
   - runs as a policy and validation layer
   - generates quantum keys in JavaScript
   - creates and validates pre-approvals
   - confirms whether a transfer meets policy and key requirements

4. Quantum key registry
   - stores public key metadata and key usage status
   - can be implemented as a smart contract registry or backend registry for MVP

5. Pre-approval engine
   - creates time-bound, nonce-protected approvals
   - rejects expired or revoked approvals
   - enforces policyHash and quantum validation

6. On-chain enforcement layer
   - validates the second authorization before transfer execution
   - implemented as the Safe Guard contract for the MVP

## 5. Product behavior

### 5.1 Approval model

Every transfer through FermionWallet must satisfy both checks:
- Safe approval from Gnosis Safe signer(s)
- FermionWallet quantum approval from a valid quantum key

This creates a 2-of-2 model for sensitive transfers.

### 5.2 Policy scope

The MVP supports:
- token allowlist / denylist
- max transfer amount
- allowed recipient list
- time-bound approvals
- nonce replay protection
- policyHash-based verification

## 6. User flows

### 6.1 Create quantum key

A user generates a quantum-safe key in JavaScript, then registers it with the FermionWallet registry using the public key hash and a valid quantum signature.

### 6.2 Create transfer pre-approval

Before a transfer, the client creates a pre-approval containing:
- token address
- spender or recipient
- amount
- validFrom
- validTo
- nonce
- quantumKeyId
- policyHash

The pre-approval is signed by the JS-generated quantum key.

### 6.3 Transfer execution

The user submits the Safe transfer as usual. Before final execution, FermionWallet checks:
- Safe approval is present
- pre-approval is valid
- quantum signature is valid
- nonce is unused
- amount is within policy bounds
- recipient is allowed
- approval has not expired or been revoked

Only then does the transfer proceed.

### Gnosis validation flow

Gnosis validation is performed by the FermionWallet Guard contract before the Safe executes the transaction.

The validation sequence is:
1. The Safe transaction is submitted.
2. The Safe verifies the owners’ signatures as part of the normal Safe execution flow.
3. If a guard is set, the Safe calls the configured Guard through `checkTransaction` before executing the target call.
4. The Guard reads the transaction metadata: `to`, `value`, `data`, `operation`, `safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`, `signatures`, and `msgSender`.
5. The Guard decodes the target call and ensures it is an allowed ERC-20 transfer, wrap, or unwrap operation.
6. The Guard resolves the relevant FermionWallet pre-approval and verifies the matching policyHash, nonce, amount, token, and recipient.
7. The Guard verifies that the stored quantum signature matches the registered public key and the exact Safe transaction payload.
8. The Guard checks that the approval is active, not expired, not revoked, and not replayed.
9. The Guard confirms the transaction amount and recipient are within the authorized policy bounds.
10. If all checks pass, the Guard returns and the Safe continues execution.
11. If any check fails, the Guard reverts and execution stops before the target call executes.

This ensures that Gnosis validates FermionWallet authorization through the Safe Guard contract, not by treating the smart contract as a normal EOA signer.

### Low-level Safe Guard execution model

The actual Safe Guard model is defined by the Gnosis Safe GuardManager. The important details are:

1. A Safe transaction is constructed with the standard Safe execution fields, including `to`, `value`, `data`, `operation`, `safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`, `signatures`, and `msgSender`.
2. The Safe owners sign the transaction off-chain.
3. The Safe contract verifies those signatures in its normal owner-signature validation flow.
4. If a guard is configured, `Safe.checkTxGuard`/the GuardManager path calls the guard’s `checkTransaction(...)` before the target call executes.
5. The Guard is expected to revert on unauthorized or policy-invalid transactions.
6. After the target call executes, the Guard can also run `checkAfterExecution(hash, success)` for follow-up validation or post-execution state checks.
7. If the guard reverts, the Safe transaction fails before execution reaches the destination contract.

For FermionWallet, the Guard logic is:
- decode the target transaction and confirm it is an allowable ERC-20 transfer, wrap, or unwrap call,
- extract the target token, destination, amount, and calldata selector,
- match the transaction against the stored FermionWallet pre-approval,
- require the quantum signature to validate against the public key stored in the FermionWallet registry,
- ensure the approval is within `validFrom` / `validTo`, not consumed or revoked, and not replayed,
- require the call to comply with Safe policy (allowlist, max amount, token whitelist, chain binding, policyHash consistency),
- return success only when all checks pass.

This works because the Guard sits in the Safe execution path, so it can veto execution even after the Safe has validated owner signatures. The Guard does not add a new EOA signer; it adds a second policy gate enforced by contract logic.

### Guard vs Module distinction

The MVP should use a Guard, not a Module, because the intent is to enforce a universal second-authorization gate on all transfers.

- Guard: receives all Safe transactions and can decide to allow or revert before execution.
- Module: typically adds custom entry points and execution paths; it is not the correct primitive for enforcing a universal guard on all Safe transactions.

For this design, the Guard is the preferred integration point because it matches the official Gnosis Safe execution model.

## Critical security hardening requirements

The initial draft of the MVP had several major security gaps. The following requirements are mandatory before production use.

1. No claim of real post-quantum security without a real PQ signature scheme
   - The MVP must not describe JavaScript HMAC-based signing as a quantum-safe mechanism.
   - The actual implementation must use a hybrid or post-quantum signature scheme, such as a standard PQC signature approved for the deployment environment, or a hybrid classical + PQ scheme with explicit compatibility rules.
   - The term "quantum key" in this document refers to a validated post-quantum or hybrid signing primitive, not a plain hash-based secret.

2. Guard must verify the exact transaction payload, not only a pre-approval ID
   - The Safe Guard must check `to`, `value`, `data`, `operation`, `nonce`, `safeTxHash`, chain ID, and token metadata.
   - A pre-approval ID alone is not sufficient authorization; it must resolve to a policy-bound payload and match the exact outgoing call.

3. Domain separation and chain binding are mandatory
   - Every quantum signature must include a domain separator that binds it to the Safe address, chain ID, policyHash, token, recipient, amount, and nonce.
   - Without chain binding, a signature could be replayed across networks or to different recipients.

4. Replay protection must be enforced at both the approval and Safe levels
   - The pre-approval nonce must be unique per Safe and per approval family.
   - The Safe `nonce` must also be checked to prevent reuse across Safe transactions.
   - If either nonce is reused, the transaction must revert.

5. The Guard must be the only execution gate for second authorization
   - The contract must not expose a public function that can be called by any user as a surrogate for transaction authorization.
   - The second authorization must only be validated in the Safe Guard execution path, not as an independent generic `execute` call.

6. Token transfers must be checked at the ABI level, not just by amount string
   - The Guard must decode the actual transaction calldata and confirm it is a supported ERC-20 transfer or wrap/unwrap operation.
   - It must reject unexpected function selectors, unknown token calls, or mismatched recipients.

7. Key revocation and emergency recovery are mandatory
   - Rotated keys must be marked invalid immediately for future use.
   - A compromised key must trigger a recovery path with a time lock, policy review, or explicit manual approval.
   - Old keys must not remain active without a clear rotation policy.

8. No bypass through direct token approval or ERC-20 transferFrom logic
   - The Guard must not rely on a generic ERC-20 `approve` flow as the second authorization mechanism.
   - The second authorization must always be tied to the specific Safe policy and pre-approval metadata.

9. Safe policy must be enforced as a maximum bound, not a suggestion
   - The policy must include allowlists, max amounts, token restrictions, and time bounds.
   - A transaction failing these rules must always revert, even if the quantum signature is valid.

10. All authorization must be auditable and immutable
   - The system must emit structured events including `safeAddress`, `token`, `recipient`, `amount`, `nonce`, `policyHash`, and `quantumKeyId`.
   - Audit logs must be retained for forensic review, incident response, and policy investigations.

11. Secret material must never be exposed to untrusted infrastructure
    - Private quantum key material must never be stored in plaintext in a generic Node process, browser localStorage, or app database.
    - The MVP must require secure key storage in an HSM, secure enclave, or an equivalent hardware-backed keystore.
    - If a browser or backend is used, the private key must be wrapped in a secure key store and never transmitted to the backend without encryption and strict access control.

12. Transaction validation must use exact calldata matching, not loose semantic matching
    - The Guard must parse calldata for the exact target method selector and arguments.
    - It must reject unexpected selectors, malformed ABI payloads, or unknown token contracts.
    - It must compare the actual `to` address, token address, amount, method type, chain ID, and `safeTxHash` with the pre-approval content.

13. Safe transaction hash and domain hash must be included in authorization
    - The quantum signature must include a domain separator that binds it to the Safe, chain, token, recipient, amount, nonce, and policyHash.
    - The signature must be validated against the exact Safe `safeTxHash` or a canonical payload hash derived from the transaction to prevent crossover signing.

14. The backend service must not become an oracle for unrestricted approval
    - The backend may prepare policy metadata and pre-approvals, but the final decision must be enforced by the Safe Guard.
    - The backend must never be the single trust anchor for transfer authorization. It is an advisory service, not a permission oracle.

15. No silent fallback to legacy allowance logic
    - Legacy `approve()` and `transferFrom()` flows must not be used as a fallback when the quantum pre-approval fails.
    - A failed second authorization must always revert, even when the token contract would otherwise allow the transfer.

16. Time windows, amount caps, and policies must be enforced in the Guard and not only at the server layer
    - The server can compute policy values, but the final decision must be enforced on-chain in the Guard.
    - The Guard must reject out-of-window, over-cap, or mismatched-policy transactions even if the service believes they are valid.

17. Fail-safe behavior must be explicit and auditable
    - If the quantum service is unavailable, the Safe must not silently fall back to a permissive mode.
    - The system must either refuse the transaction or require manual security review, with that decision logged.

18. Guard logic must be resistant to front-running and race conditions
    - Nonce checks must be atomic and bound to the Safe transaction state.
    - The Guard must not accept a pre-approval that is valid at signing time but mismatched to the final executed calldata at execution time.
    - Reuse of expired approvals or stale `policyHash` values must be rejected.

19. No implicit trust in an off-chain registry without on-chain verification
    - A backend registry is acceptable for MVP convenience, but all critical decisions must be verifiable against on-chain state or a signed attestation that includes relevant policy and key metadata.
    - The registry cannot be the only source of truth for authorization.

20. Do not allow unbounded token/recipient authorization surfaces
    - The Safe policy must define token allowlists, destination allowlists, max amounts, and per-wallet or per-token budgets.
    - The registry must not allow a key to authorize arbitrary token transfers without policy restrictions.

21. Use explicit authorized call types only
    - The Guard must permit only known safe function calls, such as ERC-20 `transfer`, `transferFrom`, or the explicit wrapped token functionality stated in the spec.
    - It must reject arbitrary contract calls, delegatecalls, or broad calls that could trigger unpredictable logic.

22. Guard must be non-upgradeable or upgradeable only with strict governance controls
    - If upgradeable, the upgrade path must require Safe governance approval and a security review, with emergency pause and rollback capabilities.
    - Unauthorized upgrades or guard changes must not be possible.

23. The MVP must not claim operational security if the system relies on a single backend service as the authorization authority
    - The system should be designed as a defense-in-depth model where the Safe remains the control plane and the Guard enforces the final decision.

24. Signature verification algorithm must be explicit and audited
    - The spec must state which signature algorithm is used, the hash function, the domain separator format, and the canonical serialization rules.
    - The implementation must avoid ambiguity in encoding and should use standard serialization rules to prevent malleability or signature confusion.

25. The system must include explicit emergency revocation and incident response flow
    - Any suspected compromise of a quantum key or add-on service must trigger immediate revocation of the relevant key, policy lockout, and Safe-level review.
    - The incident path must be reversible only by authorized governance and documented in an audit trail.

## 7. MVP API contract

The API is divided into three layers:
- Gnosis Safe add-on integration API
- Solidity smart-contract methods
- JavaScript client methods

The Gnosis add-on API is the integration interface that allows a Safe to delegate second-authorization checks to FermionWallet before final execution.

### 7.0 Gnosis Safe add-on integration API

This is the minimal protocol for integrating FermionWallet as a Safe Guard. This is the supported integration path for the MVP and is the correct way to plug logic into Gnosis Safe without pretending a smart contract can behave like a normal EOA signer.

#### 1. `POST /api/v1/gnosis/authorize-transfer`

- Purpose: validate whether a proposed Safe transfer is eligible for second authorization by FermionWallet.
- Body:

```json
{
  "safeAddress": "0xSafeAddress",
  "token": "0xTokenAddress",
  "to": "0xRecipient",
  "amount": "2000000000000000000",
  "nonce": "tx-001",
  "policyHash": "treasury-policy-v1",
  "quantumKeyId": "qk-123"
}
```

- Response:

```json
{
  "status": "approved",
  "preApprovalId": "pa-123",
  "requiresSecondAuthorization": true,
  "policyHash": "treasury-policy-v1"
}
```

- Validation rules:
  - Safe address must be a recognized Safe
  - token must be supported by the Safe policy
  - recipient must be whitelisted or policy-compliant
  - quantum key must be active and registered

#### 2. `POST /api/v1/gnosis/confirm-transfer`

- Purpose: final confirmation step after Safe approval has been obtained and before execution.
- Body:

```json
{
  "safeAddress": "0xSafeAddress",
  "preApprovalId": "pa-123",
  "quantumSignature": "0xabc...",
  "recipient": "0xRecipient",
  "amount": "2000000000000000000"
}
```

- Response:

```json
{
  "status": "authorized",
  "safeApproved": true,
  "quantumApproved": true,
  "transferAuthorized": true
}
```

- Validation rules:
  - Safe approval must already exist
  - pre-approval must be valid and unexpired
  - quantum signature must match the registered key
  - amount must not exceed the approved amount

#### 3. `GET /api/v1/gnosis/safes/:safeAddress/policies`

- Purpose: fetch the active policy configuration for a Safe.
- Response:

```json
{
  "safeAddress": "0xSafeAddress",
  "policies": {
    "allowlist": ["0xRecipientA", "0xRecipientB"],
    "maxAmount": "10000000000000000000",
    "tokens": ["0xTokenAddress"],
    "requireQuantumSecondApproval": true
  }
}
```

#### 4. `POST /api/v1/gnosis/keys/register`

- Purpose: register a JavaScript-generated quantum key for a Safe.
- Body:

```json
{
  "safeAddress": "0xSafeAddress",
  "quantumKeyId": "qk-123",
  "publicKeyHash": "0xabc...",
  "quantumSignature": "0xdef...",
  "erc20Token": "0xTokenAddress"
}
```

- Response:

```json
{
  "status": "registered",
  "quantumKeyId": "qk-123",
  "safeAddress": "0xSafeAddress"
}
```

#### 5. `POST /api/v1/gnosis/keys/rotate`

- Purpose: rotate a Safe-linked quantum key.
- Body:

```json
{
  "safeAddress": "0xSafeAddress",
  "quantumKeyId": "qk-123",
  "publicKeyHash": "0xnewkey..."
}
```

- Response:

```json
{
  "status": "rotated",
  "oldQuantumKeyId": "qk-123",
  "newQuantumKeyId": "qk-456"
}
```

### 7.1 Solidity smart-contract API

#### 1. `registerQuantumKeyPair(bytes32 quantumKeyId, bytes32 publicKeyHash, bytes calldata quantumSignature, address erc20Token)`

- Purpose: register a JavaScript-generated quantum key and bind it to a supported ERC-20 token context.
- Signature: `function registerQuantumKeyPair(bytes32 quantumKeyId, bytes32 publicKeyHash, bytes calldata quantumSignature, address erc20Token) external returns (bool success);`
- Inputs:
  - `quantumKeyId`: unique key ID created off-chain
  - `publicKeyHash`: public key hash generated in JavaScript
  - `quantumSignature`: signature proving ownership and validity of the key
  - `erc20Token`: the target ERC-20 token for the key
- Returns: `success`
- Emits: `QuantumKeyCreated`
- Validation rules:
  - signature must verify against the key and public key hash
  - token must be supported by the Safe policy or vault
  - duplicate registration for same key or same token must reject

#### 2. `rotateQuantumKey(bytes32 quantumKeyId, bytes32 publicKeyHash)`

- Purpose: rotate a quantum key and bind the new public key hash.
- Signature: `function rotateQuantumKey(bytes32 quantumKeyId, bytes32 publicKeyHash) external returns (bytes32 newQuantumKeyId, bytes32 newPublicKeyHash);`
- Inputs:
  - current key ID
  - new public key hash generated in JavaScript
- Returns: new key ID and new public key hash
- Emits: `QuantumKeyRotated`

#### 3. `getQuantumKeyStatus(bytes32 quantumKeyId)`

- Purpose: query the status of a registered quantum key.
- Signature: `function getQuantumKeyStatus(bytes32 quantumKeyId) external view returns (bool active, uint64 createdAt, uint64 rotatedAt, uint256 useCounter);`
- Returns: key lifecycle metadata

#### 4. `createPreApproval(...)`

- Purpose: create a time-bounded approval for a transfer or wrapped token operation.
- Signature:

```solidity
function createPreApproval(
    address token,
    address spender,
    uint256 amount,
    uint64 validFrom,
    uint64 validTo,
    bytes32 nonce,
    bytes32 quantumKeyId,
    bytes32 policyHash,
    bytes calldata signature
) external returns (bytes32 preApprovalId);
```

- Inputs:
  - token
  - spender
  - amount
  - validFrom
  - validTo
  - nonce
  - quantumKeyId
  - policyHash
  - signature
- Returns: `preApprovalId`
- Emits: `PreApprovalCreated`

#### 5. `validatePreApproval(bytes32 preApprovalId)`

- Purpose: validate the pre-approval state and signature.
- Signature: `function validatePreApproval(bytes32 preApprovalId) external view returns (bool valid, string memory reason);`
- Returns: valid flag and reason

#### 6. `executePreApprovedTransfer(bytes32 preApprovalId, address recipient, uint256 amount)`

- Purpose: execute a transfer only when the Safe and the quantum approval are both valid.
- Signature: `function executePreApprovedTransfer(bytes32 preApprovalId, address recipient, uint256 amount) external returns (bool success);`
- Returns: success flag
- Emits: `PreApprovalExecuted`

#### 7. `revokePreApproval(bytes32 preApprovalId)`

- Purpose: revoke a pending pre-approval.
- Signature: `function revokePreApproval(bytes32 preApprovalId) external returns (bool revoked);`
- Returns: revocation status

#### 8. `wrapERC20(address token, uint256 amount, bytes32 preApprovalId)`

- Purpose: wrap ERC-20 tokens only if a valid quantum pre-approval exists.
- Signature: `function wrapERC20(address token, uint256 amount, bytes32 preApprovalId) external returns (uint256 wrappedAmount);`
- Returns: wrapped amount
- Requires: valid pre-approval and policy compliance

#### 9. `unwrapERC20(address token, uint256 amount, bytes32 preApprovalId)`

- Purpose: unwrap only after explicit quantum-safe authorization.
- Signature: `function unwrapERC20(address token, uint256 amount, bytes32 preApprovalId) external returns (uint256 unwrappedAmount);`
- Returns: unwrapped amount
- Requires: valid pre-approval and remaining wrapped balance

### 7.2 JavaScript client API

#### 1. `generateQuantumKeyPair()`

- Purpose: generate a quantum-safe key pair in JavaScript.
- Signature: `generateQuantumKeyPair()`
- Returns:
  - `quantumKeyId`
  - `publicKey`
  - `algorithm`
  - `status`

#### 2. `rotateQuantumKey(quantumKeyId, publicKey)`

- Purpose: rotate the quantum key.
- Signature: `rotateQuantumKey(quantumKeyId, publicKey)`
- Returns: rotated key metadata

#### 3. `getQuantumKeyStatus(quantumKeyId)`

- Purpose: inspect a key’s lifecycle status.
- Signature: `getQuantumKeyStatus(quantumKeyId)`
- Returns: status and metadata

#### 4. `createPreApproval(params)`

- Purpose: generate a signed pre-approval for transfer validation.
- Signature:

```js
async function createPreApproval({
  token,
  spender,
  amount,
  validFrom,
  validTo,
  nonce,
  quantumKeyId,
  policyHash
})
```

- Returns: pre-approval object with signature and status

#### 5. `validatePreApproval(preApprovalId)`

- Purpose: confirm a pre-approval is valid.
- Signature: `validatePreApproval(preApprovalId)`
- Returns: `{ valid, reason?, preApproval? }`

#### 6. `executePreApprovedTransfer(preApprovalId, recipient, amount)`

- Purpose: execute a pre-approved transfer.
- Signature: `executePreApprovedTransfer(preApprovalId, recipient, amount)`
- Returns: success payload

#### 7. `revokePreApproval(preApprovalId)`

- Purpose: revoke an active pre-approval.
- Signature: `revokePreApproval(preApprovalId)`
- Returns: revocation status

#### 8. `wrapERC20(token, amount, preApprovalId)`

- Purpose: wrap ERC-20 tokens with a valid quantum pre-approval.
- Signature: `wrapERC20(token, amount, preApprovalId)`
- Returns: wrapped amount status

#### 9. `unwrapERC20(token, amount, preApprovalId)`

- Purpose: unwrap tokens after validation.
- Signature: `unwrapERC20(token, amount, preApprovalId)`
- Returns: unwrapped amount status

## 8. MVP non-goals

The MVP does not include:
- full post-quantum cryptographic standardization
- full cross-chain bridging support
- arbitrary treasury automation beyond pre-approval enforcement
- full wallet replacement features outside the Gnosis Safe integration model

## 9. MVP acceptance criteria

The MVP is complete when:
- a normal Gnosis Safe wallet can integrate FermionWallet as a second authorization layer,
- a JavaScript-generated quantum key can be registered and rotated,
- a transfer can only proceed when both Safe and quantum approvals are valid,
- expired, revoked, or replayed pre-approvals are rejected,
- wrap and unwrap flows require valid quantum pre-approvals,
- all critical actions emit structured audit metadata.

## 10. MVP summary

FermionWallet MVP is a Gnosis Safe add-on that adds a second authorization using a quantum key. The Safe remains the governance and execution entry point, while the FermionWallet quantum key becomes an additional, policy-aware authorization layer for sensitive token transfers.
