# FermionWallet MVP Spec

## Component design files

- [Gnosis Safe Wallet](./gnosis-safe-wallet.md)
- [FermionWallet Guard Contract](./fermionwallet-guard-module.md)
- [FermionWallet Add-on Service](./fermionwallet-add-on-service.md)
- [Quantum Key Registry](./quantum-key-registry.md)
- [Pre-approval Engine](./pre-approval-engine.md)
- [Ledger XMSS App](./ledger-xmss-app.md)
- [UI Help (with screenshots)](./ui-help.md)
- [On-chain Enforcement Layer](./on-chain-enforcement-layer.md)
- [Release Specification](./release-spec.md)

## Architecture diagram

```text
+---------------------+       +---------------------------+
| Treasury / Ops      |       | FermionWallet Add-on     |
| UI / Backend        | ----> | Service                   |
+---------------------+       | - key ceremony (Ledger)  |
                                | - pre-approval relaying  |
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
                              | - consumes a matching     |
                              |   pre-approval            |
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

FermionWallet is a security add-on for a standard Gnosis Safe wallet. It adds a second authorization step for high-value token transfers by validating an XMSS quantum signature — from a hardware-generated key held by the Quantum Administrator — before the transfer is executed.

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

FermionWallet adds a second approval path that is tied to a quantum-safe XMSS signing key generated on the Quantum Administrator's Ledger and verified on-chain against the key registered for the Safe.

## 3. MVP goal

Build an MVP add-on that:
- integrates with normal Gnosis Safe wallets,
- generates and manages the Quantum Administrator's XMSS key anchored to Ledger hardware — never in browser or Node.js process memory unencrypted,
- creates a pre-approval for a transfer,
- requires the quantum key as second authorization before execution,
- supports standard ERC-20 token transfer flows.

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
   - orchestrates quantum key generation anchored to the Ledger (the sole hardware trust anchor)
   - creates and validates pre-approvals
   - confirms whether a transfer meets policy and key requirements

4. Quantum key registry
   - stores public key metadata and key usage status
   - **must be on-chain**: the used-leaf-index bitmap is consensus-critical (XMSS leaf reuse = forgery), so key state and leaf tracking live in the registry/Guard contract; any backend copy is a read-only cache/index, never a source of truth

5. Pre-approval engine
   - creates time-bound, nonce-protected approvals
   - rejects expired or revoked approvals
   - verifies both hybrid signature halves (ECDSA + XMSS) on-chain at creation; binds `policyHash` into the signed payload (policy limits themselves are enforced off-chain for now)

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

Only time-bound approvals, replay protection and the ERC-20 selector deny-list / permit-list are enforced on-chain today. Token and recipient allowlists and amount caps are enforced off-chain by the add-on service; the Guard stores `policyHash` as part of the signed approval but does not check it against an on-chain policy.

## 6. User flows

### 6.1 Create quantum key

The Quantum Administrator generates an XMSS key on the Ledger. The Safe owners co-sign its public key (root and SEED), the Ledger attests it, and the Administrator registers it on-chain with `registerQuantumKey` (see [quantum-key-registry.md](./quantum-key-registry.md)).

### 6.2 Create transfer pre-approval

Before a transfer, the client creates a pre-approval containing:
- token address
- recipient
- amount
- validFrom
- validTo
- nonce
- quantumKeyId
- xmssLeafIndex
- policyHash
- txHash (optional: pins the approval to one Safe transaction)

The Ledger signs it with both hybrid halves (ECDSA and XMSS) over one EIP-712 digest, and the relayer submits it to `createPreApproval`, which verifies both halves on-chain.

### 6.3 Transfer execution

The user submits the Safe transfer as usual. Before final execution, FermionWallet checks:
- Safe approval is present (the Safe checks owner signatures before calling the Guard)
- a live pre-approval matches the transfer: token, recipient and exact amount, or the pinned Safe transaction hash
- the pre-approval is unused, not revoked, inside its validity window, and its key is not revoked

The quantum signature was already verified when the pre-approval was created. Amount caps and recipient allowlists are not checked on-chain yet.

Only then does the transfer proceed.

### Gnosis validation flow

Gnosis validation is performed by the FermionWallet Guard contract before the Safe executes the transaction.

The validation sequence is:
1. The Safe transaction is submitted.
2. The Safe verifies the owners’ signatures as part of the normal Safe execution flow.
3. If a guard is set, the Safe calls the configured Guard through `checkTransaction` before executing the target call.
4. The Guard reads the transaction metadata: `to`, `value`, `data`, `operation`, `safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`, `signatures`, and `msgSender`.
5. The Guard classifies the target call and dispatches by pre-approval class: ERC-20 `transfer` → `TRANSFER`; native ETH or permit-listed call → `PAYLOAD` (exact-payload binding); Safe self-call (`setGuard`, modules, owners) or Guard policy call → `ADMIN` (exact payload + mandatory timelock). Delegatecall reverts unless the target is the pinned `MultiSendCallOnly` (a batch, matched as `PAYLOAD`). See the Guard spec's "Pre-approval classes".
6. The Guard looks up a matching pre-approval: first by the pinned `safeTxHash`, then by the class's fields (token, recipient and exact amount for `TRANSFER`; target, value and calldata hash otherwise).
7. The Guard checks that the approval is unused, not revoked, inside its validity window, and that its key is not revoked. Signatures are not re-verified: both halves were verified when the approval was created.
8. The Guard marks the approval used, atomically with execution.
9. If all checks pass, the Guard returns and the Safe continues execution.
10. If any check fails, the Guard reverts and execution stops before the target call executes.

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
- decode the target transaction and classify it (ERC-20 `transfer`, native send, permit-listed call, batch, or administrative self-call),
- extract the target token, destination, amount, and calldata selector,
- match the transaction against the stored FermionWallet pre-approval,
- rely on the quantum signature check done at creation, against the public key stored in the FermionWallet registry,
- ensure the approval is within `validFrom` / `validTo`, not consumed or revoked, and not replayed,
- enforce the selector deny-list and the Safe's permit-list (amount caps, token and recipient allowlists are not enforced on-chain yet),
- return success only when all checks pass.

This works because the Guard sits in the Safe execution path, so it can veto execution even after the Safe has validated owner signatures. The Guard does not add a new EOA signer; it adds a second policy gate enforced by contract logic.

### Guard vs Module distinction

The MVP should use a Guard, not a Module, because the intent is to enforce a universal second-authorization gate on all transfers.

- Guard: receives all Safe transactions and can decide to allow or revert before execution.
- Module: typically adds custom entry points and execution paths; it is not the correct primitive for enforcing a universal guard on all Safe transactions.

For this design, the Guard is the preferred integration point because it matches the official Gnosis Safe execution model.

## Critical security hardening requirements

The initial draft of the MVP had several major security gaps. The following requirements are mandatory before production use.

Current status against the code: the on-chain policy limits in items 9, 16 and 20 (amount caps, token and recipient allowlists, per-token budgets) are not implemented yet and are enforced only off-chain; the Safe nonce in item 4 is bound only when an approval is pinned to a `safeTxHash`; and item 21's "`transfer` only" is the default permit-list, which each Safe can extend through a timelocked `ADMIN` approval.

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
   - The Guard must decode the actual transaction calldata and confirm it is a supported ERC-20 `transfer` operation.
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
    - **The Ledger is the sole hardware — and the sole home of key material.** The classical (ECDSA) key and the XMSS key both live inside the Ledger's ST33 secure element, managed by the [FermionWallet Ledger XMSS app](./ledger-xmss-app.md). The monotonic leaf counter is in secure-element NVRAM. There is no server HSM, no cloud enclave, and no host-side seed or software keystore of any kind — the backend only relays signatures it can never produce.
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
    - Key state and the XMSS used-leaf bitmap must live on-chain; leaf tracking is consensus-critical and a backend copy can only be a read-only cache.
    - The registry cannot be the only source of truth for authorization.

20. Do not allow unbounded token/recipient authorization surfaces
    - The Safe policy must define token allowlists, destination allowlists, max amounts, and per-wallet or per-token budgets.
    - The registry must not allow a key to authorize arbitrary token transfers without policy restrictions.

21. Use explicit authorized call types only
    - The Guard must permit only known safe function calls: ERC-20 `transfer` for the MVP. `approve`, `increaseAllowance`, `permit`, and `transferFrom` are explicitly denied (allowance-exfiltration surface — see the Guard spec).
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

#### 4. ~~`POST /api/v1/gnosis/keys/register`~~ — **Removed (security)**

> Removed. The backend must never accept or originate key material. Keys are hardware-generated on the Ledger and registered **only on-chain** via the co-signed `registerQuantumKey` (see §7.1 and `quantum-key-registry.md`). A backend write path would reintroduce the ID-indirection attack and contradict the on-chain-only registry mandate. The old body also bound the key to a single `erc20Token`; the current model is one Active key per Safe covering all assets.

#### 5. `GET /api/v1/gnosis/keys/:safeAddress`

- Purpose: read-only cache of the on-chain registry state (never authoritative).
- Response:

```json
{
  "safeAddress": "0xSafeAddress",
  "quantumKeyId": "0xkeyid...",
  "xmssRoot": "0xroot...",
  "status": "Active",
  "treeHeight": 20,
  "leafUsage": { "used": 1042, "total": 1048576 },
  "source": "on-chain (block 21504233)"
}
```

#### 6. ~~`POST /api/v1/gnosis/keys/rotate`~~ — **Removed (security)**

> Removed for the same reason as endpoint 4 — the old body accepted a bare `publicKeyHash` with **no authentication whatsoever** (no old-key proof, no owner signatures), letting anyone who reached the backend swap the quantum key. Rotation happens only on-chain via `rotateQuantumKey` (old-key XMSS proof + attestation + owner co-signatures, §7.1).

### 7.1 Solidity smart-contract API

> **No custom execution entrypoints.** This contract has **no function that moves tokens**. All transfers flow exclusively through `Safe.execTransaction` → Guard `checkTransaction` → target ERC-20 `transfer`. Any function that could execute, wrap, or forward a transfer outside that path would bypass both the Safe multisig and the Guard, and is forbidden (see security rule 5 and the Guard spec's "Forbidden original code").

All functions below live on one deployed contract, `FermionWalletGuard` (the registry and pre-approval engine are abstract bases compiled into it). The normative, complete ABI — every function, event and custom error — is in [fermionwallet-guard-module.md → FermionWallet-specific ABI](./fermionwallet-guard-module.md#fermionwallet-specific-abi); this section summarizes the main entry points.

#### 1. `registerQuantumKey`

- Signature: `function registerQuantumKey(address safe, address quantumAdmin, bytes32 xmssRoot, bytes32 xmssSeed, uint32 treeHeight, bytes32 parameterSet, uint256 validUntil, bytes calldata ledgerAttestation, bytes calldata ownerSignatures) external returns (bytes32 quantumKeyId);`
- Purpose: register the Administrator's hardware-generated XMSS public key (root + public SEED) and Ledger EOA as the Safe's quantum key, in one co-signed transaction.
- Inputs:
  - `safe`: the Safe being enrolled. The caller is the Administrator's relayer, never the Safe, so the Safe is explicit.
  - `quantumAdmin`: the Administrator's Ledger EOA — every hybrid pre-approval's ECDSA half is verified against it.
  - `xmssRoot`, `xmssSeed`: the XMSS public key; `treeHeight` (1..20) and `parameterSet` are fixed for the key's lifetime.
  - `validUntil`: ceremony deadline.
  - `ledgerAttestation`: EIP-712 `QuantumKeyAttestation { safe, xmssRoot, xmssSeed, treeHeight, parameterSet, registryNonce }` signed by `quantumAdmin`.
  - `ownerSignatures`: owner-threshold signatures over EIP-712 `ApproveQuantumKey { safe, quantumAdmin, xmssRoot, xmssSeed, treeHeight, parameterSet, registryNonce, validUntil }`, checked through the Safe's legacy `checkSignatures(bytes32,bytes,bytes)` (portable across Safe 1.3.0 / 1.4.1 / 1.5.0).
- Emits: `QuantumKeyRegistered`.
- Reverts if the Safe already has an Active key, this Safe registered the root before, a parameter is zero/out of range, `validUntil` has passed, a signature fails, or the Safe has a fallback handler or unguarded modules. Consumes the Safe's `registryNonce` (stale ceremonies die). Lifecycle: [quantum-key-registry.md](./quantum-key-registry.md).

#### 2. `rotateQuantumKey`

- Signature: `function rotateQuantumKey(address safe, address newQuantumAdmin, bytes32 newXmssRoot, bytes32 newXmssSeed, uint32 treeHeight, bytes32 parameterSet, uint256 validUntil, bytes calldata oldKeyXmssProof, bytes calldata ledgerAttestation, bytes calldata ownerSignatures) external returns (bytes32 newQuantumKeyId);`
- Purpose: rotate to a new key (and optionally a new Administrator). All three proofs are mandatory: owner threshold over EIP-712 `RotateQuantumKey { safe, oldQuantumKeyId, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, registryNonce, validUntil }`, the new key's attestation, and an XMSS signature by the old key over the same digest (consumes one old-key leaf).
- Emits: `QuantumKeyRotated`. Atomically: old → `Rotated`, new → `Active`; any pending key revocation is cancelled.
- Emergency revocation without the old key: `requestKeyRevocation` → `EMERGENCY_ROTATION_TIMELOCK` → `executeKeyRevocation` (see [quantum-key-registry.md](./quantum-key-registry.md#key-rotation-procedure-quantum-administrator)).

#### 3. Key queries

- `getKey(bytes32 quantumKeyId) returns (KeyRegistration)` — status, root, seed, height, parameter set, admin, timestamps, `useCounter`.
- `safeToQuantumKey(address safe) returns (bytes32)` — the Safe's Active key (zero if none).
- `isLeafUsed(bytes32 quantumKeyId, uint32 leafIndex) returns (bool)`; `registryNonce(address safe) returns (uint256)`.

#### 4. `createPreApproval` (TRANSFER)

- Signature: `function createPreApproval(PreApprovalRequest calldata req, bytes calldata ecdsaSignature, bytes calldata xmssSignature) external returns (bytes32 preApprovalId);`
- `PreApprovalRequest { safe, token, recipient, amount, target, value, dataHash, validFrom, validTo, nonce, quantumKeyId, xmssLeafIndex, policyHash, txHash }` — one request shape for all three create functions; class-irrelevant fields must be zero.
- `txHash`: exact `safeTxHash` pin (Tier 1); `bytes32(0)` = field-matched FIFO queue (Tier 2) per commitment `keccak256(abi.encode(safe, class, token, recipient, amount))`, capped at `MAX_COMMITMENT_QUEUE`; dead entries are pruned and never count toward the cap.
- Both hybrid halves must verify over the same EIP-712 digest: ECDSA via `SignatureChecker` against the key's `quantumAdmin`; XMSS (`abi.encode(XMSS.Signature)`, ~2.8 KB at h=20) against the key's root and seed, consuming leaf `req.xmssLeafIndex`. Either half invalid ⇒ revert.
- The key must be the Safe's Active key; `validTo - validFrom ≥ 15 minutes`. Emits `PreApprovalCreated`.

#### 4b. `createPayloadPreApproval` and `createAdminPreApproval`

- Same signature shape as `createPreApproval`. They authorize what TRANSFER cannot — native currency sends, allowlisted calls, `MultiSendCallOnly` batches (PAYLOAD), and any Safe self-call or Guard policy call (ADMIN) — by binding `target`, `value` and `dataHash = keccak256(calldata)`.
- `createAdminPreApproval` requires `target` to be the Safe or the Guard and `validFrom ≥ block.timestamp + ADMIN_TIMELOCK`, and emits a loud `AdminPreApprovalCreated` so owners can revoke during the delay.
- With the quantum-key-independent emergency de-guard path, this guarantees the **no-brick invariant**. Dispatch rules: [fermionwallet-guard-module.md → Pre-approval classes](./fermionwallet-guard-module.md#pre-approval-classes).

#### 5. `validatePreApproval(bytes32 preApprovalId)`

- Signature: `function validatePreApproval(bytes32 preApprovalId) external view returns (bool valid, string memory reason);`
- Off-chain convenience: checks the approval's state (exists, unused, unrevoked, inside its window, key not revoked). Signatures are not re-checked — they were verified once, at creation. Never the consumption mechanism.

#### 6. `revokePreApproval(bytes32 preApprovalId)`

- Signature: `function revokePreApproval(bytes32 preApprovalId) external returns (bool);`
- Callable by the Safe or the key's `quantumAdmin`; also by any single owner of the Safe, directly from the owner's address, **except for ADMIN approvals** — those only the Safe (owner threshold, no quantum approval needed) or the Administrator can revoke, so one owner cannot veto the threshold's governance changes (e.g. their own removal). Emits `PreApprovalRevoked`.

> **Removed (security):** earlier drafts defined `executePreApprovedTransfer`, `wrapERC20`, and `unwrapERC20`. These were custom execution entrypoints that would let any holder of a valid pre-approval move tokens **without** the Safe multisig or the Guard — bypassing both authorization layers. They are deleted; pre-approvals are consumed only inside the Guard's `checkTransaction` path during `Safe.execTransaction`.

### 7.2 JavaScript client API

> The client is an **orchestration layer only** — it never generates or holds quantum key material (hardware does), and it never executes transfers (the Safe does).

#### 1. `generateQuantumKey()`

- Purpose: orchestrate Ledger-anchored XMSS key generation and return the public metadata.
- Signature: `generateQuantumKey()`
- Returns:
  - `xmssRoot`, `xmssSeed`, `treeHeight`, `parameterSet`
  - `quantumAdmin` (the Ledger's admin address)
  - `ledgerAttestation`
  - `ceremonyCode` (6 BIP-39 words derived from the root)

#### 2. `rotateQuantumKey(params)`

- Purpose: run the rotation ceremony (old-key proof + new-key attestation + owner co-signatures) and submit `rotateQuantumKey` on-chain.
- Signature: `rotateQuantumKey({ oldQuantumKeyId })`
- Returns: rotated key metadata

#### 3. `getQuantumKeyStatus(quantumKeyId)`

- Purpose: inspect a key’s lifecycle status (reads the on-chain `getKey`).
- Signature: `getQuantumKeyStatus(quantumKeyId)`
- Returns: status and metadata

#### 4. `createPreApproval(params)`

- Purpose: generate a signed pre-approval for transfer validation.
- Signature:

```js
async function createPreApproval({
  safe,
  token,
  recipient,
  amount,
  validFrom,
  validTo,
  nonce,
  quantumKeyId,
  policyHash,
  txHash // optional safeTxHash pin; omit for field matching
})
```

- Returns: pre-approval object with both hybrid signature halves (`ecdsaSignature` and `xmssSignature`, both from the Ledger in one confirmation) and status; the relayer submits both to the on-chain `createPreApproval`

#### 5. `validatePreApproval(preApprovalId)`

- Purpose: confirm a pre-approval is valid.
- Signature: `validatePreApproval(preApprovalId)`
- Returns: `{ valid, reason?, preApproval? }`

#### 6. `revokePreApproval(preApprovalId)`

- Purpose: revoke an active pre-approval.
- Signature: `revokePreApproval(preApprovalId)`
- Returns: revocation status

> **Removed (security):** `executePreApprovedTransfer`, `wrapERC20`, `unwrapERC20` — see the note in §7.1. Execution happens only via `Safe.execTransaction`; the client's job ends when the pre-approval exists on-chain.

## 8. MVP non-goals

The MVP does not include:
- full post-quantum cryptographic standardization
- full cross-chain bridging support
- arbitrary treasury automation beyond pre-approval enforcement
- full wallet replacement features outside the Gnosis Safe integration model

## 9. MVP acceptance criteria

The MVP is complete when:
- a normal Gnosis Safe wallet can integrate FermionWallet as a second authorization layer,
- a Ledger-anchored XMSS key can be registered and rotated with full authentication (owner co-signatures + attestation + old-key proof),
- a transfer can only proceed when both Safe and quantum approvals are valid,
- expired, revoked, or replayed pre-approvals are rejected,
- no code path can move tokens outside `Safe.execTransaction` → Guard → ERC-20 `transfer`,
- all critical actions emit structured audit metadata.

## 10. MVP summary

FermionWallet MVP is a Gnosis Safe add-on that adds a second authorization using a quantum key. The Safe remains the governance and execution entry point, while the FermionWallet quantum key becomes an additional, policy-aware authorization layer for sensitive token transfers.
