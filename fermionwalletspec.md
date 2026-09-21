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

FermionWallet adds a second approval path that is tied to a quantum-safe signing key generated in JavaScript and validated against a registry and policy engine.

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
5. The Guard classifies the target call and dispatches by pre-approval class: ERC-20 `transfer` → `TRANSFER`; native ETH or allowlisted call → `PAYLOAD` (exact-payload binding); Safe self-call (`setGuard`, modules, owners) → `ADMIN` (exact payload + mandatory timelock). Delegatecall always reverts. See the Guard spec's "Pre-approval classes".
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
- decode the target transaction and confirm it is an allowable ERC-20 `transfer` call,
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

#### 1. `registerQuantumKey(address safe, address quantumAdmin, bytes32 xmssRoot, uint32 treeHeight, bytes32 parameterSet, bytes calldata ledgerAttestation, bytes calldata ownerSignatures)`

- Purpose: register the Quantum Administrator's hardware-generated XMSS root — together with the Administrator's classical Ledger address — as the Safe's quantum approval key, in one co-signed transaction.
- Signature: `function registerQuantumKey(address safe, address quantumAdmin, bytes32 xmssRoot, uint32 treeHeight, bytes32 parameterSet, bytes calldata ledgerAttestation, bytes calldata ownerSignatures) external returns (bytes32 quantumKeyId);`
- Inputs:
  - `safe`: the Safe being enrolled — the registry is a shared singleton called by the Administrator's relayer EOA, so the Safe can never be inferred from `msg.sender`; this address selects whose `checkSignatures` verifies the owner threshold and where the key binding (`safeToQuantumKey[safe]`) is stored
  - `quantumAdmin`: the Administrator's Ledger EOA — stored on-chain as the address every hybrid pre-approval's ECDSA half is verified against; must match the signer of `ledgerAttestation`
  - `xmssRoot`: public XMSS root exported from the Ledger-anchored key generation
  - `treeHeight`, `parameterSet`: key parameters, fixed for the key's lifetime
  - `ledgerAttestation`: the Administrator's EIP-712 hardware attestation over the root, signed by `quantumAdmin`
  - `ownerSignatures`: Safe-owner-threshold EIP-712 signatures over `ApproveQuantumKey { safe, quantumAdmin, xmssRoot, treeHeight, parameterSet, registryNonce, validUntil }` — owners sign the root and the admin address themselves, never an opaque ID
- Returns: `quantumKeyId`
- Emits: `QuantumKeyRegistered`
- Validation rules:
  - owner threshold verified via the supplied Safe's own `checkSignatures` — the EIP-712 digest binds `safe` and `block.chainid`, so signatures cannot be replayed against another Safe or chain
  - attestation must verify against the supplied `quantumAdmin` address, which is stored in the registration
  - `registryNonce` must be current (bumped on success — stale ceremonies unusable)
  - duplicate root registration must reject
  - see [quantum-key-registry.md](./quantum-key-registry.md) for the full lifecycle

#### 2. `rotateQuantumKey(address safe, address newQuantumAdmin, bytes32 newXmssRoot, uint32 treeHeight, bytes32 parameterSet, bytes calldata oldKeyXmssProof, bytes calldata ledgerAttestation, bytes calldata ownerSignatures)`

- Purpose: rotate to a new XMSS root (and optionally a new Administrator device). **Authentication is mandatory**: proof of the old key, hardware attestation of the new key, and owner-threshold co-signatures.
- Signature: `function rotateQuantumKey(address safe, address newQuantumAdmin, bytes32 newXmssRoot, uint32 treeHeight, bytes32 parameterSet, bytes calldata oldKeyXmssProof, bytes calldata ledgerAttestation, bytes calldata ownerSignatures) external returns (bytes32 newQuantumKeyId);`
- Inputs:
  - `safe`: the enrolled Safe whose key is being rotated (explicit for the shared singleton, as in `registerQuantumKey`)
  - `oldKeyXmssProof`: XMSS signature by the current active key over the rotation payload (consumes one leaf)
  - remaining inputs as in `registerQuantumKey`, bound to the rotation payload
- Returns: `newQuantumKeyId`
- Emits: `QuantumKeyRotated`
- Validation rules:
  - old key must be `Active`; it transitions to `Rotated` atomically
  - emergency rotation without the old key requires Safe governance plus the Guard's time-locked path
  - unauthenticated rotation must be impossible: missing any of the three proofs reverts
  - full operator procedure (routine and emergency) in [quantum-key-registry.md → Key rotation procedure](./quantum-key-registry.md#key-rotation-procedure-quantum-administrator)

#### 3. `getQuantumKeyStatus(bytes32 quantumKeyId)`

- Purpose: query the status of a registered quantum key.
- Signature: `function getQuantumKeyStatus(bytes32 quantumKeyId) external view returns (bool active, uint64 createdAt, uint64 rotatedAt, uint256 useCounter);`
- Returns: key lifecycle metadata

#### 4. `createPreApproval(...)`

- Purpose: create a time-bounded approval for a transfer.
- Signature:

```solidity
function createPreApproval(
    address safe,       // the enrolled Safe this approval is for — the creator is the
                        // Administrator's relayer, so the Safe must be explicit; both
                        // signed halves bind (safe, chainid, ...) against replay
    address token,
    address recipient,
    uint256 amount,
    uint64 validFrom,
    uint64 validTo,
    bytes32 nonce,
    bytes32 quantumKeyId,
    uint32 xmssLeafIndex,
    bytes32 policyHash,
    bytes32 txHash,     // exact safeTxHash pin (Tier 1, preferred — proposed-then-authorized flow);
                        // bytes32(0) = field-matched FIFO queue (Tier 2); identical recurring
                        // transfers queue instead of reverting; stale entries are skipped lazily
    bytes calldata ecdsaSignature, // Ledger EIP-712 half (65 B) — verified against quantumAdmin
    bytes calldata xmssSignature   // XMSS half (RFC 8391 tuple, ~2.8 KB at h=20) — verified against xmssRoot
) external returns (bytes32 preApprovalId);
```

- Inputs:
  - safe
  - token
  - recipient
  - amount
  - validFrom
  - validTo
  - nonce
  - quantumKeyId
  - xmssLeafIndex
  - policyHash
  - txHash (optional Tier-1 pin)
  - ecdsaSignature (classical hybrid half — the Ledger human-in-the-loop anchor)
  - xmssSignature (post-quantum hybrid half)
- Returns: `preApprovalId`
- Emits: `PreApprovalCreated`
- Storage/lookup: pinned approvals live in `approvalByTxHash[safe][safeTxHash]` (collision-free — Safe nonces differentiate identical transfers); field-matched approvals (`txHash == bytes32(0)`) append to a bounded FIFO queue per commitment `keccak256(safe, class, token, recipient, amount)` (max `MAX_COMMITMENT_QUEUE = 16`), so identical recurring payouts can be queued concurrently and a stale unexecuted approval never blocks new ones — `checkTransaction` skips expired/revoked entries lazily.
- Validation rules: **both halves must verify over the same EIP-712 digest** — ECDSA via `SignatureChecker` against the registered `quantumAdmin`, XMSS against the registered `xmssRoot` with on-chain leaf consumption. Either half missing or invalid ⇒ revert. A backend holding only the XMSS seed cannot mint approvals without the Ledger, and a stolen Ledger cannot mint them without the XMSS key.

#### 4b. `createPayloadPreApproval(...)` and `createAdminPreApproval(...)`

- Purpose: authorize what the `TRANSFER` struct cannot represent — **native ETH transfers**, **administrative Safe self-calls**, and **`MultiSendCallOnly` batches** (one approval, one leaf per batch; `dataHash` binds the full batch calldata) — via exact-payload binding (`target`, `value`, `dataHash = keccak256(data)`). Both take `address safe` as the first parameter and a `txHash` Tier-1 pin, like `createPreApproval`.
- `createAdminPreApproval` covers `setGuard` (including `address(0)` — the sanctioned Guard-removal path), `setModuleGuard`, `enableModule`/`disableModule`, and owner/threshold changes. It reverts unless `validFrom ≥ block.timestamp + ADMIN_TIMELOCK` and emits a loud `AdminPreApprovalCreated` event so watchers can revoke during the delay.
- Together with the quantum-key-independent emergency de-guard path, this guarantees the **no-brick invariant**: the Safe can always, eventually, remove the Guard. Full signatures and dispatch rules in [fermionwallet-guard-module.md → Pre-approval classes](./fermionwallet-guard-module.md#pre-approval-classes).

#### 5. `validatePreApproval(bytes32 preApprovalId)`

- Purpose: validate the pre-approval state and signature.
- Signature: `function validatePreApproval(bytes32 preApprovalId) external view returns (bool valid, string memory reason);`
- Returns: valid flag and reason

#### 6. `revokePreApproval(bytes32 preApprovalId)`

- Purpose: revoke a pending pre-approval.
- Signature: `function revokePreApproval(bytes32 preApprovalId) external returns (bool revoked);`
- Returns: revocation status

> **Removed (security):** earlier drafts defined `executePreApprovedTransfer`, `wrapERC20`, and `unwrapERC20`. These were custom execution entrypoints that would let any holder of a valid pre-approval move tokens **without** the Safe multisig or the Guard — bypassing both authorization layers. They are deleted; pre-approvals are consumed only inside the Guard's `checkTransaction` path during `Safe.execTransaction`.

### 7.2 JavaScript client API

> The client is an **orchestration layer only** — it never generates or holds quantum key material (hardware does), and it never executes transfers (the Safe does).

#### 1. `generateQuantumKey()`

- Purpose: orchestrate Ledger-anchored XMSS key generation and return the public metadata.
- Signature: `generateQuantumKey()`
- Returns:
  - `xmssRoot`, `treeHeight`, `parameterSet`
  - `ledgerAttestation`
  - `ceremonyCode` (6 BIP-39 words derived from the root)

#### 2. `rotateQuantumKey(params)`

- Purpose: run the rotation ceremony (old-key proof + new-key attestation + owner co-signatures) and submit `rotateQuantumKey` on-chain.
- Signature: `rotateQuantumKey({ oldQuantumKeyId })`
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
  safe,
  token,
  recipient,
  amount,
  validFrom,
  validTo,
  nonce,
  quantumKeyId,
  policyHash
})
```

- Returns: pre-approval object with both hybrid signature halves (`ecdsaSignature` from the Ledger, `xmssSignature` from the XMSS signer) and status; the relayer submits both to the on-chain `createPreApproval`

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
