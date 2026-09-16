# FermionWallet Guard Contract

## Programming language

- Solidity `^0.8.24` (overflow checks on by default, `transient` storage available for reentrancy depth)

## Principle: library-first, almost no original code

The Guard is glue. Every security primitive must come from an audited, pinned open-source library. FermionWallet-owned Solidity is limited to:

1. mapping a decoded ERC-20 `transfer` onto a stored pre-approval, and
2. reverting when that mapping fails.

Anything else — Guard interface, ERC165, pause, access control, reentrancy, EIP-712, hashing, signature checks, nonce bitmaps, allowlists, Safe tx hash — **must be inherited or called, never reimplemented.** Duplicating `ITransactionGuard` in this repo is a defect: a locally compiled `interfaceId` can disagree with Safe’s `GuardManager` and `setGuard` reverts `GS300`.

## Mandatory libraries (pin exact releases in `package.json` / `foundry.toml`)

### Safe — execution model (do not fork)

| Use | Import |
|---|---|
| Guard base + ERC165 that Safe actually checks | `@safe-global/safe-contracts` → `BaseTransactionGuard`, `ITransactionGuard` |
| `CALL` vs `DELEGATECALL` | `@safe-global/safe-contracts` → `Enum` |
| Recompute the Safe tx hash (use `nonce - 1` inside `checkTransaction`) | `@safe-global/safe-contracts` → `ISafe.getTransactionHash(...)` on `msg.sender` |
| Module-path coverage (Safe ≥ 1.5) | `@safe-global/safe-contracts` → `IModuleGuard`, `BaseModuleGuard` |

Do **not** copy these files into the repo. Depend on the published package.

### OpenZeppelin Contracts — all operational security

| Concern | Use this, not custom code |
|---|---|
| Pause / fail-closed circuit breaker | `Pausable` (`_pause` / `_unpause`) |
| Nested-tx / reentrancy depth | `ReentrancyGuardTransient` (or `ReentrancyGuard` if transient is unavailable) |
| Who may register, rotate, pause, revoke | `AccessControl` (roles) + `Ownable2Step` only if a single admin is required |
| Domain separation (Safe, chainId, policyHash) | `EIP712` |
| Classical half of a hybrid signature; ERC-1271 for institutional signers | `SignatureChecker.isValidSignatureNow` (not raw `ecrecover`) |
| Hash helpers | `MessageHashUtils` |
| ERC-20 selector constants | `IERC20` |
| Address zero / contract checks | `Address`, constructor `require`s |
| Packed ints | `SafeCast` |
| Single-use nonces | `BitMaps` |
| Token / recipient allowlists | `EnumerableSet` |
| Time windows | `Time` (OZ) rather than ad-hoc `block.timestamp` arithmetic |
| Custom errors pattern | OZ-style custom errors; do not invent a parallel error system |

Do **not** use OpenZeppelin upgradeable proxies for the Guard. The Guard is non-upgradeable; a new Guard is a new deployment set via Safe `setGuard`.

Do **not** mix OpenZeppelin `IERC165` with a locally copied `ITransactionGuard`. ERC165 for the Guard comes only from Safe’s `BaseTransactionGuard`.

### Post-quantum / hybrid cryptography — no home-grown “quantum HMAC”

| Layer | Library |
|---|---|
| Classical hybrid half (on-chain) | OpenZeppelin `SignatureChecker` + `EIP712` |
| PQ signature scheme | A NIST-selected algorithm (ML-DSA / Dilithium, or SLH-DSA / SPHINCS+) via a **pinned, independently audited** verifier. Do not write lattice math. |
| If a gas-viable audited Solidity PQ verifier is not available on the target chain | Verify the PQ signature in the add-on service using `liboqs` (C) or `@noble/post-quantum` (JS), commit `signatureHash` on-chain at `createPreApproval`, and keep `checkTransaction` as O(1) hash/bitmap lookups. Document that trust boundary. Never substitute `crypto.createHmac` and call it quantum-safe. |

### Tooling (not runtime, but mandatory)

- Foundry (`forge`, `forge-std`) for tests against `@safe-global/safe-contracts` Safe.sol
- OpenZeppelin `ContractInspector` / Slither, plus `solhint`
- `viem` or `ethers` **v6** only for deploy/scripts — no cryptographic policy in JS except via `@noble/post-quantum` / `liboqs`

## Required inheritance (this is the contract)

```solidity
// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {BaseTransactionGuard, ITransactionGuard} from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";
import {ISafe} from "@safe-global/safe-contracts/contracts/interfaces/ISafe.sol";

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {BitMaps} from "@openzeppelin/contracts/utils/structs/BitMaps.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract FermionWalletGuard is
    BaseTransactionGuard,
    Pausable,
    ReentrancyGuardTransient,
    AccessControl,
    EIP712
{
    // FermionWallet-owned code is only: decode transfer calldata,
    // look up pre-approval, compare fields, consume bitmap nonce, revert.
}
```

`supportsInterface` is inherited from `BaseTransactionGuard`. Override it only to *add* `type(IModuleGuard).interfaceId` if a module guard is combined in the same contract; never replace the Safe IDs.

Safe’s install check remains:

```solidity
if (guard != address(0) && !ITransactionGuard(guard).supportsInterface(type(ITransactionGuard).interfaceId))
    revertWithError("GS300");
```

That `interfaceId` must be the one from **Safe’s** package, which is why we inherit instead of copy.

## Forbidden original code

The following, if written by hand in this repo, is a spec violation:

- A local `ITransactionGuard` / `BaseTransactionGuard` / `Enum` / `IERC165`
- A local `ecrecover` wrapper, HMAC, or “quantum signature” function
- A local pause flag, reentrancy mutex, or role mapping
- A local EIP-712 domain separator or Safe tx hasher (call `ISafe.getTransactionHash`)
- A local nonce-used mapping when `BitMaps` will do
- Upgradeable-proxy scaffolding
- Any `tx.origin` check

## Official Safe interface (reference only — import, do not paste into production)

The signatures the Guard must satisfy, provided by `@safe-global/safe-contracts`:

```solidity
function checkTransaction(
    address to,
    uint256 value,
    bytes memory data,
    Enum.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes memory signatures,
    address msgSender
) external;

function checkAfterExecution(bytes32 hash, bool success) external;
```

## FermionWallet-specific ABI

This is the application-level ABI for key registration, policy pre-approvals, and Safe enforcement. It is additive to the official Safe Guard interface; it is not a replacement for it.

```solidity
interface IFermionWalletGuard is ITransactionGuard {
    struct KeyRegistration {
        bytes32 quantumKeyId;
        bytes32 publicKeyHash;
        address erc20Token;
        bool active;
        uint64 createdAt;
        uint64 rotatedAt;
        uint256 useCounter;
    }

    struct PreApproval {
        bytes32 id;
        address safe;
        address token;
        address recipient;
        uint256 amount;
        uint64 validFrom;
        uint64 validTo;
        bytes32 nonce;
        bytes32 quantumKeyId;
        bytes32 policyHash;
        bytes32 txHash;
        bytes32 signatureHash; // hash of the quantum signature; full bytes are verified once at creation, never stored
        bool used;
        bool revoked;
    }

    event QuantumKeyRegistered(bytes32 indexed quantumKeyId, address indexed safe, address indexed token, bytes32 publicKeyHash);
    event QuantumKeyRotated(bytes32 indexed oldKeyId, bytes32 indexed newKeyId, address indexed safe);
    event PreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed token, uint256 amount);
    event PreApprovalUsed(bytes32 indexed id, address indexed safe, address indexed recipient, uint256 amount);
    event PreApprovalRevoked(bytes32 indexed id, address indexed safe);

    function registerQuantumKeyPair(
        bytes32 quantumKeyId,
        bytes32 publicKeyHash,
        bytes calldata quantumSignature,
        address erc20Token
    ) external returns (bool success);

    function rotateQuantumKey(
        bytes32 quantumKeyId,
        bytes32 newPublicKeyHash,
        bytes calldata oldKeySignature,
        bytes calldata newKeySignature
    ) external returns (bytes32 newQuantumKeyId, bytes32 newPublicKeyHashOut);

    function createPreApproval(
        address token,
        address recipient,
        uint256 amount,
        uint64 validFrom,
        uint64 validTo,
        bytes32 nonce,
        bytes32 quantumKeyId,
        bytes32 policyHash,
        bytes32 txHash,
        bytes calldata signature
    ) external returns (bytes32 preApprovalId);

    function validatePreApproval(bytes32 preApprovalId) external view returns (bool valid, string memory reason);
    function revokePreApproval(bytes32 preApprovalId) external returns (bool revoked);

    // Emergency circuit breaker: deny-all mode. Pausing is fast (guardian or Safe);
    // unpausing requires Safe governance plus time lock.
    event GuardPaused(address indexed by);
    event GuardUnpaused(address indexed by);
    function pause() external;
    function unpause() external;
    function paused() external view returns (bool);
}
```

## Mandatory Safe Guard rules

- The contract must implement the official Gnosis Safe `ITransactionGuard` interface exactly.
- It must expose `checkTransaction(...)` with the exact Safe parameter list and types.
- It must implement `checkAfterExecution(bytes32 hash, bool success)`.
- It must implement `supportsInterface(bytes4 interfaceId)` so Safe can validate it during `setGuard(...)`.
- It must not expose any fake execution entrypoint such as `executeTransaction`, `exec`, or any custom function that is meant to act like a signer.
- A Smart contract cannot be a normal EOA signer in Safe. It is a guard, not a signer.
- `checkTransaction` is the pre-execution permit/deny check. It reverts to deny; it returns to allow.
- `checkAfterExecution` is post-execution bookkeeping only. It must never be used as the primary authorization gate.
- The Safe can be configured with a guard only if it supports `type(ITransactionGuard).interfaceId`.

## Access control rules

- `checkTransaction(...)` must require that `msg.sender` is an enrolled Safe. Without this, anyone can call it directly and consume single-use pre-approvals, creating a denial-of-service on legitimate transfers.
- `registerQuantumKeyPair(...)` must only be callable by the enrolled Safe (via a Safe transaction) or an explicitly authorized registrar, and must verify the quantum signature over a registration payload bound to the Safe address and chain ID.
- `rotateQuantumKey(...)` must require proof of authorization: a signature by the old key (normal rotation) plus a possession proof by the new key. Emergency rotation without the old key must go through Safe governance with a time lock.
- `revokePreApproval(...)` must only be callable by the enrolled Safe or the key holder that created the approval.
- `createPreApproval(...)` must verify the quantum signature on-chain before storing the approval; it must not accept unverified records.

## Module bypass — mandatory mitigation

Safe transaction guards are only invoked in the `execTransaction` path. Transactions executed by an enabled Safe Module through `execTransactionFromModule` **bypass the transaction guard entirely** in Safe v1.3.0/v1.4.1.

Required mitigations:

- The Safe must have **no enabled modules**, verified at enrollment and re-checked in `checkTransaction`, or
- On Safe v1.5.0+, a FermionWallet `IModuleGuard` must also be installed via `setModuleGuard(...)`, implementing `checkModuleTransaction(...)` and `checkAfterModuleExecution(...)` with the same policy checks.
- The Guard must reject any Safe transaction that calls `enableModule(...)` on the Safe itself unless it carries an explicit quantum authorization for a module change.

## Guard-removal and self-call protection

A Safe transaction whose target is the Safe itself can call `setGuard(address(0))` and silently remove the enforcement layer, or call `enableModule`, `addOwnerWithThreshold`, `changeThreshold`, etc.

The Guard must therefore:

- treat any transaction with `to == safe` as a restricted administrative action,
- require a dedicated, explicitly-scoped quantum authorization (distinct policyHash class) for `setGuard`, `setModuleGuard`, `enableModule`, `disableModule`, and owner/threshold changes,
- reject all other self-calls by default.

Note the operational trade-off: a buggy Guard can brick the Safe (every tx reverts, including the tx to remove the Guard). The design must include an audited emergency path — e.g., a time-locked administrative pre-approval class that permits `setGuard(address(0))` after a delay — so funds are never permanently frozen.

## Gas refund constraints

Safe's refund mechanism (`gasPrice`, `gasToken`, `refundReceiver`) pays out after execution and can drain the Safe if unconstrained. The Guard must enforce for the MVP:

- `gasPrice == 0` (no refunds), or
- an explicit policy cap on refund parameters with `refundReceiver` restricted to an allowlist and `gasToken` restricted to approved tokens.

## Safe nonce recomputation quirk

In `Safe.execTransaction`, the transaction hash is computed with the current `nonce`, then `nonce` is incremented, and only afterwards is the guard's `checkTransaction(...)` called. If the Guard recomputes the safeTxHash to match it against a pre-approval `txHash`, it must use `safe.nonce() - 1`, not the current nonce. Getting this wrong makes every hash comparison fail (or worse, validates the wrong transaction).

## Pre-approval consumption semantics

- The single-use flag must be set (approval marked `used`) **inside `checkTransaction`**, which is a state-changing CALL from the Safe — this is permitted for guards and is the only safe place to consume the approval atomically with execution.
- `validatePreApproval` remains a `view` convenience for off-chain checks; it must never be the consumption mechanism.
- If execution later fails, `checkAfterExecution(hash, success)` may record the failure, but the approval stays consumed — replay after a failed execution requires a fresh pre-approval.

## Best-practice hardening (round 3 virtual security test)

### Reentrancy and nested Safe transactions

The target call executed by the Safe can re-enter `Safe.execTransaction`, causing the Guard's `checkTransaction` to run again before the outer `checkAfterExecution` completes. Requirements:

- The Guard must track execution depth per Safe (e.g., a transient counter set in `checkTransaction` and cleared in `checkAfterExecution`).
- Nested Safe executions must be rejected by default for the MVP (`depth > 1` reverts).
- All state writes (approval consumption, counters) follow checks-effects-interactions; the Guard makes no external calls except reads from the registry.

### Emergency pause (circuit breaker)

- The Guard must support a deny-all `pause()` that makes every `checkTransaction` revert.
- Pausing must be fast and low-privilege (a designated guardian or any Safe owner) because a compromised key holder can otherwise front-run revocations with an execution.
- Unpausing must be slow and high-privilege: Safe governance plus a time lock.
- Pausing fails closed — this is the correct failure direction for a security guard.

### Signature storage and verification cost

- The full quantum signature is verified once in `createPreApproval` and only its hash (`signatureHash`) is stored; unbounded `bytes` must not be persisted (gas-griefing and storage-bloat vector).
- On-chain post-quantum verification (e.g., Dilithium/Falcon) is gas-heavy. The implementation must bound verification gas, and if full PQ verification is infeasible on the target chain, the MVP must use a documented commit-verify scheme (hash commitment on-chain, PQ verification at creation time, with the trust boundary explicitly stated) rather than silently skipping verification.
- `checkTransaction` itself must be O(1): lookups and comparisons only, no signature re-verification loops (DoS protection, since guard gas is charged to every Safe tx).

### ERC-20 selector policy (allowance exfiltration)

The Guard must maintain an explicit selector allowlist and deny everything else. In particular it must **reject** by default:

- `approve(address,uint256)`, `increaseAllowance(address,uint256)`, `permit(...)` — granting an allowance is a stealth-drain path equivalent to a transfer,
- `transferFrom(address,address,uint256)` pulling from third parties,
- any unknown or non-standard selector.

Allowed selectors for the MVP: `transfer(address,uint256)` and the explicitly documented wrap/unwrap calls, each matched against a pre-approval.

### Batching (MultiSend)

- `MultiSend` executes via delegatecall and is already rejected by the delegatecall default-deny.
- `MultiSendCallOnly` must also be rejected for the MVP: batched calls would need per-leg decoding and per-leg pre-approvals. Batch support, if added later, must decode every inner call and require a matching pre-approval for each.

### Timestamp handling

- `validFrom`/`validTo` rely on `block.timestamp`, which validators can skew by seconds. Approval windows must have a minimum granularity (e.g., ≥ 15 minutes) and must never be used as a sub-minute security boundary.

### Immutability and deployment hygiene

- The Guard must be non-upgradeable (no proxy). Fixes ship as a new Guard set via Safe governance.
- Constructor/initializer must validate all addresses (no zero address, registry must pass an interface check).
- Use custom errors with explicit reason data for every revert path; every state change emits an event for off-chain monitoring.
- `tx.origin` must never be used for any authorization decision.
- Lock the compiler to a recent audited Solidity version; enable overflow checks (default ≥ 0.8) and run static analysis (Slither) plus a professional audit before mainnet.

## Virtual brain test against Safe semantics

The following checks are the minimum correctness review for the FermionWallet guard.

1. If `Safe.setGuard(address(guard))` is called with a contract that does not implement `ITransactionGuard`, Safe reverts.
2. If the Guard is set correctly but a transaction is invalid, `checkTransaction` must revert.
3. If the Guard returns without revert, Safe continues execution.
4. If `operation == Enum.Operation.DelegateCall`, the Guard must reject the transaction unless the policy explicitly permits delegatecall usage. For this MVP, it should reject delegatecalls by default.
5. If the approved `token`, `recipient`, `amount`, `nonce`, `policyHash`, or chain binding do not match the transaction, the guard must revert.
6. If the quantum signature was created for a different Safe, chain ID, or payload hash, the guard must revert.
7. If `validFrom`/`validTo` are exceeded, or the approval is revoked or already used, the guard must revert.
8. If `msgSender` is used as trust input, it must be treated as merely the initiating caller and not as proof of a valid quantum authorization.
9. The guard must not trust the base transaction calldata alone; it must decode and validate the exact target call details.
10. The guard must not hold the final authority to transfer funds directly. It only decides to allow or reject the Safe transaction.
11. If a module is enabled on the Safe, the tx guard is bypassed via `execTransactionFromModule`; the guard must detect enabled modules or a module guard must be installed.
12. If a random address calls `checkTransaction` directly, it must revert (caller is not an enrolled Safe) so approvals cannot be burned by attackers.
13. If the Safe tx targets the Safe itself (`setGuard`, `enableModule`, owner changes), it must be rejected unless explicitly quantum-authorized as an admin action.
14. If `gasPrice != 0` with an unapproved `gasToken`/`refundReceiver`, the guard must revert (refund drain protection).
15. When recomputing the safeTxHash inside `checkTransaction`, the guard must use `nonce - 1`, because the Safe increments its nonce before invoking the guard.
16. If the target call re-enters `Safe.execTransaction` (nested Safe tx), the guard's depth tracking must detect it and revert.
17. If the guard is paused, every `checkTransaction` must revert (deny-all, fail-closed).
18. If the decoded selector is `approve`, `increaseAllowance`, `permit`, or `transferFrom`, the guard must revert — allowance grants are equivalent to transfers.
19. If the target is `MultiSend` or `MultiSendCallOnly`, the guard must revert for the MVP (no per-leg validation exists yet).
20. If a pre-approval window is shorter than the minimum granularity, `createPreApproval` must revert (timestamp-manipulation margin).
21. If `ITransactionGuard` / `BaseTransactionGuard` / `Enum` / ERC165 are copied into this repo instead of imported from `@safe-global/safe-contracts`, that is a defect (`interfaceId` can disagree with `GuardManager` → `GS300`).
22. If pause, reentrancy, roles, EIP-712, bitmaps, or `ecrecover` are hand-rolled, that is a defect — use OpenZeppelin.
23. If Safe tx hash is recomputed locally instead of `ISafe(msg.sender).getTransactionHash(...)`, that is a defect.
24. If hybrid/PQ verification uses HMAC or a custom lattice implementation, that is a defect — `SignatureChecker` + pinned audited PQ verifier or `liboqs` / `@noble/post-quantum` at the documented trust boundary.
25. `supportsInterface` must be the inherited Safe implementation (optionally extended for `IModuleGuard`), never a from-scratch ERC165.

## Guard behavior requirements for FermionWallet

The Guard must:

- inspect the Safe transaction before execution,
- decode the target call and confirm it is an allowed ERC-20 transfer or supported wrapped-token action,
- read the corresponding pre-approval record,
- confirm `token`, `recipient`, `amount`, `nonce`, and `policyHash` match the exact payload,
- validate the quantum signature against the registered public key metadata,
- confirm key status is active and not rotated or revoked,
- enforce chain binding and domain separation,
- ensure the approval is within its validity window and unused,
- reject any transaction that does not match the exact authorization.

The Guard is the enforcement layer. The backend service creates and validates the pre-approval, but the final decision happens on-chain in the Safe Guard.

## Low-level Safe execution model

The real Safe flow is:

1. A Safe owner signs the transaction off-chain.
2. The transaction is submitted to the Safe.
3. Safe verifies owner signatures using its normal multisig logic.
4. If a guard is set, Safe calls `checkTransaction(...)` before it executes the target contract call.
5. The Guard validates the transaction against policy and FermionWallet auth metadata.
6. If the Guard reverts, the Safe transaction fails before reaching the destination contract.
7. If the Guard returns, execution continues to the target address.
8. After execution, Safe may call `checkAfterExecution(...)` for audit or state checks.

This is not a “contract signer” flow. It is a guard veto pattern between Safe signature validation and target execution.

## Security flaws fixed in this version

The major problems fixed here are:

- No fake EOA-signer claim: the contract is not a signer and never acts like one.
- Official interface alignment: the file now matches the actual Safe Guard signature exactly.
- Guard contract trust model clarified: the Guard cannot be the source of execution; Safe is the source of execution.
- `supportsInterface` requirement added to match Safe validation checks.
- `setGuard` compatibility requirement added so the design matches official Safe contract behavior.
- `delegatecall` risk explicitly called out as a rejection condition for the MVP.
- `msgSender` misuse avoided: it is not the second authorization; it is only a transaction context field.
- Post-execution semantics clarified: `checkAfterExecution` is not the primary authorization gate.
- Module bypass closed: enabled modules bypass the tx guard; the spec now requires no modules or a paired `IModuleGuard`.
- `checkTransaction` caller restriction added: prevents attackers from burning single-use approvals.
- Self-call/guard-removal bypass closed: `setGuard`, `enableModule`, and owner changes require explicit admin authorization.
- Refund-drain attack closed: `gasPrice`/`gasToken`/`refundReceiver` constrained by policy.
- Safe nonce quirk documented: hash recomputation must use `nonce - 1` inside `checkTransaction`.
- Key rotation now requires old-key + new-key signature proofs instead of an unauthenticated call.
- Bricking risk addressed: time-locked emergency path to remove the Guard so funds cannot be permanently frozen.
- Reentrancy via nested Safe transactions closed with depth tracking.
- Emergency deny-all pause added (fast pause, time-locked unpause) to beat revocation front-running.
- On-chain signature-bytes storage removed (hash only); PQ verification gas bounded; `checkTransaction` kept O(1).
- Allowance-based exfiltration closed: `approve`/`increaseAllowance`/`permit`/`transferFrom` denied by selector allowlist.
- MultiSend and MultiSendCallOnly batching rejected until per-leg validation exists.
- Timestamp-manipulation margin enforced via minimum approval-window granularity.
- Non-upgradeable deployment, zero-address checks, custom errors, no `tx.origin`, locked compiler, Slither + audit required.
- Library-first: inherit Safe `BaseTransactionGuard`; do not copy Guard/ERC165 (avoids `GS300` interfaceId mismatch).
- OpenZeppelin supplies pause, transient reentrancy, AccessControl, EIP-712, SignatureChecker (ERC-1271), BitMaps, EnumerableSet — no hand-rolled equivalents.
- Safe tx hash via `ISafe.getTransactionHash`, not a local hasher.
- PQ/hybrid via pinned audited verifier or `liboqs` / `@noble/post-quantum`; HMAC is not a quantum signature.

## Production constraints

Before production deployment, FermionWallet must ensure:

- real post-quantum or hybrid cryptography is used for the quantum approval path,
- signatures are bound to chain ID, Safe address, nonce, token, recipient, amount, and policy hash,
- all approvals are nonce-protected and single-use,
- key revocation, rotation, and incident-response flows are in place,
- the Guard rejects unknown selectors and unsupported call patterns,
- the Safe policy allowlist and amount caps are enforced in the Guard,
- the contract is audited and reviewed under the actual Safe execution semantics before mainnet use.

## Summary

The FermionWallet Guard must be a real Safe Guard, not a pseudo-signer contract.

The correct design is:

- Safe owner signatures remain the first approval layer.
- FermionWallet adds a second approval layer by validating a quantum-based authorization inside `checkTransaction(...)`.
- If the validation is invalid, the Guard reverts and the safe transaction fails.
- If the validation is valid, Safe continues execution normally.

This is the correct integration pattern for a Gnosis Safe wallet and the version of the spec that matches the official Smart Account execution model.
