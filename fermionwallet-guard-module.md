# FermionWallet Guard Contract

## Table of contents

- [Programming language](#programming-language)
- [Principle: library-first, almost no original code](#principle-library-first-almost-no-original-code)
- [Mandatory libraries (pin exact releases in `package.json` / `foundry.toml`)](#mandatory-libraries-pin-exact-releases-in-packagejson--foundrytoml)
  - [Safe — execution model (do not fork)](#safe--execution-model-do-not-fork)
  - [OpenZeppelin Contracts — all operational security](#openzeppelin-contracts--all-operational-security)
  - [Post-quantum cryptography — the Quantum Administrator's XMSS key](#post-quantum-cryptography--the-quantum-administrators-xmss-key)
  - [Tooling (not runtime, but mandatory)](#tooling-not-runtime-but-mandatory)
- [Required inheritance (this is the contract)](#required-inheritance-this-is-the-contract)
- [Forbidden original code](#forbidden-original-code)
- [Official Safe interface (reference only — import, do not paste into production)](#official-safe-interface-reference-only--import-do-not-paste-into-production)
- [FermionWallet-specific ABI](#fermionwallet-specific-abi)
- [Mandatory Safe Guard rules](#mandatory-safe-guard-rules)
- [Access control rules](#access-control-rules)
- [Module bypass — mandatory mitigation](#module-bypass--mandatory-mitigation)
- [Guard-removal and self-call protection](#guard-removal-and-self-call-protection)
- [Pre-approval classes](#pre-approval-classes)
- [Gas refund constraints](#gas-refund-constraints)
- [Safe nonce recomputation quirk](#safe-nonce-recomputation-quirk)
- [Pre-approval consumption semantics](#pre-approval-consumption-semantics)
- [Best-practice hardening (round 3 virtual security test)](#best-practice-hardening-round-3-virtual-security-test)
  - [Reentrancy and nested Safe transactions](#reentrancy-and-nested-safe-transactions)
  - [Emergency pause (circuit breaker)](#emergency-pause-circuit-breaker)
  - [Signature storage and verification cost](#signature-storage-and-verification-cost)
  - [ERC-20 selector policy (allowance exfiltration)](#erc-20-selector-policy-allowance-exfiltration)
  - [Batching (MultiSend)](#batching-multisend)
  - [Timestamp handling](#timestamp-handling)
  - [Immutability and deployment hygiene](#immutability-and-deployment-hygiene)
- [Virtual brain test against Safe semantics](#virtual-brain-test-against-safe-semantics)
- [Guard behavior requirements for FermionWallet](#guard-behavior-requirements-for-fermionwallet)
- [Low-level Safe execution model](#low-level-safe-execution-model)
- [Who calls `checkTransaction`, exactly](#who-calls-checktransaction-exactly)
  - [The contracts involved](#the-contracts-involved)
  - [The exact call sequence inside `Safe.execTransaction`](#the-exact-call-sequence-inside-safeexectransaction)
  - [Consequences the implementation must honor](#consequences-the-implementation-must-honor)
- [Security flaws fixed in this version](#security-flaws-fixed-in-this-version)
- [Production constraints](#production-constraints)
- [Summary](#summary)

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

### Post-quantum cryptography — the Quantum Administrator's XMSS key

The second authorization is produced by a designated **Quantum Administrator** holding a **permanent, stateful XMSS key** (RFC 8391; NIST-approved via SP 800-208). XMSS verification is pure hashing, which the EVM executes cheaply — enabling **full on-chain PQ verification** with no commit-verify trust boundary.

| Layer | Choice |
|---|---|
| PQ signature scheme | **XMSS** (e.g., `XMSS-SHA2_20_256` or a keccak-instantiated variant), one long-lived key per Quantum Administrator, good for 2^20 (~1M) pre-approvals |
| On-chain verification | Solidity XMSS verifier: WOTS+ chain recomputation + L-tree + Merkle auth path to the registered root. Pure `keccak256`/`sha256` — estimated 0.4–1M gas per `createPreApproval`, benchmarked in Foundry as an acceptance criterion |
| State management (critical) | Each signature consumes one leaf index. **Index reuse is catastrophic** (forgery becomes possible), so the contract tracks used indices in an OpenZeppelin `BitMaps` bitmap keyed by `(quantumKeyId, leafIndex)` and reverts on reuse. The add-on service must persist its index counter atomically before releasing any signature |
| Classical hybrid half (on-chain) | OpenZeppelin `SignatureChecker` + `EIP712` — the pre-approval is valid only if **both** the XMSS and the classical signature verify |
| Key lifecycle | Registered as a single XMSS root (`xmssRoot`) in the registry via the co-signed one-shot `registerQuantumKey`. When leaf indices near exhaustion, the Administrator rotates to a new root via `rotateQuantumKey` (old-key + new-key signature proofs, per the access-control rules) |
| Off-chain signing | `@noble/post-quantum` / liboqs XMSS implementation in the add-on service; never `crypto.createHmac` labeled as quantum-safe |

### Existing open-source Solidity code for XMSS

Surveyed (2026-09); use as reference/baseline, not drop-in:

| Repo | What it has | License | Assessment |
|---|---|---|---|
| [`ruslan-ilesik/poqeth`](https://github.com/ruslan-ilesik/poqeth) | **The only complete XMSS verifier in Solidity** (`src/xmss/xmss.sol`), plus WOTS+, SPHINCS+, MAYO; Foundry tests; backed by the peer-reviewed paper [eprint 2025/091](https://eprint.iacr.org/2025/091) ("poqeth: Efficient post-quantum signature verification on Ethereum") | ⚠️ SPDX `UNLICENSED`, no LICENSE file (README claims open source — **contact authors before any reuse**) | Research-grade: ADRS modeled as a separate storage contract, `console.sol` imports — correct algorithmically, but gas-unoptimized and not production code. Best used as the correctness reference and Foundry gas baseline |
| [`QuipNetwork/hashsigs-solidity`](https://github.com/QuipNetwork/hashsigs-solidity) | Production-oriented **WOTS+** (`contracts/WOTSPlus.sol`) — the one-time-signature core of XMSS, but no L-tree/Merkle layer; companion Rust/TS/Python implementations for cross-testing; actively maintained | AGPL-3.0 (copyleft — fine for reference and open-source deployment; review before proprietary linking) | Cleanest vetted WOTS+ building block available |

Nothing else exists: ZKNox (ETHFALCON/ETHDILITHIUM) covers only lattice schemes; no LMS or other XMSS Solidity implementations were found.

**Plan of record — implemented:** FermionWallet's XMSS verifier is implemented in-house as a clean-room, **MIT-licensed** Solidity library at [`contracts/src/XMSS.sol`](./contracts/src/XMSS.sol) (no code taken from the unlicensed or AGPL repos above; written directly from RFC 8391). It is validated against an independent Python RFC 8391 reference (`contracts/py/xmss_ref.py`) with positive vectors at multiple tree heights plus tamper tests, and benchmarked in Foundry: **942,783 gas** per verification at h=10 (~973k extrapolated at h=20) — within the 0.4–1M target. Remaining before mainnet: cross-check against poqeth's published numbers and the same external audit as the Guard.

Why XMSS over the alternatives:
- **ML-DSA / Falcon**: lattice math costs tens of millions of gas on the EVM — no audited gas-viable verifier exists.
- **One-time WOTS+ per approval**: cheaper per verification, but forces a key registration per pre-approval; the permanent XMSS root gives the Quantum Administrator one enrollable identity.
- **SLH-DSA**: stateless and conservative but ~8–50 KB signatures; retained as documented fallback if XMSS state management is deemed operationally too risky.

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
    enum KeyStatus { None, Active, Rotated, Revoked }

    struct KeyRegistration {
        bytes32 quantumKeyId;   // keccak256(safe, xmssRoot, registryNonce)
        bytes32 xmssRoot;       // the XMSS public root itself — one key per Safe, all tokens
        uint32 treeHeight;
        bytes32 parameterSet;   // e.g. XMSS-SHA2_20_256
        KeyStatus status;
        uint64 createdAt;
        uint64 rotatedAt;
        uint256 useCounter;
    }

    enum ApprovalClass {
        TRANSFER, // ERC-20 transfer: token/recipient/amount binding
        PAYLOAD,  // exact payload: native ETH or policy-allowlisted call
        ADMIN     // exact payload, target == safe; mandatory ADMIN_TIMELOCK
    }

    struct PreApproval {
        bytes32 id;
        address safe;
        ApprovalClass class;
        // TRANSFER class fields (zero for other classes)
        address token;
        address recipient;
        uint256 amount;
        // PAYLOAD / ADMIN class fields (zero for TRANSFER)
        address target;
        uint256 value;
        bytes32 dataHash;   // keccak256 of the exact calldata; binds the full payload
        // common fields
        uint64 validFrom;   // for ADMIN: >= createdAt + ADMIN_TIMELOCK, enforced at creation
        uint64 validTo;
        bytes32 nonce;
        bytes32 quantumKeyId;
        uint32 xmssLeafIndex;
        bytes32 policyHash;
        bytes32 txHash;     // TRANSFER only, optional exact safeTxHash pin; bytes32(0) = match by fields
        bytes32 signatureHash; // hash of the quantum signature; full bytes are verified once at creation, never stored
        bool used;
        bool revoked;
    }

    event QuantumKeyRegistered(bytes32 indexed quantumKeyId, address indexed safe, bytes32 xmssRoot, uint32 treeHeight);
    event QuantumKeyRotated(bytes32 indexed oldKeyId, bytes32 indexed newKeyId, address indexed safe);
    event PreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed token, uint256 amount);
    event AdminPreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed target, bytes32 dataHash, uint64 executableAt);
    event PreApprovalUsed(bytes32 indexed id, address indexed safe, address indexed recipient, uint256 amount);
    event PreApprovalRevoked(bytes32 indexed id, address indexed safe);

    // Co-signed one-shot registration (see quantum-key-registry.md). Not bound to
    // any token: one Active key per Safe covers all assets. ownerSignatures are
    // EIP-712 clear-signatures over the root itself, verified via Safe.checkSignatures;
    // registryNonce (included in the signed struct) prevents replay.
    function registerQuantumKey(
        bytes32 xmssRoot,
        uint32 treeHeight,
        bytes32 parameterSet,
        bytes calldata ledgerAttestation,
        bytes calldata ownerSignatures
    ) external returns (bytes32 quantumKeyId);

    // Rotation = registration + old-key XMSS possession proof over the new root.
    // Emergency rotation without the old key goes through Safe governance with a time lock.
    function rotateQuantumKey(
        bytes32 newXmssRoot,
        uint32 treeHeight,
        bytes32 parameterSet,
        bytes calldata oldKeyXmssProof,
        bytes calldata ledgerAttestation,
        bytes calldata ownerSignatures
    ) external returns (bytes32 newQuantumKeyId);

    // ── Pre-approval creation ───────────────────────────────────────────────
    // One Guard instance serves many Safes, and the creator is the Administrator's
    // relayer EOA — NOT the Safe. Every create function therefore takes the target
    // `safe` explicitly. The XMSS-signed payload binds (safe, chainid, class, all
    // class fields, validity, nonce, leafIndex, policyHash) — the EIP-712 domain
    // separator uses the Guard address + chainid, and `safe` is a struct field —
    // so a signature can never be replayed against another Safe or chain.
    //
    // Lookup at execution time: checkTransaction recomputes
    //   commitment = keccak256(safe, class, token, recipient, amount)          // TRANSFER
    //   commitment = keccak256(safe, class, target, value, keccak256(data))    // PAYLOAD / ADMIN
    // and consults `activeApproval[commitment] → preApprovalId`. At most one
    // unconsumed approval may exist per commitment (creation reverts otherwise),
    // so no txHash is needed for PAYLOAD/ADMIN; TRANSFER may optionally pin an
    // exact safeTxHash via `txHash` (bytes32(0) = match by fields).

    // TRANSFER class (fast path, no timelock)
    function createPreApproval(
        address safe,
        address token,
        address recipient,
        uint256 amount,
        uint64 validFrom,
        uint64 validTo,
        bytes32 nonce,
        bytes32 quantumKeyId,
        uint32 xmssLeafIndex,
        bytes32 policyHash,
        bytes32 txHash,
        bytes calldata signature
    ) external returns (bytes32 preApprovalId);

    // PAYLOAD class: native ETH sends and policy-allowlisted non-transfer calls.
    // Binds the exact payload via dataHash = keccak256(data); operation is always CALL.
    function createPayloadPreApproval(
        address safe,
        address target,
        uint256 value,
        bytes32 dataHash,
        uint64 validFrom,
        uint64 validTo,
        bytes32 nonce,
        bytes32 quantumKeyId,
        uint32 xmssLeafIndex,
        bytes32 policyHash,
        bytes calldata signature
    ) external returns (bytes32 preApprovalId);

    // ADMIN class: self-calls only (setGuard incl. address(0), setModuleGuard,
    // enable/disableModule, owner/threshold changes). Reverts unless
    // validFrom >= block.timestamp + ADMIN_TIMELOCK. Emits AdminPreApprovalCreated
    // so watchers can revoke during the delay. This is the sanctioned unbrick path.
    function createAdminPreApproval(
        address safe,   // also the call target: ADMIN is self-call only
        uint256 value,
        bytes32 dataHash,
        uint64 validFrom,
        uint64 validTo,
        bytes32 nonce,
        bytes32 quantumKeyId,
        uint32 xmssLeafIndex,
        bytes32 policyHash,
        bytes calldata signature
    ) external returns (bytes32 preApprovalId);

    function ADMIN_TIMELOCK() external view returns (uint64); // immutable, set at deployment

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
- `registerQuantumKey(...)` must verify the owner co-signatures (Safe threshold, via `checkSignatures`) over an EIP-712 struct that binds the XMSS root itself, the Safe address, chain ID, `registryNonce`, and a validity deadline. It must reject if the Safe already has an Active key, and bump `registryNonce` on success.
- `rotateQuantumKey(...)` must additionally verify an XMSS possession proof by the **old** key over the new root (consuming one leaf), plus owner co-signatures as above. Emergency rotation without the old key must go through Safe governance with a time lock.
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

Note the operational trade-off: a buggy Guard can brick the Safe (every tx reverts, including the tx to remove the Guard). This is resolved by the **pre-approval class system** below plus the time-locked emergency de-guard path — together they guarantee the no-brick invariant.

## Pre-approval classes

A single transfer-shaped `PreApproval` struct cannot represent admin operations or native ETH — which would make the Guard impossible to remove (deadlock: the Guard blocks admin self-calls without quantum authorization, but a transfer-only struct can never express `setGuard(address(0))`). The engine therefore defines **three classes**, all XMSS-signed, all consuming one leaf index:

| Class | Binds | Covers | Timelock |
|---|---|---|---|
| `TRANSFER` (0) | `token`, `recipient`, `amount` | ERC-20 `transfer` fast path | none (validity window only) |
| `PAYLOAD` (1) | exact payload: `target`, `value`, `keccak256(data)`, `operation == CALL` | native ETH sends (`data.length == 0, value > 0`) and policy-allowlisted non-transfer calls | policy-set, min 15 min |
| `ADMIN` (2) | exact payload, `target == safe` | `setGuard` (incl. `address(0)`), `setModuleGuard`, `enableModule`/`disableModule`, owner/threshold changes | **mandatory on-chain timelock** (immutable `ADMIN_TIMELOCK`, e.g. 48 h): `validFrom ≥ block.timestamp + ADMIN_TIMELOCK` enforced at creation |

`checkTransaction` dispatch order:

1. `operation == DELEGATECALL` → revert, **unless** `to == MULTISEND_CALL_ONLY` (the canonical, immutably-pinned `MultiSendCallOnly` address) → batch path below. No other delegatecall target can ever be authorized.
2. `to == safe` or selector in the admin set → require a matching, timelock-elapsed `ADMIN` approval.
3. `data.length == 0 && value > 0` → require a matching `PAYLOAD` approval (exact `to` + `value`).
4. ERC-20 `transfer` selector → require a matching `TRANSFER` approval.
5. Anything else → require a matching `PAYLOAD` approval **and** the target+selector on the policy allowlist; otherwise revert.

`ADMIN` approvals emit a distinct, loud `AdminPreApprovalCreated(safe, target, dataHash, executableAt)` event at creation — the timelock exists precisely so owners, watchers, and the dashboard can see a pending guard-removal or owner change and revoke it (`revokePreApproval` works throughout the delay).

**No-brick invariant** (must be test-covered): at any reachable contract state, at least one of these paths can remove the Guard —
1. `ADMIN` pre-approval for `setGuard(address(0))` + owner-signed Safe transaction, after `ADMIN_TIMELOCK`;
2. the emergency de-guard path (Safe-governance-initiated, longer timelock, **no quantum key required**) — for the case where the XMSS key is lost or the verifier itself is buggy.
Neither path may depend on any component that the Guard can render unusable (in particular, path 2 must not require a quantum signature, and both paths must work while the Guard is paused).

### Emergency de-guard path — mechanism

The fallback (path 2) is implemented **in the Guard itself**, so it requires no external contract and survives every Guard state:

1. `requestEmergencyDeGuard()` — callable only by the enrolled Safe (`msg.sender == safe`), i.e., via a normal owner-threshold Safe transaction. **`checkTransaction` hardcodes an allow** for the single case `to == address(this) && selector == requestEmergencyDeGuard.selector && value == 0 && operation == CALL`, bypassing pause state and all pre-approval requirements — this is the one transaction the Guard may never block, and the allow must be the first check in `checkTransaction`.
2. The request starts `EMERGENCY_TIMELOCK` (immutable, materially longer than `ADMIN_TIMELOCK`, e.g., 14 days) and emits `EmergencyDeGuardRequested(safe, executableAt)` — the dashboard treats this as a highest-severity alert to all owners and the Administrator.
3. During the window, the request can be cancelled by either a quantum `ADMIN`-class pre-approved transaction or another owner-signed Safe call to `cancelEmergencyDeGuard()` (also hardcoded-allowed) — whichever party is still healthy can stop a malicious request.
4. After expiry, `checkTransaction` permits exactly one self-call: `setGuard(address(0))`, with no pre-approval required. Nothing else is unlocked.

Threat trade-off, stated plainly: during an emergency de-guard the classical owner threshold is temporarily the only defense — exactly the pre-quantum status quo. The long timelock plus loud events is the mitigation; institutions that cannot accept it can set `EMERGENCY_TIMELOCK` longer at deployment. The alternative (no fallback) converts a lost XMSS key or a verifier bug into permanently frozen funds, which is strictly worse.


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

Allowed selectors for the MVP: `transfer(address,uint256)` only, matched against a pre-approval. No wrap/unwrap or other custom token actions — every additional selector is attack surface and must go through a spec change plus re-audit.

### Batching (MultiSend)

An outright MultiSend ban is unusable for the target audience — a 50-recipient payroll would cost 50 Safe transactions, 50 pre-approvals (~1M gas of XMSS verification each), ~400 Ledger button presses, and 50 leaves, which predictably pushes teams to remove the Guard for batch days. Batching is therefore supported, narrowly:

- **Only `MultiSendCallOnly`, only the pinned address.** The Guard stores the canonical `MultiSendCallOnly` (v1.4.1) address as an immutable. It is the sole permitted delegatecall target; `MultiSend` (which allows inner delegatecalls) stays banned forever.
- **One `PAYLOAD` pre-approval per batch.** `dataHash = keccak256(multiSendCalldata)` binds every leg — order, targets, values, calldata — with a single XMSS signature and a single leaf. Any post-signature mutation changes the hash and the Guard reverts.
- **On-chain per-leg structural checks.** Even though the hash already binds the batch, `checkTransaction` must decode the `MultiSendCallOnly` payload and enforce, per leg: `operation == CALL` (redundant with `MultiSendCallOnly` but checked anyway), leg target is not the Safe, the Guard, or the registry (no admin ops smuggled inside batches — those go through `ADMIN` alone), leg selector is `transfer` or on the policy allowlist, and per-token summed amounts respect the policy caps. Decoding N legs is a few hundred gas per leg — noise next to the XMSS verification.
- **Bounded size.** Policy sets `maxBatchLegs` (default 100) so decoding cannot be gas-griefed.
- **Ledger UX.** The device binds the batch `dataHash` and displays: leg count, per-token totals, and the hash — it cannot render 50 legs. The leg-by-leg review happens in the add-on UI with two-source verification; the on-chain per-leg checks above are the backstop that holds even if the host lies about the legs. One press-sequence, one leaf, whole payroll.

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
19. If the target is `MultiSend` (the delegatecall-capable variant) the guard must revert. `MultiSendCallOnly` is permitted only at the pinned canonical address, only with a batch `PAYLOAD` pre-approval binding `keccak256` of the full batch calldata, and only after the per-leg structural checks in "Batching (MultiSend)" pass.
20. If a pre-approval window is shorter than the minimum granularity, `createPreApproval` must revert (timestamp-manipulation margin).
21. If `ITransactionGuard` / `BaseTransactionGuard` / `Enum` / ERC165 are copied into this repo instead of imported from `@safe-global/safe-contracts`, that is a defect (`interfaceId` can disagree with `GuardManager` → `GS300`).
22. If pause, reentrancy, roles, EIP-712, bitmaps, or `ecrecover` are hand-rolled, that is a defect — use OpenZeppelin.
23. If Safe tx hash is recomputed locally instead of `ISafe(msg.sender).getTransactionHash(...)`, that is a defect.
24. If hybrid/PQ verification uses HMAC or a custom lattice implementation, that is a defect — `SignatureChecker` + pinned audited PQ verifier or `liboqs` / `@noble/post-quantum` at the documented trust boundary.
25. `supportsInterface` must be the inherited Safe implementation (optionally extended for `IModuleGuard`), never a from-scratch ERC165.

## Guard behavior requirements for FermionWallet

The Guard must:

- inspect the Safe transaction before execution,
- decode the target call and confirm it is an allowed ERC-20 `transfer`,
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

## Who calls `checkTransaction`, exactly

`checkTransaction` is called by **the Safe account itself** — specifically, by the Safe **proxy contract** executing the Safe singleton's `execTransaction` code via `DELEGATECALL`. No other contract, service, or user is a legitimate caller.

### The contracts involved

1. **SafeProxy** — the on-chain address of the Safe account (the address that holds the funds). It contains no logic; every call to it is `DELEGATECALL`ed to the Safe singleton.
2. **Safe singleton** (`Safe.sol`, e.g. v1.4.1) — the canonical implementation. It inherits `GuardManager`, which stores the guard address in the dedicated storage slot `GUARD_STORAGE_SLOT` (`keccak256("guard_manager.guard.address")`), set previously by `setGuard(address)` — itself callable only via a Safe transaction (`SelfAuthorized`).
3. **FermionWalletGuard** — this contract. It receives a plain external `CALL` from the Safe proxy address.

### The exact call sequence inside `Safe.execTransaction`

When an owner or relayer calls `execTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures)` on the Safe proxy:

1. The proxy `DELEGATECALL`s the singleton's `execTransaction`. All storage reads (owners, threshold, nonce, guard slot) hit the **proxy's** storage.
2. The singleton computes `txHash = getTransactionHash(..., nonce)` using the **current** nonce.
3. It increments `nonce`.
4. It runs `checkSignatures(txHash, signatures)` — the classical multisig check. If signatures are invalid, it reverts here; the guard is never reached.
5. It loads the guard address from `GUARD_STORAGE_SLOT`. If the slot is zero, no guard is consulted.
6. If nonzero, the Safe makes an **external `CALL`** (not delegatecall):
   `ITransactionGuard(guard).checkTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures, msg.sender)`
   - Inside the Guard, `msg.sender` **is the Safe proxy address**. This is the property our access-control check relies on (`require(enrolledSafe[msg.sender])`).
   - The final `msgSender` *parameter* is the EOA/relayer that called `execTransaction` — informational only, never a trust anchor.
   - Because it is a `CALL`, the Guard runs with its **own** storage and may write state (consume the pre-approval, set the reentrancy depth marker).
7. Any revert in the Guard bubbles up and aborts `execTransaction` — the target call never executes.
8. If the Guard returns, the Safe executes the target call (`CALL` or `DELEGATECALL` per `operation`).
9. The Safe then calls `checkAfterExecution(txHash, success)` on the same guard — again a plain `CALL` from the proxy address.
10. Refund logic (if `gasPrice != 0`) runs last.

### Consequences the implementation must honor

- **Caller identity check**: the only valid `msg.sender` for `checkTransaction`/`checkAfterExecution` is an enrolled Safe proxy. Anyone can *technically* call the Guard (it is a public external function on a public contract), which is precisely why the Guard must revert for non-enrolled callers instead of mutating state.
- **Nonce is already incremented** when the Guard runs (step 3 precedes step 6): recompute the safeTxHash with `ISafe(msg.sender).nonce() - 1`.
- **The guard slot is per-Safe**: each Safe proxy stores its own guard address; one deployed FermionWalletGuard instance can serve many Safes, keyed by `msg.sender`.
- **Module path is separate**: `execTransactionFromModule` does not run this sequence and never touches `GUARD_STORAGE_SLOT` (pre-1.5); the module-guard mitigation section above applies.
- **Signature validation precedes the guard**: the Guard can assume owner approval already happened; it is strictly the *second* authorization.

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
- Batching supported via pinned `MultiSendCallOnly` only: one hash-bound pre-approval per batch, on-chain per-leg structural checks; delegatecall-capable `MultiSend` rejected always.
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
