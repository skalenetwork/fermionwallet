# FermionWallet Guard Contract

## Table of contents

- [Programming language](#programming-language)
- [Principle: library-first, almost no original code](#principle-library-first-almost-no-original-code)
- [No global powers](#no-global-powers)
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

## No global powers

The Guard is one contract shared by every enrolled Safe, so any power over the Guard itself is a power over all customers. There is none:

- no admin, owner, guardian, or role of any kind (no `AccessControl`, no `Ownable`);
- no global pause, and no governance-curated list (such as a fallback-handler allowlist);
- no upgrade path: the Guard is non-upgradeable (no proxy, no `selfdestruct`, no delegatecall to mutable code).

Every control is scoped to one Safe and held by that Safe's owners: its pause, its selector policy, its key, its pre-approvals, and whether the Guard is attached at all. **Only a Safe's owners can change or remove the Guard attached to that Safe**, because `setGuard` is a Safe self-call that needs the owner threshold. A new Guard version is a new deployment, which each Safe adopts (or not) on its own. Any future change that adds a power reaching more than one Safe violates this spec.

## Mandatory libraries (pin exact releases in `package.json` / `foundry.toml`)

### Safe — execution model (do not fork)

| Use | Import |
|---|---|
| Guard base + ERC165 that Safe actually checks | `@safe-global/safe-contracts` → `BaseTransactionGuard`, `ITransactionGuard` |
| `CALL` vs `DELEGATECALL` | `@safe-global/safe-contracts` → `Enum` |
| Recompute the Safe tx hash (use `nonce - 1` inside `checkTransaction`) | `@safe-global/safe-contracts` → `ISafe.getTransactionHash(...)` on `msg.sender` |
| Module-path coverage (Safe ≥ 1.5) | `@safe-global/safe-contracts` → `IModuleGuard`, `BaseModuleGuard` |
| Self-call selectors | `IGuardManager`, `IFallbackManager`, `IModuleManager`; `MultiSendCallOnly.multiSend` |
| Module list and guard / fallback-handler slots | `ISafe.getModulesPaginated`, `ISafe.getStorageAt` (the slot getters are internal in Safe) |

Do **not** copy these files into the repo. Depend on the published package.

### OpenZeppelin Contracts — all operational security

Pinned release: **v5.2.0** (the first release with `Bytes`).

| Concern | Use this, not custom code |
|---|---|
| Nested Safe-tx depth, per Safe | `TransientSlot` + `SlotDerivation` keyed by Safe. `ReentrancyGuardTransient` is deliberately **not** used: it is one global lock, which on a shared singleton would block unrelated Safes |
| Domain separation (Guard address, chainId) | `EIP712` |
| Classical half of a hybrid signature; ERC-1271 for institutional signers | `SignatureChecker.isValidSignatureNow` (not raw `ecrecover`) |
| Single-use owner-signed registry messages | `Nonces` (`registryNonce(safe)`) |
| Used XMSS leaves | `BitMaps` |
| Tier-2 approval queues | `DoubleEndedQueue` |
| Calldata decoding (`transfer`, self-call arguments, `multiSend(bytes)`) | `Bytes.slice` + `abi.decode` |
| Checked narrowing casts | `SafeCast` |
| ERC-20 selector constants | `IERC20`, `IERC20Permit` |
| Custom errors pattern | OZ-style custom errors; do not invent a parallel error system |

Hand-written code remains only where no library fits: the MultiSend packed-leg loop, and the XMSS hashing assembly (gas limit).

Do **not** use OpenZeppelin upgradeable proxies for the Guard. The Guard is non-upgradeable; a new Guard is a new deployment set via Safe `setGuard`.

Do **not** mix OpenZeppelin `IERC165` with a locally copied `ITransactionGuard`. The interface IDs for the Guard come from Safe’s own `ITransactionGuard` and `IModuleGuard`.

### Post-quantum cryptography — the Quantum Administrator's XMSS key

The second authorization is produced by a designated **Quantum Administrator** holding a **permanent, stateful XMSS key** (RFC 8391; NIST-approved via SP 800-208). XMSS verification is pure hashing, which the EVM executes cheaply — enabling **full on-chain PQ verification** with no commit-verify trust boundary.

| Layer | Choice |
|---|---|
| PQ signature scheme | **XMSS** (e.g., `XMSS-SHA2_20_256` or a keccak-instantiated variant), one long-lived key per Quantum Administrator, good for 2^20 (~1M) pre-approvals |
| On-chain verification | Solidity XMSS verifier: WOTS+ chain recomputation + L-tree + Merkle auth path to the registered root. Pure SHA-256 hashing through the precompile (`XMSS-SHA2_*_256`) — 736,700 gas measured per verification at h = 20, benchmarked in Foundry as an acceptance criterion |
| State management (critical) | Each signature consumes one leaf index. **Index reuse is catastrophic** (forgery becomes possible), so the contract tracks used indices in an OpenZeppelin `BitMaps` bitmap keyed by `(quantumKeyId, leafIndex)` and reverts on reuse. The Ledger app commits its leaf counter before releasing any signature |
| Classical hybrid half (on-chain) | OpenZeppelin `SignatureChecker` + `EIP712` — the pre-approval is valid only if **both** the XMSS and the classical signature verify |
| Key lifecycle | Registered as a single XMSS root (`xmssRoot`) in the registry via the co-signed one-shot `registerQuantumKey`. When leaf indices near exhaustion, the Administrator rotates to a new root via `rotateQuantumKey` (owner co-signatures, the Ledger's attestation of the new key, and an XMSS possession proof by the old key, per the access-control rules) |
| Off-chain signing | The FermionWallet XMSS Ledger app — the only signer; the add-on service holds no keys (the demo simulates the device with the RFC 8391 reference code in `contracts/py/`). Never `crypto.createHmac` labeled as quantum-safe |

### Existing open-source Solidity code for XMSS

Surveyed (2026-09); use as reference/baseline, not drop-in:

| Repo | What it has | License | Assessment |
|---|---|---|---|
| [`ruslan-ilesik/poqeth`](https://github.com/ruslan-ilesik/poqeth) | **The only complete XMSS verifier in Solidity** (`src/xmss/xmss.sol`), plus WOTS+, SPHINCS+, MAYO; Foundry tests; backed by the peer-reviewed paper [eprint 2025/091](https://eprint.iacr.org/2025/091) ("poqeth: Efficient post-quantum signature verification on Ethereum") | ⚠️ SPDX `UNLICENSED`, no LICENSE file (README claims open source — **contact authors before any reuse**) | Research-grade: ADRS modeled as a separate storage contract, `console.sol` imports — correct algorithmically, but gas-unoptimized and not production code. Best used as the correctness reference and Foundry gas baseline |
| [`QuipNetwork/hashsigs-solidity`](https://github.com/QuipNetwork/hashsigs-solidity) | Production-oriented **WOTS+** (`contracts/WOTSPlus.sol`) — the one-time-signature core of XMSS, but no L-tree/Merkle layer; companion Rust/TS/Python implementations for cross-testing; actively maintained | AGPL-3.0 (copyleft — fine for reference and open-source deployment; review before proprietary linking) | Cleanest vetted WOTS+ building block available |

Nothing else exists: ZKNox (ETHFALCON/ETHDILITHIUM) covers only lattice schemes; no LMS or other XMSS Solidity implementations were found.

**Plan of record — implemented:** FermionWallet's XMSS verifier is implemented in-house as a clean-room, **MIT-licensed** Solidity library at [`contracts/src/XMSS.sol`](./contracts/src/XMSS.sol) (no code taken from the unlicensed or AGPL repos above; written directly from RFC 8391), with leaf consumption enforced by the registry's used-leaf bitmap in [`contracts/src/QuantumKeyRegistry.sol`](./contracts/src/QuantumKeyRegistry.sol). It is validated against an independent Python RFC 8391 reference (`contracts/py/xmss_ref.py`) with positive vectors at h = 4, 10, and **20 (the production parameter set)** plus tamper and fuzz tests, and benchmarked in Foundry: **736,700 gas measured** per verification at h=20 — within the 0.4–1M target. Remaining before mainnet: cross-check against poqeth's published numbers and the same external audit as the Guard.

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

// contracts/src/FermionWalletGuard.sol (abridged)
contract FermionWalletGuard is
    PreApprovalEngine,     // abstract: pre-approvals; inherits QuantumKeyRegistry
                           // (abstract: keys, leaf bitmaps; inherits EIP712, Nonces)
    BaseTransactionGuard,  // Safe: checkTransaction / checkAfterExecution
    BaseModuleGuard        // Safe >= 1.5: checkModuleTransaction / checkAfterModuleExecution
{
    // One contract, one storage: keys, pre-approvals and per-Safe policy are shared
    // by both hooks. No AccessControl, no Ownable, no Pausable (see "No global powers").
}
```

`supportsInterface` reports exactly `type(ITransactionGuard).interfaceId`, `type(IModuleGuard).interfaceId` and `type(IERC165).interfaceId`, using Safe's own interface definitions.

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
- A global pause flag or any role mapping (the per-Safe pause and per-Safe transient depth counter are the only exceptions — see "No global powers")
- A local EIP-712 domain separator or Safe tx hasher (call `ISafe.getTransactionHash`)
- A local nonce counter or used-bit mapping when `Nonces` / `BitMaps` will do
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
// The deployed contract is FermionWalletGuard, which also contains
// QuantumKeyRegistry and PreApprovalEngine (abstract bases — never deployed alone).
// Every function below is on that one address. Reference: contracts/src/*.sol.
interface IFermionWalletGuard is ITransactionGuard, IModuleGuard {
    // ── Types ────────────────────────────────────────────────────────────────
    enum KeyStatus { None, Active, Rotated, Revoked }

    struct KeyRegistration {
        bytes32 quantumKeyId;   // keccak256(abi.encodePacked(safe, xmssRoot, registryNonce))
        address safe;
        address quantumAdmin;   // Administrator's Ledger EOA — the ECDSA half of every
                                // hybrid signature is verified against this address
        bytes32 xmssRoot;       // XMSS public root — one key per Safe, all tokens
        bytes32 xmssSeed;       // XMSS public SEED — mandatory verification input (RFC 8391)
        uint32 treeHeight;      // 1..20
        bytes32 parameterSet;   // e.g. keccak256("XMSS-SHA2_20_256")
        KeyStatus status;
        uint64 createdAt;
        uint64 rotatedAt;
        uint256 useCounter;     // leaves consumed under this key
    }

    enum ApprovalClass {
        TRANSFER, // ERC-20 transfer: token/recipient/amount binding, no timelock
        PAYLOAD,  // exact payload: native ETH, allowlisted calls, MultiSendCallOnly batches
        ADMIN     // exact payload, target == safe or this Guard; mandatory ADMIN_TIMELOCK
    }

    struct PreApproval {
        bytes32 id;             // keccak256(abi.encodePacked(safe, nonce))
        address safe;
        ApprovalClass class_;
        // TRANSFER class fields (zero for other classes)
        address token;
        address recipient;
        uint256 amount;
        // PAYLOAD / ADMIN class fields (zero for TRANSFER)
        address target;
        uint256 value;
        bytes32 dataHash;       // keccak256 of the exact calldata; binds the full payload
        // common fields
        uint64 validFrom;       // ADMIN: >= block.timestamp + ADMIN_TIMELOCK at creation
        uint64 validTo;
        bytes32 nonce;          // approval ID salt (NOT the Safe nonce)
        bytes32 quantumKeyId;
        uint32 xmssLeafIndex;
        bytes32 policyHash;     // signed and stored; not checked against an on-chain policy
        bytes32 txHash;         // any class: exact safeTxHash pin (Tier 1); bytes32(0) = Tier 2
        bytes32 signatureHash;  // keccak256 of the XMSS signature; full bytes never stored
        bool used;
        bool revoked;
    }

    // Calldata request shared by all three create functions — one shape, three
    // class-specific validators. Class-irrelevant fields must be zero (creation
    // reverts NonZeroClassFields otherwise).
    struct PreApprovalRequest {
        address safe;
        address token;      // TRANSFER only
        address recipient;  // TRANSFER only
        uint256 amount;     // TRANSFER only
        address target;     // PAYLOAD / ADMIN only
        uint256 value;      // PAYLOAD / ADMIN only
        bytes32 dataHash;   // PAYLOAD / ADMIN only: keccak256 of the exact calldata
        uint64 validFrom;
        uint64 validTo;
        bytes32 nonce;
        bytes32 quantumKeyId;
        uint32 xmssLeafIndex;
        bytes32 policyHash;
        bytes32 txHash;     // exact safeTxHash pin (Tier 1); bytes32(0) = field-matched queue (Tier 2)
    }

    // ── Deployment parameters (all immutable; there is no admin) ────────────
    // constructor(address multiSendCallOnly, uint64 adminTimelock, uint64 emergencyTimelock,
    //             uint32 maxBatchLegs, uint32 maxCommitmentQueue)
    // emergencyTimelock must exceed adminTimelock; it also sets EMERGENCY_ROTATION_TIMELOCK.
    function MULTISEND_CALL_ONLY() external view returns (address);
    function ADMIN_TIMELOCK() external view returns (uint64);
    function EMERGENCY_TIMELOCK() external view returns (uint64);           // emergency de-guard
    function EMERGENCY_ROTATION_TIMELOCK() external view returns (uint64);  // key revocation
    function MAX_BATCH_LEGS() external view returns (uint32);
    function MAX_COMMITMENT_QUEUE() external view returns (uint32);
    function MIN_WINDOW() external view returns (uint64);                   // constant, 15 minutes

    // ── Key registry ─────────────────────────────────────────────────────────
    // Co-signed one-shot registration (see quantum-key-registry.md). The caller is
    // the Administrator's relayer EOA, never the Safe, so `safe` is explicit.
    // ownerSignatures: owner threshold over EIP-712 ApproveQuantumKey, verified
    // through the Safe's legacy checkSignatures(bytes32,bytes,bytes) form (portable
    // across Safe 1.3.0 / 1.4.1 / 1.5.0). ledgerAttestation: EIP-712
    // QuantumKeyAttestation signed by quantumAdmin. Rejects: an existing key,
    // a root this Safe registered before, invalid params, an expired deadline.
    function registerQuantumKey(
        address safe,
        address quantumAdmin,
        bytes32 xmssRoot,
        bytes32 xmssSeed,
        uint32 treeHeight,
        bytes32 parameterSet,
        uint256 validUntil,
        bytes calldata ledgerAttestation,
        bytes calldata ownerSignatures
    ) external returns (bytes32 quantumKeyId);

    // Rotation = registration + an XMSS signature by the OLD key over the same
    // RotateQuantumKey digest (consumes one old-key leaf). Atomic: old → Rotated,
    // new → Active. Supersedes (cancels) any pending key revocation.
    function rotateQuantumKey(
        address safe,
        address newQuantumAdmin,   // may equal the current one
        bytes32 newXmssRoot,
        bytes32 newXmssSeed,
        uint32 treeHeight,
        bytes32 parameterSet,
        uint256 validUntil,
        bytes calldata oldKeyXmssProof,
        bytes calldata ledgerAttestation,
        bytes calldata ownerSignatures
    ) external returns (bytes32 newQuantumKeyId);

    // Emergency revocation without the old key. Owner-threshold RequestKeyRevocation
    // signatures (single-use: the request consumes the registry nonce), then
    // EMERGENCY_ROTATION_TIMELOCK, then anyone may execute. Execution revokes exactly
    // the key the request named (RevocationSuperseded if it was rotated meanwhile).
    // Only the Safe itself may cancel — never the Administrator's key alone.
    function requestKeyRevocation(address safe, uint256 validUntil, bytes calldata ownerSignatures) external;
    function cancelKeyRevocation(address safe) external;   // msg.sender == safe
    function executeKeyRevocation(address safe) external;  // permissionless after the timelock

    function getKey(bytes32 quantumKeyId) external view returns (KeyRegistration memory);
    function safeToQuantumKey(address safe) external view returns (bytes32); // Active key, or 0
    function enrolledSafe(address safe) external view returns (bool);        // sticky
    function registryNonce(address safe) external view returns (uint256);   // == nonces(safe)
    function nonces(address safe) external view returns (uint256);          // OpenZeppelin Nonces
    function rootRegistered(address safe, bytes32 xmssRoot) external view returns (bool);
    function isLeafUsed(bytes32 quantumKeyId, uint32 leafIndex) external view returns (bool);
    function keyRevocationExecutableAt(address safe) external view returns (uint64);
    function keyRevocationKeyId(address safe) external view returns (bytes32);

    // ── Pre-approval creation ────────────────────────────────────────────────
    // HYBRID signature verification (both halves mandatory, same EIP-712 digest):
    //   * ecdsaSignature: the Ledger's classical half, verified via
    //     SignatureChecker.isValidSignatureNow against the key's quantumAdmin.
    //   * xmssSignature: abi.encode(XMSS.Signature{leafIdx, r, wotsSig[67], authPath[h]})
    //     (~2.8 KB at h=20), verified against the key's root/seed; the leaf is
    //     consumed in the on-chain bitmap and must equal req.xmssLeafIndex.
    // The digest binds safe, class, every class field, validity, nonce, key, leaf
    // index, policyHash and txHash; the domain binds the Guard address and chainid.
    // The key must be the Safe's Active key; validTo - validFrom >= MIN_WINDOW and
    // validTo > now. No maximum window is enforced on-chain.
    //
    // Lookup at execution time — two tiers, both bounded:
    //   Tier 1 (pinned): approvalByTxHash[safe][safeTxHash]. A pin may be replaced
    //     only once its approval is expired, revoked, or under a revoked key (never
    //     while live or used; TxHashAlreadyPinned otherwise).
    //   Tier 2 (field-matched, txHash == 0): a FIFO queue (OpenZeppelin
    //     DoubleEndedQueue) per commitment
    //       keccak256(abi.encode(safe, class, token, recipient, amount))       // TRANSFER
    //       keccak256(abi.encode(safe, class, target, value, dataHash))        // PAYLOAD / ADMIN
    //     Identical recurring payouts queue. Permanently dead entries (used,
    //     revoked, expired, revoked key) are popped from the front on every create
    //     and consume, and a create that hits the cap first compacts dead entries
    //     out of the whole queue, so they never count toward the MAX_COMMITMENT_QUEUE cap;
    //     not-yet-valid entries stay queued. Consumption takes the first
    //     currently-valid entry. Tier 1 is tried first; a dead pin falls through.
    // Approvals of a Rotated key stay consumable; a Revoked key's do not.
    function createPreApproval(          // TRANSFER; token, recipient != 0
        PreApprovalRequest calldata req,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature
    ) external returns (bytes32 preApprovalId);

    function createPayloadPreApproval(   // PAYLOAD; target != 0
        PreApprovalRequest calldata req,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature
    ) external returns (bytes32 preApprovalId);

    // ADMIN: req.target must be the Safe itself (setGuard, setFallbackHandler(0),
    // setModuleGuard, enable/disableModule, owner/threshold changes — any self-call)
    // or this Guard (setSelectorPolicy). Reverts unless
    // req.validFrom >= block.timestamp + ADMIN_TIMELOCK.
    function createAdminPreApproval(
        PreApprovalRequest calldata req,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature
    ) external returns (bytes32 preApprovalId);

    // Callable by the Safe or the key's quantumAdmin; also by any single owner of the
    // Safe directly — except ADMIN approvals, which only the Safe (owner threshold)
    // or the quantumAdmin can revoke. Not callable on used/revoked approvals.
    function revokePreApproval(bytes32 preApprovalId) external returns (bool);
    // Off-chain convenience: checks state only (signatures were verified at creation).
    function validatePreApproval(bytes32 preApprovalId) external view returns (bool valid, string memory reason);
    function getPreApproval(bytes32 preApprovalId) external view returns (PreApproval memory);
    function approvalByTxHash(address safe, bytes32 safeTxHash) external view returns (bytes32);

    // ── Per-Safe policy ──────────────────────────────────────────────────────
    // Selector permit-list, {transfer} at first enrollment (a re-registration after
    // key revocation leaves it unchanged); consulted for every selector, transfer
    // included. Only the Safe may call it, which
    // routes it through ADMIN (to == this Guard). Deny-listed selectors (approve,
    // increaseAllowance, permit, transferFrom) can never be allowed.
    function setSelectorPolicy(address safe, bytes4 selector, bool allowed) external;
    function allowedSelectors(address safe, bytes4 selector) external view returns (bool);

    // ── Per-Safe pause (there is no global pause) ────────────────────────────
    // pauseSafe: any single owner of the Safe, the Safe, or its quantumAdmin.
    // After an unpause, single-key actors are blocked for ADMIN_TIMELOCK
    // (safePauseCooldownUntil); only the Safe may re-pause then. Unpause: the Safe
    // only — requestUnpauseSafe, then unpauseSafe after ADMIN_TIMELOCK. A re-pause
    // does not cancel a pending unpause.
    function pauseSafe(address safe) external;
    function requestUnpauseSafe() external;
    function unpauseSafe() external;
    function safePaused(address safe) external view returns (bool);
    function safeUnpauseExecutableAt(address safe) external view returns (uint64);
    function safePauseCooldownUntil(address safe) external view returns (uint64);

    // ── Emergency de-guard (no quantum key required) ─────────────────────────
    function requestEmergencyDeGuard() external;         // msg.sender == enrolled Safe
    function cancelEmergencyDeGuard(address safe) external; // msg.sender == safe only
    function emergencyDeGuardExecutableAt(address safe) external view returns (uint64);

    // ── Events ───────────────────────────────────────────────────────────────
    event QuantumKeyRegistered(bytes32 indexed quantumKeyId, address indexed safe, bytes32 xmssRoot, uint32 treeHeight);
    event QuantumKeyRotated(bytes32 indexed oldKeyId, bytes32 indexed newKeyId, address indexed safe);
    event KeyRevocationRequested(address indexed safe, bytes32 indexed quantumKeyId, uint64 executableAt);
    event KeyRevocationCancelled(address indexed safe, bytes32 indexed quantumKeyId);
    event QuantumKeyRevoked(bytes32 indexed quantumKeyId, address indexed safe);
    event LeafConsumed(bytes32 indexed quantumKeyId, uint32 indexed leafIndex, bytes32 digest);
    event PreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed token, uint256 amount);
    event PayloadPreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed target, bytes32 dataHash);
    event AdminPreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed target, bytes32 dataHash, uint64 executableAt);
    event PreApprovalUsed(bytes32 indexed id, address indexed safe, address indexed recipient, uint256 amount); // recipient/amount = target/value for PAYLOAD/ADMIN
    event PreApprovalRevoked(bytes32 indexed id, address indexed safe);
    event TransactionChecked(address indexed safe, bytes32 indexed safeTxHash, bytes32 indexed preApprovalId);
    event ModuleTransactionChecked(address indexed safe, address indexed module, bytes32 indexed preApprovalId);
    event SelectorPolicyChanged(address indexed safe, bytes4 indexed selector, bool allowed);
    event SafePaused(address indexed safe, address indexed by);
    event SafeUnpauseRequested(address indexed safe, uint64 executableAt);
    event SafeUnpaused(address indexed safe);
    event EmergencyDeGuardRequested(address indexed safe, uint64 executableAt);
    event EmergencyDeGuardCancelled(address indexed safe, address indexed by);
    event EmergencyDeGuardCleared(address indexed safe);

    // ── Custom errors (the fallback UI: Safe{Wallet} simulation shows these) ──
    // Enforcement: NotEnrolledSafe, SafePausedError, NestedSafeTransaction,
    //   GasRefundForbidden, DelegateCallForbidden, ModuleDelegateCallForbidden,
    //   ModulesEnabledWithoutModuleGuard, ModuleGuardNotWired, FallbackHandlerForbidden,
    //   DeniedSelector, SelectorNotAllowed, NativeValueOnTransfer,
    //   MalformedTransferCalldata, MalformedBatch, BatchTooLarge,
    //   ForbiddenBatchLegTarget, NoMatchingPreApproval.
    // Pre-approvals: ApprovalExists, InvalidWindow, AdminTimelockNotRespected,
    //   InvalidAdminTarget, NonZeroClassFields, InvalidEcdsaSignature, WrongQuantumKey,
    //   LeafIndexDoesNotMatchSignature, TxHashAlreadyPinned, CommitmentQueueFull,
    //   UnknownApproval, NotRevocable.
    // Registry: ZeroAddress, InvalidKeyParams, SafeAlreadyEnrolled, NoActiveKey,
    //   SignatureExpired, InvalidAttestation, RootAlreadyRegistered, LeafAlreadyUsed,
    //   InvalidXmssSignature, LeafIndexMismatch, RevocationNotRequested,
    //   RevocationTimelocked, RevocationSuperseded, NotAuthorized.
    // Pause / de-guard: SafeNotPaused, PauseCooldown, UnpauseNotRequested,
    //   UnpauseTimelocked, EmergencyDeGuardNotRequested.
    // Owner-signature failures surface as the Safe's own GS0xx errors.
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
- `registerQuantumKey(...)` runs on a **shared singleton** whose caller is the Administrator's relayer EOA, so the target `safe` is an explicit parameter — it determines which Safe's `checkSignatures` is consulted and which `safeToQuantumKey[safe]` slot is written; `msg.sender` must never be used to infer the Safe. It must verify the owner co-signatures (Safe threshold, via the legacy `checkSignatures(bytes32,bytes,bytes)` form for Safe 1.3/1.4/1.5 portability) over an EIP-712 struct that binds the XMSS root itself, the `quantumAdmin` address, the `safe` address, chain ID, `registryNonce`, and a validity deadline — so a mempool front-runner cannot redirect a ceremony to a different Safe. It must verify that `ledgerAttestation` is signed by `quantumAdmin`, reject if the Safe already has an Active key, reject same-Safe root reuse while allowing cross-Safe reuse, and bump the per-safe `registryNonce` on success.
- `rotateQuantumKey(...)` must additionally verify an XMSS signature by the **old** key over the same `RotateQuantumKey` digest the owners signed (which binds the new root; consumes one leaf), plus owner co-signatures as above. It supersedes any pending key revocation. Emergency revocation without the old key goes through `requestKeyRevocation` → `EMERGENCY_ROTATION_TIMELOCK` → `executeKeyRevocation`; its owner signatures are single-use (the request consumes the registry nonce), only the Safe itself can cancel it, and execution revokes only the key the request named.
- `revokePreApproval(...)` is callable by the Safe or the `quantumAdmin` of the key that created the approval, and by **any single owner** of the Safe directly from the owner's address — revocation is deliberately cheaper than approval — **except for ADMIN approvals**, which a single owner cannot revoke: ADMIN approvals are how the threshold changes governance (including removing a rogue owner), so one owner must not be able to veto them. The Safe can still revoke them with an owner-threshold transaction the Guard never blocks.
- `createPreApproval(...)` (all classes) must verify **both hybrid halves** on-chain before storing the approval: the ECDSA half via `SignatureChecker.isValidSignatureNow` against the registered `quantumAdmin`, and the XMSS half against the registered `xmssRoot` with leaf-bitmap consumption. It must not accept unverified records, and a valid XMSS half with a missing/invalid ECDSA half must revert (the Ledger anchor is not optional).
- Enrollment must verify Safe posture before accepting a Safe: no fallback handler, and no unguarded modules. Operators must also revoke pre-existing token/Permit2 allowances before enrollment; allowances granted before the Guard cannot be policed by it.

## Module bypass — mandatory mitigation

Safe transaction guards are only invoked in the `execTransaction` path. Transactions executed by an enabled Safe Module through `execTransactionFromModule` **bypass the transaction guard entirely** in Safe v1.3.0/v1.4.1.

Required mitigations:

- The Safe must have **no enabled modules**, verified at enrollment and re-checked in `checkTransaction`, or
- On Safe v1.5.0+, this same FermionWallet contract must already be installed as the Safe's `IModuleGuard` via `setModuleGuard(...)`, implementing `checkModuleTransaction(...)` and `checkAfterModuleExecution(...)` with the same policy checks.

**Module-guard architecture (resolved):** the tx guard and the module guard are **one contract**. `FermionWalletGuard` inherits `BaseTransactionGuard` *and* `BaseModuleGuard`, overrides `supportsInterface` to report both `type(ITransactionGuard).interfaceId` and `type(IModuleGuard).interfaceId` (per the note in "Contract header" above), and routes `checkModuleTransaction(to, value, data, operation, module)` through the same class-dispatch pipeline as `checkTransaction` — with these module-specific rules: `operation == DELEGATECALL` from a module is always rejected (no MultiSend exception); matching is Tier 2 only (module transactions have no `safeTxHash`); the module address is logged in `ModuleTransactionChecked`; the same fallback-handler rules apply (a module can never install a handler); and a module-executed `setGuard` clears any emergency de-guard request, via `checkAfterModuleExecution`. The Safe's own pause applies to module transactions too. On Safe < 1.5.0 the module-guard entry points are never wired, so `enableModule` is rejected outright and enrollment enforces the "no enabled modules" rule. "Wired" means both that the Safe's module-guard slot (`keccak256("module_manager.module_guard.address")`) holds this Guard **and** that the Safe's `VERSION()` is ≥ 1.5.0: on v1.3.0/v1.4.1 that slot is ordinary storage the singleton never reads (a Safe downgraded from 1.5 keeps a stale value, and a pre-enrollment delegatecall can plant one), so the Guard never trusts it there — a Safe without a parseable `VERSION()` ≥ 1.5 counts as unwired (fail closed). On those versions the residual posture is therefore: a module enabled in the window between enrollment and `setGuard` still executes unguarded (the Guard never sees `execTransactionFromModule`), while every owner transaction fails closed with `ModulesEnabledWithoutModuleGuard` until the quantum-approved `disableModule` remediation.
- `enableModule(...)` is rejected with `ModuleGuardNotWired` unless this Guard is already wired as the Safe's module guard. On Safe v1.5 the required order is two separate quantum-approved admin actions: `setModuleGuard(guard)` first, then `enableModule(...)`.
- The module-posture check must exempt remediation self-calls: `disableModule(...)`, `setModuleGuard(...)`, and the quantum-approved `setGuard(address(0))` Guard removal path, so an unsafe module posture never blocks its own repair. Every remediation self-call (`disableModule`, `setModuleGuard`, `setFallbackHandler(address(0))`) is exempt from **both** posture checks: a Safe that installed a handler and a module before attaching the Guard is bad on both counts, and neither repair may be blocked by the other defect.

## Guard-removal and self-call protection

A Safe transaction whose target is the Safe itself can call `setGuard(address(0))` and silently remove the enforcement layer, or call `enableModule`, `addOwnerWithThreshold`, `changeThreshold`, etc.

The Guard must therefore:

- treat any transaction with `to == safe` (or `to ==` the Guard) as a restricted administrative action requiring a matching, timelock-elapsed `ADMIN` approval — this covers `setGuard`, `setModuleGuard`, `enableModule`, `disableModule`, owner/threshold changes, and **every other self-call** (the Guard does not enumerate self-call selectors; the exact calldata is bound by the approval),
- additionally reject `enableModule` unless this Guard is already the module guard, and reject `setFallbackHandler` to any non-zero handler even with an approval. The Guard recognises the `setFallbackHandler` and `setGuard` self-calls by selector and first argument word, **not** by exact calldata length: Safe's ABI decoder ignores trailing calldata, so `setFallbackHandler(h) ‖ junk` installs `h` just like the canonical 36-byte call and must be rejected the same way (and a padded `setGuard` ends the Guard's tenure like any other).

Note the operational trade-off: a buggy Guard can brick the Safe (every tx reverts, including the tx to remove the Guard). This is resolved by the **pre-approval class system** below plus the time-locked emergency de-guard path — together they guarantee the no-brick invariant.

## ERC-1271 fallback-handler mitigation

Safe's default `CompatibilityFallbackHandler` can validate owner ECDSA signatures through `isValidSignature` without creating a Safe transaction, which lets Permit/Permit2 and signature-order protocols bypass the Guard. FermionWallet therefore treats fallback-handler posture as part of enrollment and every checked transaction:

- A guarded Safe has **no** fallback handler. There is no allowlist: curating one would be a global power over every Safe (see "No global powers").
- `checkTransaction`, `checkModuleTransaction`, and enrollment read the Safe fallback-handler slot and revert if it is nonzero.
- Remediation is exempt: quantum-approved `setGuard(address(0))` removal and the ADMIN self-call `setFallbackHandler(address(0))` are never blocked; installing any other handler is rejected.
- Operators must revoke pre-existing token and Permit2 allowances before enrollment, because allowances created before the Guard was installed cannot be retroactively controlled.

## Pre-approval classes

A single transfer-shaped `PreApproval` struct cannot represent admin operations or native ETH — which would make the Guard impossible to remove (deadlock: the Guard blocks admin self-calls without quantum authorization, but a transfer-only struct can never express `setGuard(address(0))`). The engine therefore defines **three classes**, all XMSS-signed, all consuming one leaf index:

| Class | Binds | Covers | Timelock |
|---|---|---|---|
| `TRANSFER` (0) | `token`, `recipient`, `amount` | ERC-20 `transfer` fast path | none (validity window only) |
| `PAYLOAD` (1) | exact payload: `target`, `value`, `keccak256(data)` (the operation is not part of the approval; the dispatch path fixes it) | native currency sends (empty calldata), policy-allowlisted non-transfer calls, and `MultiSendCallOnly` batches (delegatecall, `target` = the pinned MultiSendCallOnly) | none beyond the validity window (min 15 min) |
| `ADMIN` (2) | exact payload, `target == safe` or `target ==` the Guard | any Safe self-call (`setGuard` incl. `address(0)`, `setFallbackHandler(address(0))`, `setModuleGuard`, `enableModule`/`disableModule`, owner/threshold changes, …) and Guard policy calls (`setSelectorPolicy`) | **mandatory on-chain timelock** (immutable `ADMIN_TIMELOCK`, e.g. 48 h): `validFrom ≥ block.timestamp + ADMIN_TIMELOCK` enforced at creation |

`checkTransaction` dispatch order:

1. `operation == DELEGATECALL` → revert (`DelegateCallForbidden`), **unless** `to == MULTISEND_CALL_ONLY` (the immutably-pinned `MultiSendCallOnly` address) → per-leg checks, then a matching `PAYLOAD` approval over the whole batch calldata. No other delegatecall target can ever be authorized.
2. `to == safe` or `to ==` the Guard → require a matching, timelock-elapsed `ADMIN` approval.
3. Empty calldata (any `value`, including zero) → require a matching `PAYLOAD` approval (exact `to` + `value`).
4. Deny-listed selector (`approve`, `increaseAllowance`, `permit`, `transferFrom`) → revert (`DeniedSelector`).
5. The selector must be on the Safe's permit-list (`SelectorNotAllowed`) — `transfer` included: it is on the list from enrollment, and a Safe that removed it has no `TRANSFER` fast path. The permit-list is keyed by selector only, not by target; the approval itself binds the exact target.
6. ERC-20 `transfer` → `value` must be zero (`NativeValueOnTransfer`), calldata must decode canonically, then require a matching `TRANSFER` approval.
7. Anything else → require a matching `PAYLOAD` approval.

`ADMIN` approvals emit a distinct, loud `AdminPreApprovalCreated(safe, target, dataHash, executableAt)` event at creation — the timelock exists precisely so owners, watchers, and the dashboard can see a pending guard-removal or owner change and revoke it (`revokePreApproval` works throughout the delay).

**No-brick invariant** (must be test-covered): at any reachable contract state, at least one of these paths can remove the Guard —
1. `ADMIN` pre-approval for `setGuard(address(0))` + owner-signed Safe transaction, after `ADMIN_TIMELOCK` (works while the Safe is paused);
2. the emergency de-guard path (Safe-governance-initiated, longer timelock, **no quantum key required**) — for the case where the XMSS key is lost or the verifier itself is buggy;
3. for a Safe that has **never enrolled** (no key ever registered): `setGuard(address(0))` is always allowed. The Guard protects nothing for such a Safe, and without this a Safe that attached the Guard before enrolling — while it still had a fallback handler or module, so enrollment itself is refused — would be frozen forever.
None of these paths may depend on any component that the Guard can render unusable (in particular, path 2 must not require a quantum signature, and paths 1 and 2 must work while the Safe is paused; a never-enrolled Safe cannot be paused).

### Emergency de-guard path — mechanism

The fallback (path 2) is implemented **in the Guard itself**, so it requires no external contract and survives every Guard state:

1. `requestEmergencyDeGuard()` — callable only by the enrolled Safe (`msg.sender == safe`), i.e., via a normal owner-threshold Safe transaction. **`checkTransaction` hardcodes an allow** (zero-value `CALL` only, and — like every Safe transaction under this Guard — `gasPrice == 0`), bypassing pause, enrollment and all pre-approval requirements, for this family of calls — the one family the Guard may never block, checked first in `checkTransaction` (only the gas-refund ban comes before it):
   - Safe → Guard, the owner safety calls: `requestEmergencyDeGuard()`, `cancelEmergencyDeGuard(safe)`, `pauseSafe(safe)`, `requestUnpauseSafe()`, `unpauseSafe()`, `revokePreApproval(id)`, `cancelKeyRevocation(safe)`. Each re-checks its own authority; none can move funds or weaken enforcement.
   - Safe → Safe: `setGuard(address(0))` once the emergency timelock has matured, or at any time for a never-enrolled Safe.

   The check order is **normative** — getting it wrong silently destroys the only no-brick safety net, and the bug is invisible until the exact moment the escape hatch is needed:

   ```solidity
   function checkTransaction(address to, uint256 value, bytes calldata data, Enum.Operation operation, ...) external {
       // 0. The gas-refund ban. It is a parameter of the signed transaction, not Safe
       //    state, so it never blocks an escape call (re-sign with gasPrice = 0); checked
       //    any later, an escape call could pay the Safe's balance out as a "refund".
       if (gasPrice != 0) revert GasRefundForbidden();

       // 1. Then — before pause, before enrollment, before everything else:
       //    the emergency escape hatch may never be blocked by any other state.
       if (_isEmergencyEscapeCall(to, value, data, operation)) return;
       //    (matches the owner safety calls to the Guard — requestEmergencyDeGuard,
       //     cancelEmergencyDeGuard, pauseSafe, requestUnpauseSafe, unpauseSafe,
       //     revokePreApproval, cancelKeyRevocation — and setGuard(address(0)) once the
       //     emergency timelock has expired; an escape call still increments the depth counter)

       // 2. Only THEN the Safe's own deny-all pause (never blocks the quantum-approved
       //    setGuard(address(0)) removal):
       if (safePaused[safe] && !isGuardRemoval) revert SafePausedError(safe);

       // 3. Then enrollment, reentrancy depth, class dispatch, pre-approval matching…
   }
   ```

   ```solidity
   // WRONG — a paused Safe is permanently bricked, because unpausing is itself
   // time-locked governance and the key may be lost:
   if (safePaused[safe]) revert SafePausedError(safe);
   ...
   if (_isEmergencyEscapeCall(...)) return; // unreachable while paused
   ```

   A mandatory test (see production checklist) executes `requestEmergencyDeGuard` **while the Safe is paused** and asserts success.
2. The request starts `EMERGENCY_TIMELOCK` (immutable, materially longer than `ADMIN_TIMELOCK`, e.g., 14 days) and emits `EmergencyDeGuardRequested(safe, executableAt)` — the dashboard treats this as a highest-severity alert to all owners and the Administrator.
3. During the window, only the Safe itself can cancel: an owner-threshold Safe transaction to `cancelEmergencyDeGuard(safe)` (hardcoded-allowed, no quantum approval needed). The Quantum Administrator's key alone cannot cancel — otherwise a stolen Ledger could veto every emergency removal forever and brick the Safe.
4. After expiry, `checkTransaction` permits exactly one self-call: `setGuard(address(0))`, with no pre-approval required. Nothing else is unlocked. Any executed `setGuard` (by either path, owner- or module-executed) clears the request in `checkAfterExecution` / `checkAfterModuleExecution`, so a later re-attached Guard starts clean.

Threat trade-off, stated plainly: during an emergency de-guard the classical owner threshold is temporarily the only defense — exactly the pre-quantum status quo. The long timelock plus loud events is the mitigation; institutions that cannot accept it can set `EMERGENCY_TIMELOCK` longer at deployment. The alternative (no fallback) converts a lost XMSS key or a verifier bug into permanently frozen funds, which is strictly worse.


## Gas refund constraints

Safe's refund mechanism (`gasPrice`, `gasToken`, `refundReceiver`) pays out after execution and can drain the Safe if unconstrained. The Guard enforces `gasPrice == 0` (no refunds at all) and reverts with `GasRefundForbidden` otherwise. A future version could instead allow refunds under an explicit policy cap, with `refundReceiver` restricted to an allowlist and `gasToken` restricted to approved tokens; this is not implemented.

## Safe nonce recomputation quirk

**Cross-chain replay (post-MVP note).** Pre-approval signatures use an EIP-712 domain bound to the Guard address **and `block.chainid`**, so a pre-approval signed for chain A verifies nowhere else — including on a CREATE2 twin of the same Safe at the same address on chain B, and on either fork after a chain split (the fork with a changed chainid rejects old signatures). This is the intended behavior, not a defect: cross-chain approvals must be signed per chain, one Ledger confirmation each. The MVP is single-chain; multi-chain operation multiplies leaf consumption by the number of chains and is a policy decision, not a protocol change.

**Caller identity.** `checkTransaction`/`checkAfterExecution` have no dedicated caller parameter — the calling Safe *is* `msg.sender`. The Guard must treat `msg.sender` as the Safe identity and verify it is an **enrolled** Safe (`safeToQuantumKey[msg.sender]` exists with an `Active` key); calls from unenrolled addresses revert. This is safe precisely because `setGuard` can only be set by the Safe itself, so only a Safe that governance-installed this Guard ever calls these hooks; but the enrollment check still matters — it stops a *different, attacker-controlled* contract from calling `checkTransaction` directly to consume another Safe's field-matched pre-approvals (the commitment includes `safe`, and `safe` is taken from `msg.sender`, never from calldata, in the consumption path). Note the asymmetry with the create/register functions, where `msg.sender` is the relayer and `safe` is explicit calldata: consumption trusts `msg.sender`, creation never does.

In `Safe.execTransaction`, the transaction hash is computed with the current `nonce`, then `nonce` is incremented, and only afterwards is the guard's `checkTransaction(...)` called. If the Guard recomputes the safeTxHash to match it against a pre-approval `txHash`, it must use `safe.nonce() - 1`, not the current nonce. Getting this wrong makes every hash comparison fail (or worse, validates the wrong transaction).

**How the Guard recomputes the hash — no forked hasher needed.** This has been raised repeatedly in reviews as a "blocker" on the claim that `getTransactionHash` reads the nonce from storage. That claim is **false**: verified against the deployed source, `safe-global/safe-smart-account` **v1.4.1 `Safe.sol` lines 427–440** (and v1.3.0 `GnosisSafe.sol` equivalently) declare the function with an explicit `uint256 _nonce` as the last parameter — it exists precisely so off-chain signers can compute future hashes. Safe v1.3.0 and v1.4.1 expose exactly the interface required:

```solidity
// Safe v1.3.0 / v1.4.1 — GnosisSafe.sol / Safe.sol (public view)
function getTransactionHash(
    address to, uint256 value, bytes calldata data, Enum.Operation operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address refundReceiver,
    uint256 _nonce                    // ← explicit nonce parameter, NOT read from storage
) public view returns (bytes32);
```

The last parameter is an **explicit `_nonce`** (it exists precisely so off-chain signers can compute future hashes), so inside `checkTransaction` the Guard calls:

```solidity
bytes32 safeTxHash = ISafe(msg.sender).getTransactionHash(
    to, value, data, operation, safeTxGas, baseGas, gasPrice,
    gasToken, refundReceiver,
    ISafe(msg.sender).nonce() - 1     // nonce was already incremented by execTransaction
);
```

This uses the Safe's own hashing (correct domain separator, correct typehash, correct version quirks) with zero local reimplementation. The `nonce() - 1` subtraction cannot underflow in this call path: `checkTransaction` only runs from inside `execTransaction`, after the increment, so `nonce ≥ 1`. A mandatory integration test (see production checklist) deploys a real Safe + Guard, creates a pinned pre-approval for the known future `safeTxHash` at nonce `N`, executes at nonce `N`, and asserts the Guard's recomputed hash matches — this single test catches both the off-by-one and any Safe-version hashing drift.

## Pre-approval consumption semantics

- The single-use flag must be set (approval marked `used`) **inside `checkTransaction`**, which is a state-changing CALL from the Safe — this is permitted for guards and is the only safe place to consume the approval atomically with execution.
- `validatePreApproval` remains a `view` convenience for off-chain checks; it must never be the consumption mechanism.
- If execution later fails, `checkAfterExecution(hash, success)` may record the failure, but the approval stays consumed — replay after a failed execution requires a fresh pre-approval.

## Best-practice hardening (round 3 virtual security test)

### Reentrancy and nested Safe transactions

The target call executed by the Safe can re-enter `Safe.execTransaction`, causing the Guard's `checkTransaction` to run again before the outer `checkAfterExecution` completes. Requirements:

- The Guard tracks execution depth per Safe with a transient counter (`TransientSlot` at a `SlotDerivation` slot keyed by the Safe), incremented in `checkTransaction` and decremented in `checkAfterExecution`.
- Nested Safe executions of the same Safe are rejected (`NestedSafeTransaction`) when the counter is non-zero. Escape-hatch calls are never rejected, but they also increment the counter, so a nested escape call cannot reset an enclosing transaction's depth.
- The module path (`checkModuleTransaction`) does not touch the depth counter.
- All state writes (approval consumption, counters) follow checks-effects-interactions. The Guard's only external calls are read-only: calls to a Safe (`nonce`, `getTransactionHash`, `getModulesPaginated`, `getStorageAt`, `VERSION`, `isOwner`, and the legacy `checkSignatures` during registry ceremonies), the ERC-1271 `isValidSignature` staticcall that `SignatureChecker` makes when `quantumAdmin` is a contract, and the SHA-256 precompile.

### Emergency pause (circuit breaker)

- Each Safe has its own deny-all pause (`pauseSafe`) that makes every non-escape `checkTransaction` for that Safe revert. There is no global pause (see "No global powers").
- Pausing must be fast and low-privilege (any single owner of that Safe, the Safe itself, or its Quantum Administrator) because a compromised key holder can otherwise front-run revocations with an execution.
- Unpausing must be slow and high-privilege: that Safe's owner threshold plus a time lock. A re-pause must not cancel a pending owner-threshold unpause request; the timer survives and unpause executes at maturity.
- After unpause, a per-Safe cooldown of `ADMIN_TIMELOCK` blocks single-key actors (individual owners and the Quantum Administrator) from re-pausing. Only the Safe itself, via owner-threshold transaction, may pause during the cooldown.
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

Allowed selectors at the Safe's first enrollment: `transfer(address,uint256)` only, matched against a pre-approval. Each Safe may add selectors to its own permit-list through the ADMIN path — or remove them, `transfer` included, which then blocks `transfer` calls outright; every additional selector is attack surface.

**Allowlist storage and governance (resolved):** the deny-list above is **hardcoded** (immutable constants checked first — `approve`, `increaseAllowance`, `permit`, `transferFrom` can never be re-enabled by any governance action, only by a new Guard deployment). The permit-list is per-Safe policy state: `mapping(address safe => mapping(bytes4 selector => bool)) allowedSelectors`, initialized at the Safe's first enrollment to `{transfer}` only (registering a new key after an emergency key revocation does not reset it). Adding or removing a selector is a **policy change**, executed exactly like other policy mutations: an `ADMIN`-class pre-approval (hybrid dual signature + owner threshold + the mandatory `ADMIN_TIMELOCK`) targeting the Guard's `setSelectorPolicy(safe, selector, allowed)`. No EOA or Guard deployer can modify any Safe's allowlist. The permit-list is keyed by selector only (not target + selector); the PAYLOAD approval binds the exact target.

**Not yet implemented on-chain:** token and recipient allowlists, amount caps, and a maximum validity window. `policyHash` is signed and stored but not checked against any on-chain policy; these limits are currently enforced only off-chain by the add-on service.

### Batching (MultiSend)

An outright MultiSend ban is unusable for the target audience — a 50-recipient payroll would cost 50 Safe transactions, 50 pre-approvals (~1M gas of XMSS verification each), ~400 Ledger button presses, and 50 leaves, which predictably pushes teams to remove the Guard for batch days. Batching is therefore supported, narrowly:

- **Only `MultiSendCallOnly`, only the pinned address.** The Guard stores one `MultiSendCallOnly` address as an immutable (the deploy script defaults to the v1.4.1 deployment). Safes whose Safe{Wallet} batches through another MultiSendCallOnly version cannot batch through this Guard. It is the sole permitted delegatecall target; `MultiSend` (which allows inner delegatecalls) stays banned forever.
- **One `PAYLOAD` pre-approval per batch.** `dataHash = keccak256(multiSendCalldata)` binds every leg — order, targets, values, calldata — with a single XMSS signature and a single leaf. Any post-signature mutation changes the hash and the Guard reverts.
- **On-chain per-leg structural checks.** Even though the hash already binds the batch, `checkTransaction` must decode the `MultiSendCallOnly` payload and enforce, per leg: `operation == CALL` (redundant with `MultiSendCallOnly` but checked anyway), leg target is not the Safe, `address(0)` (which `MultiSendCallOnly` rewrites to the Safe itself), the Guard (which contains the registry), or `MultiSendCallOnly` itself (no admin ops smuggled inside batches — those go through `ADMIN` alone), a leg with calldata carries a selector that is not deny-listed and is on the Safe's permit-list (`transfer` included — it is not exempt), and 1–3-byte leg calldata is malformed. Legs with empty calldata (native value) are allowed; the batch hash binds them. Per-token amount caps are not yet implemented. Decoding N legs is a few hundred gas per leg — noise next to the XMSS verification.
- **Bounded size.** The immutable `MAX_BATCH_LEGS` (deploy-script default 100) caps decoding so it cannot be gas-griefed.
- **Strict decoding — malformed batches revert immediately.** `MultiSendCallOnly` legs are packed as `(uint8 operation, address to, uint256 value, uint256 dataLength, bytes data)`. The outer `multiSend(bytes)` argument is decoded with `abi.decode` (the same decoding `MultiSendCallOnly` performs). The Guard's leg decoder must, before touching any leg contents: (1) revert if the remaining bytes are shorter than the 85-byte fixed leg header, (2) revert if `dataLength` overruns the remaining calldata (truncation), (3) revert if, after the last leg, any trailing bytes remain (`offset != data.length` — no smuggled suffix), and (4) revert the moment the leg counter exceeds `MAX_BATCH_LEGS` (`BatchTooLarge`), *before* decoding further legs. Each check is O(1) per leg, so the worst-case adversarial input costs at most `MAX_BATCH_LEGS` header reads before the revert — no unbounded traversal to EOF is possible.
- **Ledger UX.** The device binds the batch `dataHash` and displays: leg count, per-token totals, and the hash — it cannot render 50 legs. The leg-by-leg review happens in the add-on UI with two-source verification; the on-chain per-leg checks above are the backstop that holds even if the host lies about the legs. One press-sequence, one leaf, whole payroll.

### Timestamp handling

- `validFrom`/`validTo` rely on `block.timestamp`, which validators can skew by seconds. Approval windows must have a minimum granularity (e.g., ≥ 15 minutes) and must never be used as a sub-minute security boundary.

### Immutability and deployment hygiene

- The Guard must be non-upgradeable: no proxy, no initializer, no `DELEGATECALL`, `SELFDESTRUCT`, `CALLCODE`, `CREATE` or `CREATE2` in its runtime code (enforced by `test_guardBytecodeHasNoUpgradeOrSelfDestructPath`). Fixes ship as a new Guard, set by each Safe's owners.
- The constructor validates `multiSendCallOnly` (non-zero, has code) and that `emergencyTimelock > adminTimelock`.
- Use custom errors with explicit reason data for every revert path; every state change emits an event for off-chain monitoring.
- `tx.origin` must never be used for any authorization decision.
- Lock the compiler to a recent audited Solidity version; enable overflow checks (default ≥ 0.8) and run static analysis (Slither) plus a professional audit before mainnet.

## Virtual brain test against Safe semantics

The following checks are the minimum correctness review for the FermionWallet guard.

1. If `Safe.setGuard(address(guard))` is called with a contract that does not implement `ITransactionGuard`, Safe reverts.
2. If the Guard is set correctly but a transaction is invalid, `checkTransaction` must revert.
3. If the Guard returns without revert, Safe continues execution.
4. If `operation == Enum.Operation.DelegateCall`, the Guard must reject the transaction unless the target is the pinned `MultiSendCallOnly` (see 19).
5. If no live approval matches the transaction — by `safeTxHash` pin, or by the class's field commitment (`token`/`recipient`/`amount`, or `target`/`value`/`dataHash`) — the guard must revert.
6. If the quantum signature was created for a different Safe, chain ID, or payload hash, the guard must revert.
7. If `validFrom`/`validTo` are exceeded, or the approval is revoked or already used, the guard must revert.
8. If `msgSender` is used as trust input, it must be treated as merely the initiating caller and not as proof of a valid quantum authorization.
9. The guard must not trust the base transaction calldata alone; it must decode and validate the exact target call details.
10. The guard must not hold the final authority to transfer funds directly. It only decides to allow or reject the Safe transaction.
11. If a module is enabled on the Safe, the tx guard is bypassed via `execTransactionFromModule`; the guard must detect enabled modules or a module guard must be installed. `enableModule` must be rejected unless this Guard is already wired as module guard, and remediation calls must remain possible.
12. If a random address calls `checkTransaction` directly, it must revert (caller is not an enrolled Safe) so approvals cannot be burned by attackers.
13. If the Safe tx targets the Safe itself (`setGuard`, `enableModule`, owner changes, any other self-call) or the Guard, it must be rejected unless explicitly quantum-authorized as an admin action.
14. If `gasPrice != 0`, the guard must revert (refund drain protection; the MVP allows no refunds) — escape-hatch calls included: this check comes before the escape hatch, or an owners-only escape call could pay the Safe's balance out as its refund.
15. When recomputing the safeTxHash inside `checkTransaction`, the guard must use `nonce - 1`, because the Safe increments its nonce before invoking the guard.
16. If the target call re-enters `Safe.execTransaction` (nested Safe tx), the guard's depth tracking must detect it and revert.
17. If the Safe is paused, every `checkTransaction` for it must revert (deny-all, fail-closed) — except the escape-hatch calls and the quantum-approved `setGuard(address(0))` removal (no-brick).
18. If the decoded selector is `approve`, `increaseAllowance`, `permit`, or `transferFrom`, the guard must revert — allowance grants are equivalent to transfers.
18a. If the Safe has a nonzero fallback handler, enrollment and every checked transaction must revert except remediation (`setFallbackHandler(address(0))`, the module remediations `disableModule`/`setModuleGuard`, or the approved Guard removal).
18b. If a `transfer` call carries native `value`, the guard must revert (`NativeValueOnTransfer`): a TRANSFER approval never authorizes ETH.
19. If the target is `MultiSend` (the delegatecall-capable variant) the guard must revert. `MultiSendCallOnly` is permitted only at the pinned canonical address, only with a batch `PAYLOAD` pre-approval binding `keccak256` of the full batch calldata, and only after the per-leg structural checks in "Batching (MultiSend)" pass.
20. If a pre-approval window is shorter than the minimum granularity, `createPreApproval` must revert (timestamp-manipulation margin).
21. If `ITransactionGuard` / `BaseTransactionGuard` / `Enum` / ERC165 are copied into this repo instead of imported from `@safe-global/safe-contracts`, that is a defect (`interfaceId` can disagree with `GuardManager` → `GS300`).
22. If EIP-712, nonces, bitmaps, queues, calldata decoding, or `ecrecover` are hand-rolled, that is a defect — use OpenZeppelin. Any global pause or role is a defect ("No global powers").
23. If Safe tx hash is recomputed locally instead of `ISafe(msg.sender).getTransactionHash(...)`, that is a defect.
24. If hybrid/PQ verification uses HMAC or a custom lattice implementation, that is a defect — `SignatureChecker` + pinned audited PQ verifier or `liboqs` / `@noble/post-quantum` at the documented trust boundary.
25. `supportsInterface` must report the Safe package's `ITransactionGuard` and `IModuleGuard` interface IDs (plus ERC-165), never locally re-declared interfaces.

## Guard behavior requirements for FermionWallet

The Guard must:

- inspect the Safe transaction before execution,
- classify the call (batch, admin, native, transfer, allowlisted call) and decode it,
- find a live pre-approval matching the exact payload (Tier 1 pin or Tier 2 field commitment),
- confirm the Safe's key is Active (approvals of a Rotated key stay usable; a Revoked key's do not) — signatures were verified once, at creation,
- enforce chain binding and domain separation,
- ensure the approval is within its validity window and unused,
- enforce fallback-handler and module posture before allowing normal transactions,
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
   - Inside the Guard, `msg.sender` **is the Safe proxy address**. This is the property our access-control check relies on (the Safe must have an Active key: `_requireEnrolledActive(msg.sender)`).
   - The final `msgSender` *parameter* is the EOA/relayer that called `execTransaction` — informational only, never a trust anchor.
   - Because it is a `CALL`, the Guard runs with its **own** storage and may write state (consume the pre-approval, update the reentrancy depth counter).
7. Any revert in the Guard bubbles up and aborts `execTransaction` — the target call never executes.
8. If the Guard returns, the Safe executes the target call (`CALL` or `DELEGATECALL` per `operation`).
9. Refund logic runs (only if `gasPrice != 0`, which this Guard never allows).
10. The Safe then calls `checkAfterExecution(txHash, success)` on the same guard — again a plain `CALL` from the proxy address.

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
- Module bypass closed: enabled modules bypass the tx guard; the spec now requires no modules or a paired `IModuleGuard`, rejects `enableModule` until the module guard is wired, and exempts remediation calls.
- `checkTransaction` caller restriction added: prevents attackers from burning single-use approvals.
- Self-call/guard-removal bypass closed: `setGuard`, `enableModule`, and owner changes require explicit admin authorization.
- Refund-drain attack closed: `gasPrice` must be zero, so no refund is ever paid.
- Safe nonce quirk documented: hash recomputation must use `nonce - 1` inside `checkTransaction`.
- Key rotation now requires owner co-signatures, the Ledger's attestation of the new key, and an old-key XMSS possession proof instead of an unauthenticated call.
- Bricking risk addressed: time-locked emergency path to remove the Guard so funds cannot be permanently frozen.
- Reentrancy via nested Safe transactions closed with depth tracking.
- Emergency deny-all pause added (fast pause, time-locked unpause) to beat revocation front-running, with anti-veto cooldown so one owner or the Administrator cannot freeze the Safe forever.
- On-chain signature-bytes storage removed (hash only); PQ verification gas bounded; `checkTransaction` kept O(1).
- Allowance-based exfiltration closed: `approve`/`increaseAllowance`/`permit`/`transferFrom` denied by selector allowlist, and ERC-1271 fallback-handler bypasses closed by requiring no fallback handler.
- Batching supported via pinned `MultiSendCallOnly` only: one hash-bound pre-approval per batch, on-chain per-leg structural checks; delegatecall-capable `MultiSend` rejected always.
- Timestamp-manipulation margin enforced via minimum approval-window granularity.
- Non-upgradeable deployment, zero-address checks, custom errors, no `tx.origin`, locked compiler, Slither + audit required.
- Library-first: inherit Safe `BaseTransactionGuard`; do not copy Guard/ERC165 (avoids `GS300` interfaceId mismatch).
- OpenZeppelin supplies EIP-712, SignatureChecker (ERC-1271), Nonces, BitMaps, DoubleEndedQueue, Bytes, SlotDerivation/TransientSlot, SafeCast — no hand-rolled equivalents.
- Safe tx hash via `ISafe.getTransactionHash`, not a local hasher.
- PQ/hybrid via pinned audited verifier or `liboqs` / `@noble/post-quantum`; HMAC is not a quantum signature.

## Production constraints

Before production deployment, FermionWallet must ensure:

- real post-quantum or hybrid cryptography is used for the quantum approval path,
- signatures are bound to chain ID, Safe address, nonce, token, recipient, amount, and policy hash,
- all approvals are nonce-protected and single-use,
- key revocation, rotation, and incident-response flows are in place,
- the Guard rejects unknown selectors and unsupported call patterns,
- the Safe policy allowlist and amount caps are enforced in the Guard (selector permit-list: done; amount caps, token/recipient allowlists, maximum window: not yet),
- an integration test exists that deploys a real Safe + Guard, pins a pre-approval to the `safeTxHash` of nonce `N`, executes at nonce `N`, and asserts the Guard's `getTransactionHash(..., nonce() - 1)` recomputation matches (catches the nonce off-by-one and Safe-version hash drift),
- fuzz/negative tests cover malformed MultiSend batches (truncated leg header, overrunning `dataLength`, trailing bytes, > `MAX_BATCH_LEGS`) — all must revert cheaply,
- tests assert fallback-handler posture enforcement and the remediation exemptions (`setFallbackHandler(address(0))` and quantum-approved Guard removal),
- tests assert `enableModule` rejects until the Guard is wired as module guard, while `disableModule`/`setModuleGuard` remediation is not deadlocked,
- the core flows (enrollment, `setGuard`, Tier 1/Tier 2, MultiSendCallOnly batch, pause and emergency de-guard, fallback-handler ban, module posture, `nonce() - 1`, depth unwinding) run end to end on real Safe v1.3.0 and v1.4.1 singletons, L1 and L2 (`test/LegacySafeIntegration.t.sol`; v1.5.0 in `test/GuardIntegration.t.sol`),
- tests assert re-pause does not cancel a pending unpause and the post-unpause cooldown blocks single-key pausers,
- a test asserts the emergency de-guard selector allow executes **before** the pause check (`requestEmergencyDeGuard` succeeds while the Safe is paused),
- a test asserts the deployed Guard bytecode has no upgrade or self-destruct opcodes,
- the contract is audited and reviewed under the actual Safe execution semantics before mainnet use.

## Summary

The FermionWallet Guard must be a real Safe Guard, not a pseudo-signer contract.

The correct design is:

- Safe owner signatures remain the first approval layer.
- FermionWallet adds a second approval layer by validating a quantum-based authorization inside `checkTransaction(...)`.
- If the validation is invalid, the Guard reverts and the safe transaction fails.
- If the validation is valid, Safe continues execution normally.

This is the correct integration pattern for a Gnosis Safe wallet and the version of the spec that matches the official Smart Account execution model.
