# Fermion Guard

**Status: specification for v2. Not implemented yet, not deployed, and unaudited.** Nothing in this
document, in the verifier library it calls or in the key factory it relies on has had an external
audit. This document is normative for the Fermion Guard contract; every normative sentence carries an
`[FG-###]` tag, defined once in the [requirement index](#requirement-index).

Fermion Guard is a post-quantum gate for a Safe. The Safe keeps its owners, its threshold and its whole
ecosystem; the Guard adds one rule: **no Safe transaction executes without a quantum approval** — a hybrid
ECDSA + ML-DSA signature by the Safe's Quantum Administrator over that exact transaction. Its sibling
product, [Fermion Wallet](./fermion-wallet.md), is a standalone vault instead.

## Contents

- [What it does](#what-it-does)
- [Non-goals](#non-goals)
- [Safe mechanics](#safe-mechanics)
- [Interface](#interface)
- [Enrollment](#enrollment)
- [Quantum approval](#quantum-approval)
- [Inline and stored approvals](#inline-and-stored-approvals)
- [Transaction rules](#transaction-rules)
- [Safe message approval](#safe-message-approval)
- [Modules](#modules)
- [Key rotation](#key-rotation)
- [Emergency removal](#emergency-removal)
- [Deployment](#deployment)
- [Gas](#gas)
- [What can go wrong](#what-can-go-wrong)
- [Residual risks](#residual-risks)
- [Requirement index](#requirement-index)

## What it does

1. The Safe's owners pick one **Quantum Administrator**: one key pair (an ECDSA key, the **admin**, and an
   ML-DSA key) derived for this Safe alone. The Safe enrolls it in the Guard and sets the Guard as its
   transaction guard (and, on Safe 1.5.0, as its module guard). [FG-001]
2. From then on **every** Safe transaction — owner-executed or module-executed — needs a quantum approval
   of that exact transaction, on top of the owners' threshold. The only exceptions are the emergency-removal
   calls and the Safe revoking a stored approval. Off-chain messages the Safe signs through ERC-1271
   (Permit2, CoW orders, SIWE) need one too, through the Guard's gated fallback handler. [FG-002]
3. An approval travels **inline** (appended to the Safe transaction's `signatures`) or is **stored** ahead
   of time (`preApprove`) and consumed once. [FG-003]
4. If the Quantum Administrator's key is lost, the owners remove the Guard through a 14-day emergency
   removal that only they can cancel. [FG-004]

The Guard never moves funds. It only lets a Safe transaction through or makes it revert. [FG-005]

## Non-goals

- **No global powers.** One Guard serves every enrolled Safe, so any power over the Guard is a power over
  all of them. There is no owner, admin role, guardian, allow-list or upgrade path; the Guard is not a proxy
  and has no `selfdestruct`. Every control is scoped to one Safe and held by that Safe. [FG-006]
- **No pause.** A Quantum Administrator who wants to stop the Safe stops approving. [FG-007]
- **No on-chain spending policy.** No amount caps, token or recipient allow-lists or selector lists. Every
  transaction needs an approval; limits live in the signer's or custodian's policy. [FG-008]
- **No exemptions.** Apart from the calls named in [FG-002], no target, selector or amount passes without an
  approval. [FG-009]
- **No verifier switching.** The verifier address is fixed at deployment; a new verifier means a new Guard
  and re-enrollment. [FG-010]
- **No fake signer.** The Guard is a guard, never a Safe owner, and exposes no execution entry point.
  [FG-011]

## Safe mechanics

These facts about Safe hold for 1.3.0, 1.4.1 and 1.5.0, the three versions the Guard supports. The Guard is
correct only if they hold. [FG-012]

### Who calls the Guard

`Safe.execTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver,
signatures)`, running in the Safe proxy's context:

1. computes `txHash = getTransactionHash(..., nonce)` with the **current** nonce, then increments the nonce;
2. checks the owners' signatures (`checkSignatures`); if they fail, the Guard is never reached;
3. loads the guard from `keccak256("guard_manager.guard.address")` and, if it is set, makes a plain `CALL`:
   `checkTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver,
   signatures, msg.sender)`;
4. executes the call (`CALL` or `DELEGATECALL`), pays a refund only if `gasPrice != 0`;
5. calls `checkAfterExecution(txHash, success)` on the guard it loaded in step 3, even if this transaction
   changed the guard.

Consequences the Guard honours:

- **The Safe is `msg.sender`.** Inside `checkTransaction` the caller is the Safe proxy; the trailing
  `msgSender` parameter is the executor and carries no authority. A Safe is never taken from calldata in a
  checking path. [FG-013]
- **The nonce has already moved.** The Guard recomputes the hash as
  `ISafe(msg.sender).getTransactionHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken,
  refundReceiver, ISafe(msg.sender).nonce() - 1)`, using the Safe's own hasher (its explicit `_nonce`
  parameter exists on all three versions). It never reimplements the Safe's EIP-712 hashing. [FG-014]
- **Owner signatures precede the Guard.** The quantum approval is strictly the second authorization.
  [FG-015]
- **Reverting denies, returning allows.** `checkAfterExecution` is bookkeeping only, never the gate. [FG-016]
- **The Guard runs with its own storage.** It may write state (consume an approval) inside
  `checkTransaction`. [FG-017]

### Interface identity

The Guard inherits Safe's own `BaseTransactionGuard` and `BaseModuleGuard` and imports `ITransactionGuard`,
`IModuleGuard` and `Enum` from the pinned Safe package. `supportsInterface` reports exactly
`type(ITransactionGuard).interfaceId`, `type(IModuleGuard).interfaceId` and `type(IERC165).interfaceId`.
A locally re-declared interface could compile to a different id and make `setGuard` revert with `GS300`.
[FG-018]

### Modules and the module guard

On Safe 1.3.0 and 1.4.1, `execTransactionFromModule` never calls the transaction guard: an enabled module
bypasses it completely. Safe 1.5.0 adds a **module guard** (slot
`keccak256("module_manager.module_guard.address")`), which it calls as
`checkModuleTransaction(address to, uint256 value, bytes data, Enum.Operation operation, address module)
returns (bytes32 moduleTxHash)` before the call and `checkAfterModuleExecution(bytes32 moduleTxHash, bool
success)` after it, passing back the returned hash. A module transaction has no `signatures` argument, no
Safe nonce and no `safeTxHash`. [FG-019]

### Version detection

The Guard reads the Safe's `VERSION()` string and recognises exactly `"1.3.0"`, `"1.4.1"` and `"1.5.0"`.
The module guard slot counts as **wired** only when `VERSION()` is `"1.5.0"` **and** the slot holds this
Guard; on 1.3.0 and 1.4.1 the slot is ordinary storage the singleton never reads, so a value there is
ignored. A Safe whose `VERSION()` cannot be read or is not one of the three fails closed. Storage slots are
read through the Safe's `getStorageAt`. [FG-020]

### Trailing signature bytes

On all three versions, `checkNSignatures` requires only `signatures.length >= threshold * 65` and
bounds-checks each contract signature's offset and length against `signatures.length`. Bytes after the
last owner signature are never read by the Safe, and `signatures` is not part of `safeTxHash`. The inline
approval relies on this. [FG-021]

## Interface

```solidity
interface IFermionGuard is ITransactionGuard, IModuleGuard /* IERC165 */ {
    struct Enrollment {
        uint256 algorithm;          // 0x0101 | 0x0102 | 0x0103; 0 = not enrolled
        address admin;              // ECDSA half: an EOA
        bytes32 publicKeyHash;      // keccak256(ML-DSA public key)
        address publicKeyPointer;   // the public key, stored as code
        uint64  epoch;              // bumped on every rotation and on enrollment end
        uint64  removalExecutableAt;// 0 = no emergency removal pending
        uint256 nonce;              // sequential, for ModuleTxApproval, Revocation and KeyRotation
    }

    struct StoredApproval {
        uint64 validFrom;
        uint64 validUntil;
        uint64 epoch;               // the key epoch when stored
    }

    // Immutables and constants
    function VERIFIER() external view returns (address);            // IPQVerifier
    function KEY_FACTORY() external view returns (address);         // MLDSAKeyFactory
    function FALLBACK_HANDLER() external view returns (address);    // gated fallback handler, created by the Guard
    function isMultiSendCallOnly(address target) external view returns (bool);
    function REMOVAL_DELAY() external pure returns (uint64);        // 14 days
    function MAX_WINDOW() external pure returns (uint64);           // 24 hours
    function MAX_BATCH_LEGS() external pure returns (uint256);      // 100

    // Enrollment: called by the Safe itself (msg.sender == safe)
    function enroll(uint256 algorithm, address admin, bytes calldata publicKey) external;

    // Rotation: anyone may submit; the CURRENT key's hybrid signature over KeyRotation is the authority
    function rotateKey(address safe, uint256 algorithm, address admin, bytes calldata publicKey, uint256 nonce,
        uint64 validFrom, uint64 validUntil, bytes calldata ecdsaSignature, bytes calldata pqSignature) external;

    // Stored approvals: anyone may submit (relayer); the hybrid signature is the authority
    function preApprove(address safe, bytes32 safeTxHash, uint64 validFrom, uint64 validUntil,
        bytes calldata ecdsaSignature, bytes calldata pqSignature) external;
    function preApproveModuleTx(address safe, address module, address to, uint256 value, bytes32 dataHash,
        uint256 nonce, uint64 validFrom, uint64 validUntil,
        bytes calldata ecdsaSignature, bytes calldata pqSignature) external;
    function preApproveMessage(address safe, bytes32 safeMessageHash, uint64 validFrom, uint64 validUntil,
        bytes calldata ecdsaSignature, bytes calldata pqSignature) external;

    // Revocation: by the Safe itself, or hybrid-signed by the Quantum Administrator
    function revoke(bytes32 approvalId) external;                            // msg.sender == safe
    function revokeSigned(address safe, bytes32 approvalId, uint256 nonce, uint64 validFrom,
        uint64 validUntil, bytes calldata ecdsaSignature, bytes calldata pqSignature) external;

    // Emergency removal: called by the Safe itself
    function requestRemoval() external;
    function cancelRemoval() external;

    // Views
    function enrollment(address safe) external view returns (Enrollment memory);
    function storedApproval(address safe, bytes32 approvalId) external view returns (StoredApproval memory);
    function isRevoked(address safe, bytes32 approvalId) external view returns (bool);
    // Gated fallback handler query: a stored approval, else the inline approval at the end of `signature`
    function isMessageApproved(address safe, bytes32 safeMessageHash, bytes calldata signature)
        external view returns (bool);
    function publicKey(address safe) external view returns (bytes memory);
    function eip712Domain() external view returns (
        bytes1 fields, string memory name, string memory version, uint256 chainId,
        address verifyingContract, bytes32 salt, uint256[] memory extensions);

    // Safe hooks (exact Safe signatures, from the Safe package)
    // checkTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address payable,bytes,address)
    // checkAfterExecution(bytes32,bool)
    // checkModuleTransaction(address,uint256,bytes,Enum.Operation,address) returns (bytes32)
    // checkAfterModuleExecution(bytes32,bool)

    event Enrolled(address indexed safe, address indexed admin, uint256 algorithm, bytes32 publicKeyHash);
    event KeyRotated(address indexed safe, address indexed admin, uint256 algorithm, bytes32 publicKeyHash, uint64 epoch);
    event EnrollmentEnded(address indexed safe);
    event ApprovalStored(address indexed safe, bytes32 indexed approvalId, uint64 validFrom, uint64 validUntil);
    event ApprovalUsed(address indexed safe, bytes32 indexed approvalId, bool inline);
    event ApprovalRevoked(address indexed safe, bytes32 indexed approvalId, bool bySafe);
    event RemovalRequested(address indexed safe, uint64 executableAt);
    event RemovalCancelled(address indexed safe);
}
```

The whole external interface is the one above plus the four Safe hooks. [FG-022]

A Safe that has not reverted, rotated or ended its enrollment keeps exactly one Quantum Administrator.
[FG-023]

## Enrollment

`enroll` is called by the Safe itself, as an ordinary Safe transaction (`msg.sender` is the Safe). It
reverts unless: [FG-024]

1. the Safe is not enrolled;
2. `VERSION()` is `"1.3.0"`, `"1.4.1"` or `"1.5.0"`;
3. `algorithm` is `0x0101` (ML-DSA-44), `0x0102` (ML-DSA-65) or `0x0103` (ML-DSA-87), and `publicKey` has
   that set's length (1312, 1952 or 2592 bytes);
4. `admin` is non-zero and has no code — the classical half is checked only by ECDSA recovery, never through
   ERC-1271;
5. the key's precomputation is fully registered in the key factory (A and `tr ‖ NTT(t1·2^d)` both stored),
   so every later approval takes the fast verification path; registration is done beforehand, permissionlessly,
   through the key factory;
6. the Safe's fallback handler slot holds `address(0)` or this Guard's `FALLBACK_HANDLER`.

Enrollment needs public keys, not a signature: the holder confirms the admin address and the key hash on the
device before the Safe enrolls them ([the Ledger app](./ledger-app.md#signing-flows)).

On success the Guard stores the public key as contract code (CREATE2 from the Guard, salt `publicKeyHash`),
records the enrollment with a fresh epoch, and emits `Enrolled`. [FG-025]

The Quantum Administrator's key is one key per contract: a key enrolled for one Safe is never used for
another Safe or for a Fermion Wallet. ML-DSA-44 is the default and ML-DSA-65 is chosen at enrollment;
ML-DSA-87 is accepted by the contract but has no v2 signer. Derivation is specified in
[the Ledger app](./ledger-app.md#key-derivation). [FG-026]

**Recommended setup transaction.** One Safe transaction, a `MultiSendCallOnly` batch executed while the Safe
has no guard yet: `setFallbackHandler(guard.FALLBACK_HANDLER())`; on 1.5.0, `setModuleGuard(guard)`; then
`guard.enroll(...)`; then `setGuard(guard)`.
Because the Safe has no guard when the batch runs, nothing checks it; the batch rules in
[Transaction rules](#transaction-rules) apply only once the Guard is set. [FG-027]

**A Safe that set the Guard but is not enrolled** (or whose enrollment ended) is protected by nothing and
must not be bricked by it. For such a Safe, `checkTransaction` allows only: a `CALL` to the Guard's
`enroll`, `setGuard(address(0))` and `setModuleGuard(address(0))`; everything else reverts `NotEnrolled`.
`checkModuleTransaction` reverts for it. [FG-028]

**Enrollment ends** when the Safe's guard slot stops holding this Guard. `checkAfterExecution` and
`checkAfterModuleExecution` read the slot; if it no longer holds this Guard, they delete the enrollment,
any pending removal and the stored public-key reference, bump the epoch (killing every stored approval) and
emit `EnrollmentEnded`. A Guard set again later starts from a fresh `enroll`. [FG-029]

## Quantum approval

A quantum approval is a **hybrid signature** — ECDSA and ML-DSA over the same 32-byte EIP-712 digest — by
the Safe's enrolled key. Both halves are always required. [FG-030]

- **ECDSA half:** 65 bytes `r ‖ s ‖ v`, OpenZeppelin `ECDSA.tryRecover`, must recover to the enrolled
  `admin`. [FG-031]
- **ML-DSA half:** FIPS 204 pure ML-DSA with an empty context over the 32 digest bytes, checked by
  `IPQVerifier(VERIFIER).verify(algorithm, publicKey, abi.encodePacked(digest), pqSignature)` with the
  enrolled algorithm id and public key. [FG-032]

### Domain

```
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
name              = "FermionGuard"
version           = "2"
chainId           = block.chainid
verifyingContract = the Guard
```

An approval verifies only on the chain it was signed for and only at this Guard. [FG-033] The digest is
`keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct(message))`; the signer computes it from the fields it
displays, never from a host-supplied hash. [FG-034]

### Signed types

The Guard defines exactly five signed types. Every one carries `validFrom` and `validUntil`. [FG-035]

```
SafeTxApproval(address safe,bytes32 safeTxHash,uint64 validFrom,uint64 validUntil)
ModuleTxApproval(address safe,address module,address to,uint256 value,bytes32 dataHash,uint256 nonce,uint64 validFrom,uint64 validUntil)
SafeMessageApproval(address safe,bytes32 safeMessageHash,uint64 validFrom,uint64 validUntil)
Revocation(address safe,bytes32 approvalId,uint256 nonce,uint64 validFrom,uint64 validUntil)
KeyRotation(address safe,uint256 algorithm,bytes32 publicKeyHash,address admin,uint256 nonce,uint64 validFrom,uint64 validUntil)
```

Each typehash is `keccak256` of its string above, and each `hashStruct` is
`keccak256(abi.encode(TYPEHASH, field1, ..., fieldN))` in the listed order (all fields are static). [FG-036]

| Type | Approves | `approvalId` |
|---|---|---|
| `SafeTxApproval` | one Safe transaction, identified by the Safe's own `safeTxHash` | `safeTxHash` |
| `ModuleTxApproval` | one module call: `module` calls `to` with `value` and calldata whose keccak256 is `dataHash` (operation is always `CALL`) | `keccak256(abi.encode(module, to, value, dataHash))` |
| `SafeMessageApproval` | one off-chain message the Safe may answer ERC-1271 for, identified by the Safe's message hash ([Safe message approval](#safe-message-approval)) | `safeMessageHash` |
| `Revocation` | killing the approval `approvalId` of `safe` | — |
| `KeyRotation` | replacing the Safe's key by the key `publicKeyHash` of set `algorithm` with its `admin`; signed by the **current** key ([Key rotation](#key-rotation)) | — |

**What `safeTxHash` binds.** It is the Safe's EIP-712 digest of the SafeTx struct under the Safe's own
domain (chain id and Safe address): `to`, `value`, `keccak256(data)`, `operation`, `safeTxGas`, `baseGas`,
`gasPrice`, `gasToken`, `refundReceiver` and the Safe nonce. A `SafeTxApproval` therefore binds the whole
transaction and the Safe nonce; the signer rebuilds `safeTxHash` from the fields it displays. [FG-037]

**Replay.**
- A `SafeTxApproval` is single-use because its `safeTxHash` contains the Safe nonce, which the Safe
  increments on execution. It carries no Guard nonce, so any number of stored approvals for different
  pending transactions can coexist. [FG-038]
- `ModuleTxApproval`, `Revocation` and `KeyRotation` carry the Safe's sequential Guard `nonce`
  (`Enrollment.nonce`). Each is valid only at the current value, which it increments when accepted. [FG-039]
- A `SafeMessageApproval` is **not** single-use: ERC-1271 is a view and records nothing, so an approved
  message stays approved until its window closes, it is revoked, or the epoch moves. Replay protection for
  the message itself is the consuming protocol's (a Permit2 nonce, a CoW order uid, a SIWE nonce). [FG-040]

### Validity window

Every path requires `validFrom <= block.timestamp <= validUntil` and `validUntil - validFrom <= 24 hours`.
For a stored approval the window is checked both when it is stored and when it is consumed. Validators can
skew `block.timestamp` by seconds; windows are never a sub-minute boundary. [FG-041]

### Check order

Every hybrid signature is checked in this order, stopping at the first failure: shape (lengths), validity
window, Guard nonce (where the type has one), ECDSA recovery against the admin, ML-DSA through
`IPQVerifier`. A stale or wrong-key approval is refused without the ML-DSA verification. [FG-042]

## Inline and stored approvals

A `SafeTxApproval` reaches the Guard in one of two ways. The signer signs identical bytes either way.
[FG-043]

### Inline

The executor appends the approval to the Safe transaction's `signatures`, after every owner signature and
every contract-signature data block: [FG-044]

```
signatures = ownerSignatures ‖ approval
approval   = validFrom (uint64, 8 bytes big-endian)
           ‖ validUntil (uint64, 8 bytes big-endian)
           ‖ ecdsa (65 bytes: r ‖ s ‖ v)
           ‖ mldsa (signature bytes of the enrolled algorithm: 2420 | 3309 | 4627)
```

The approval has a fixed length `L` = 81 + the ML-DSA signature size: 2501 bytes (ML-DSA-44), 3390
(ML-DSA-65) or 4708 (ML-DSA-87). This is the same layout as a Fermion Wallet ERC-1271 signature
([Safe owner (ERC-1271)](./fermion-wallet.md#safe-owner-erc-1271)). [FG-045]

**How the Guard finds it.** The Guard knows the enrolled algorithm, hence `L`, and reads the last `L` bytes
of `signatures`. There is no marker and no length prefix. Because Safe ignores trailing bytes
([FG-021]) and `signatures` is not hashed into `safeTxHash`, appending the approval changes neither the
owners' check nor the hash, on 1.3.0, 1.4.1 and 1.5.0 alike. If `signatures` is shorter than `L`, or the last
`L` bytes are not a valid approval, there is no inline approval. [FG-046]

An inline approval is verified inside `checkTransaction` over `SafeTxApproval(safe, safeTxHash, validFrom,
validUntil)`, where `safe` is `msg.sender` and `safeTxHash` is recomputed with `nonce() - 1`. It is checked
against `isRevoked(safe, safeTxHash)` like a stored one. [FG-047]

### Stored

`preApprove(safe, safeTxHash, validFrom, validUntil, ecdsaSignature, pqSignature)` is permissionless (the
hybrid signature is the authority). It reverts unless the Safe is enrolled, `safeTxHash` is not revoked, the
window is valid, and the hybrid signature verifies with the Safe's current key. It then stores
`StoredApproval{validFrom, validUntil, epoch}` under `(safe, safeTxHash)`, replacing any earlier one, and
emits `ApprovalStored`. [FG-048]

This path exists for front ends that only press the Safe's Execute button (Safe{Wallet}, custodian tooling,
Ledger Enterprise Multisig): the approval is already on-chain, so `signatures` can stay unmodified. [FG-049]

**Consumption.** In `checkTransaction`, if a stored approval for `(msg.sender, safeTxHash)` exists, its
`epoch` equals the current epoch and its window contains `block.timestamp`, the Guard deletes it and lets the
transaction through. A stored approval is used at most once. If the Safe transaction's inner call fails,
the approval stays consumed: the Safe nonce has moved anyway. [FG-050]

**Precedence.** `checkTransaction` looks for a live stored approval first (one storage read) and parses the
inline approval only if there is none. If neither exists the transaction reverts with
`NoQuantumApproval`. [FG-051]

**Key epoch.** The epoch increments on every rotation and when enrollment ends. A stored approval whose
epoch is not the current one is dead, so rotating the key kills every approval the old key stored. An
inline approval is always verified against the current key, so it needs no epoch. [FG-052]

**Dead approvals are harmless.** A stored approval whose `safeTxHash` was executed can never match again,
because the Safe nonce has moved past it. Nobody needs to clean it up. [FG-053]

### Revoke

An approval can be revoked before it is used, by either side: [FG-054]

- **By the Safe:** `revoke(approvalId)` with `msg.sender == safe`, as an ordinary Safe transaction (owner
  threshold). This call needs **no** quantum approval: it only removes permission, and requiring the
  Quantum Administrator's key would make it useless when that key is the problem.
- **By the Quantum Administrator:** `revokeSigned(safe, approvalId, nonce, validFrom, validUntil, ecdsa,
  pqSignature)`, a hybrid-signed `Revocation`, submitted by anyone.

Revoking `approvalId` deletes the stored approval under it, if any, **and** marks `(safe, approvalId)` as
revoked: no approval for that `safeTxHash` or `safeMessageHash`, inline or stored, is ever accepted again.
Without the mark, the revoked signature — which is public once submitted — could simply be stored again or
appended inline. To do the same payment afterwards, the owners build a new Safe transaction (at a later
nonce, or with any field changed). [FG-055]

For a module approval, revoking deletes the stored record; the revoked `ModuleTxApproval` cannot be
resubmitted because its Guard nonce has been used. [FG-056]

### Module approvals are stored only

`checkModuleTransaction` receives no signatures, so a module call can only be approved ahead of time with
`preApproveModuleTx`. It reverts unless the Safe is enrolled, the window and Guard nonce are valid and the
hybrid signature verifies; it then increments the Guard nonce and stores `StoredApproval{validFrom,
validUntil, epoch}` under `keccak256(abi.encode(module, to, value, dataHash))`. A second live approval under
the same id replaces the first. [FG-057]

## Transaction rules

`checkTransaction` applies these steps in this order. The order is normative: getting it wrong either
destroys the escape hatch or lets an escape call drain the Safe. [FG-058]

1. **Refund ban.** `gasPrice == 0`, `gasToken == address(0)` and `refundReceiver == address(0)`, else
   `GasRefundForbidden`. This comes first, before the escape calls, because an escape call that paid a
   refund could pay the Safe's balance out to the executor. [FG-059]
2. **Not enrolled.** If `msg.sender` is not enrolled, apply [FG-028] and stop. [FG-060]
3. **Escape calls.** A `CALL` with `value == 0` that is one of the following passes with **no** quantum
   approval, regardless of every rule below, and nothing else ever does: [FG-061]
   - to the Guard: `requestRemoval()`, `cancelRemoval()`, `revoke(bytes32)`;
   - to the Safe itself, only while an emergency removal is pending **and** `block.timestamp >=
     removalExecutableAt`: `setGuard(address(0))`, `setModuleGuard(address(0))`.

   Each escape call re-checks its own authority inside the Guard; none can move funds or weaken
   enforcement except the final removal, which the owners waited 14 days for. Calls are recognised by
   selector and first argument word, not by exact calldata length, because Safe's ABI decoding ignores
   trailing calldata. [FG-062]
4. **Freeze.** While an emergency removal is pending, only rescue transfers continue past this step (see
   [Emergency removal](#emergency-removal)); everything else reverts `RemovalPending`. [FG-063]
5. **Operation.** `DELEGATECALL` reverts `DelegateCallForbidden` unless `to` is one of the pinned
   `MultiSendCallOnly` deployments, in which case the batch is decoded and checked leg by leg (below).
   `MultiSend` (which allows inner delegatecalls) is never accepted. [FG-064]
6. **Self-administration.** A `CALL` to the Safe itself must be one of the nine named admin functions —
   `addOwnerWithThreshold`, `removeOwner`, `swapOwner`, `changeThreshold`, `setGuard`, `setFallbackHandler`,
   `enableModule`, `disableModule`, `setModuleGuard` — recognised by selector; any other self-call, decodable
   or not, reverts `SelfCallForbidden` (decision record C9: a self-call is the Safe-takeover vector). Of the
   nine: [FG-065]
   - `enableModule` reverts `ModuleGuardNotWired` unless the module guard is wired ([FG-020]);
   - `setModuleGuard(x)` with `x` other than this Guard reverts while any module is enabled;
   - `setFallbackHandler(x)` reverts `FallbackHandlerForbidden` unless `x` is `address(0)` or
     `FALLBACK_HANDLER`;
   - the others proceed to step 8, where they need an approval like any transaction.
7. **Posture.** If any module is enabled (`getModulesPaginated`) and the module guard is not wired, every
   transaction reverts `ModulesUnguarded`, except `disableModule` to the Safe itself. If the fallback handler
   slot holds anything but `address(0)` or `FALLBACK_HANDLER`, every transaction reverts
   `FallbackHandlerForbidden`, except `setFallbackHandler(address(0))` and
   `setFallbackHandler(FALLBACK_HANDLER)`. Each exempted remediation is exempt from both checks and proceeds
   to step 8. [FG-066]
8. **Quantum approval.** Recompute `safeTxHash` ([FG-014]); refuse it if revoked; consume a live stored
   approval, else verify an inline one ([FG-051]); else revert `NoQuantumApproval`. Emit `ApprovalUsed`.
   [FG-067]

`checkTransaction` performs at most one ML-DSA verification, and only in step 8. [FG-068]

### Batches

The only delegatecall target is a pinned `MultiSendCallOnly`: the canonical deployments for Safe 1.3.0,
1.4.1 and 1.5.0, fixed as constructor arguments. The batch's `safeTxHash` already binds every leg, and the
quantum approval approves the whole batch. [FG-069]

The Guard still decodes the `multiSend(bytes)` payload strictly and reverts `MalformedBatch` if: the
selector is not `multiSend`; fewer bytes remain than an 85-byte leg header (`uint8 operation, address to,
uint256 value, uint256 dataLength`); `dataLength` overruns the payload; or any bytes remain after the last
leg. It reverts `BatchTooLarge` the moment the leg count exceeds `MAX_BATCH_LEGS` = 100 (the v1 guard's
batch-leg limit), before decoding further. Every check is O(1) per leg. [FG-070]

Every leg is checked under the same rules as a single transaction (decision record C7): its `operation`
must be `CALL` (no nested delegatecall); a leg whose `to` is a `MultiSendCallOnly` reverts
`ForbiddenBatchLegTarget`; a leg whose `to` is the Safe or `address(0)` (which `MultiSendCallOnly`
rewrites to the Safe) is a self-call and obeys step 6, so an unnamed self-call reverts `SelfCallForbidden`;
and while a removal is pending every leg must be a rescue-transfer shape ([FG-090]). Escape calls are never
recognised inside a batch: as legs they need the batch's approval like any other call. Step 6 reads the
Safe's state when `checkTransaction` runs, so a leg cannot rely on an earlier leg of the same batch (for
example, `setModuleGuard` followed by `enableModule` fails closed). The signer shows every leg before
approving a batch ([the signer requirements](./signer-requirements.md#safe-batches)). [FG-071]

Module transactions get no batch exception: a module `DELEGATECALL` is refused even to a
`MultiSendCallOnly` ([FG-076]).

### Reentrancy

A Safe transaction may execute another transaction of the same Safe. Each nested `execTransaction` runs
the Guard again with its own `safeTxHash` and needs its own approval; the Guard keeps no depth counter.
`checkAfterExecution` does only the enrollment-end check ([FG-029]). [FG-072]

### Allowances granted before enrollment

The Guard sees transactions. A token or Permit2 allowance the Safe granted before enrollment can still be
spent by its spender with no Safe transaction. Operators revoke such allowances before enrolling. [FG-073]

## Safe message approval

The Safe's ERC-1271 answers are the other way owners could act without a Safe transaction: Safe's
`CompatibilityFallbackHandler` answers `isValidSignature` for the Safe with the owners' signatures alone, so
a Permit2 permit, a CoW order or a SIWE login signed by the owners would bypass the Guard. Fermion Guard
therefore keeps a **gated fallback handler** (decision record C8): the Safe answers ERC-1271 only for messages
the Quantum Administrator approved. [FG-106]

**The handler.** The Guard creates its fallback handler in its own constructor (with CREATE, so the
handler's address is a function of the Guard's) and exposes it as `FALLBACK_HANDLER`. It is Safe's
`CompatibilityFallbackHandler` from the pinned Safe package — token callbacks, `simulate` and
`getMessageHash` unchanged — with both `isValidSignature` forms replaced. A guarded Safe's fallback handler
is `address(0)` or `FALLBACK_HANDLER`, nothing else ([FG-024], [FG-065], [FG-066]). [FG-107]

**The Safe message hash** is computed exactly as Safe's own handler computes it, for the calling Safe (the
`msg.sender` of the forwarded call): [FG-108]

```
SafeMessage(bytes message)                         // Safe's own type, under the Safe's own domain
safeMessageHash = keccak256(0x19 ‖ 0x01 ‖ safe.domainSeparator() ‖
                            keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message))))
message = abi.encode(hash)  for isValidSignature(bytes32 hash, bytes signature)  → magic 0x1626ba7e
message = data              for isValidSignature(bytes data, bytes signature)    → magic 0x20c13b0b
```

For a Permit2 permit or a CoW order, `hash` is the order's EIP-712 hash; for SIWE text, its EIP-191 hash.
The signer receives the message itself, computes `hash`, then `safeMessageHash`, then the approval digest,
and shows the message ([the signer requirements](./signer-requirements.md#safe-messages)). [FG-109]

**The approval** is `SafeMessageApproval(address safe,bytes32 safeMessageHash,uint64 validFrom,uint64
validUntil)` under the Guard's domain ([Quantum approval](#quantum-approval)), accepted in either form, like
a Safe-transaction approval: [FG-110]

- **stored:** `preApproveMessage(safe, safeMessageHash, validFrom, validUntil, ecdsa, pqSignature)`,
  permissionless, which verifies the hybrid signature with the current key and stores
  `StoredApproval{validFrom, validUntil, epoch}` under `safeMessageHash`;
- **inline:** the last `L` bytes of the ERC-1271 `signature`, after the owners' signatures, in the layout of
  [FG-045].

**The answer.** The handler returns the form's magic value only if both of these hold, and `0xffffffff`
otherwise, never reverting on malformed input: [FG-111]

1. the owners' signatures over `safeMessageHash` are valid, checked through the Safe exactly as Safe's own
   handler checks them; the on-chain `signedMessages` path (empty `signature`) is **not** accepted, because
   its entries could have been written before enrollment;
2. `isMessageApproved(safe, safeMessageHash, signature)` on the Guard is true: the Safe is enrolled, no
   emergency removal is pending, `safeMessageHash` is not revoked, and either a stored approval with the
   current epoch and a window containing `block.timestamp` exists, or the inline approval verifies (window,
   ECDSA, ML-DSA).

A message approval is never consumed ([FG-040]). It is revoked like any approval — `revoke(safeMessageHash)`
by the Safe, or a signed `Revocation` — which bars it for good ([FG-055]). [FG-112]

An inline message approval makes the consuming protocol pay one ML-DSA verification inside its
`isValidSignature` call (2.68M / 3.66M / 5.53M gas for 44 / 65 / 87, key registered); a protocol with a tight
ERC-1271 gas budget needs the stored form. Not measured end to end. [FG-113]

## Modules

- **Only on Safe 1.5.0, only with the Guard as module guard.** `enableModule` is refused unless
  `VERSION()` is `"1.5.0"` and the module guard slot holds this Guard ([FG-065]); on 1.3.0 and 1.4.1 it is
  always refused. [FG-074]
- **Order on 1.5.0:** `setModuleGuard(guard)` first, then `enableModule(module)`, as two quantum-approved
  Safe transactions (or the setup batch of [FG-027]). [FG-075]
- **Every module transaction is gated.** `checkModuleTransaction` reverts unless: the Safe is enrolled; no
  emergency removal is pending (module transactions are frozen entirely while one is); `operation` is `CALL`
  (module delegatecall is always refused, `MultiSendCallOnly` included); `to` is not the Guard; a
  call to the Safe itself obeys [FG-065]; and a live stored `ModuleTxApproval` exists under
  `keccak256(abi.encode(module, to, value, keccak256(data)))` with the current epoch and a window containing
  `block.timestamp`. It deletes the approval and returns its id, which Safe passes back to
  `checkAfterModuleExecution`. [FG-076]
- **No exemptions** for modules: no allow-listed module, no allow-listed call. [FG-077]
- **Dedicated screen.** The signer shows `enableModule` on its own screen naming the module; see
  [the signer requirements](./signer-requirements.md#display-and-refusal-rules). [FG-078]
- **Unguarded modules fail closed.** A module enabled before the Guard was set, on any version, or any
  module while the module guard is not wired, makes every owner transaction revert until the
  quantum-approved `disableModule` ([FG-066]). During that window the module itself still executes
  unguarded on 1.3.0 and 1.4.1, because those versions never call any guard for module transactions.
  [FG-079]

## Key rotation

The current key approves the new key. `rotateKey(safe, algorithm, admin, publicKey, nonce, validFrom,
validUntil, ecdsaSignature, pqSignature)` is permissionless; its authority is a hybrid signature by the
Safe's **current** key over `KeyRotation(safe, algorithm, keccak256(publicKey), admin, nonce, validFrom,
validUntil)`. The signer shows the new key's hash, its parameter set and its admin on a rotation screen
([the Ledger app](./ledger-app.md#signing-flows)). [FG-080]

`rotateKey` reverts unless the Safe is enrolled, no emergency removal is pending (the freeze covers
rotation), the Guard nonce and window are valid, the current key's hybrid signature verifies, and the new key
passes checks 3–5 of [FG-024]: valid algorithm and length, admin an EOA, precomputation registered beforehand
through the key factory. [FG-081]

On success the Guard stores the new public key as code, replaces algorithm, admin, key hash and pointer,
increments the Guard nonce and the epoch (every approval the old key stored dies) and emits `KeyRotated`.
The new key may use a different parameter set and always has a different admin, since the ECDSA key is
derived per key slot. [FG-082]

A lost or compromised key cannot rotate itself; the owners use [emergency removal](#emergency-removal) and
re-enroll a new key. [FG-083]

## Emergency removal

The one escape hatch, for a lost key or a broken verifier. It needs no quantum key. [FG-084]

1. **Request.** The Safe calls `requestRemoval()` (owner threshold; an escape call, no approval). It
   reverts if one is pending. It sets `removalExecutableAt = block.timestamp + 14 days` and emits
   `RemovalRequested`. [FG-085]
2. **Wait.** `REMOVAL_DELAY` is a constant 14 days. The event is the highest-severity alert for every owner
   and for the event watcher. [FG-086]
3. **Cancel — owners only.** Only the Safe can call `cancelRemoval()` (owner threshold; an escape call). The
   Quantum Administrator cannot cancel or veto: a stolen key must not be able to hold the Safe hostage.
   [FG-087]
4. **Remove.** Once `block.timestamp >= removalExecutableAt`, the Safe may execute `setGuard(address(0))`
   and, on 1.5.0, `setModuleGuard(address(0))`, with no approval. When the guard slot no longer holds the
   Guard, the enrollment ends ([FG-029]). [FG-088]

**Freeze.** While a removal is pending, the Safe is frozen: `checkTransaction` lets through only the escape
calls of [FG-061] and **rescue transfers**, and `checkModuleTransaction` lets nothing through. A rescue
transfer still needs the owner threshold **and** a quantum approval, so it moves assets only to a
destination both sides approve. [FG-089]

A rescue transfer is a transaction whose shape is one of the following, with `to` neither the Safe nor the
Guard: [FG-090]

| Shape | `operation` | `value` | `data` |
|---|---|---|---|
| ETH | `CALL` | any | empty |
| ERC-20 | `CALL` | 0 | `transfer(address,uint256)` (`0xa9059cbb`), exactly 68 bytes |
| ERC-721 | `CALL` | 0 | `transferFrom(address,address,uint256)` (`0x23b872dd`), `safeTransferFrom(address,address,uint256)` (`0x42842e0e`) or `safeTransferFrom(address,address,uint256,bytes)` (`0xb88d4fde`), with `from` = the Safe |
| ERC-1155 | `CALL` | 0 | `safeTransferFrom(address,address,uint256,uint256,bytes)` (`0xf242432a`) or `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)` (`0x2eb2c2d6`), with `from` = the Safe |
| Batch | `DELEGATECALL` to a pinned `MultiSendCallOnly` | 0 | every leg one of the four shapes above, with `operation` `CALL` |

The freeze stops compromised owners from burning Safe nonces, changing owners or threshold, enabling modules
or rotating the key during the 14 days, while honest owners and an honest Quantum Administrator can still
move assets out together. [FG-091]

**Threat model: case 1 only.** Emergency removal is designed for the case where some owners are compromised
but honest owners still hold enough working keys to reach the threshold: they can cancel a malicious
request, and with the Quantum Administrator they can rescue assets during the freeze. There is no
rescue-sweep module and no recovery address. Case 2 — an attacker who holds the threshold exclusively — is
not defended: such an attacker can request removal, wait 14 days and remove the Guard. That is a documented
residual risk. [FG-092]

## Deployment

The Guard is one contract shared by every enrolled Safe, deployed through the Arachnid deterministic
deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C` with a fixed salt, at the same address on every chain
(Ethereum mainnet, Base, Arbitrum, Optimism). Constructor arguments: the verifier (`IPQVerifier`), the key
factory, and the three pinned `MultiSendCallOnly` addresses. It has no owner and no initialization;
anyone may deploy it on a new chain. Its address is the same on a chain only if the constructor arguments
are: the verifier, the key factory and the `MultiSendCallOnly` deployments must be at their canonical
addresses there. [FG-093]

The verifier and key factory are the shared ones Fermion Wallet uses
([deployment](./fermion-wallet.md#deployment)). [FG-094]

## Gas

From the measured table in the decision record; re-measure after the Glamsterdam repricing. [FG-095]

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| ML-DSA verify, key registered (through `IPQVerifier`) — paid once per inline approval, `preApprove`, `preApproveModuleTx`, `preApproveMessage`, `revokeSigned`, `rotateKey` | 2.68M | 3.66M | 5.53M |
| ML-DSA verify, from scratch (never on the Guard's paths: enrollment requires a registered key) | 5.75M | 9.13M | 14.23M |
| Inline approval appended to `signatures` | 2501 B | 3390 B | 4708 B |

Not measured: a whole guarded Safe transaction (inline or stored), `enroll`, `rotateKey`, consuming a stored
approval, a gated ERC-1271 answer, key-factory registration of a Guard key, and batch decoding. A guarded Safe transaction runs at
most one Guard verification; with Fermion Wallet owners it also runs one verification per such owner, and
all of them must fit the 16,777,216-gas per-transaction cap (EIP-7825) together. [FG-096]

## What can go wrong

| Situation | Outcome |
|---|---|
| Quantum adversary breaks the owners' ECDSA keys | Every transaction still needs a quantum approval |
| Quantum adversary breaks the admin's ECDSA key | Still needs the ML-DSA half |
| Flaw in the ML-DSA verifier | Still needs the admin's ECDSA half and the owners' threshold |
| Owners sign a transaction the Quantum Administrator never saw | Reverts `NoQuantumApproval` |
| An approval is replayed | The Safe nonce has moved; `safeTxHash` differs |
| An approval is moved to another Safe, chain or Guard | Different `safe`, domain or `safeTxHash`; ECDSA recovers another address |
| A stored approval should not be used | The Safe or the Quantum Administrator revokes it; the hash is barred for good ([FG-055]) |
| The key is rotated with approvals still stored | The epoch moves; they are dead ([FG-052]) |
| A module was enabled before the Guard | Owner transactions fail closed until `disableModule`; on 1.3.0/1.4.1 the module runs unguarded meanwhile ([FG-079]) |
| A transaction asks for a gas refund | Reverts, escape calls included ([FG-059]) |
| A delegatecall to anything but a pinned `MultiSendCallOnly` | Reverts ([FG-064]) |
| The Quantum Administrator's key is lost | Owners request removal; after 14 days they remove the Guard ([FG-088]) |
| A thief with the key tries to block removal | Cannot cancel ([FG-087]) |
| Compromised owners request removal (case 1) | Honest owners cancel, or rescue assets with the Quantum Administrator during the freeze |
| An attacker holds the owner threshold alone (case 2) | Removes the Guard after 14 days. Residual ([FG-092]) |
| The Guard is set before enrolling | Only `enroll`, `setGuard(0)` and `setModuleGuard(0)` pass ([FG-028]) |
| Owners sign a Permit2 or CoW order off-chain | The Safe answers ERC-1271 only with a message approval ([FG-111]) |
| Owners try to install `CompatibilityFallbackHandler` | Reverts ([FG-065]); a Safe that already has it cannot enroll ([FG-024]) |
| An allowance granted before enrollment | Still spendable with no Safe transaction ([FG-073]) |

## Residual risks

- **Unaudited.** The Guard, mldsa-solidity and the key factory have had no external audit. [FG-097]
- **Case 2.** An attacker who holds the owner threshold exclusively can remove the Guard after 14 days;
  only monitoring and moving assets in time help, and moving them needs the attacker's cooperation.
  [FG-098]
- **ML-DSA-87 is contract-level only.** The Guard accepts it, but no v2 signer produces it: the Ledger app
  ships ML-DSA-44 and ML-DSA-65 and the nShield signer is a design document. [FG-099]
- **Old allowances and reusable message approvals.** Allowances granted before enrollment bypass the
  Guard ([FG-073]); operators revoke token and Permit2 allowances before enrolling. A message approval can
  be presented any number of times within its window ([FG-040]); the consuming protocol's own nonce is the
  replay guard. [FG-100]
- **Unguarded modules on 1.3.0/1.4.1** between enabling and the Guard being set ([FG-079]). [FG-101]
- **One secret per role.** The Quantum Administrator's key derives from a recovery phrase; phrase
  compromise yields both halves. See [security](./security.md). [FG-102]
- **Signer side channels.** The Ledger SDK documents no side-channel hardening for ML-DSA; treat it as
  unhardened. [FG-103]
- **Gas headroom.** Inline approvals with ML-DSA-87, together with Fermion Wallet owners, may approach the
  per-transaction cap; L2 cap behaviour is unverified on live networks before release. [FG-104]
- **Fixed verifier.** A verifier bug needs a new Guard: emergency removal or an approved `setGuard` to the
  new one, then re-enrollment. [FG-105]

## Requirement index

| ID | Requirement |
|---|---|
| FG-001 | Each Safe has one Quantum Administrator key (ECDSA admin plus ML-DSA), enrolled by the Safe, with the Guard set as transaction guard and, on 1.5.0, module guard. |
| FG-002 | Every Safe transaction, owner- or module-executed, needs a quantum approval of that exact transaction, except the emergency-removal calls and the Safe's own revoke; the Safe's ERC-1271 messages need one too. |
| FG-003 | An approval is either appended inline to `signatures` or stored ahead and consumed once. |
| FG-004 | A lost key is handled by a 14-day, owners-only-cancellable emergency removal. |
| FG-005 | The Guard never moves funds; it only allows or reverts. |
| FG-006 | The Guard has no owner, role, allow-list, proxy, `selfdestruct` or any power reaching more than one Safe. |
| FG-007 | There is no pause. |
| FG-008 | There is no on-chain spending policy. |
| FG-009 | Nothing outside the calls named in FG-002 passes without an approval. |
| FG-010 | The verifier address is fixed at deployment. |
| FG-011 | The Guard is never a Safe owner and exposes no execution entry point. |
| FG-012 | The listed Safe mechanics hold for Safe 1.3.0, 1.4.1 and 1.5.0. |
| FG-013 | The Safe is `msg.sender`; `msgSender` carries no authority; a checking path never takes the Safe from calldata. |
| FG-014 | `safeTxHash` is recomputed with the Safe's own `getTransactionHash` and `nonce() - 1`. |
| FG-015 | The quantum approval is checked after the owners' signatures. |
| FG-016 | `checkTransaction` reverts to deny and returns to allow; `checkAfterExecution` is never the gate. |
| FG-017 | Approval consumption happens inside `checkTransaction`. |
| FG-018 | Guard interfaces come from the Safe package; `supportsInterface` reports exactly the transaction-guard, module-guard and ERC-165 ids. |
| FG-019 | Module transactions bypass the transaction guard; on 1.5.0 the module guard hooks have the listed signatures and no signatures argument. |
| FG-020 | `VERSION()` must be one of the three supported strings; the module guard counts as wired only on 1.5.0 with this Guard in the slot; anything else fails closed. |
| FG-021 | Safe ignores bytes after the owner signatures, and `signatures` is not part of `safeTxHash`. |
| FG-022 | The external interface is exactly the one listed plus the four Safe hooks. |
| FG-023 | An enrolled Safe has exactly one Quantum Administrator. |
| FG-024 | `enroll` is called by the Safe and checks: not enrolled, supported version, algorithm and key length, admin an EOA, key registered in the factory, and a fallback handler of `address(0)` or `FALLBACK_HANDLER`. |
| FG-025 | Enrollment stores the public key as code and records the enrollment with a fresh epoch. |
| FG-026 | A Guard key is used for one Safe only; ML-DSA-44 default, ML-DSA-65 opt-in, ML-DSA-87 accepted. |
| FG-027 | The recommended setup is one `MultiSendCallOnly` batch run before the Guard is set: module guard, enroll, guard. |
| FG-028 | For a Safe that is not enrolled, only `enroll`, `setGuard(0)` and `setModuleGuard(0)` pass, and module transactions revert. |
| FG-029 | When the guard slot no longer holds the Guard, the after-execution hooks end the enrollment, clear a pending removal and bump the epoch. |
| FG-030 | A quantum approval is an ECDSA and an ML-DSA signature over the same digest; both are required. |
| FG-031 | The ECDSA half is 65 bytes, checked with `ECDSA.tryRecover`, and must recover to the enrolled admin. |
| FG-032 | The ML-DSA half is pure ML-DSA with empty context over the digest, checked through `IPQVerifier` with the enrolled algorithm and key. |
| FG-033 | The EIP-712 domain is name "FermionGuard", version "2", the chain id and the Guard's address. |
| FG-034 | The signer computes the digest from displayed fields, never from a host-supplied hash. |
| FG-035 | The Guard defines exactly the five signed types listed, each with `validFrom` and `validUntil`. |
| FG-036 | Typehashes and struct hashes are exactly as listed. |
| FG-037 | A `SafeTxApproval` binds every SafeTx field, the Safe, the chain and the Safe nonce through `safeTxHash`. |
| FG-038 | A `SafeTxApproval` is single-use through the Safe nonce and carries no Guard nonce. |
| FG-039 | `ModuleTxApproval`, `Revocation` and `KeyRotation` carry the Safe's sequential Guard nonce, valid only at its current value. |
| FG-040 | A `SafeMessageApproval` is not consumed; it stays valid for its window unless revoked or the epoch moves. |
| FG-041 | Every path enforces the validity window of at most 24 hours; stored approvals are checked when stored and when consumed. |
| FG-042 | Checks run in the order shape, window, Guard nonce, ECDSA, ML-DSA. |
| FG-043 | The signer signs identical bytes for inline and stored approvals. |
| FG-044 | An inline approval is appended after all owner signatures and contract-signature data. |
| FG-045 | The inline approval is `validFrom ‖ validUntil ‖ ecdsa ‖ mldsa`, of fixed length 81 + the ML-DSA signature size. |
| FG-046 | The Guard reads the inline approval as the last `L` bytes of `signatures`, with no marker or length prefix. |
| FG-047 | An inline approval is verified in `checkTransaction` over the recomputed `safeTxHash` and is subject to revocation. |
| FG-048 | `preApprove` is permissionless, verifies the hybrid signature with the current key, and stores the approval with its window and epoch. |
| FG-049 | Stored approvals let front ends execute with unmodified `signatures`. |
| FG-050 | A live stored approval is deleted when consumed and stays consumed if the inner call fails. |
| FG-051 | A live stored approval takes precedence over an inline one; with neither, the transaction reverts. |
| FG-052 | The epoch increments on rotation and on enrollment end; stored approvals from another epoch are dead. |
| FG-053 | Stored approvals for executed transactions are harmless and need no cleanup. |
| FG-054 | An approval can be revoked by the Safe without a quantum approval, or by the Quantum Administrator with a hybrid-signed `Revocation`. |
| FG-055 | Revoking deletes the stored approval and permanently bars that `safeTxHash`, inline and stored. |
| FG-056 | Revoking a module approval deletes it; its Guard nonce prevents resubmission. |
| FG-057 | Module calls are approved only through `preApproveModuleTx`, stored under `keccak256(abi.encode(module, to, value, dataHash))`. |
| FG-058 | `checkTransaction` applies its steps in the normative order. |
| FG-059 | Non-zero `gasPrice`, `gasToken` or `refundReceiver` reverts first, before the escape calls. |
| FG-060 | A Safe that is not enrolled is handled by FG-028 before any other rule. |
| FG-061 | The escape calls pass with no approval and are exactly `requestRemoval`, `cancelRemoval`, `revoke`, and after the removal delay `setGuard(0)` and `setModuleGuard(0)`. |
| FG-062 | Escape calls re-check their own authority and are recognised by selector and first argument word. |
| FG-063 | While a removal is pending, only escape calls and rescue transfers pass. |
| FG-064 | `DELEGATECALL` is refused unless the target is a pinned `MultiSendCallOnly`; `MultiSend` is never accepted. |
| FG-065 | A self-call must be one of the nine named admin functions, else `SelfCallForbidden`; `enableModule` needs a wired module guard; `setModuleGuard` away from the Guard is refused while any module is enabled; `setFallbackHandler` accepts only `address(0)` or `FALLBACK_HANDLER`. |
| FG-066 | With an unguarded module, or a fallback handler other than `address(0)` or `FALLBACK_HANDLER`, every transaction except the matching remediation reverts. |
| FG-067 | The last step requires a live, unrevoked stored or inline approval of the recomputed `safeTxHash`. |
| FG-068 | `checkTransaction` performs at most one ML-DSA verification. |
| FG-069 | The pinned `MultiSendCallOnly` deployments are those of Safe 1.3.0, 1.4.1 and 1.5.0, fixed at construction. |
| FG-070 | Batch decoding is strict (`MalformedBatch`) and bounded by `MAX_BATCH_LEGS` = 100 (`BatchTooLarge`). |
| FG-071 | Each batch leg is a `CALL` checked under the single-transaction rules, self-call rules included; no leg targets a `MultiSendCallOnly`; escape calls get no exemption inside a batch; the signer shows every leg. |
| FG-072 | Nested Safe transactions each need their own approval; there is no depth counter. |
| FG-073 | Allowances granted before enrollment are outside the Guard's reach. |
| FG-074 | Modules are allowed only on Safe 1.5.0 with the Guard wired as module guard. |
| FG-075 | On 1.5.0 the module guard is set before any module is enabled. |
| FG-076 | Every module transaction needs a live stored `ModuleTxApproval`, a `CALL`, a target other than the Guard, and no pending removal. |
| FG-077 | There are no module exemptions. |
| FG-078 | The signer shows `enableModule` on its own screen. |
| FG-079 | Unguarded modules make owner transactions fail closed until `disableModule`; on 1.3.0/1.4.1 they still run unguarded meanwhile. |
| FG-080 | `rotateKey` is permissionless and authorized by the current key's hybrid signature over `KeyRotation`. |
| FG-081 | `rotateKey` checks the Guard nonce, window and signature, checks the new key like `enroll`, and is refused during a pending removal. |
| FG-082 | Rotation replaces the key and admin and increments the Guard nonce and the epoch. |
| FG-083 | A lost or compromised key is replaced through emergency removal and re-enrollment. |
| FG-084 | Emergency removal needs no quantum key. |
| FG-085 | `requestRemoval` is a Safe-only escape call that starts a 14-day delay and is refused if one is pending. |
| FG-086 | `REMOVAL_DELAY` is a constant 14 days and the request emits an event. |
| FG-087 | Only the Safe can cancel a pending removal; the Quantum Administrator cannot. |
| FG-088 | After the delay, `setGuard(0)` and `setModuleGuard(0)` pass with no approval, and enrollment ends. |
| FG-089 | While a removal is pending, Safe transactions are limited to escape calls and rescue transfers, which still need the threshold and an approval; module transactions are refused. |
| FG-090 | Rescue transfers are exactly the listed ETH, ERC-20, ERC-721, ERC-1155 and `MultiSendCallOnly` batch shapes, not to the Safe or the Guard. |
| FG-091 | The freeze blocks every governance change during the delay. |
| FG-092 | The threat model covers case 1 only; case 2 is a documented residual risk; there is no rescue module or recovery address. |
| FG-093 | The Guard is deployed through the Arachnid deterministic deployer with a fixed salt, no owner and no initialization. |
| FG-094 | The Guard uses the same verifier and key factory as Fermion Wallet. |
| FG-095 | Gas figures come from the measured table and are re-measured after the Glamsterdam repricing. |
| FG-096 | Unmeasured costs are labelled as such; all verifications in one Safe transaction must fit the per-transaction cap together. |
| FG-097 | The Guard and everything it calls are unaudited, and the documentation says so. |
| FG-098 | Case 2 is not defended. |
| FG-099 | ML-DSA-87 is accepted by the contract but has no v2 signer. |
| FG-100 | Old allowances bypass the Guard and message approvals are reusable within their window; operators revoke allowances before enrolling. |
| FG-101 | Modules on 1.3.0/1.4.1 can run unguarded before the Guard is set. |
| FG-102 | The Quantum Administrator's phrase is the single secret behind both halves. |
| FG-103 | The Ledger's ML-DSA is treated as side-channel unhardened. |
| FG-104 | ML-DSA-87 inline approvals may approach the per-transaction cap; L2 cap behaviour is unverified on live networks. |
| FG-105 | A verifier bug requires a new Guard and re-enrollment. |
| FG-106 | The Safe answers ERC-1271 only for messages the Quantum Administrator approved, through a gated fallback handler. |
| FG-107 | The Guard creates its fallback handler in its constructor: Safe's `CompatibilityFallbackHandler` with both `isValidSignature` forms replaced. |
| FG-108 | The Safe message hash is computed exactly as Safe's own handler computes it, for both forms. |
| FG-109 | The signer receives the message itself and computes its hash, the Safe message hash and the approval digest. |
| FG-110 | A `SafeMessageApproval` is accepted stored (`preApproveMessage`) or inline at the end of the ERC-1271 signature. |
| FG-111 | The handler returns the magic value only with valid owner signatures (never the `signedMessages` path) and a live, unrevoked message approval, and `0xffffffff` otherwise. |
| FG-112 | A message approval is never consumed and is revoked like any approval. |
| FG-113 | An inline message approval costs the consuming protocol one ML-DSA verification; the stored form avoids it. |
