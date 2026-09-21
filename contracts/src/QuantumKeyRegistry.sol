// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {ISafe} from "@safe-global/safe-contracts/contracts/interfaces/ISafe.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {BitMaps} from "@openzeppelin/contracts/utils/structs/BitMaps.sol";
import {XMSS} from "./XMSS.sol";

/// @dev Version-portable owner-threshold check. Safe v1.3.0 and v1.4.1 expose ONLY
///      `checkSignatures(bytes32,bytes,bytes)`; v1.5.0 keeps it as a compatibility
///      overload. The v1.5-only `checkSignatures(address,bytes32,bytes)` form must
///      never be used here: on ≤ v1.4.1 its selector matches nothing, and a Safe
///      WITHOUT a fallback handler then returns empty success from FallbackManager —
///      silently skipping owner verification entirely (with the default
///      CompatibilityFallbackHandler it reverts instead, blocking onboarding).
///      The legacy form's `msg.sender`-as-executor hazard (owner pre-approved hashes)
///      does not apply: msg.sender is this registry contract, never a Safe owner.
interface ISafeLegacySignatures {
    function checkSignatures(bytes32 dataHash, bytes calldata data, bytes memory signatures) external view;
}

/// @title QuantumKeyRegistry — co-signed lifecycle of the Quantum Administrator's XMSS key
/// @notice On-chain registry per quantum-key-registry.md. Exactly one `Active` key per
///         Safe; activation is a co-signed one-shot: owner-threshold EIP-712 signatures
///         over the XMSS root itself (verified via the Safe's own `checkSignatures`)
///         plus the Administrator's Ledger attestation, in a single transaction.
///         Rotation additionally consumes one leaf of the *old* key as a possession
///         proof. Emergency revocation (old key lost) is owner-governed behind
///         `EMERGENCY_ROTATION_TIMELOCK`, cancellable throughout the delay.
/// @dev    Abstract: deployed only as part of `FermionWalletGuard` (one contract, one
///         storage — see fermionwallet-guard-module.md, "Module-guard architecture").
///         The used-leaf bitmap lives here because leaf state is a property of the
///         key, not of any particular approval.
abstract contract QuantumKeyRegistry is EIP712, Nonces {
    using SignatureChecker for address;
    using BitMaps for BitMaps.BitMap;

    // ── Types ───────────────────────────────────────────────────────────────

    enum KeyStatus {
        None,
        Active,
        Rotated,
        Revoked
    }

    struct KeyRegistration {
        bytes32 quantumKeyId; // keccak256(safe, xmssRoot, registryNonce)
        address safe;
        address quantumAdmin; // Ledger EOA — ECDSA half of every hybrid signature
        bytes32 xmssRoot; //     XMSS public root (RFC 8391)
        bytes32 xmssSeed; //     XMSS public SEED (bitmask/key derivation — verification input)
        uint32 treeHeight;
        bytes32 parameterSet; // e.g. keccak256("XMSS-SHA2_20_256")
        KeyStatus status;
        uint64 createdAt;
        uint64 rotatedAt;
        uint256 useCounter; //   leaves consumed under this key (approvals + rotation proof)
    }

    // ── Errors ──────────────────────────────────────────────────────────────

    error ZeroAddress();
    error InvalidKeyParams();
    error SafeAlreadyEnrolled(address safe);
    error NoActiveKey(address safe);
    error SignatureExpired(uint256 validUntil);
    error InvalidAttestation();
    error LeafAlreadyUsed(bytes32 quantumKeyId, uint32 leafIndex);
    error InvalidXmssSignature();
    error LeafIndexMismatch(uint32 expected, uint32 actual);
    error RevocationNotRequested(address safe);
    error RevocationTimelocked(uint64 executableAt);
    error RevocationSuperseded(address safe, bytes32 requestedKeyId);
    error NotAuthorized();
    error RootAlreadyRegistered(bytes32 xmssRoot);

    // ── Events ──────────────────────────────────────────────────────────────

    event QuantumKeyRegistered(
        bytes32 indexed quantumKeyId, address indexed safe, bytes32 xmssRoot, uint32 treeHeight
    );
    event QuantumKeyRotated(bytes32 indexed oldKeyId, bytes32 indexed newKeyId, address indexed safe);
    event KeyRevocationRequested(address indexed safe, bytes32 indexed quantumKeyId, uint64 executableAt);
    event KeyRevocationCancelled(address indexed safe, bytes32 indexed quantumKeyId);
    event QuantumKeyRevoked(bytes32 indexed quantumKeyId, address indexed safe);
    event LeafConsumed(bytes32 indexed quantumKeyId, uint32 indexed leafIndex, bytes32 digest);

    // ── EIP-712 type hashes (owners clear-sign the root itself — never opaque IDs) ──

    bytes32 internal constant APPROVE_KEY_TYPEHASH = keccak256(
        "ApproveQuantumKey(address safe,address quantumAdmin,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 internal constant ROTATE_KEY_TYPEHASH = keccak256(
        "RotateQuantumKey(address safe,bytes32 oldQuantumKeyId,address newQuantumAdmin,bytes32 newXmssRoot,bytes32 newXmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 internal constant ATTEST_KEY_TYPEHASH = keccak256(
        "QuantumKeyAttestation(address safe,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce)"
    );
    bytes32 internal constant REVOKE_KEY_TYPEHASH = keccak256(
        "RequestKeyRevocation(address safe,bytes32 quantumKeyId,uint256 registryNonce,uint256 validUntil)"
    );

    // ── Storage ─────────────────────────────────────────────────────────────

    /// Emergency (no-old-key) revocation delay — the security boundary that stops a
    /// Ledger thief from beating the owners to a quiet key swap.
    uint64 public immutable EMERGENCY_ROTATION_TIMELOCK;

    mapping(bytes32 quantumKeyId => KeyRegistration) internal _keys;
    /// The one Active key per Safe (bytes32(0) = none). Never reused as an
    /// "enrolled" flag — see `enrolledSafe`.
    mapping(address safe => bytes32 quantumKeyId) public safeToQuantumKey;
    /// Sticky enrollment flag: set at first registration, never cleared, so the
    /// emergency de-guard path stays reachable even after key revocation.
    mapping(address safe => bool) public enrolledSafe;
    /// Used-leaf bitmap per key. Consensus-critical — XMSS leaf reuse enables forgery
    /// (quantum-key-registry.md, "on-chain only").
    mapping(bytes32 quantumKeyId => BitMaps.BitMap) private _usedLeaves;
    /// Pending emergency revocations: safe => executableAt (0 = none pending).
    mapping(address safe => uint64) public keyRevocationExecutableAt;
    /// The exact key each pending revocation names. Execution revokes THIS key only:
    /// revoking "whatever is active" would let a stale request destroy a key that was
    /// legitimately rotated in (owner-co-signed) while the request matured.
    mapping(address safe => bytes32) public keyRevocationKeyId;
    /// Every XMSS root ever registered by a given Safe, in any status. A root is a
    /// one-shot identity: re-registering it would start a fresh, empty used-leaf
    /// bitmap under a new quantumKeyId and silently disable the on-chain leaf-reuse
    /// check that backs up the Ledger's counter.
    ///
    /// Deliberately scoped PER SAFE, not global. A global registry would let anyone
    /// front-run a pending registration: the root is public calldata in the mempool,
    /// and `safe` is only self-authenticated (its own `checkSignatures`), so an
    /// attacker contract with a no-op `checkSignatures` could claim any root first
    /// and permanently DoS the victim's enrollment and rotation for one tx of gas.
    /// Cross-Safe root reuse harms only the reuser (desynced leaf bitmaps), and every
    /// hybrid pre-approval digest binds the Safe address, so a squatted root under an
    /// attacker's fake Safe is useless against the legitimate one.
    mapping(address safe => mapping(bytes32 xmssRoot => bool)) public rootRegistered;

    constructor(uint64 emergencyRotationTimelock) {
        EMERGENCY_ROTATION_TIMELOCK = emergencyRotationTimelock;
    }

    // ── Views ───────────────────────────────────────────────────────────────

    function getKey(bytes32 quantumKeyId) external view returns (KeyRegistration memory) {
        return _keys[quantumKeyId];
    }

    function isLeafUsed(bytes32 quantumKeyId, uint32 leafIndex) public view returns (bool) {
        return _usedLeaves[quantumKeyId].get(leafIndex);
    }

    /// Per-Safe ceremony nonce (OpenZeppelin `Nonces`). Bound into every owner-signed
    /// registry digest and consumed by each registration, rotation, revocation request
    /// and revocation — so every owner-signed registry message is single-use.
    function registryNonce(address safe) public view returns (uint256) {
        return nonces(safe);
    }

    modifier onlySafe(address safe) {
        if (msg.sender != safe) revert NotAuthorized();
        _;
    }

    /// True iff `account` is currently an owner of `safe`. Never reverts: a Safe that
    /// can't answer is treated as having no owners.
    function _isSafeOwner(address safe, address account) internal view returns (bool) {
        try ISafe(payable(safe)).isOwner(account) returns (bool owner) {
            return owner;
        } catch {
            return false;
        }
    }

    /// The Active key registration for `safe`; reverts if none.
    function _activeKey(address safe) internal view returns (KeyRegistration storage k) {
        bytes32 id = safeToQuantumKey[safe];
        k = _keys[id];
        if (id == bytes32(0) || k.status != KeyStatus.Active) revert NoActiveKey(safe);
    }

    // ── Registration (co-signed one-shot) ───────────────────────────────────

    /// @notice Activate a freshly generated XMSS key for `safe` in one transaction.
    /// @dev Shared singleton: the caller is the Administrator's relayer EOA, never the
    ///      Safe — `safe` is explicit calldata and `msg.sender` carries no authority
    ///      here (asymmetric with the consumption path, where the Safe IS msg.sender).
    ///      Neither side can act alone: owner-threshold signatures over the root are
    ///      verified via the Safe's own `checkSignatures`, and the attestation must be
    ///      signed by `quantumAdmin` (the Ledger). The digest binds safe, chainid,
    ///      registry address, registryNonce, and a deadline — front-runners cannot
    ///      redirect a ceremony, and stale ceremonies die when the nonce advances.
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
    ) external returns (bytes32 quantumKeyId) {
        if (safeToQuantumKey[safe] != bytes32(0)) revert SafeAlreadyEnrolled(safe);
        _validateKeyParams(safe, quantumAdmin, xmssRoot, xmssSeed, treeHeight, parameterSet);
        if (rootRegistered[safe][xmssRoot]) revert RootAlreadyRegistered(xmssRoot);
        if (block.timestamp > validUntil) revert SignatureExpired(validUntil);

        uint256 nonce = nonces(safe);

        // Owner threshold co-signs the root itself (anti-substitution property).
        bytes32 ownerDigest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    APPROVE_KEY_TYPEHASH, safe, quantumAdmin, xmssRoot, xmssSeed, treeHeight, parameterSet, nonce, validUntil
                )
            )
        );
        // Verified via the legacy overload (portable across Safe 1.3.0/1.4.1/1.5.0);
        // the relayer never counts toward the threshold (executor is this contract).
        ISafeLegacySignatures(safe).checkSignatures(ownerDigest, "", ownerSignatures);

        _verifyAttestation(safe, quantumAdmin, xmssRoot, xmssSeed, treeHeight, parameterSet, nonce, ledgerAttestation);

        quantumKeyId = _storeKey(safe, quantumAdmin, xmssRoot, xmssSeed, treeHeight, parameterSet, nonce);
        emit QuantumKeyRegistered(quantumKeyId, safe, xmssRoot, treeHeight);
        _afterEnrollment(safe);
    }

    // ── Rotation (registration + old-key possession proof) ──────────────────

    /// @notice Rotate to a new XMSS key: same co-signed one-shot as registration, plus
    ///         an XMSS signature by the OLD key over the rotation digest (consuming one
    ///         final old-key leaf). Atomic: old → Rotated, new → Active — no window
    ///         with zero or two active keys.
    function rotateQuantumKey(
        address safe,
        address newQuantumAdmin,
        bytes32 newXmssRoot,
        bytes32 newXmssSeed,
        uint32 treeHeight,
        bytes32 parameterSet,
        uint256 validUntil,
        bytes calldata oldKeyXmssProof,
        bytes calldata ledgerAttestation,
        bytes calldata ownerSignatures
    ) external returns (bytes32 newQuantumKeyId) {
        KeyRegistration storage oldKey = _activeKey(safe);
        _validateKeyParams(safe, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet);
        if (rootRegistered[safe][newXmssRoot]) revert RootAlreadyRegistered(newXmssRoot);
        if (block.timestamp > validUntil) revert SignatureExpired(validUntil);

        uint256 nonce = nonces(safe);
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ROTATE_KEY_TYPEHASH,
                    safe,
                    oldKey.quantumKeyId,
                    newQuantumAdmin,
                    newXmssRoot,
                    newXmssSeed,
                    treeHeight,
                    parameterSet,
                    nonce,
                    validUntil
                )
            )
        );

        ISafeLegacySignatures(safe).checkSignatures(digest, "", ownerSignatures);
        _verifyAttestation(safe, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, nonce, ledgerAttestation);
        // Possession proof: the old key signs the same digest, one leaf consumed.
        _verifyAndConsumeXmss(oldKey.quantumKeyId, digest, oldKeyXmssProof);

        bytes32 oldId = oldKey.quantumKeyId;
        oldKey.status = KeyStatus.Rotated;
        oldKey.rotatedAt = uint64(block.timestamp);

        // An owner-co-signed rotation supersedes any pending revocation of the old
        // key: the compromise it addressed is resolved, and the successor key must
        // never be destroyed by the stale request.
        if (keyRevocationExecutableAt[safe] != 0) {
            keyRevocationExecutableAt[safe] = 0;
            keyRevocationKeyId[safe] = bytes32(0);
            emit KeyRevocationCancelled(safe, oldId);
        }

        newQuantumKeyId = _storeKey(safe, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, nonce);
        emit QuantumKeyRotated(oldId, newQuantumKeyId, safe);
    }

    // ── Emergency revocation (old key lost / compromised) ───────────────────

    /// @notice Owner-governed revocation without the old key, behind a time lock.
    ///         After execution the Safe has NO active key (fresh `registerQuantumKey`
    ///         follows); the time lock is what stops a Ledger thief from racing the
    ///         owners to a quiet swap. Watchers can cancel throughout the delay.
    function requestKeyRevocation(address safe, uint256 validUntil, bytes calldata ownerSignatures) external {
        KeyRegistration storage k = _activeKey(safe);
        if (block.timestamp > validUntil) revert SignatureExpired(validUntil);

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(REVOKE_KEY_TYPEHASH, safe, k.quantumKeyId, _useNonce(safe), validUntil))
        );
        ISafeLegacySignatures(safe).checkSignatures(digest, "", ownerSignatures);
        // The nonce is consumed above: a request's owner signatures work exactly once,
        // so nobody can replay them from chain history to re-arm a cancelled request.
        // (Side effect by design: in-flight ceremony signatures also go stale.)

        uint64 executableAt = uint64(block.timestamp) + EMERGENCY_ROTATION_TIMELOCK;
        keyRevocationExecutableAt[safe] = executableAt;
        keyRevocationKeyId[safe] = k.quantumKeyId;
        emit KeyRevocationRequested(safe, k.quantumKeyId, executableAt);
    }

    /// @notice Cancel a pending revocation — only the Safe (owner-threshold transaction).
    ///         The Quantum Administrator's key alone must NOT be able to cancel: this is
    ///         the owners' remedy for a lost or stolen Ledger, and a thief holding the
    ///         Ledger could otherwise block it forever.
    function cancelKeyRevocation(address safe) external onlySafe(safe) {
        KeyRegistration storage k = _activeKey(safe);
        if (keyRevocationExecutableAt[safe] == 0) revert RevocationNotRequested(safe);
        keyRevocationExecutableAt[safe] = 0;
        keyRevocationKeyId[safe] = bytes32(0);
        emit KeyRevocationCancelled(safe, k.quantumKeyId);
    }

    /// @notice Execute a matured revocation (permissionless — the authorization is the
    ///         owner-signed request plus the elapsed time lock).
    function executeKeyRevocation(address safe) external {
        uint64 executableAt = keyRevocationExecutableAt[safe];
        if (executableAt == 0) revert RevocationNotRequested(safe);
        if (block.timestamp < executableAt) revert RevocationTimelocked(executableAt);

        // Revoke exactly the key the request named. If an owner-co-signed rotation
        // replaced it while the request matured, the request is void (the rotation
        // already addressed the compromise) — never revoke the successor key.
        bytes32 keyId = keyRevocationKeyId[safe];
        keyRevocationExecutableAt[safe] = 0;
        keyRevocationKeyId[safe] = bytes32(0);
        if (safeToQuantumKey[safe] != keyId) revert RevocationSuperseded(safe, keyId);

        KeyRegistration storage k = _keys[keyId];
        k.status = KeyStatus.Revoked;
        safeToQuantumKey[safe] = bytes32(0);
        _useNonce(safe); // kill concurrent stale ceremonies
        emit QuantumKeyRevoked(keyId, safe);
    }

    // ── XMSS leaf consumption (single enforcement point) ────────────────────

    /// @dev Decode, verify, and consume an XMSS signature over `digest` for `keyId`.
    ///      Reverts on leaf reuse (checked BEFORE the ~1M-gas verification), height
    ///      mismatch, or verification failure. Verify-then-mark: XMSS.verify's only
    ///      external touch is the SHA-256 precompile via staticcall — no reentrancy
    ///      window between check and effect.
    function _verifyAndConsumeXmss(bytes32 keyId, bytes32 digest, bytes calldata xmssSignature)
        internal
        returns (uint32 leafIndex)
    {
        KeyRegistration storage k = _keys[keyId];
        XMSS.Signature memory sig = abi.decode(xmssSignature, (XMSS.Signature));

        if (sig.authPath.length != k.treeHeight) {
            revert LeafIndexMismatch(k.treeHeight, SafeCast.toUint32(sig.authPath.length));
        }
        leafIndex = sig.leafIdx;

        BitMaps.BitMap storage used = _usedLeaves[keyId];
        if (used.get(leafIndex)) revert LeafAlreadyUsed(keyId, leafIndex);

        if (!XMSS.verify(digest, sig, XMSS.PublicKey({root: k.xmssRoot, seed: k.xmssSeed}))) {
            revert InvalidXmssSignature();
        }

        used.set(leafIndex);
        unchecked {
            ++k.useCounter;
        }
        emit LeafConsumed(keyId, leafIndex, digest);
    }

    // ── Internals ───────────────────────────────────────────────────────────

    function _validateKeyParams(
        address safe,
        address quantumAdmin,
        bytes32 xmssRoot,
        bytes32 xmssSeed,
        uint32 treeHeight,
        bytes32 parameterSet
    ) private pure {
        if (safe == address(0) || quantumAdmin == address(0)) revert ZeroAddress();
        if (
            xmssRoot == bytes32(0) || xmssSeed == bytes32(0) || parameterSet == bytes32(0) || treeHeight == 0
                || treeHeight > XMSS.MAX_HEIGHT
        ) revert InvalidKeyParams();
    }

    function _verifyAttestation(
        address safe,
        address quantumAdmin,
        bytes32 xmssRoot,
        bytes32 xmssSeed,
        uint32 treeHeight,
        bytes32 parameterSet,
        uint256 nonce,
        bytes calldata ledgerAttestation
    ) private view {
        bytes32 attestDigest = _hashTypedDataV4(
            keccak256(abi.encode(ATTEST_KEY_TYPEHASH, safe, xmssRoot, xmssSeed, treeHeight, parameterSet, nonce))
        );
        // SignatureChecker (ERC-1271-aware), never raw ecrecover.
        if (!quantumAdmin.isValidSignatureNow(attestDigest, ledgerAttestation)) revert InvalidAttestation();
    }

    function _storeKey(
        address safe,
        address quantumAdmin,
        bytes32 xmssRoot,
        bytes32 xmssSeed,
        uint32 treeHeight,
        bytes32 parameterSet,
        uint256 nonce
    ) private returns (bytes32 quantumKeyId) {
        quantumKeyId = keccak256(abi.encodePacked(safe, xmssRoot, nonce));
        _keys[quantumKeyId] = KeyRegistration({
            quantumKeyId: quantumKeyId,
            safe: safe,
            quantumAdmin: quantumAdmin,
            xmssRoot: xmssRoot,
            xmssSeed: xmssSeed,
            treeHeight: treeHeight,
            parameterSet: parameterSet,
            status: KeyStatus.Active,
            createdAt: uint64(block.timestamp),
            rotatedAt: 0,
            useCounter: 0
        });
        safeToQuantumKey[safe] = quantumKeyId;
        rootRegistered[safe][xmssRoot] = true;
        enrolledSafe[safe] = true;
        _useCheckedNonce(safe, nonce);
    }

    /// Hook for the Guard: initialize per-Safe policy defaults at first enrollment.
    function _afterEnrollment(address safe) internal virtual;
}
