// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

/// @title QuantumKeyRegistry — executable specification of the key state machine
/// @notice The rules of `quantum-key-registry.md` written as plain code: at most one
///         Active key per Safe, sticky enrollment, one-shot roots, a per-Safe ceremony nonce
///         consumed by every owner-signed action, and an emergency revocation behind
///         a time lock that only the Safe can cancel and that a rotation supersedes.
///         `RegistryEquivalence.t.sol` proves `QuantumKeyRegistry` makes exactly these
///         state transitions, for all inputs, with Halmos.
///
///         Scope: the state machine. Authorization (owner-threshold signatures, the
///         Ledger attestation) and XMSS verification are abstracted — by the
///         `PermissiveSafe` and `PermissiveSigner` stubs at the top of
///         `RegistryEquivalence.t.sol`, and under "Security notes" in
///         `contracts/README.md`, which also gives the Halmos command.
library RegistrySpec {
    enum Status {
        None,
        Active,
        Rotated,
        Revoked
    }

    /// Everything the registry records about one Safe.
    struct SafeState {
        bytes32 activeKeyId; // 0 = no active key
        bool enrolled; //      sticky: set at the first registration, never cleared
        uint64 revocationExecutableAt; // 0 = no pending revocation
        bytes32 revocationKeyId; //      the key a pending revocation names
        uint256 nonce; //                per-Safe ceremony nonce
    }

    /// A key's identity is the Safe, the root and the nonce that registered it.
    function keyId(address safe, bytes32 xmssRoot, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(safe, xmssRoot, nonce));
    }

    /// Key parameters a registration or rotation must satisfy (§ "Registration").
    function paramsValid(address safe, address quantumAdmin, bytes32 root, bytes32 seed, uint32 treeHeight, bytes32 parameterSet, uint256 maxHeight)
        internal
        pure
        returns (bool)
    {
        return safe != address(0) && quantumAdmin != address(0) && root != bytes32(0) && seed != bytes32(0)
            && parameterSet != bytes32(0) && treeHeight != 0 && treeHeight <= maxHeight;
    }

    /// Registration: only when the Safe has no Active key, the root is new for this
    /// Safe, the parameters are valid and the deadline has not passed.
    function canRegister(SafeState memory s, bool rootUsedBefore, bool paramsOk, uint256 nowTs, uint256 validUntil)
        internal
        pure
        returns (bool)
    {
        return s.activeKeyId == bytes32(0) && paramsOk && !rootUsedBefore && nowTs <= validUntil;
    }

    /// State after a registration: the new key is Active, enrollment sticks, the root
    /// is spent and the nonce advances. A pending revocation is NOT cleared here — it
    /// names the old key, and `executeKeyRevocation` refuses a superseded request.
    function afterRegister(SafeState memory s, address safe, bytes32 root) internal pure returns (SafeState memory) {
        s.activeKeyId = keyId(safe, root, s.nonce);
        s.enrolled = true;
        s.nonce += 1;
        return s;
    }

    /// State after a rotation: old key Rotated, new key Active in the same transaction,
    /// any pending revocation cancelled (an owner-co-signed rotation supersedes it).
    function afterRotate(SafeState memory s, address safe, bytes32 newRoot) internal pure returns (SafeState memory) {
        s.activeKeyId = keyId(safe, newRoot, s.nonce);
        s.enrolled = true;
        s.nonce += 1;
        s.revocationExecutableAt = 0;
        s.revocationKeyId = bytes32(0);
        return s;
    }

    /// A revocation request needs an Active key and an unexpired deadline.
    function canRequestRevocation(SafeState memory s, uint256 nowTs, uint256 validUntil) internal pure returns (bool) {
        return s.activeKeyId != bytes32(0) && nowTs <= validUntil;
    }

    /// The request arms the time lock from *now*: re-requesting can only ever move the
    /// deadline later, never earlier.
    function afterRequestRevocation(SafeState memory s, uint256 nowTs, uint64 timelock) internal pure returns (SafeState memory) {
        s.revocationExecutableAt = uint64(nowTs) + timelock;
        s.revocationKeyId = s.activeKeyId;
        s.nonce += 1;
        return s;
    }

    /// Only the Safe itself may cancel, and only while a request is pending.
    function canCancelRevocation(SafeState memory s, address caller, address safe) internal pure returns (bool) {
        return caller == safe && s.activeKeyId != bytes32(0) && s.revocationExecutableAt != 0;
    }

    function afterCancelRevocation(SafeState memory s) internal pure returns (SafeState memory) {
        s.revocationExecutableAt = 0;
        s.revocationKeyId = bytes32(0);
        return s;
    }

    /// Execution is permissionless once the time lock has elapsed, but only for the
    /// key the request named: a rotation in the meantime voids it.
    function canExecuteRevocation(SafeState memory s, uint256 nowTs) internal pure returns (bool) {
        return s.revocationExecutableAt != 0 && nowTs >= s.revocationExecutableAt && s.revocationKeyId == s.activeKeyId;
    }

    /// A matured, non-superseded request clears the pending state, revokes that key and
    /// leaves the Safe with no Active key; the nonce advances to kill stale ceremonies.
    function afterExecuteRevocation(SafeState memory s) internal pure returns (SafeState memory) {
        s.activeKeyId = bytes32(0);
        s.revocationExecutableAt = 0;
        s.revocationKeyId = bytes32(0);
        s.nonce += 1;
        return s;
    }

    function eq(SafeState memory a, SafeState memory b) internal pure returns (bool) {
        return a.activeKeyId == b.activeKeyId && a.enrolled == b.enrolled
            && a.revocationExecutableAt == b.revocationExecutableAt && a.revocationKeyId == b.revocationKeyId
            && a.nonce == b.nonce;
    }
}
