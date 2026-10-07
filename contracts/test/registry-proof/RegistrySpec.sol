// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.24;

/// @title QuantumKeyRegistry — executable specification of the key state machine
/// @notice The rules of `quantum-key-registry.md` written as plain code: at most one
///         Active key per Safe, a per-key status that tells a Rotated key from a
///         Revoked one, sticky enrollment, one-shot roots, a per-Safe ceremony nonce
///         consumed by every owner-signed action, and an emergency revocation behind
///         a time lock that only the Safe can cancel and that a rotation supersedes.
///         `RegistryEquivalence.t.sol` proves `QuantumKeyRegistry` makes exactly these
///         state transitions, for all inputs, with Halmos.
///
///         Scope: the state machine over the six fields of `SafeState`. Each lemma
///         installs an ARBITRARY such state (the harness's `primeState`) that satisfies
///         `invariant` and then runs one transition, so the proofs range over the whole
///         abstract state space rather than over whatever a genesis-to-here call
///         sequence happens to reach, and every successful transition is proven to
///         preserve `invariant` again. The all-zero genesis state satisfies it, so
///         induction covers every reachable state.
///
///         Assuming `invariant` is what makes the transition lemmas tractable, and it
///         is also what would make the `activeKeyStatus == Status.Active` clauses below
///         vacuous, since the invariant already rules out a non-Active key sitting in
///         `activeKeyId`. `check_activeKeyStatusIsEnforced` is the one lemma that does
///         NOT assume the invariant: it installs that broken state on purpose and proves
///         the registry still refuses to rotate, request or cancel from it. Read those
///         clauses as proven by that lemma, not by the ones that assume them away.
///
///         Deliberately abstracted, and why:
///         - Owner-threshold signatures and the Ledger attestation: the `PermissiveSafe`
///           and `PermissiveSigner` stubs in `RegistryEquivalence.t.sol` accept every
///           signature, so the lemmas say what the registry does GIVEN that both
///           authorizations succeeded. See "Security notes" in `contracts/README.md`.
///         - The Guard's enrollment posture check ([QKR-006]: a fallback handler or
///           unguarded enabled modules) lives in `FermionGuard._afterEnrollment`, not
///           here. It is NOT silently missing: it enters this specification as the
///           `postureOk` parameter of `canRegister`, and the harness's hook refuses
///           whenever it is false — so the proof does cover that a hook refusal vetoes
///           the whole registration atomically. What the posture check itself *is*
///           belongs to the Guard's own proof, not to the registry's.
///         - XMSS verification. `rotateQuantumKey` consumes one leaf of the old key as
///           a possession proof, and a valid XMSS signature is out of reach inside the
///           symbolic model: Halmos treats SHA-256 as an uninterpreted function even on
///           concrete input, so the 67 WOTS+ chain lengths stay symbolic and the chains
///           fork (`lib/xmss-solidity/PROOF.md`: at h = 2 with a symbolic message the
///           solver did not finish in 40 minutes). `canRotate` therefore states the
///           preconditions that are about registry STATE, and `check_rotate` proves the
///           registry reaches the possession proof exactly when they hold. The effects
///           of a SUCCEEDING rotation — `afterRotate`, and the old key turning Rotated —
///           are unreachable for Halmos and are covered by the concrete-vector Foundry
///           tests instead (`GuardIntegration.t.sol`, `DocExamples.t.sol`), so
///           `invariant` preservation across `Rotate` is assumed, not proven.
///         - Used-leaf accounting (the per-root bitmap) is not a `SafeState` field, so
///           "the rotation leaf is unused" is outside `canRotate` as well.
///
///         Note for callers: every `after*` function writes the transition's effects
///         THROUGH its `SafeState memory` argument (that is how Solidity passes memory
///         structs) and returns the same struct. Never hand one a pre-state you still
///         need afterwards — see `_scratch` in `RegistryEquivalence.t.sol`.
library RegistrySpec {
    enum Status {
        None,
        Active,
        Rotated,
        Revoked
    }

    /// The registry stores a revocation deadline in a `uint64`, and Solidity's checked
    /// arithmetic reverts rather than wrap, so a request that would overflow is refused.
    uint256 internal constant MAX_TIMESTAMP = type(uint64).max;

    /// Everything the registry records about one Safe.
    struct SafeState {
        bytes32 activeKeyId; // 0 = no active key
        Status activeKeyStatus; // the status recorded for `activeKeyId` (`None` when there is none)
        bool enrolled; //      sticky: set at the first registration, never cleared
        uint64 revocationExecutableAt; // 0 = no pending revocation
        bytes32 revocationKeyId; //      the key a pending revocation names
        uint256 nonce; //                per-Safe ceremony nonce
    }

    /// The state invariant. Every lemma assumes it of the state before the transition
    /// and proves it of the state after, so the proofs cover exactly the reachable
    /// states: the genesis state (all zero, no key, not enrolled) satisfies it.
    function invariant(SafeState memory s) internal pure returns (bool) {
        return (s.activeKeyId == bytes32(0) || s.activeKeyStatus == Status.Active)
            && (s.activeKeyId != bytes32(0) || s.activeKeyStatus == Status.None)
            && (s.revocationExecutableAt == 0 || s.revocationKeyId != bytes32(0))
            && (s.revocationExecutableAt != 0 || s.revocationKeyId == bytes32(0));
    }

    /// A key's identity is the Safe, the root and the nonce that registered it.
    function keyId(address safe, bytes32 xmssRoot, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(safe, xmssRoot, nonce));
    }

    /// The status the registry must record for a key that is no longer the Safe's
    /// Active key: `Rotated` if a rotation retired it, `Revoked` if an executed
    /// revocation did (§ "Key states"; [QKR-011] hangs off this distinction — a Rotated
    /// key's approvals stay executable, a Revoked key's do not).
    function statusOfRetiredKey(bool retiredByRevocation) internal pure returns (Status) {
        return retiredByRevocation ? Status.Revoked : Status.Rotated;
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
    /// Safe, the parameters are valid, the deadline has not passed and the Safe's
    /// posture is acceptable to the Guard's enrollment hook ([QKR-006]).
    function canRegister(SafeState memory s, bool rootUsedBefore, bool paramsOk, bool postureOk, uint256 nowTs, uint256 validUntil)
        internal
        pure
        returns (bool)
    {
        return s.activeKeyId == bytes32(0) && paramsOk && !rootUsedBefore && nowTs <= validUntil && postureOk;
    }

    /// State after a registration: the new key is Active, enrollment sticks, the root
    /// is spent and the nonce advances. A pending revocation is NOT cleared here — it
    /// names the old key, and `executeKeyRevocation` refuses a superseded request.
    function afterRegister(SafeState memory s, address safe, bytes32 root) internal pure returns (SafeState memory) {
        s.activeKeyId = keyId(safe, root, s.nonce);
        s.activeKeyStatus = Status.Active;
        s.enrolled = true;
        s.nonce += 1;
        return s;
    }

    /// Rotation: only from an Active key, and then under the same key-parameter rules as
    /// a registration — valid parameters, a root this Safe has not used, an unelapsed
    /// deadline. The three proofs a rotation also needs (the old key's XMSS possession
    /// proof, the new key's Ledger attestation, the owner threshold) are the abstracted
    /// ones; see the scope note at the top of this file.
    function canRotate(SafeState memory s, bool rootUsedBefore, bool paramsOk, uint256 nowTs, uint256 validUntil)
        internal
        pure
        returns (bool)
    {
        return s.activeKeyId != bytes32(0) && s.activeKeyStatus == Status.Active && paramsOk && !rootUsedBefore
            && nowTs <= validUntil;
    }

    /// State after a rotation: old key Rotated (`statusOfRetiredKey(false)`), new key
    /// Active in the same transaction, any pending revocation cancelled (an
    /// owner-co-signed rotation supersedes it).
    function afterRotate(SafeState memory s, address safe, bytes32 newRoot) internal pure returns (SafeState memory) {
        s.activeKeyId = keyId(safe, newRoot, s.nonce);
        s.activeKeyStatus = Status.Active;
        s.enrolled = true;
        s.nonce += 1;
        s.revocationExecutableAt = 0;
        s.revocationKeyId = bytes32(0);
        return s;
    }

    /// A revocation request needs an Active key, an unexpired deadline, and a deadline
    /// that still fits the registry's `uint64` field once the time lock is added.
    function canRequestRevocation(SafeState memory s, uint256 nowTs, uint256 validUntil, uint64 timelock)
        internal
        pure
        returns (bool)
    {
        return s.activeKeyId != bytes32(0) && s.activeKeyStatus == Status.Active && nowTs <= validUntil
            && nowTs + timelock <= MAX_TIMESTAMP;
    }

    /// The request arms the time lock from *now*, by the registry's immutable
    /// `EMERGENCY_ROTATION_TIMELOCK` (that is what `timelock` is). The assignment is
    /// unconditional, so it is NOT the spec that stops a re-request from shortening a
    /// pending deadline: `nowTs` never decreases between two blocks, and monotonic
    /// `nowTs` plus a fixed `timelock` gives a non-decreasing deadline.
    /// `check_revocationTimelockNeverShortens` proves exactly that, and assumes the
    /// monotonicity it rests on.
    function afterRequestRevocation(SafeState memory s, uint256 nowTs, uint64 timelock) internal pure returns (SafeState memory) {
        s.revocationExecutableAt = uint64(nowTs) + timelock;
        s.revocationKeyId = s.activeKeyId;
        s.nonce += 1;
        return s;
    }

    /// Only the Safe itself may cancel, and only while a request is pending against an
    /// Active key.
    function canCancelRevocation(SafeState memory s, address caller, address safe) internal pure returns (bool) {
        return caller == safe && s.activeKeyId != bytes32(0) && s.activeKeyStatus == Status.Active
            && s.revocationExecutableAt != 0;
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

    /// A matured, non-superseded request clears the pending state, revokes that key
    /// (`statusOfRetiredKey(true)`) and leaves the Safe with no Active key; the nonce
    /// advances to kill stale ceremonies.
    function afterExecuteRevocation(SafeState memory s) internal pure returns (SafeState memory) {
        s.activeKeyId = bytes32(0);
        s.activeKeyStatus = Status.None;
        s.revocationExecutableAt = 0;
        s.revocationKeyId = bytes32(0);
        s.nonce += 1;
        return s;
    }

    function eq(SafeState memory a, SafeState memory b) internal pure returns (bool) {
        return a.activeKeyId == b.activeKeyId && a.activeKeyStatus == b.activeKeyStatus && a.enrolled == b.enrolled
            && a.revocationExecutableAt == b.revocationExecutableAt && a.revocationKeyId == b.revocationKeyId
            && a.nonce == b.nonce;
    }
}
