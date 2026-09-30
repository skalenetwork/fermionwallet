// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";

/// @title FermionGuard and PreApprovalEngine — executable specification
/// @notice The normative rules of `fermionguard-module.md` and `pre-approval-engine.md`
///         written as plain code: which calls escape the Guard untouched, who may
///         pause and unpause and when, which selectors can never be permitted, and
///         when a pre-approval is live, dead or consumable.
///         `GuardEquivalence.t.sol` proves the contracts make exactly these decisions,
///         for all inputs, with Halmos.
///
///         Scope: decisions and state transitions. Signature verification, XMSS and
///         the Safe's own behaviour are abstracted — see README.md in this folder.
library GuardSpec {
    // ── Selectors the Guard knows ──────────────────────────────────────────

    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 internal constant APPROVE = bytes4(keccak256("approve(address,uint256)"));
    bytes4 internal constant TRANSFER_FROM = bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 internal constant INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));
    bytes4 internal constant PERMIT =
        bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"));
    bytes4 internal constant SET_GUARD = bytes4(keccak256("setGuard(address)"));

    /// Owner safety calls to the Guard itself: 4-byte (no argument) and 36-byte (one
    /// argument) forms, per "the one family of transactions the Guard may never block".
    bytes4 internal constant REQUEST_EMERGENCY_DEGUARD = bytes4(keccak256("requestEmergencyDeGuard()"));
    bytes4 internal constant REQUEST_UNPAUSE = bytes4(keccak256("requestUnpauseSafe()"));
    bytes4 internal constant UNPAUSE = bytes4(keccak256("unpauseSafe()"));
    bytes4 internal constant CANCEL_EMERGENCY_DEGUARD = bytes4(keccak256("cancelEmergencyDeGuard(address)"));
    bytes4 internal constant PAUSE = bytes4(keccak256("pauseSafe(address)"));
    bytes4 internal constant REVOKE_PRE_APPROVAL = bytes4(keccak256("revokePreApproval(bytes32)"));
    bytes4 internal constant CANCEL_KEY_REVOCATION = bytes4(keccak256("cancelKeyRevocation(address)"));

    /// Selectors that may never be added to a Safe's permit-list: each one lets value
    /// leave the Safe later, outside any transaction the Guard would see.
    function isDeniedSelector(bytes4 selector) internal pure returns (bool) {
        return selector == APPROVE || selector == TRANSFER_FROM || selector == INCREASE_ALLOWANCE
            || selector == PERMIT;
    }

    // ── The escape hatch ───────────────────────────────────────────────────

    /// The Guard's own state that the escape-hatch decision reads.
    struct EscapeState {
        bool enrolled; //                  has this Safe ever registered a key
        uint64 deGuardExecutableAt; //     0 = no pending emergency de-guard
        uint256 nowTs;
    }

    /// A call escapes the Guard — no approval, no pause, no enrollment check — exactly
    /// when it is a plain zero-value CALL and either
    ///   a) it targets the Guard and is one of the seven owner safety calls, in its
    ///      canonical 4- or 36-byte form; or
    ///   b) it is the Safe calling `setGuard(0)` on itself, and the Safe either never
    ///      enrolled or has a matured emergency de-guard request.
    /// Anything else is checked normally.
    function isEscapeCall(
        EscapeState memory s,
        address guard,
        address safe,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) internal pure returns (bool) {
        if (operation != Enum.Operation.Call || value != 0 || data.length < 4) return false;
        bytes4 selector = bytes4(data);

        if (to == guard) {
            if (data.length == 4) {
                return selector == REQUEST_EMERGENCY_DEGUARD || selector == REQUEST_UNPAUSE || selector == UNPAUSE;
            }
            if (data.length == 36) {
                return selector == CANCEL_EMERGENCY_DEGUARD || selector == PAUSE || selector == REVOKE_PRE_APPROVAL
                    || selector == CANCEL_KEY_REVOCATION;
            }
            return false;
        }

        // setGuard(newGuard) as a Safe self-call. The match is on the selector and the
        // first argument word, never the exact length: Safe's decoder ignores trailing
        // calldata, so padded calldata must be treated the same as the canonical form.
        if (to != safe || data.length < 36 || selector != SET_GUARD) return false;
        if (!isCanonicalAddressWord(data, 4)) return false; // dirty upper bits: not a valid call
        if (addressArg(data, 4) != address(0)) return false; // only detaching is ever unlocked

        if (!s.enrolled) return true; // a Safe the Guard protects nothing for
        return s.deGuardExecutableAt != 0 && s.nowTs >= s.deGuardExecutableAt;
    }

    /// The word at `offset` is a canonically encoded address (upper 96 bits zero).
    function isCanonicalAddressWord(bytes memory data, uint256 offset) internal pure returns (bool) {
        uint256 word;
        assembly ("memory-safe") {
            word := mload(add(add(data, 32), offset))
        }
        return word >> 160 == 0;
    }

    function addressArg(bytes memory data, uint256 offset) internal pure returns (address) {
        uint256 word;
        assembly ("memory-safe") {
            word := mload(add(add(data, 32), offset))
        }
        return address(uint160(word));
    }

    // ── Pause and unpause ──────────────────────────────────────────────────

    /// The pause-related state of one Safe.
    struct PauseState {
        bool enrolled;
        bool paused;
        uint64 unpauseExecutableAt; // 0 = no pending unpause
        uint64 cooldownUntil; //       single-key actors may not pause before this
        uint256 nowTs;
    }

    /// Pausing is fast and low-privilege: the Safe itself, any single owner, or the
    /// Quantum Administrator. The Safe is never subject to the cooldown; the two
    /// single-key actors are, so one stolen key cannot re-freeze a Safe the owner
    /// threshold has just unpaused.
    function canPause(PauseState memory s, bool callerIsSafe, bool callerIsOwnerOrAdmin) internal pure returns (bool) {
        if (!s.enrolled) return false;
        if (callerIsSafe) return true;
        if (!callerIsOwnerOrAdmin) return false;
        return s.nowTs >= s.cooldownUntil;
    }

    /// Only the Safe may start the unpause delay, and only while paused.
    function canRequestUnpause(PauseState memory s, bool callerIsSafe) internal pure returns (bool) {
        return callerIsSafe && s.paused;
    }

    /// Only the Safe may finish an unpause, and only after the admin time lock.
    function canUnpause(PauseState memory s, bool callerIsSafe) internal pure returns (bool) {
        return callerIsSafe && s.unpauseExecutableAt != 0 && s.nowTs >= s.unpauseExecutableAt;
    }

    /// After an unpause the Safe is live again, the request is cleared, and the
    /// cooldown starts: the owner threshold gets a guaranteed working window.
    function afterUnpause(PauseState memory s, uint64 adminTimelock) internal pure returns (PauseState memory) {
        s.paused = false;
        s.unpauseExecutableAt = 0;
        s.cooldownUntil = uint64(s.nowTs) + adminTimelock;
        return s;
    }

    // ── Pre-approval lifecycle ─────────────────────────────────────────────

    /// The stored fields of a pre-approval that decide whether it can be consumed.
    struct ApprovalState {
        bool exists;
        bool used;
        bool revoked;
        uint64 validFrom;
        uint64 validTo;
        bool keyUsable; // the key is Active or Rotated (revocation kills approvals)
    }

    /// Consumable now: exists, unspent, not revoked, inside its window, key usable.
    function isConsumable(ApprovalState memory a, uint256 nowTs) internal pure returns (bool) {
        return a.exists && !a.used && !a.revoked && nowTs >= a.validFrom && nowTs <= a.validTo && a.keyUsable;
    }

    /// Dead: can never become consumable again, however long anyone waits. A
    /// not-yet-valid approval is NOT dead — its window is still ahead.
    function isDead(ApprovalState memory a, uint256 nowTs) internal pure returns (bool) {
        return a.used || a.revoked || nowTs > a.validTo || !a.keyUsable;
    }

    /// Revocation is deliberately cheap: the Safe, the Administrator of the key that
    /// created it, or any single owner — except that a single owner may not revoke an
    /// ADMIN approval, which is how the threshold changes governance.
    function canRevoke(ApprovalState memory a, bool callerIsSafe, bool callerIsAdmin, bool callerIsOwner, bool isAdminClass)
        internal
        pure
        returns (bool)
    {
        if (!a.exists) return false;
        bool authorized = callerIsSafe || callerIsAdmin || (callerIsOwner && !isAdminClass);
        return authorized && !a.used && !a.revoked;
    }
}
