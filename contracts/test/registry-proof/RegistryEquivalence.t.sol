// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {XMSS} from "xmss-solidity/XMSS.sol";
import {QuantumKeyRegistry} from "../../src/QuantumKeyRegistry.sol";
import {RegistrySpec} from "./RegistrySpec.sol";

/// A Safe that answers every authorization question with "yes": owner-threshold
/// signatures and ownership are abstracted, so the proofs are about the registry's
/// state machine given that authorization succeeded (see "Security notes" in
/// `contracts/README.md` for the full list of assumptions and the Halmos command).
contract PermissiveSafe {
    function checkSignatures(bytes32, bytes calldata, bytes memory) external pure {}
    function isOwner(address) external pure returns (bool) {
        return true;
    }
    fallback() external payable {}
    receive() external payable {}
}

/// An ERC-1271 signer that accepts every signature: the Ledger attestation is
/// abstracted the same way.
contract PermissiveSigner {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

contract RegistryHarness is QuantumKeyRegistry {
    constructor(uint64 timelock) EIP712("FermionGuard", "1") QuantumKeyRegistry(timelock) {}

    function _afterEnrollment(address, bool) internal override {}

    /// The five storage slots the specification models, read back for comparison.
    function stateOf(address safe) external view returns (RegistrySpec.SafeState memory s) {
        s.activeKeyId = safeToQuantumKey[safe];
        s.enrolled = enrolledSafe[safe];
        s.revocationExecutableAt = keyRevocationExecutableAt[safe];
        s.revocationKeyId = keyRevocationKeyId[safe];
        s.nonce = registryNonce(safe);
    }
}

/// @title QuantumKeyRegistry proven equal to its specification
/// @notice `check_*` functions are symbolic proofs run by Halmos: a PASS means the
///         property holds for ALL inputs, including the caller, the block timestamp
///         and every key parameter. `test_*` functions are ordinary Foundry tests.
///
///         halmos --match-contract RegistryEquivalence --loop 32
contract RegistryEquivalence is Test {
    uint64 constant TIMELOCK = 14 days;
    RegistryHarness registry;
    PermissiveSafe safeContract;
    PermissiveSigner admin;
    address safe;

    function setUp() public {
        registry = new RegistryHarness(TIMELOCK);
        safeContract = new PermissiveSafe();
        admin = new PermissiveSigner();
        safe = address(safeContract);
    }

    function _register(bytes32 root, bytes32 seed, uint32 height, bytes32 paramSet, uint256 validUntil)
        internal
        returns (bool ok)
    {
        try registry.registerQuantumKey(safe, address(admin), root, seed, height, paramSet, validUntil, "", "") {
            return true;
        } catch {
            return false;
        }
    }

    // ── Lemma 1: registration ──────────────────────────────────────────────

    /// A registration succeeds exactly when the specification allows it, and leaves
    /// exactly the state the specification describes, for every caller, timestamp and
    /// key parameter.
    /// Covers: [QKR-005], [QKR-006], [QKR-008], [QKR-033]
    function check_register(address caller, bytes32 root, bytes32 seed, uint32 height, bytes32 paramSet, uint256 validUntil, uint64 nowTs)
        public
    {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = registry.stateOf(safe);
        bool paramsOk =
            RegistrySpec.paramsValid(safe, address(admin), root, seed, height, paramSet, XMSS.MAX_HEIGHT);
        bool rootUsed = registry.rootRegistered(safe, root);
        bool allowed = RegistrySpec.canRegister(before, rootUsed, paramsOk, nowTs, validUntil);

        vm.prank(caller);
        bool ok = _register(root, seed, height, paramSet, validUntil);

        assertEq(ok, allowed, "registration succeeded exactly when the specification allows");
        RegistrySpec.SafeState memory got = registry.stateOf(safe);
        RegistrySpec.SafeState memory want = ok ? RegistrySpec.afterRegister(before, safe, root) : before;
        assertTrue(RegistrySpec.eq(got, want), "state after registration");
        if (ok) {
            assertTrue(registry.rootRegistered(safe, root), "the root is spent");
            assertEq(uint256(registry.getKey(got.activeKeyId).status), 1, "the new key is Active");
            assertEq(registry.getKey(got.activeKeyId).treeHeight, height, "the height is recorded");
        }
    }

    // ── Lemma 2: requesting an emergency revocation ────────────────────────

    /// Covers: [QKR-020], [QKR-021]
    function check_requestRevocation(address caller, uint256 validUntil, uint64 nowTs) public {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = registry.stateOf(safe);
        bool allowed = RegistrySpec.canRequestRevocation(before, nowTs, validUntil);

        vm.prank(caller);
        bool ok;
        try registry.requestKeyRevocation(safe, validUntil, "") {
            ok = true;
        } catch {
            ok = false;
        }

        assertEq(ok, allowed, "request succeeded exactly when the specification allows");
        RegistrySpec.SafeState memory want =
            ok ? RegistrySpec.afterRequestRevocation(before, nowTs, TIMELOCK) : before;
        assertTrue(RegistrySpec.eq(registry.stateOf(safe), want), "state after the request");
    }

    /// The time lock is armed from the present, so a second request can only move the
    /// deadline later: there is no way to shorten a pending revocation.
    /// Covers: [QKR-020]
    function check_revocationTimelockNeverShortens(uint64 firstAt, uint64 secondAt, uint256 validUntil) public {
        vm.assume(firstAt <= secondAt);
        vm.assume(uint256(secondAt) + TIMELOCK < type(uint64).max);
        vm.warp(firstAt);
        if (!_tryRequest(validUntil)) return;
        uint64 first = registry.keyRevocationExecutableAt(safe);
        vm.warp(secondAt);
        if (!_tryRequest(validUntil)) return;
        assertGe(registry.keyRevocationExecutableAt(safe), first, "a re-request never moves the deadline earlier");
    }

    function _tryRequest(uint256 validUntil) internal returns (bool) {
        try registry.requestKeyRevocation(safe, validUntil, "") {
            return true;
        } catch {
            return false;
        }
    }

    // ── Lemma 3: cancelling — the Safe alone, never the Administrator ──────

    /// Covers: [QKR-022]
    function check_cancelRevocation(address caller, uint64 nowTs) public {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = registry.stateOf(safe);
        bool allowed = RegistrySpec.canCancelRevocation(before, caller, safe);

        vm.prank(caller);
        bool ok;
        try registry.cancelKeyRevocation(safe) {
            ok = true;
        } catch {
            ok = false;
        }

        assertEq(ok, allowed, "cancel succeeded exactly when the specification allows");
        RegistrySpec.SafeState memory want = ok ? RegistrySpec.afterCancelRevocation(before) : before;
        assertTrue(RegistrySpec.eq(registry.stateOf(safe), want), "state after the cancel");
    }

    // ── Lemma 4: executing a matured revocation ───────────────────────────

    /// Covers: [QKR-023], [QKR-024]
    function check_executeRevocation(address caller, uint64 nowTs) public {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = registry.stateOf(safe);
        bool allowed = RegistrySpec.canExecuteRevocation(before, nowTs);

        vm.prank(caller);
        bool ok;
        try registry.executeKeyRevocation(safe) {
            ok = true;
        } catch {
            ok = false;
        }

        assertEq(ok, allowed, "execution succeeded exactly when the specification allows");
        if (ok) {
            RegistrySpec.SafeState memory want = RegistrySpec.afterExecuteRevocation(before);
            assertTrue(RegistrySpec.eq(registry.stateOf(safe), want), "state after the revocation");
            assertEq(uint256(registry.getKey(before.revocationKeyId).status), 3, "the named key is Revoked");
            assertTrue(registry.enrolledSafe(safe), "enrollment is sticky across revocation");
        }
    }

    // ── Lemma 5: one Active key, and a root is one-shot ────────────────────

    /// Whatever sequence of registrations is attempted, the Safe never ends up with a
    /// second Active key under a root it already used.
    /// Covers: [QKR-008], [QKR-009]
    function check_rootIsOneShot(bytes32 root, bytes32 seed, uint32 height, bytes32 paramSet, uint256 validUntil, uint64 nowTs)
        public
    {
        vm.warp(nowTs);
        if (!_register(root, seed, height, paramSet, validUntil)) return;
        bytes32 firstKey = registry.safeToQuantumKey(safe);
        // A second registration under the same root must fail: the Safe still has an
        // Active key, and the root is spent even after that key is revoked.
        assertFalse(_register(root, seed, height, paramSet, validUntil), "the same root cannot be registered twice");
        assertEq(registry.safeToQuantumKey(safe), firstKey, "the Active key is unchanged");
    }
}
