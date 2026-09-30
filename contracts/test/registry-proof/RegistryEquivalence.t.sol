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
    error PostureRefused();

    /// Stands in for the Guard's enrollment posture check ([QKR-006]): the registry
    /// itself has none, the Guard's `_afterEnrollment` does. Symbolic per lemma.
    bool public postureOk = true;
    /// Set by the hook, so a lemma can prove the hook ran and what it was told.
    /// Both roll back with the transaction, so they are only ever observed on success.
    bool public enrollmentHookRan;
    bool public sawFirstEnrollment;

    constructor(uint64 timelock) EIP712("FermionGuard", "1") QuantumKeyRegistry(timelock) {}

    function setPostureOk(bool ok) external {
        postureOk = ok;
    }

    function _afterEnrollment(address, bool firstEnrollment) internal override {
        if (!postureOk) revert PostureRefused();
        enrollmentHookRan = true;
        sawFirstEnrollment = firstEnrollment;
    }

    /// The six storage reads the specification models, read back for comparison.
    function stateOf(address safe) external view returns (RegistrySpec.SafeState memory s) {
        s.activeKeyId = safeToQuantumKey[safe];
        s.activeKeyStatus = RegistrySpec.Status(uint8(_keys[s.activeKeyId].status));
        s.enrolled = enrolledSafe[safe];
        s.revocationExecutableAt = keyRevocationExecutableAt[safe];
        s.revocationKeyId = keyRevocationKeyId[safe];
        s.nonce = registryNonce(safe);
    }

    /// Install an ARBITRARY registry state for `safe`, so a lemma can prove a
    /// transition from every state in the abstract state space instead of only from the
    /// states a genesis-to-here call sequence happens to reach. Callers cut the
    /// unreachable ones out with `RegistrySpec.invariant`.
    ///
    /// Test-only, and the reason the proofs are not vacuous: building the pre-state by
    /// *calling* the registry is what silently confined the earlier revocation lemmas to
    /// the "this Safe has no key at all" branch, where every one of them passes for
    /// free.
    function primeState(
        address safe,
        bytes32 activeKeyId,
        uint8 activeKeyStatus,
        bool enrolled,
        uint64 revocationExecutableAt,
        bytes32 revocationKeyId,
        bytes32 root,
        bytes32 seed,
        uint32 treeHeight
    ) external {
        if (activeKeyId != bytes32(0)) {
            _keys[activeKeyId] = KeyRegistration({
                quantumKeyId: activeKeyId,
                safe: safe,
                quantumAdmin: address(this),
                xmssRoot: root,
                xmssSeed: seed,
                treeHeight: treeHeight,
                parameterSet: keccak256("XMSS-SHA2_20_256"),
                status: KeyStatus(activeKeyStatus),
                createdAt: 0,
                rotatedAt: 0,
                useCounter: 0
            });
            rootRegistered[safe][root] = true;
        }
        safeToQuantumKey[safe] = activeKeyId;
        enrolledSafe[safe] = enrolled;
        keyRevocationExecutableAt[safe] = revocationExecutableAt;
        keyRevocationKeyId[safe] = revocationKeyId;
    }
}

/// @title QuantumKeyRegistry proven equal to its specification
/// @notice `check_*` functions are symbolic proofs run by Halmos: a PASS means the
///         property holds for ALL inputs, including the caller, the block timestamp,
///         every key parameter AND every prior registry state satisfying
///         `RegistrySpec.invariant` — each lemma installs an arbitrary such state with
///         `primeState` before it acts, and proves the invariant again afterwards.
///         `test_*` functions are ordinary Foundry tests.
///
///         halmos --match-contract RegistryEquivalence --loop 32 --solver-timeout-assertion 0
contract RegistryEquivalence is Test {
    /// The primed key's own root and seed. Concrete: their values are irrelevant to
    /// every lemma, while a symbolic new root still explores both the "this Safe used
    /// this root" and "it did not" branches against them.
    bytes32 constant PRIMED_ROOT = keccak256("primed root");
    bytes32 constant PRIMED_SEED = keccak256("primed seed");

    RegistryHarness registry;
    PermissiveSafe safeContract;
    PermissiveSigner admin;
    address safe;
    /// Read back from the contract, never a literal: the specification's `timelock` IS
    /// `EMERGENCY_ROTATION_TIMELOCK` by construction.
    uint64 timelock;

    function setUp() public {
        registry = new RegistryHarness(14 days);
        safeContract = new PermissiveSafe();
        admin = new PermissiveSigner();
        safe = address(safeContract);
        timelock = registry.EMERGENCY_ROTATION_TIMELOCK();
    }

    /// Install an arbitrary invariant-satisfying pre-state and return it.
    function _prime(bytes32 keyId, uint8 status, bool enrolled, uint64 revAt, bytes32 revKeyId, uint32 height)
        internal
        returns (RegistrySpec.SafeState memory before)
    {
        vm.assume(status <= uint8(type(QuantumKeyRegistry.KeyStatus).max));
        vm.assume(height >= 1 && height <= XMSS.MAX_HEIGHT);
        registry.primeState(safe, keyId, status, enrolled, revAt, revKeyId, PRIMED_ROOT, PRIMED_SEED, height);
        before = registry.stateOf(safe);
        vm.assume(RegistrySpec.invariant(before));
    }

    /// A second, independent read of the same pre-state, for handing to the
    /// specification's `after*` helpers. They take a `SafeState memory` — which Solidity
    /// passes by reference — and write the transition's effects through it, so handing
    /// one the baseline a lemma still has to compare against would silently corrupt that
    /// baseline. Call this BEFORE the transition; afterwards `stateOf` is the post-state.
    function _scratch() internal view returns (RegistrySpec.SafeState memory) {
        return registry.stateOf(safe);
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
    /// exactly the state the specification describes, for every caller, timestamp,
    /// key parameter, Safe posture and prior registry state.
    /// Covers: [QKR-005], [QKR-006], [QKR-007], [QKR-008], [QKR-033]
    function check_register(
        address caller,
        bytes32 root,
        bytes32 seed,
        uint32 height,
        bytes32 paramSet,
        uint256 validUntil,
        uint64 nowTs,
        bool postureOk,
        bytes32 pKey,
        uint8 pStatus,
        bool pEnrolled,
        uint64 pRevAt,
        bytes32 pRevKey,
        uint32 pHeight
    ) public {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = _prime(pKey, pStatus, pEnrolled, pRevAt, pRevKey, pHeight);
        RegistrySpec.SafeState memory scratch = _scratch();
        registry.setPostureOk(postureOk);
        bool paramsOk =
            RegistrySpec.paramsValid(safe, address(admin), root, seed, height, paramSet, XMSS.MAX_HEIGHT);
        bool rootUsed = registry.rootRegistered(safe, root);
        bool allowed = RegistrySpec.canRegister(before, rootUsed, paramsOk, postureOk, nowTs, validUntil);

        vm.prank(caller);
        bool ok = _register(root, seed, height, paramSet, validUntil);

        assertEq(ok, allowed, "registration succeeded exactly when the specification allows");
        RegistrySpec.SafeState memory got = registry.stateOf(safe);
        RegistrySpec.SafeState memory want = ok ? RegistrySpec.afterRegister(scratch, safe, root) : before;
        assertTrue(RegistrySpec.eq(got, want), "state after registration");
        if (ok) {
            assertTrue(registry.rootRegistered(safe, root), "the root is spent");
            assertEq(registry.getKey(got.activeKeyId).treeHeight, height, "the height is recorded");
            assertTrue(registry.enrollmentHookRan(), "the enrollment hook ran");
            assertEq(
                registry.sawFirstEnrollment(),
                !before.enrolled,
                "the hook is told first-enrollment exactly when the Safe was not enrolled yet"
            );
            assertTrue(RegistrySpec.invariant(got), "the invariant is preserved");
        }
    }

    // ── Lemma 2: rotation — the state gate ─────────────────────────────────

    /// The rotation's possession proof is reached exactly when the specification's
    /// state preconditions hold, and a refused rotation changes nothing.
    ///
    /// The lemma passes a well-formed but unverifiable possession proof: zero
    /// authentication nodes against a key of height at least 1, so
    /// `_verifyAndConsumeXmss` always reverts `LeafIndexMismatch`. Every state
    /// precondition (`_activeKey` including the key's status, `_validateKeyParams`,
    /// `rootRegistered`, `validUntil`) is checked BEFORE that revert and both
    /// authorization stubs sit between, so "the revert is `LeafIndexMismatch`" is
    /// exactly "the state gate opened". A rotation that gets past the gate cannot be
    /// carried through symbolically — see the scope note in `RegistrySpec.sol` — so
    /// `afterRotate` is not proven here.
    /// Covers: [QKR-008], [QKR-009], [QKR-012], [QKR-017]
    function check_rotate(
        address caller,
        bytes32 newRoot,
        bytes32 newSeed,
        uint32 height,
        bytes32 paramSet,
        uint256 validUntil,
        uint64 nowTs,
        bytes32 pKey,
        uint8 pStatus,
        bool pEnrolled,
        uint64 pRevAt,
        bytes32 pRevKey,
        uint32 pHeight
    ) public {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = _prime(pKey, pStatus, pEnrolled, pRevAt, pRevKey, pHeight);
        bool paramsOk =
            RegistrySpec.paramsValid(safe, address(admin), newRoot, newSeed, height, paramSet, XMSS.MAX_HEIGHT);
        bool rootUsed = registry.rootRegistered(safe, newRoot);
        bool allowed = RegistrySpec.canRotate(before, rootUsed, paramsOk, nowTs, validUntil);

        // Default-initialised: leaf 0, a zero randomiser, a zero WOTS+ signature and —
        // the point — an empty authentication path.
        XMSS.Signature memory sig;
        bytes memory proof = abi.encode(sig);

        vm.prank(caller);
        bool reachedProof;
        try registry.rotateQuantumKey(
            safe, address(admin), newRoot, newSeed, height, paramSet, validUntil, proof, "", ""
        ) {
            assertTrue(false, "a rotation whose possession proof cannot verify must never succeed");
        } catch (bytes memory reason) {
            reachedProof =
                reason.length >= 4 && bytes4(reason) == QuantumKeyRegistry.LeafIndexMismatch.selector;
        }

        assertEq(reachedProof, allowed, "the possession proof is reached exactly when the state gate allows");
        assertTrue(RegistrySpec.eq(registry.stateOf(safe), before), "a refused rotation changes nothing");
    }

    // ── Lemma 3: requesting an emergency revocation ────────────────────────

    /// Covers: [QKR-020], [QKR-021]
    function check_requestRevocation(
        address caller,
        uint256 validUntil,
        uint64 nowTs,
        bytes32 pKey,
        uint8 pStatus,
        bool pEnrolled,
        uint64 pRevAt,
        bytes32 pRevKey,
        uint32 pHeight
    ) public {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = _prime(pKey, pStatus, pEnrolled, pRevAt, pRevKey, pHeight);
        RegistrySpec.SafeState memory scratch = _scratch();
        bool allowed = RegistrySpec.canRequestRevocation(before, nowTs, validUntil, timelock);

        vm.prank(caller);
        bool ok;
        try registry.requestKeyRevocation(safe, validUntil, "") {
            ok = true;
        } catch {
            ok = false;
        }

        assertEq(ok, allowed, "request succeeded exactly when the specification allows");
        RegistrySpec.SafeState memory got = registry.stateOf(safe);
        RegistrySpec.SafeState memory want =
            ok ? RegistrySpec.afterRequestRevocation(scratch, nowTs, timelock) : before;
        assertTrue(RegistrySpec.eq(got, want), "state after the request");
        if (ok) {
            assertTrue(RegistrySpec.invariant(got), "the invariant is preserved");
        }
    }

    /// The time lock is armed from the present with a fixed delay, so as long as time
    /// only moves forward a second request can never move the deadline earlier: there
    /// is no way to shorten a pending revocation.
    /// Covers: [QKR-020]
    function check_revocationTimelockNeverShortens(
        uint64 firstAt,
        uint64 secondAt,
        uint256 validUntil,
        bytes32 pKey,
        uint8 pStatus,
        bool pEnrolled,
        uint32 pHeight
    ) public {
        vm.assume(firstAt <= secondAt);
        vm.assume(uint256(secondAt) + timelock <= RegistrySpec.MAX_TIMESTAMP);
        _prime(pKey, pStatus, pEnrolled, 0, bytes32(0), pHeight);
        vm.warp(firstAt);
        if (!_tryRequest(validUntil)) return;
        uint64 first = registry.keyRevocationExecutableAt(safe);
        assertTrue(first != 0, "the first request armed the time lock");
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

    // ── Lemma 4: cancelling — the Safe alone, never the Administrator ──────

    /// Covers: [QKR-022]
    function check_cancelRevocation(
        address caller,
        uint64 nowTs,
        bytes32 pKey,
        uint8 pStatus,
        bool pEnrolled,
        uint64 pRevAt,
        bytes32 pRevKey,
        uint32 pHeight
    ) public {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = _prime(pKey, pStatus, pEnrolled, pRevAt, pRevKey, pHeight);
        RegistrySpec.SafeState memory scratch = _scratch();
        bool allowed = RegistrySpec.canCancelRevocation(before, caller, safe);

        vm.prank(caller);
        bool ok;
        try registry.cancelKeyRevocation(safe) {
            ok = true;
        } catch {
            ok = false;
        }

        assertEq(ok, allowed, "cancel succeeded exactly when the specification allows");
        RegistrySpec.SafeState memory got = registry.stateOf(safe);
        RegistrySpec.SafeState memory want = ok ? RegistrySpec.afterCancelRevocation(scratch) : before;
        assertTrue(RegistrySpec.eq(got, want), "state after the cancel");
        if (ok) {
            assertTrue(RegistrySpec.invariant(got), "the invariant is preserved");
        }
    }

    // ── Lemma 5: executing a matured revocation ───────────────────────────

    /// Covers: [QKR-011], [QKR-023], [QKR-024]
    function check_executeRevocation(
        address caller,
        uint64 nowTs,
        bytes32 pKey,
        uint8 pStatus,
        bool pEnrolled,
        uint64 pRevAt,
        bytes32 pRevKey,
        uint32 pHeight
    ) public {
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = _prime(pKey, pStatus, pEnrolled, pRevAt, pRevKey, pHeight);
        RegistrySpec.SafeState memory scratch = _scratch();
        bool allowed = RegistrySpec.canExecuteRevocation(before, nowTs);

        vm.prank(caller);
        bool ok;
        try registry.executeKeyRevocation(safe) {
            ok = true;
        } catch {
            ok = false;
        }

        assertEq(ok, allowed, "execution succeeded exactly when the specification allows");
        RegistrySpec.SafeState memory got = registry.stateOf(safe);
        RegistrySpec.SafeState memory want = ok ? RegistrySpec.afterExecuteRevocation(scratch) : before;
        assertTrue(RegistrySpec.eq(got, want), "state after the revocation");
        if (ok) {
            assertEq(
                uint256(registry.getKey(before.revocationKeyId).status),
                uint256(RegistrySpec.statusOfRetiredKey(true)),
                "the named key is Revoked, not merely Rotated"
            );
            assertEq(registry.enrolledSafe(safe), before.enrolled, "enrollment is sticky across revocation");
            assertTrue(RegistrySpec.invariant(got), "the invariant is preserved");
        }
    }

    // ── Lemma 6: one Active key, and a root is one-shot ────────────────────

    /// Whatever sequence of registrations is attempted from genesis, the Safe never
    /// ends up with a second Active key under a root it already used. Unlike the
    /// lemmas above this one starts at genesis on purpose: it is about a call
    /// *sequence*, not about a single transition.
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

    // ── Lemma 7: the time lock is the immutable, for every value of it ─────

    /// `EMERGENCY_ROTATION_TIMELOCK` is what arms the deadline — not the 14 days this
    /// suite happens to deploy with. Proven for every constructor value.
    /// Covers: [QKR-020]
    function check_timelockIsTheImmutable(uint64 anyTimelock, uint64 nowTs, uint256 validUntil, bytes32 pKey, uint8 pStatus, uint32 pHeight)
        public
    {
        registry = new RegistryHarness(anyTimelock);
        timelock = registry.EMERGENCY_ROTATION_TIMELOCK();
        assertEq(timelock, anyTimelock, "the constructor argument is the immutable");
        vm.warp(nowTs);
        RegistrySpec.SafeState memory before = _prime(pKey, pStatus, true, 0, bytes32(0), pHeight);
        RegistrySpec.SafeState memory scratch = _scratch();
        bool allowed = RegistrySpec.canRequestRevocation(before, nowTs, validUntil, timelock);
        bool ok = _tryRequest(validUntil);
        assertEq(ok, allowed, "request succeeded exactly when the specification allows");
        RegistrySpec.SafeState memory want =
            ok ? RegistrySpec.afterRequestRevocation(scratch, nowTs, timelock) : before;
        assertTrue(RegistrySpec.eq(registry.stateOf(safe), want), "the deadline is now + the immutable");
    }
}
