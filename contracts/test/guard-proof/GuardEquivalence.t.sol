// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";
import {DoubleEndedQueue} from "@openzeppelin/contracts/utils/structs/DoubleEndedQueue.sol";
import {FermionGuard} from "../../src/FermionGuard.sol";
import {PreApprovalEngine} from "../../src/PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "../../src/QuantumKeyRegistry.sol";
import {GuardSpec} from "./GuardSpec.sol";

/// A Safe that answers every authorization question with "yes": ownership is
/// abstracted, so these proofs are about the Guard's decisions given the caller's
/// role, not about how the Safe decides roles (see README.md in this folder).
contract PermissiveSafe {
    /// The safeTxHash this Safe reports for every transaction, so the proofs can pin a
    /// Tier-1 approval at it. Real Safes hash the payload; that hashing is Safe's own
    /// property, and collapsing it here is what makes `checkTransaction` symbolically
    /// executable at all.
    bytes32 public constant TX_HASH = keccak256("fermionguard.proof.safeTxHash");

    function isOwner(address) external pure returns (bool) {
        return true;
    }
    function checkSignatures(bytes32, bytes calldata, bytes memory) external pure {}
    function getStorageAt(uint256, uint256) external pure returns (bytes memory) {
        return abi.encode(uint256(0)); // no fallback handler, no module guard
    }
    function getModulesPaginated(address, uint256) external pure returns (address[] memory m, address next) {
        next = address(0x1); // sentinel: no modules enabled
    }
    /// `checkTransaction` reads `nonce() - 1`: must be >= 1 or every path reverts on the
    /// underflow and the `checkTransaction` lemmas below would pass vacuously.
    function nonce() external pure returns (uint256) {
        return 1;
    }
    function getTransactionHash(
        address,
        uint256,
        bytes memory,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address,
        uint256
    ) external pure returns (bytes32) {
        return TX_HASH;
    }
    fallback() external payable {}
    receive() external payable {}
}

/// Stand-in for MultiSendCallOnly: the constructor requires a deployed contract.
contract MultiSendStub {
    fallback() external payable {}
}

/// A Safe that says "no" to every ownership question.
contract StrangerSafe {
    function isOwner(address) external pure returns (bool) {
        return false;
    }
    fallback() external payable {}
    receive() external payable {}
}

contract GuardHarness is FermionGuard {
    using DoubleEndedQueue for DoubleEndedQueue.Bytes32Deque;

    constructor(address multiSend, uint64 adminTimelock, uint64 emergencyTimelock, uint32 maxLegs, uint32 maxQueue)
        FermionGuard(multiSend, adminTimelock, emergencyTimelock, maxLegs, maxQueue)
    {}

    /// The escape-hatch decision, exposed for the proof.
    function isEscapeCall(address safe, address to, uint256 value, bytes memory data, Enum.Operation operation)
        external
        view
        returns (bool)
    {
        return _isEmergencyEscapeCall(safe, to, value, data, operation);
    }

    function isDenied(bytes4 selector) external pure returns (bool) {
        return _isDeniedSelector(selector);
    }

    // ── Seeding: the proofs start from an arbitrary but well-formed state ───
    // Creation and consumption run signature and XMSS verification, which these
    // lemmas abstract; the state they would produce is written directly instead.

    function seedEnrollment(address safe, bool enrolled) external {
        enrolledSafe[safe] = enrolled;
    }

    function seedPause(address safe, bool paused, uint64 unpauseAt, uint64 cooldownUntil) external {
        safePaused[safe] = paused;
        safeUnpauseExecutableAt[safe] = unpauseAt;
        safePauseCooldownUntil[safe] = cooldownUntil;
    }

    function seedDeGuard(address safe, uint64 executableAt) external {
        emergencyDeGuardExecutableAt[safe] = executableAt;
    }

    function seedKey(address safe, bytes32 keyId, address admin, KeyStatus status) external {
        safeToQuantumKey[safe] = keyId;
        _keys[keyId].quantumKeyId = keyId;
        _keys[keyId].safe = safe;
        _keys[keyId].quantumAdmin = admin;
        _keys[keyId].status = status;
    }

    function seedApproval(
        bytes32 id,
        address safe,
        ApprovalClass class_,
        bytes32 keyId,
        uint64 validFrom,
        uint64 validTo,
        bool used,
        bool revoked
    ) external {
        PreApproval storage a = _approvals[id];
        a.id = id;
        a.safe = safe;
        a.class_ = class_;
        a.quantumKeyId = keyId;
        a.validFrom = validFrom;
        a.validTo = validTo;
        a.used = used;
        a.revoked = revoked;
    }

    /// Write a whole approval record, so every matchable field is symbolic.
    function seedFullApproval(PreApproval memory a) external {
        _approvals[a.id] = a;
    }

    function seedPin(address safe, bytes32 txHash, bytes32 id) external {
        approvalByTxHash[safe][txHash] = id;
    }

    function seedQueued(bytes32 commitment, bytes32 id) external {
        _queue[commitment].pushBack(id);
    }

    function seedAllowedSelector(address safe, bytes4 selector) external {
        allowedSelectors[safe][selector] = true;
    }

    function queueLength(bytes32 commitment) external view returns (uint256) {
        return _queue[commitment].length();
    }

    function commitmentOf(PreApproval memory a) external pure returns (bytes32) {
        return _commitment(a);
    }

    /// The Guard-internal consumption step, exposed so the lemmas can drive it directly:
    /// reaching it through `createPreApproval` would need an XMSS verification.
    function consume(address safe, bytes32 safeTxHash, PreApproval memory expected) external returns (bytes32) {
        return _consumeMatching(safe, safeTxHash, expected);
    }

    function pauseStateOf(address safe) external view returns (bool, uint64, uint64) {
        return (safePaused[safe], safeUnpauseExecutableAt[safe], safePauseCooldownUntil[safe]);
    }
}

/// @title FermionGuard and PreApprovalEngine checked against their specification
/// @notice `check_*` functions are symbolic proofs run by Halmos. A PASS means the
///         property holds for every value of that function's arguments — but the
///         arguments are the scope: where a lemma fixes a target, a payload or a
///         timestamp to a constant, it says so in its own doc comment, and the
///         contract's authorization and signature checks are replaced throughout by
///         the permissive mocks above. What is and is not covered, including the parts
///         of these contracts no lemma reaches at all, is listed in README.md.
///
///         halmos --match-contract GuardEquivalence --loop 32 --solver-timeout-assertion 0
contract GuardEquivalence is Test {
    uint64 constant ADMIN_TIMELOCK = 2 days;
    uint64 constant EMERGENCY_TIMELOCK = 14 days;
    uint32 constant MAX_LEGS = 8;
    uint32 constant MAX_QUEUE = 16;

    GuardHarness guard;
    PermissiveSafe safeContract;
    address safe;

    function setUp() public {
        guard = new GuardHarness(address(new MultiSendStub()), ADMIN_TIMELOCK, EMERGENCY_TIMELOCK, MAX_LEGS, MAX_QUEUE);
        safeContract = new PermissiveSafe();
        safe = address(safeContract);
    }

    // ── Lemma 1: the escape hatch admits exactly the documented calls ──────

    /// For every target, value, operation, stored state and 4-byte call to the Guard,
    /// the Guard's escape-hatch decision equals the specification's.
    function check_escapeHatch_guardCalls4(bytes4 selector, uint256 value, bool enrolled, uint64 deGuardAt, uint64 nowTs, bool isCall)
        public
    {
        vm.warp(nowTs);
        guard.seedEnrollment(safe, enrolled);
        guard.seedDeGuard(safe, deGuardAt);
        bytes memory data = abi.encodePacked(selector);
        Enum.Operation op = isCall ? Enum.Operation.Call : Enum.Operation.DelegateCall;

        bool got = guard.isEscapeCall(safe, address(guard), value, data, op);
        bool want = GuardSpec.isEscapeCall(
            GuardSpec.EscapeState(enrolled, deGuardAt, nowTs), address(guard), safe, address(guard), value, data, op
        );
        assertEq(got, want, "4-byte call to the Guard");
    }

    /// The same for the 36-byte (one-argument) safety calls.
    function check_escapeHatch_guardCalls36(bytes4 selector, bytes32 arg, uint256 value, bool enrolled, uint64 deGuardAt, uint64 nowTs)
        public
    {
        vm.warp(nowTs);
        guard.seedEnrollment(safe, enrolled);
        guard.seedDeGuard(safe, deGuardAt);
        bytes memory data = abi.encodePacked(selector, arg);

        bool got = guard.isEscapeCall(safe, address(guard), value, data, Enum.Operation.Call);
        bool want = GuardSpec.isEscapeCall(
            GuardSpec.EscapeState(enrolled, deGuardAt, nowTs),
            address(guard),
            safe,
            address(guard),
            value,
            data,
            Enum.Operation.Call
        );
        assertEq(got, want, "36-byte call to the Guard");
    }

    /// The `setGuard` self-call path, including padded calldata: only detaching, and
    /// only when the Safe never enrolled or the emergency time lock has matured.
    function check_escapeHatch_setGuard(bytes32 argWord, uint256 value, bool enrolled, uint64 deGuardAt, uint64 nowTs, bool padded)
        public
    {
        vm.warp(nowTs);
        guard.seedEnrollment(safe, enrolled);
        guard.seedDeGuard(safe, deGuardAt);
        bytes memory data = padded
            ? abi.encodePacked(GuardSpec.SET_GUARD, argWord, bytes32(0))
            : abi.encodePacked(GuardSpec.SET_GUARD, argWord);

        bool got;
        try guard.isEscapeCall(safe, safe, value, data, Enum.Operation.Call) returns (bool r) {
            got = r;
        } catch {
            // A non-canonical address word makes the Guard's abi.decode revert; the
            // specification calls that "not an escape call", and a revert in
            // checkTransaction blocks the transaction, which is the same outcome.
            assertFalse(GuardSpec.isCanonicalAddressWord(data, 4), "only dirty address bits may revert");
            return;
        }
        bool want = GuardSpec.isEscapeCall(
            GuardSpec.EscapeState(enrolled, deGuardAt, nowTs), address(guard), safe, safe, value, data, Enum.Operation.Call
        );
        assertEq(got, want, "setGuard self-call");
    }

    /// No call to any third party ever escapes, whatever its calldata.
    function check_escapeHatch_thirdPartyNeverEscapes(address to, bytes32 word, uint256 value, bool enrolled, uint64 deGuardAt, uint64 nowTs)
        public
    {
        vm.assume(to != address(guard) && to != safe);
        vm.warp(nowTs);
        guard.seedEnrollment(safe, enrolled);
        guard.seedDeGuard(safe, deGuardAt);
        bytes memory data = abi.encodePacked(GuardSpec.SET_GUARD, word);
        try guard.isEscapeCall(safe, to, value, data, Enum.Operation.Call) returns (bool got) {
            assertFalse(got, "a third-party call escaped the Guard");
        } catch {} // a revert blocks the transaction: also not an escape
    }

    // ── Lemma 2: the deny-list can never be permitted ──────────────────────

    /// The four denied selectors are exactly the specification's, and
    /// `setSelectorPolicy` refuses every one of them however it is called.
    function check_deniedSelectors(bytes4 selector, bool allow) public {
        assertEq(guard.isDenied(selector), GuardSpec.isDeniedSelector(selector), "deny-list membership");
        vm.prank(safe);
        try guard.setSelectorPolicy(safe, selector, allow) {
            assertFalse(GuardSpec.isDeniedSelector(selector), "a denied selector was accepted");
            assertEq(guard.allowedSelectors(safe, selector), allow, "the permit-list records the change");
        } catch {
            assertTrue(GuardSpec.isDeniedSelector(selector), "a permitted selector was refused");
        }
    }

    /// Only the Safe itself may change its permit-list.
    function check_selectorPolicyOnlySafe(address caller, bytes4 selector, bool allow) public {
        vm.assume(caller != safe);
        vm.assume(!GuardSpec.isDeniedSelector(selector));
        bool before = guard.allowedSelectors(safe, selector);
        vm.prank(caller);
        try guard.setSelectorPolicy(safe, selector, allow) {
            fail("a stranger changed the permit-list");
        } catch {}
        assertEq(guard.allowedSelectors(safe, selector), before, "the permit-list is unchanged");
    }

    // ── Lemma 3: pause, request unpause, unpause ───────────────────────────

    function check_pause(address caller, bool enrolled, bool paused, uint64 unpauseAt, uint64 cooldownUntil, uint64 nowTs)
        public
    {
        vm.warp(nowTs);
        guard.seedEnrollment(safe, enrolled);
        guard.seedPause(safe, paused, unpauseAt, cooldownUntil);
        GuardSpec.PauseState memory s = GuardSpec.PauseState(enrolled, paused, unpauseAt, cooldownUntil, nowTs);
        // The Safe mock says everyone is an owner, so any caller other than the Safe
        // is exactly the "single-key actor" case.
        bool want = GuardSpec.canPause(s, caller == safe, true);

        vm.prank(caller);
        bool ok;
        try guard.pauseSafe(safe) {
            ok = true;
        } catch {
            ok = false;
        }
        assertEq(ok, want, "pause succeeded exactly when the specification allows");
        (bool nowPaused,, uint64 cooldownAfter) = guard.pauseStateOf(safe);
        assertEq(nowPaused, ok ? true : paused, "paused flag");
        assertEq(cooldownAfter, cooldownUntil, "a pause never moves the cooldown");
    }

    /// A re-pause never cancels a pending owner-threshold unpause.
    function check_pauseNeverCancelsPendingUnpause(address caller, uint64 unpauseAt, uint64 cooldownUntil, uint64 nowTs) public {
        vm.warp(nowTs);
        guard.seedEnrollment(safe, true);
        guard.seedPause(safe, true, unpauseAt, cooldownUntil);
        vm.prank(caller);
        try guard.pauseSafe(safe) {} catch {}
        (, uint64 after_,) = guard.pauseStateOf(safe);
        assertEq(after_, unpauseAt, "the pending unpause survives a re-pause");
    }

    function check_requestUnpause(address caller, bool paused, uint64 unpauseAt, uint64 nowTs) public {
        vm.warp(nowTs);
        vm.assume(uint256(nowTs) + ADMIN_TIMELOCK <= type(uint64).max);
        guard.seedEnrollment(caller, true);
        guard.seedPause(caller, paused, unpauseAt, 0);
        GuardSpec.PauseState memory s = GuardSpec.PauseState(true, paused, unpauseAt, 0, nowTs);

        vm.prank(caller);
        bool ok;
        try guard.requestUnpauseSafe() {
            ok = true;
        } catch {
            ok = false;
        }
        assertEq(ok, GuardSpec.canRequestUnpause(s, true), "request succeeded exactly when the spec allows");
        if (ok) {
            (, uint64 execAt,) = guard.pauseStateOf(caller);
            assertEq(execAt, uint64(nowTs) + ADMIN_TIMELOCK, "the unpause delay runs from now");
        }
    }

    function check_unpause(address caller, bool paused, uint64 unpauseAt, uint64 cooldownUntil, uint64 nowTs) public {
        vm.warp(nowTs);
        vm.assume(uint256(nowTs) + ADMIN_TIMELOCK <= type(uint64).max);
        guard.seedEnrollment(caller, true);
        guard.seedPause(caller, paused, unpauseAt, cooldownUntil);
        GuardSpec.PauseState memory s = GuardSpec.PauseState(true, paused, unpauseAt, cooldownUntil, nowTs);

        vm.prank(caller);
        bool ok;
        try guard.unpauseSafe() {
            ok = true;
        } catch {
            ok = false;
        }
        assertEq(ok, GuardSpec.canUnpause(s, true), "unpause succeeded exactly when the spec allows");
        if (ok) {
            GuardSpec.PauseState memory want = GuardSpec.afterUnpause(s, ADMIN_TIMELOCK);
            (bool p, uint64 execAt, uint64 cd) = guard.pauseStateOf(caller);
            assertEq(p, want.paused, "no longer paused");
            assertEq(execAt, want.unpauseExecutableAt, "the request is cleared");
            assertEq(cd, want.cooldownUntil, "the cooldown starts now");
        }
    }

    // ── Lemma 4: emergency de-guard ────────────────────────────────────────

    function check_requestEmergencyDeGuard(address caller, bool enrolled, uint64 nowTs) public {
        vm.warp(nowTs);
        vm.assume(uint256(nowTs) + EMERGENCY_TIMELOCK <= type(uint64).max);
        guard.seedEnrollment(caller, enrolled);
        uint64 before = guard.emergencyDeGuardExecutableAt(caller);

        vm.prank(caller);
        bool ok;
        try guard.requestEmergencyDeGuard() {
            ok = true;
        } catch {
            ok = false;
        }
        assertEq(ok, enrolled, "only an enrolled Safe may request");
        assertEq(
            guard.emergencyDeGuardExecutableAt(caller),
            ok ? uint64(nowTs) + EMERGENCY_TIMELOCK : before,
            "the delay runs from now"
        );
    }

    /// Only the Safe may cancel: a stolen Administrator key must not be able to veto
    /// the owners' emergency removal.
    function check_cancelEmergencyDeGuardOnlySafe(address caller, uint64 deGuardAt) public {
        vm.assume(caller != safe);
        guard.seedDeGuard(safe, deGuardAt);
        vm.prank(caller);
        try guard.cancelEmergencyDeGuard(safe) {
            fail("a non-Safe caller cancelled the emergency de-guard");
        } catch {}
        assertEq(guard.emergencyDeGuardExecutableAt(safe), deGuardAt, "the request is untouched");
    }

    // ── Lemma 5: the pre-approval lifecycle ────────────────────────────────

    /// `validatePreApproval` agrees with the specification's consumable/dead rules for
    /// every stored approval, key status and timestamp.
    function check_approvalLifecycle(
        bytes32 id,
        uint64 validFrom,
        uint64 validTo,
        bool used,
        bool revoked,
        uint8 keyStatusRaw,
        uint64 nowTs
    ) public {
        vm.assume(id != bytes32(0));
        vm.assume(keyStatusRaw < 4);
        vm.warp(nowTs);
        bytes32 keyId = keccak256("key");
        QuantumKeyRegistry.KeyStatus status = QuantumKeyRegistry.KeyStatus(keyStatusRaw);
        guard.seedKey(safe, keyId, address(0xA11CE), status);
        guard.seedApproval(id, safe, PreApprovalEngine.ApprovalClass.TRANSFER, keyId, validFrom, validTo, used, revoked);

        bool keyUsable = status == QuantumKeyRegistry.KeyStatus.Active || status == QuantumKeyRegistry.KeyStatus.Rotated;
        GuardSpec.ApprovalState memory a = GuardSpec.ApprovalState(true, used, revoked, validFrom, validTo, keyUsable);

        (bool valid,) = guard.validatePreApproval(id);
        assertEq(valid, GuardSpec.isConsumable(a, nowTs), "validate agrees with the specification");
        // Consumable and dead are mutually exclusive, and a not-yet-valid approval is
        // neither: this is what makes queue pruning safe.
        assertFalse(GuardSpec.isConsumable(a, nowTs) && GuardSpec.isDead(a, nowTs), "consumable and dead overlap");
    }

    /// Once dead, always dead — stated about the CONTRACT's verdict, at every timestamp.
    ///
    /// The original form of this lemma quantified over a pair of times (`dead at t1`
    /// implies `not valid at any t2 >= t1`) and would not terminate: Halmos ran 55
    /// minutes on it, and still over 7 minutes after its symbolic approval id was made
    /// concrete. It is stated here in the equivalent single-timestamp form, which runs
    /// in under a second. The two are equivalent because each of the four ways an
    /// approval dies is either time-independent (`used`, `revoked`, the key revoked —
    /// none of which any later block can undo) or already monotone in time (`t > validTo`
    /// stays true as `t` grows). So "the contract refuses every dead approval, at every
    /// timestamp" is exactly "a dead approval never becomes valid later".
    function check_deadIsNeverValid(
        uint64 validFrom,
        uint64 validTo,
        bool used,
        bool revoked,
        uint8 keyStatusRaw,
        uint64 nowTs
    ) public {
        vm.assume(keyStatusRaw < 4);
        vm.warp(nowTs);
        bytes32 id = keccak256("fermionguard.proof.dead");
        bytes32 keyId = keccak256("key");
        QuantumKeyRegistry.KeyStatus status = QuantumKeyRegistry.KeyStatus(keyStatusRaw);
        guard.seedKey(safe, keyId, address(0xA11CE), status);
        guard.seedApproval(id, safe, PreApprovalEngine.ApprovalClass.TRANSFER, keyId, validFrom, validTo, used, revoked);
        bool keyUsable = status == QuantumKeyRegistry.KeyStatus.Active || status == QuantumKeyRegistry.KeyStatus.Rotated;

        (bool valid,) = guard.validatePreApproval(id);
        if (GuardSpec.isDead(GuardSpec.ApprovalState(true, used, revoked, validFrom, validTo, keyUsable), nowTs)) {
            assertFalse(valid, "the engine called an approval valid that can never be consumable again");
        }
    }

    /// Once dead, always dead — and both verdicts come from the CONTRACT: the engine
    /// itself diagnoses the approval as permanently dead at `t1` (any refusal other than
    /// "not yet valid"), and the engine itself is asked again at any later `t2`.
    ///
    /// Needs `--solver z3`. Halmos 0.3.3's bundled default, yices-smt2, does not
    /// terminate on this lemma's queries — it ran 55 minutes here without an answer,
    /// which is indistinguishable from a proof in progress. z3 answers in under a
    /// second. The same applies to the whole file; see README.md.
    function check_deadIsMonotone(
        uint64 validFrom,
        uint64 validTo,
        bool used,
        bool revoked,
        uint8 keyStatusRaw,
        uint64 t1,
        uint64 t2
    ) public {
        vm.assume(keyStatusRaw < 4);
        vm.assume(t1 <= t2);
        bytes32 id = keccak256("fermionguard.proof.monotone");
        bytes32 keyId = keccak256("key");
        guard.seedKey(safe, keyId, address(0xA11CE), QuantumKeyRegistry.KeyStatus(keyStatusRaw));
        guard.seedApproval(id, safe, PreApprovalEngine.ApprovalClass.TRANSFER, keyId, validFrom, validTo, used, revoked);

        vm.warp(t1);
        (bool validAtT1, string memory why) = guard.validatePreApproval(id);
        // "not yet valid" is the one refusal a later block can undo; every other refusal
        // the engine gives — used, revoked, expired, key revoked — must be permanent.
        bool permanentlyDead = !validAtT1 && keccak256(bytes(why)) != keccak256(bytes("not yet valid"));
        vm.warp(t2);
        (bool validAtT2,) = guard.validatePreApproval(id);
        if (permanentlyDead) assertFalse(validAtT2, "an approval the engine called dead became valid later");
    }

    /// Revocation authorization: the Safe, the key's Administrator, or any single
    /// owner — and never a single owner against an ADMIN approval.
    function check_revokeAuthorization(bytes32 id, uint8 classRaw, bool used, bool revoked, uint64 validFrom, uint64 validTo, bool callerIsSafe, bool callerIsAdmin)
        public
    {
        vm.assume(id != bytes32(0));
        vm.assume(classRaw < 3);
        bytes32 keyId = keccak256("key");
        address admin = address(0xA11CE);
        address owner = address(0x011E5);
        guard.seedKey(safe, keyId, admin, QuantumKeyRegistry.KeyStatus.Active);
        PreApprovalEngine.ApprovalClass class_ = PreApprovalEngine.ApprovalClass(classRaw);
        guard.seedApproval(id, safe, class_, keyId, validFrom, validTo, used, revoked);

        address caller = callerIsSafe ? safe : (callerIsAdmin ? admin : owner);
        GuardSpec.ApprovalState memory a = GuardSpec.ApprovalState(true, used, revoked, validFrom, validTo, true);
        bool want = GuardSpec.canRevoke(
            a,
            caller == safe,
            caller == admin,
            true, // the Safe mock treats every address as an owner
            class_ == PreApprovalEngine.ApprovalClass.ADMIN
        );

        vm.prank(caller);
        bool ok;
        try guard.revokePreApproval(id) {
            ok = true;
        } catch {
            ok = false;
        }
        assertEq(ok, want, "revocation succeeded exactly when the specification allows");
        if (ok) {
            (bool stillValid,) = guard.validatePreApproval(id);
            assertFalse(stillValid, "a revoked approval is not valid");
        }
    }

    /// An unknown approval id can never be revoked.
    function check_revokeUnknown(bytes32 id, address caller) public {
        vm.prank(caller);
        try guard.revokePreApproval(id) {
            fail("an unknown approval was revoked");
        } catch {}
    }

    // ── Lemma 6: consumption — matching, one-shot, and the two tiers ────────
    //
    // `_consumeMatching` is the only place an approval is ever spent. Creation runs a
    // full XMSS verification, which symbolic execution cannot carry, so these lemmas
    // drive consumption directly over stored state written by the harness. Everything
    // asserted is the CONTRACT's behaviour; the specification only supplies the
    // predicate it is compared against.

    bytes32 constant KEY_ID = keccak256("fermionguard.proof.key");
    address constant ADMIN = address(0xA11CE);
    bytes32 constant PINNED_ID = keccak256("fermionguard.proof.pinned");
    bytes32 constant PIN_HASH = keccak256("fermionguard.proof.pin");

    function _activate() internal {
        guard.seedEnrollment(safe, true);
        guard.seedKey(safe, KEY_ID, ADMIN, QuantumKeyRegistry.KeyStatus.Active);
    }

    /// A TRANSFER-class approval record, every matchable field a parameter.
    function _transfer(
        bytes32 id,
        address token,
        address recipient,
        uint256 amount,
        uint64 validFrom,
        uint64 validTo,
        bool used,
        bool revoked
    ) internal view returns (PreApprovalEngine.PreApproval memory a) {
        a.id = id;
        a.safe = safe;
        a.class_ = PreApprovalEngine.ApprovalClass.TRANSFER;
        a.token = token;
        a.recipient = recipient;
        a.amount = amount;
        a.validFrom = validFrom;
        a.validTo = validTo;
        a.used = used;
        a.revoked = revoked;
        a.quantumKeyId = KEY_ID;
    }

    /// What the dispatcher would hand `_consumeMatching` for an ERC-20 transfer.
    function _expectTransfer(address token, address recipient, uint256 amount)
        internal
        view
        returns (PreApprovalEngine.PreApproval memory e)
    {
        e.safe = safe;
        e.class_ = PreApprovalEngine.ApprovalClass.TRANSFER;
        e.token = token;
        e.recipient = recipient;
        e.amount = amount;
    }

    /// A pinned approval is consumed exactly when it is live AND every bound field —
    /// token, recipient, amount — matches the transaction, and consuming it marks it
    /// used. The validity window is proven at its boundaries too: `nowTs`, `validFrom`
    /// and `validTo` are all symbolic, so `>=`/`>` and `<=`/`<` are pinned down.
    function check_consumeRequiresExactFieldMatch(
        address token,
        address recipient,
        uint256 amount,
        address wantToken,
        address wantRecipient,
        uint256 wantAmount,
        uint64 validFrom,
        uint64 validTo,
        bool used,
        bool revoked,
        uint64 nowTs
    ) public {
        vm.warp(nowTs);
        _activate();
        guard.seedFullApproval(_transfer(PINNED_ID, token, recipient, amount, validFrom, validTo, used, revoked));
        guard.seedPin(safe, PIN_HASH, PINNED_ID);

        bool live = !used && !revoked && nowTs >= validFrom && nowTs <= validTo;
        bool fieldsMatch = token == wantToken && recipient == wantRecipient && amount == wantAmount;

        PreApprovalEngine.PreApproval memory e = _expectTransfer(wantToken, wantRecipient, wantAmount);
        // Nothing is queued under `e`'s commitment, so Tier 2 has nothing to offer: the
        // outcome is the Tier-1 decision alone.
        try guard.consume(safe, PIN_HASH, e) returns (bytes32 got) {
            assertTrue(live && fieldsMatch, "consumed without a live, exactly matching approval");
            assertEq(got, PINNED_ID, "the pinned approval is the one consumed");
            assertTrue(guard.getPreApproval(PINNED_ID).used, "consumption marks the approval used");
        } catch {
            assertFalse(live && fieldsMatch, "a live, exactly matching approval was refused");
        }
    }

    /// An approval is consumed at most once, on either tier and at any later time: the
    /// second attempt always fails and the `used` flag never clears.
    function check_consumedAtMostOnce(
        address token,
        address recipient,
        uint256 amount,
        uint64 validFrom,
        uint64 validTo,
        uint64 t1,
        uint64 t2,
        bool pinned
    ) public {
        vm.assume(t1 <= t2);
        _activate();
        guard.seedFullApproval(_transfer(PINNED_ID, token, recipient, amount, validFrom, validTo, false, false));
        PreApprovalEngine.PreApproval memory e = _expectTransfer(token, recipient, amount);
        bytes32 txHash;
        if (pinned) {
            txHash = PIN_HASH;
            guard.seedPin(safe, PIN_HASH, PINNED_ID);
        } else {
            guard.seedQueued(guard.commitmentOf(e), PINNED_ID);
        }

        vm.warp(t1);
        try guard.consume(safe, txHash, e) returns (bytes32 got) {
            assertEq(got, PINNED_ID, "the only approval is the one consumed");
        } catch {
            return; // nothing was spent, so there is no double spend to rule out
        }
        assertTrue(guard.getPreApproval(PINNED_ID).used, "the first consumption marks it used");

        vm.warp(t2);
        try guard.consume(safe, txHash, e) {
            fail("the same approval was consumed twice");
        } catch {}
        assertTrue(guard.getPreApproval(PINNED_ID).used, "a consumed approval stays consumed");
    }

    /// The Tier-1 pin binds ONE specific Safe transaction hash, and it is authoritative:
    /// two live, field-identical approvals pinned at different hashes, both also sitting
    /// in the Tier-2 queue, and consumption spends the one pinned at THIS hash — not the
    /// queue's front, not the other pin.
    function check_pinSelectsExactlyItsOwnApproval(
        bytes32 otherHash,
        address token,
        address recipient,
        uint256 amount,
        uint64 validFrom,
        uint64 validTo,
        uint64 nowTs,
        bool useOther
    ) public {
        vm.assume(otherHash != PIN_HASH);
        vm.assume(validFrom <= nowTs && nowTs <= validTo); // both approvals live
        vm.warp(nowTs);
        _activate();
        bytes32 first = keccak256("pinned.first");
        bytes32 second = keccak256("pinned.second");
        guard.seedFullApproval(_transfer(first, token, recipient, amount, validFrom, validTo, false, false));
        guard.seedFullApproval(_transfer(second, token, recipient, amount, validFrom, validTo, false, false));
        guard.seedPin(safe, PIN_HASH, first);
        guard.seedPin(safe, otherHash, second);

        PreApprovalEngine.PreApproval memory e = _expectTransfer(token, recipient, amount);
        bytes32 c = guard.commitmentOf(e);
        guard.seedQueued(c, first); // both are reachable on Tier 2 as well, in this order
        guard.seedQueued(c, second);

        bytes32 got = guard.consume(safe, useOther ? otherHash : PIN_HASH, e);
        assertEq(got, useOther ? second : first, "the pin did not select the approval pinned at this safeTxHash");
        assertFalse(guard.getPreApproval(useOther ? first : second).used, "the other approval was spent instead");
    }

    /// Tier 2 is FIFO: with three identical-commitment approvals queued, consumption
    /// takes the FIRST live one in queue order — never a later one, never a dead one —
    /// and never leaves the queue longer than it found it.
    function check_queueIsFifoAndNeverGrows(
        address token,
        address recipient,
        uint256 amount,
        uint64 nowTs,
        uint64 from0,
        uint64 to0,
        bool revoked0,
        uint64 from1,
        uint64 to1,
        bool revoked1,
        uint64 from2,
        uint64 to2,
        bool revoked2
    ) public {
        vm.warp(nowTs);
        _activate();
        bytes32[3] memory ids = [keccak256("q0"), keccak256("q1"), keccak256("q2")];
        uint64[3] memory from = [from0, from1, from2];
        uint64[3] memory to = [to0, to1, to2];
        bool[3] memory revoked = [revoked0, revoked1, revoked2];

        PreApprovalEngine.PreApproval memory e = _expectTransfer(token, recipient, amount);
        bytes32 c = guard.commitmentOf(e);
        for (uint256 i = 0; i < 3; ++i) {
            guard.seedFullApproval(_transfer(ids[i], token, recipient, amount, from[i], to[i], false, revoked[i]));
            guard.seedQueued(c, ids[i]);
        }
        uint256 lengthBefore = guard.queueLength(c);

        // The specification's answer: the first live entry in queue order, or 3 for none.
        uint256 firstLive = 3;
        for (uint256 i = 0; i < 3; ++i) {
            if (!revoked[i] && nowTs >= from[i] && nowTs <= to[i]) {
                firstLive = i;
                break;
            }
        }

        try guard.consume(safe, bytes32(0), e) returns (bytes32 got) {
            assertLt(firstLive, 3, "consumed although no queued approval was live");
            assertEq(got, ids[firstLive], "not FIFO: a later approval was consumed over an earlier live one");
            assertTrue(guard.getPreApproval(got).used, "the consumed entry is marked used");
        } catch {
            assertEq(firstLive, 3, "a live queued approval was skipped");
        }
        assertLe(guard.queueLength(c), lengthBefore, "consumption never grows the queue");
    }

    // ── Lemma 7: time locks never shorten ──────────────────────────────────

    /// Both Guard time locks are armed from the present, so re-requesting can only ever
    /// move the deadline later — there is no way to shorten a pending unpause or a
    /// pending emergency de-guard.
    function check_unpauseTimelockNeverShortens(uint64 t1, uint64 t2) public {
        vm.assume(t1 <= t2);
        vm.assume(uint256(t2) + ADMIN_TIMELOCK <= type(uint64).max);
        guard.seedEnrollment(safe, true);
        guard.seedPause(safe, true, 0, 0);

        vm.warp(t1);
        vm.prank(safe);
        guard.requestUnpauseSafe();
        (, uint64 first,) = guard.pauseStateOf(safe);

        vm.warp(t2);
        vm.prank(safe);
        guard.requestUnpauseSafe();
        (, uint64 second,) = guard.pauseStateOf(safe);
        assertGe(second, first, "a re-request moved the unpause deadline earlier");
    }

    function check_emergencyTimelockNeverShortens(uint64 t1, uint64 t2) public {
        vm.assume(t1 <= t2);
        vm.assume(uint256(t2) + EMERGENCY_TIMELOCK <= type(uint64).max);
        guard.seedEnrollment(safe, true);

        vm.warp(t1);
        vm.prank(safe);
        guard.requestEmergencyDeGuard();
        uint64 first = guard.emergencyDeGuardExecutableAt(safe);

        vm.warp(t2);
        vm.prank(safe);
        guard.requestEmergencyDeGuard();
        assertGe(guard.emergencyDeGuardExecutableAt(safe), first, "a re-request moved the de-guard deadline earlier");
    }

    // ── Lemma 8: checkTransaction, the enforcement path itself ─────────────

    function _checkTransaction(address to, uint256 value, bytes memory data, Enum.Operation op, uint256 gasPrice)
        internal
        returns (bool ok, bytes memory ret)
    {
        vm.prank(safe);
        (ok, ret) = address(guard).call(
            abi.encodeWithSelector(
                FermionGuard.checkTransaction.selector,
                to,
                value,
                data,
                op,
                uint256(0), // safeTxGas
                uint256(0), // baseGas
                gasPrice,
                address(0), // gasToken
                address(0), // refundReceiver
                bytes(""), // signatures — the Safe already validated them
                address(0) // msgSender
            )
        );
    }

    /// The gas-refund ban is step 0 and unconditional: a non-zero `gasPrice` is refused
    /// with `GasRefundForbidden` for every target, value, operation and payload — the
    /// escape hatch included, so no owner safety call can be turned into a token drain.
    function check_gasRefundBanned(address to, uint256 value, bytes4 selector, address arg, uint256 gasPrice, bool isCall)
        public
    {
        vm.assume(gasPrice != 0);
        _activate();
        bytes memory data = abi.encodePacked(selector, bytes32(uint256(uint160(arg))));
        (bool ok, bytes memory ret) =
            _checkTransaction(to, value, data, isCall ? Enum.Operation.Call : Enum.Operation.DelegateCall, gasPrice);
        assertFalse(ok, "a gas-refunding transaction was allowed");
        assertEq(bytes4(ret), FermionGuard.GasRefundForbidden.selector, "blocked, but for the wrong reason");
    }

    /// A paused Safe executes nothing except the escape hatch and the quantum-approved
    /// `setGuard(0)` — and it is the pause that stops it, not some later check.
    function check_pauseBlocksAllButDeGuard(address to, uint256 value, bytes4 selector, address arg, uint64 nowTs, bool isCall)
        public
    {
        vm.warp(nowTs);
        _activate();
        guard.seedPause(safe, true, 0, 0);
        bytes memory data = abi.encodePacked(selector, bytes32(uint256(uint160(arg))));
        Enum.Operation op = isCall ? Enum.Operation.Call : Enum.Operation.DelegateCall;

        bool escape = guard.isEscapeCall(safe, to, value, data, op);
        bool deGuard =
            to == safe && op == Enum.Operation.Call && value == 0 && selector == GuardSpec.SET_GUARD && arg == address(0);

        (bool ok, bytes memory ret) = _checkTransaction(to, value, data, op, 0);
        if (escape) {
            assertTrue(ok, "the escape hatch was blocked by the pause");
        } else if (!deGuard) {
            assertFalse(ok, "a paused Safe executed an ordinary transaction");
            assertEq(bytes4(ret), FermionGuard.SafePausedError.selector, "blocked, but not by the pause");
        }
    }

    /// The headline property of the whole Guard, as an iff: with NO approval anywhere in
    /// the Guard's storage, `checkTransaction` admits **exactly** the escape-hatch calls
    /// and nothing else — every other transaction is refused, and every escape call is
    /// let through. Target, value, payload shape, selector, argument and timestamp are
    /// symbolic, and the Safe's permit-list is opened for the symbolic selector so that
    /// it is the missing approval, not the policy, doing the refusing.
    ///
    /// Together with lemma 6 (an approval is spent only on a live, exact field match,
    /// and consuming it marks it used) this is "nothing executes without consuming a
    /// matching approval, except the documented escape-hatch calls".
    function check_nothingExecutesWithoutAnApproval(
        address to,
        uint256 value,
        uint8 shape,
        bytes4 selector,
        address arg,
        uint256 word,
        uint64 nowTs
    ) public {
        vm.assume(shape < 3);
        vm.warp(nowTs);
        _activate();
        guard.seedAllowedSelector(safe, selector);

        bytes memory data;
        if (shape == 1) data = abi.encodePacked(selector, bytes32(uint256(uint160(arg))));
        else if (shape == 2) data = abi.encodePacked(selector, bytes32(uint256(uint160(arg))), bytes32(word));
        // shape == 0: empty calldata, the bare native-value send

        // Plain CALLs only. With `DelegateCall` in scope this lemma reaches
        // `_checkBatchLegs`, whose `abi.decode(Bytes.slice(data, 4), (bytes))` reads
        // memory at an offset taken from the symbolic payload; Halmos 0.3.3 aborts there
        // with `NotConcreteError: symbolic memory offset`, under either solver. The
        // delegatecall branch is covered instead by `check_delegateCallOnlyToMultiSend`.
        bool escape = guard.isEscapeCall(safe, to, value, data, Enum.Operation.Call);
        (bool ok,) = _checkTransaction(to, value, data, Enum.Operation.Call, 0);
        assertEq(ok, escape, "the Guard admits exactly the escape hatch when nothing is approved");
    }

    /// The same enforcement path, driven the other way — the lemma that makes the one
    /// above non-vacuous by exercising `checkTransaction`'s success path end to end. A
    /// bare native-value send to a third party, matched by a PAYLOAD approval reachable
    /// on either tier: the transaction goes through exactly while that approval is live,
    /// and executing it is the only thing that ever spends it.
    ///
    /// The validity window, the timestamp and the tier are symbolic; the target and the
    /// value are constants. A variant with the target, the value and the approval class
    /// symbolic as well was measured and also passes — 203 paths, 12.4 s under
    /// `--solver z3` — but it is by far the heaviest lemma in the file and did not
    /// reliably finish inside a whole-file run on a loaded machine, so the deterministic
    /// form is the one kept here. The mutation evidence in planted-bugs.md is for this
    /// form: deleting `a.used = true` from `_markUsed` breaks it.
    function check_executionConsumesTheApproval(uint64 validFrom, uint64 validTo, uint64 nowTs, bool pinned) public {
        address payee = address(0xBEEF);
        vm.warp(nowTs);
        _activate();

        PreApprovalEngine.PreApproval memory a;
        a.id = PINNED_ID;
        a.safe = safe;
        a.class_ = PreApprovalEngine.ApprovalClass.PAYLOAD;
        a.target = payee;
        a.value = 1 ether;
        a.dataHash = keccak256("");
        a.validFrom = validFrom;
        a.validTo = validTo;
        a.quantumKeyId = KEY_ID;
        guard.seedFullApproval(a);
        if (pinned) guard.seedPin(safe, safeContract.TX_HASH(), PINNED_ID);
        else guard.seedQueued(guard.commitmentOf(a), PINNED_ID);

        (bool ok,) = _checkTransaction(payee, 1 ether, "", Enum.Operation.Call, 0);
        bool live = nowTs >= validFrom && nowTs <= validTo;
        assertEq(ok, live, "the transaction executed exactly while its approval was live");
        assertEq(guard.getPreApproval(PINNED_ID).used, live, "execution spends the approval, nothing else does");
    }

    /// The only delegatecall a guarded Safe may make is to the pinned MultiSendCallOnly:
    /// every other target is refused with `DelegateCallForbidden`, whatever the payload.
    function check_delegateCallOnlyToMultiSend(address to, uint256 value, bytes4 selector, address arg, uint64 nowTs)
        public
    {
        vm.assume(to != guard.MULTISEND_CALL_ONLY());
        vm.warp(nowTs);
        _activate();
        bytes memory data = abi.encodePacked(selector, bytes32(uint256(uint160(arg))));
        // A delegatecall is never an escape call (those must be plain CALLs), so the
        // Guard must reject it before it can reach any approval.
        assertFalse(guard.isEscapeCall(safe, to, value, data, Enum.Operation.DelegateCall), "a delegatecall escaped");
        (bool ok, bytes memory ret) = _checkTransaction(to, value, data, Enum.Operation.DelegateCall, 0);
        assertFalse(ok, "a delegatecall to a target other than MultiSendCallOnly was allowed");
        assertEq(bytes4(ret), FermionGuard.DelegateCallForbidden.selector, "blocked, but not as a forbidden delegatecall");
    }
}
