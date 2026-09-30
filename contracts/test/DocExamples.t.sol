// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";

import {FermionGuard} from "../src/FermionGuard.sol";
import {PreApprovalEngine, NO_MATCHING_PRE_APPROVAL} from "../src/PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "../src/QuantumKeyRegistry.sol";
import {XMSS} from "xmss-solidity/XMSS.sol";

import {MockSafe} from "./FermionGuard.t.sol";

/// @title DocExamples — the worked examples in the English documentation, executed
/// @notice Every test here reproduces one concrete claim made in prose by
///         `fermionguard-module.md`, `pre-approval-engine.md`,
///         `quantum-key-registry.md`, `threat-model.md`, `ui-help.md` or
///         `contracts/README.md`, against the real contracts. The quoted sentence
///         sits in a comment above each test; where the code exposes the number the
///         doc names (an immutable, a constant, a selector, a hash formula), the test
///         asserts equality with the code instead of restating the literal.
///
///         The Guard is deployed with the deploy-script defaults `contracts/README.md`
///         documents ("defaults 2 days, 14 days, 100, 16"), so the prose figures
///         ("48 h", "14 days", "100 legs", "15-minute minimum") are checked against
///         what a default deployment actually exposes. `test/Deploy.t.sol` separately
///         pins those defaults to `script/Deploy.s.sol`.
contract DocExamplesTest is Test {
    // contracts/README.md: "env vars ... defaults 2 days, 14 days, 100, 16"
    uint64 constant SCRIPT_DEFAULT_ADMIN_TIMELOCK = 2 days;
    uint64 constant SCRIPT_DEFAULT_EMERGENCY_TIMELOCK = 14 days;
    uint32 constant SCRIPT_DEFAULT_MAX_BATCH_LEGS = 100;
    uint32 constant SCRIPT_DEFAULT_MAX_COMMITMENT_QUEUE = 16;

    bytes32 constant ATTEST_KEY_TYPEHASH = keccak256(
        "QuantumKeyAttestation(address safe,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce)"
    );
    bytes32 constant ROTATE_KEY_TYPEHASH = keccak256(
        "RotateQuantumKey(address safe,bytes32 oldQuantumKeyId,address newQuantumAdmin,bytes32 newXmssRoot,bytes32 newXmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 constant PRE_APPROVAL_TYPEHASH = keccak256(
        "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
    );
    bytes32 constant PARAM_SET = keccak256("XMSS-SHA2_4_256-test");

    FermionGuard guard;
    MockSafe safe;
    MockToken token;
    MultiSendCallOnly msco;

    uint256 adminPk = 0xA11CE;
    address admin;
    address owner = makeAddr("owner");
    address stranger = makeAddr("stranger");
    address recipient = makeAddr("recipient");

    bytes32 keyId;
    uint32 treeHeight = 4;
    uint32 nextLeaf;
    uint256 approvalNonce;

    function setUp() public {
        admin = vm.addr(adminPk);
        msco = new MultiSendCallOnly();
        guard = new FermionGuard(
            address(msco),
            SCRIPT_DEFAULT_ADMIN_TIMELOCK,
            SCRIPT_DEFAULT_EMERGENCY_TIMELOCK,
            SCRIPT_DEFAULT_MAX_BATCH_LEGS,
            SCRIPT_DEFAULT_MAX_COMMITMENT_QUEUE
        );
        safe = new MockSafe(owner);
        token = new MockToken();
        token.mint(address(safe), 1_000_000 ether);

        keyId = _register(guard, safe, 4);
        safe.setGuardDirect(address(guard));
    }

    // ════════════════════ Timelock arithmetic ════════════════════════════════

    // threat-model.md: "Escape hatches: ADMIN-class pre-approvals under `ADMIN_TIMELOCK`
    // (48 h default) ... and a quantum-key-independent, owners-only emergency de-guard
    // under `EMERGENCY_TIMELOCK` (14 d default)."
    // fermionguard-module.md: "**mandatory on-chain timelock** (immutable
    // `ADMIN_TIMELOCK`, e.g. 48 h): `validFrom ≥ block.timestamp + ADMIN_TIMELOCK`
    // enforced at creation"
    function test_Doc_AdminTimelockIs48Hours_EnforcedAtCreation() public {
        assertEq(guard.ADMIN_TIMELOCK(), 48 hours, "doc says 48 h; deploy default is 2 days");

        uint64 earliest = uint64(block.timestamp) + guard.ADMIN_TIMELOCK();

        // One second short of the documented delay: refused.
        PreApprovalEngine.PreApprovalRequest memory tooEarly = _adminRequest(earliest - 1);
        (bytes memory e1, bytes memory x1) = _signRequest(tooEarly, 2);
        vm.expectRevert(
            abi.encodeWithSelector(PreApprovalEngine.AdminTimelockNotRespected.selector, earliest - 1, earliest)
        );
        guard.createAdminPreApproval(tooEarly, e1, x1);

        // Exactly `now + ADMIN_TIMELOCK`: accepted, and stored verbatim.
        PreApprovalEngine.PreApprovalRequest memory ok = _adminRequest(earliest);
        (bytes memory e2, bytes memory x2) = _signRequest(ok, 2);
        bytes32 id = guard.createAdminPreApproval(ok, e2, x2);
        assertEq(guard.getPreApproval(id).validFrom, earliest);
    }

    // ui-help.md: "a quantum-approved Guard removal after a 48-hour public timelock"
    // ui-help.md: during the countdown "the action cannot execute, full stop"
    function test_Doc_AdminApprovedRemovalExecutesExactlyAfter48Hours() public {
        uint64 requestedAt = uint64(block.timestamp);
        uint64 executableAt = requestedAt + guard.ADMIN_TIMELOCK();
        _approveAdminRemoval();

        // T + 48 h − 1: still inside the countdown, the removal cannot execute.
        vm.warp(executableAt - 1);
        vm.expectRevert(bytes(NO_MATCHING_PRE_APPROVAL));
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));

        // T + 48 h: it executes.
        vm.warp(executableAt);
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
        assertEq(safe.guard(), address(0));
        assertEq(executableAt - requestedAt, 48 hours);
    }

    // ui-help.md: "This path needs **no quantum signature at all** — only your normal
    // owner threshold — and takes 14 days." / "After 14 days, the owners sign and
    // execute the removal (`setGuard(address(0))` ...)"
    function test_Doc_EmergencyDeGuardRequestAtT_ExecutesAtTPlus14Days() public {
        assertEq(guard.EMERGENCY_TIMELOCK(), 14 days, "doc says 14 days; deploy default is 14 days");

        uint64 requestedAt = uint64(block.timestamp);
        safe.exec(address(guard), 0, abi.encodeCall(guard.requestEmergencyDeGuard, ()));

        uint64 executableAt = guard.emergencyDeGuardExecutableAt(address(safe));
        assertEq(executableAt, requestedAt + guard.EMERGENCY_TIMELOCK());
        assertEq(executableAt - requestedAt, 14 days);

        vm.warp(executableAt - 1);
        vm.expectRevert(bytes(NO_MATCHING_PRE_APPROVAL));
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));

        vm.warp(executableAt);
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
        assertEq(safe.guard(), address(0));
    }

    // quantum-key-registry.md: "starts `EMERGENCY_ROTATION_TIMELOCK` (set to the same
    // value as the emergency de-guard timelock, e.g. 14 days) ... After the delay,
    // anyone calls `executeKeyRevocation(safe)`."
    // threat-model.md: "wait `EMERGENCY_ROTATION_TIMELOCK` (the same 14 days)"
    // fermionguard-module.md: "emergencyTimelock ... also sets EMERGENCY_ROTATION_TIMELOCK."
    function test_Doc_KeyRevocationTimelockEqualsDeGuardTimelock_AndIs14Days() public {
        assertEq(
            guard.EMERGENCY_ROTATION_TIMELOCK(),
            guard.EMERGENCY_TIMELOCK(),
            "one constructor argument sets both timelocks"
        );
        assertEq(guard.EMERGENCY_ROTATION_TIMELOCK(), 14 days);

        uint64 requestedAt = uint64(block.timestamp);
        guard.requestKeyRevocation(address(safe), block.timestamp + 1 days, "owners-ok");

        uint64 executableAt = guard.keyRevocationExecutableAt(address(safe));
        assertEq(executableAt, requestedAt + guard.EMERGENCY_ROTATION_TIMELOCK());
        assertEq(guard.keyRevocationKeyId(address(safe)), keyId, "the request names the exact key");

        // "the request ... revokes only that recorded key" — not before it matures.
        vm.warp(executableAt - 1);
        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.RevocationTimelocked.selector, executableAt));
        guard.executeKeyRevocation(address(safe));

        // "After the delay, anyone calls executeKeyRevocation(safe)."
        vm.warp(executableAt);
        vm.prank(stranger);
        guard.executeKeyRevocation(address(safe));

        assertEq(uint8(guard.getKey(keyId).status), uint8(QuantumKeyRegistry.KeyStatus.Revoked));
        assertEq(guard.safeToQuantumKey(address(safe)), bytes32(0), "no Active key after revocation");
        assertTrue(guard.enrolledSafe(address(safe)), "enrollment is sticky");
    }

    // threat-model.md: "unpausing takes the owners `ADMIN_TIMELOCK`, after which the
    // Administrator cannot pause again for another `ADMIN_TIMELOCK`, so it can keep the
    // Safe paused at most about half the time."
    function test_Doc_UnpauseTakesAdminTimelock_AndRePauseCooldownIsAnother() public {
        vm.prank(admin);
        guard.pauseSafe(address(safe));
        assertTrue(guard.safePaused(address(safe)));

        uint64 requestedAt = uint64(block.timestamp);
        safe.exec(address(guard), 0, abi.encodeCall(guard.requestUnpauseSafe, ()));
        uint64 unpauseAt = guard.safeUnpauseExecutableAt(address(safe));
        assertEq(unpauseAt, requestedAt + guard.ADMIN_TIMELOCK());

        vm.warp(unpauseAt);
        safe.exec(address(guard), 0, abi.encodeCall(guard.unpauseSafe, ()));
        assertFalse(guard.safePaused(address(safe)));

        // The second ADMIN_TIMELOCK: the Administrator cannot re-pause during it.
        uint64 cooldownUntil = guard.safePauseCooldownUntil(address(safe));
        assertEq(cooldownUntil, unpauseAt + guard.ADMIN_TIMELOCK());
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(FermionGuard.PauseCooldown.selector, address(safe), cooldownUntil));
        guard.pauseSafe(address(safe));

        vm.warp(cooldownUntil);
        vm.prank(admin);
        guard.pauseSafe(address(safe));
        assertTrue(guard.safePaused(address(safe)));
    }

    // ════════════════════ Caps and bounds ════════════════════════════════════

    // pre-approval-engine.md: "`validTo - validFrom ≥ 15 minutes` and `validTo` in the future"
    // ui-help.md: "how long the pre-approval stays executable (15-minute minimum ...)"
    // fermionguard-module.md: "function MIN_WINDOW() external view returns (uint64);  // constant, 15 minutes"
    function test_Doc_MinimumValidityWindowIs15Minutes() public {
        assertEq(guard.MIN_WINDOW(), 15 minutes);

        uint64 from = uint64(block.timestamp);

        // One second under the minimum window.
        PreApprovalEngine.PreApprovalRequest memory shortWindow = _transferRequest(1 ether, bytes32(0));
        shortWindow.validFrom = from;
        shortWindow.validTo = from + guard.MIN_WINDOW() - 1;
        (bytes memory e1, bytes memory x1) = _signRequest(shortWindow, 0);
        vm.expectRevert(
            abi.encodeWithSelector(PreApprovalEngine.InvalidWindow.selector, shortWindow.validFrom, shortWindow.validTo)
        );
        guard.createPreApproval(shortWindow, e1, x1);

        // Exactly the minimum window: accepted.
        PreApprovalEngine.PreApprovalRequest memory exact = _transferRequest(1 ether, bytes32(0));
        exact.validFrom = from;
        exact.validTo = from + guard.MIN_WINDOW();
        (bytes memory e2, bytes memory x2) = _signRequest(exact, 0);
        bytes32 id = guard.createPreApproval(exact, e2, x2);
        assertEq(guard.getPreApproval(id).validTo - guard.getPreApproval(id).validFrom, guard.MIN_WINDOW());
    }

    // quantum-key-registry.md: "treeHeight (1..20) and parameterSet"
    // contracts/README.md: "`verify` rejects zero roots/seeds and tree heights outside 1..20."
    function test_Doc_TreeHeightRangeIs1To20() public {
        assertEq(XMSS.MAX_HEIGHT, 20, "the 1..20 range's upper bound is XMSS.MAX_HEIGHT");

        MockSafe other = new MockSafe(owner);
        (bytes32 root, bytes32 seed,) = _xmss(4, 0, bytes32(0));
        uint256 regNonce = guard.registryNonce(address(other));

        // Height 0 — below the range.
        vm.expectRevert(QuantumKeyRegistry.InvalidKeyParams.selector);
        guard.registerQuantumKey(
            address(other),
            admin,
            root,
            seed,
            0,
            PARAM_SET,
            block.timestamp + 1 days,
            _attest(guard, address(other), root, seed, 0, regNonce),
            "owners-ok"
        );

        // Height 21 — above the range.
        vm.expectRevert(QuantumKeyRegistry.InvalidKeyParams.selector);
        guard.registerQuantumKey(
            address(other),
            admin,
            root,
            seed,
            uint32(XMSS.MAX_HEIGHT) + 1,
            PARAM_SET,
            block.timestamp + 1 days,
            _attest(guard, address(other), root, seed, uint32(XMSS.MAX_HEIGHT) + 1, regNonce),
            "owners-ok"
        );
    }

    // quantum-key-registry.md: "one long-lived public root hash covering up to 2^h
    // pre-approval signatures"
    // ui-help.md: "`Sign approval — leaf #184,204 of 1,048,576`"  (2^20)
    // pre-approval-engine.md: "a `XMSS-SHA2_20_256`-class key covers ~1M approvals"
    function test_Doc_KeyCoversExactly2ToTheTreeHeightLeaves() public {
        assertEq(uint256(1) << 20, uint256(1_048_576), "the '1,048,576' the UI shows is 2^20");

        // The last leaf of a height-4 key is 2^4 - 1 = 15, and it is usable on-chain.
        uint32 lastLeaf = uint32((1 << treeHeight) - 1);
        nextLeaf = lastLeaf;
        _approveTransfer(7 ether, bytes32(0));
        assertTrue(guard.isLeafUsed(keyId, lastLeaf), "leaf 2^h - 1 is a real, usable leaf");

        // Index 2^h is outside the tree: the verifier rejects it (XMSS.sol bounds
        // `sig.leafIdx` by `1 << h`), so exactly 2^h signatures exist per key.
        bytes32 digest = keccak256("fermionguard/doc-example/leaf-bound");
        (bytes32 root, bytes32 seed, bytes memory encoded) = _xmss(treeHeight, lastLeaf, digest);
        XMSS.Signature memory sig = abi.decode(encoded, (XMSS.Signature));
        XMSS.PublicKey memory pk = XMSS.PublicKey({root: root, seed: seed});

        assertTrue(XMSS.verify(digest, sig, pk, treeHeight), "leaf 2^h - 1 verifies");
        sig.leafIdx = uint32(1 << treeHeight);
        assertFalse(XMSS.verify(digest, sig, pk, treeHeight), "leaf 2^h does not");
    }

    // pre-approval-engine.md: "Field-matched (`txHash == bytes32(0)`) approvals share a
    // bounded FIFO per commitment (OpenZeppelin `DoubleEndedQueue`, cap
    // `MAX_COMMITMENT_QUEUE`). Permanently dead entries — used, revoked, expired, or
    // tied to a revoked key — are popped ... So dead entries never count toward the cap
    // and cannot jam the queue."
    // contracts/README.md: "env vars ... `MAX_COMMITMENT_QUEUE`; defaults 2 days, 14 days,
    // 100, 16" — the fourth default is this cap.
    function test_Doc_CommitmentQueueCapAndDeadEntriesDoNotCount() public {
        assertEq(guard.MAX_COMMITMENT_QUEUE(), 16, "doc says 16; deploy default is 16");

        // A dedicated Guard with a small cap keeps the example short; the assertion is
        // against the contract's own MAX_COMMITMENT_QUEUE, not a restated literal.
        FermionGuard small = new FermionGuard(
            address(msco), SCRIPT_DEFAULT_ADMIN_TIMELOCK, SCRIPT_DEFAULT_EMERGENCY_TIMELOCK, 100, 3
        );
        MockSafe s = new MockSafe(owner);
        bytes32 k = _register(small, s, 4);
        uint32 leaf;
        uint256 n;
        uint32 cap = small.MAX_COMMITMENT_QUEUE();

        // Fill the queue to the cap with identical (same commitment) live approvals.
        for (uint32 i = 0; i < cap; ++i) {
            _createIdentical(small, s, k, leaf++, ++n);
        }

        // One more, while all `cap` are live: refused.
        vm.expectRevert(abi.encodeWithSelector(PreApprovalEngine.CommitmentQueueFull.selector, _commitmentOf(s)));
        _createIdentical(small, s, k, leaf, ++n);

        // Let them all expire: dead entries must not count toward the cap, so the
        // very next creates succeed even though `cap` entries are still queued.
        vm.warp(block.timestamp + 2 days);
        _createIdentical(small, s, k, leaf++, ++n);
        _createIdentical(small, s, k, leaf++, ++n);
    }

    // fermionguard-module.md: "`MultiSendCallOnly` legs are packed as `(uint8 operation,
    // address to, uint256 value, uint256 dataLength, bytes data)`. The Guard's leg
    // decoder must ... (1) revert if the remaining bytes are shorter than the 85-byte
    // fixed leg header"
    function test_Doc_BatchLegHeaderIsExactly85Bytes() public {
        assertEq(uint256(1 + 20 + 32 + 32), uint256(85), "uint8 + address + uint256 + uint256");
        _bumpSafeNonce();

        // 84 bytes: one byte short of a leg header.
        _expectBatchRevert(new bytes(84), abi.encodeWithSelector(FermionGuard.MalformedBatch.selector));

        // 85 bytes: a complete (empty-calldata) leg header, so the decoder gets past
        // the structural check and the transaction fails only for want of an approval.
        bytes memory oneLeg = abi.encodePacked(uint8(0), address(token), uint256(0), uint256(0));
        assertEq(oneLeg.length, 85);
        _expectBatchRevert(oneLeg, bytes(NO_MATCHING_PRE_APPROVAL));
    }

    // fermionguard-module.md: "The immutable `MAX_BATCH_LEGS` (deploy-script default 100)
    // caps decoding" / "(4) revert the moment the leg counter exceeds `MAX_BATCH_LEGS`
    // (`BatchTooLarge`), *before* decoding further legs"
    // ui-help.md: "regardless of leg count (up to the on-chain cap of 100 legs)"
    function test_Doc_BatchCapIs100Legs_AndPlusOneReverts() public {
        assertEq(guard.MAX_BATCH_LEGS(), 100, "doc says 100; deploy default is 100");
        _bumpSafeNonce();

        bytes memory leg = _leg(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)));
        bytes memory txs;
        for (uint256 i = 0; i <= guard.MAX_BATCH_LEGS(); ++i) {
            txs = bytes.concat(txs, leg);
        }
        _expectBatchRevert(
            txs,
            abi.encodeWithSelector(
                FermionGuard.BatchTooLarge.selector, uint256(guard.MAX_BATCH_LEGS()) + 1, guard.MAX_BATCH_LEGS()
            )
        );
    }

    // ════════════════════ Error names and revert strings ═════════════════════

    // fermionguard-module.md: "No matching pre-approval is NOT a custom error: it reverts
    // with the string 'FermionGuard: no quantum pre-approval for this transaction.
    // Approve it in the FermionGuard app first.'"
    // ui-help.md: Safe{Wallet} says "FermionGuard: no quantum pre-approval for this transaction"
    function test_Doc_NoMatchingPreApprovalRevertStringIsVerbatim() public {
        assertEq(
            NO_MATCHING_PRE_APPROVAL,
            "FermionGuard: no quantum pre-approval for this transaction. Approve it in the FermionGuard app first."
        );
        vm.expectRevert(bytes(NO_MATCHING_PRE_APPROVAL));
        safe.exec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)));
    }

    // threat-model.md: "any second submission reverts (`ApprovalExists` — the ID is
    // `keccak256(safe, nonce)` — and the XMSS leaf is already used)"
    // pre-approval-engine.md: "nonce (the approval's ID salt: `id =
    // keccak256(abi.encodePacked(safe, nonce))`; not the Safe nonce)"
    function test_Doc_ApprovalIdIsKeccakOfSafeAndNonce_ReplayRevertsApprovalExists() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferRequest(3 ether, bytes32(0));
        (bytes memory e1, bytes memory x1) = _signRequest(req, 0);
        bytes32 id = guard.createPreApproval(req, e1, x1);

        assertEq(id, keccak256(abi.encodePacked(address(safe), req.nonce)));
        assertTrue(id != bytes32(uint256(safe.nonce())), "the ID salt is not the Safe nonce");

        // Same (safe, nonce): refused before any signature work.
        (bytes memory e2, bytes memory x2) = _signRequest(req, 0);
        vm.expectRevert(abi.encodeWithSelector(PreApprovalEngine.ApprovalExists.selector, id));
        guard.createPreApproval(req, e2, x2);
    }

    // pre-approval-engine.md: "a pin can be replaced only after its approval can never
    // execute — expired, revoked, or created under a since-revoked key. A used pin ...
    // is never replaced; otherwise creation reverts with `TxHashAlreadyPinned`."
    function test_Doc_LivePinCannotBeReplaced_ExpiredPinCan() public {
        bytes32 pin = keccak256("some-safe-tx-hash");

        PreApprovalEngine.PreApprovalRequest memory first = _transferRequest(5 ether, pin);
        (bytes memory e1, bytes memory x1) = _signRequest(first, 0);
        bytes32 id1 = guard.createPreApproval(first, e1, x1);
        assertEq(guard.approvalByTxHash(address(safe), pin), id1);

        // While the first pin is live, the same safeTxHash cannot be re-pinned.
        PreApprovalEngine.PreApprovalRequest memory second = _transferRequest(6 ether, pin);
        (bytes memory e2, bytes memory x2) = _signRequest(second, 0);
        vm.expectRevert(abi.encodeWithSelector(PreApprovalEngine.TxHashAlreadyPinned.selector, address(safe), pin));
        guard.createPreApproval(second, e2, x2);

        // Once it expires it can never execute, so the pin is replaceable.
        vm.warp(uint256(first.validTo) + 1);
        PreApprovalEngine.PreApprovalRequest memory third = _transferRequest(6 ether, pin);
        (bytes memory e3, bytes memory x3) = _signRequest(third, 0);
        bytes32 id3 = guard.createPreApproval(third, e3, x3);
        assertEq(guard.approvalByTxHash(address(safe), pin), id3);
    }

    // fermionguard-module.md: "the deny-list above is **hardcoded** (immutable constants
    // checked first — `approve`, `increaseAllowance`, `permit`, `transferFrom` can never
    // be re-enabled by any governance action, only by a new Guard deployment)"
    function test_Doc_DeniedSelectorsCanNeverBeEnabled() public {
        bytes4[4] memory denied = [
            IERC20.approve.selector,
            bytes4(keccak256("increaseAllowance(address,uint256)")),
            IERC20Permit.permit.selector,
            IERC20.transferFrom.selector
        ];

        for (uint256 i = 0; i < denied.length; ++i) {
            // No governance action can add them to a Safe's permit-list.
            vm.prank(address(safe));
            vm.expectRevert(abi.encodeWithSelector(FermionGuard.DeniedSelector.selector, denied[i]));
            guard.setSelectorPolicy(address(safe), denied[i], true);
            assertFalse(guard.allowedSelectors(address(safe), denied[i]));
        }

        // And a transaction carrying one is refused by selector, with that selector.
        vm.expectRevert(
            abi.encodeWithSelector(FermionGuard.DeniedSelector.selector, IERC20.approve.selector)
        );
        safe.exec(address(token), 0, abi.encodeCall(IERC20.approve, (recipient, 1 ether)));
    }

    // fermionguard-module.md: "initialized at the Safe's first enrollment to `{transfer}`
    // only (registering a new key after an emergency key revocation does not reset it)"
    // quantum-key-registry.md: "The Guard initialises the Safe's selector permit-list to
    // `{transfer}` only at the Safe's **first** registration; registering a new key after
    // an emergency revocation keeps the permit-list the owners have governed into place."
    function test_Doc_PermitListIsTransferOnlyAtFirstEnrollment_AndSurvivesReRegistration() public {
        assertTrue(guard.allowedSelectors(address(safe), IERC20.transfer.selector));
        bytes4 extra = bytes4(keccak256("someOtherCall(uint256)"));
        assertFalse(guard.allowedSelectors(address(safe), extra));

        // Owners govern a selector onto the list (setSelectorPolicy is Safe-only).
        vm.prank(stranger);
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.setSelectorPolicy(address(safe), extra, true);
        vm.prank(address(safe));
        guard.setSelectorPolicy(address(safe), extra, true);
        // …and remove `transfer` from it.
        vm.prank(address(safe));
        guard.setSelectorPolicy(address(safe), IERC20.transfer.selector, false);

        // Emergency revocation, then a fresh registration on a new root.
        guard.requestKeyRevocation(address(safe), block.timestamp + 1 days, "owners-ok");
        vm.warp(block.timestamp + guard.EMERGENCY_ROTATION_TIMELOCK());
        guard.executeKeyRevocation(address(safe));
        _register(guard, safe, 5);

        // The permit-list the owners governed into place is untouched.
        assertTrue(guard.allowedSelectors(address(safe), extra), "added selector survives");
        assertFalse(
            guard.allowedSelectors(address(safe), IERC20.transfer.selector), "removed selector is not re-enabled"
        );
    }

    // quantum-key-registry.md: "XMSS root uniqueness is scoped **per Safe**: reusing a
    // root on another Safe is harmless and allowed, but reusing the same root for the
    // same Safe rejects"
    function test_Doc_RootUniquenessIsScopedPerSafe() public {
        (bytes32 root,,) = _xmss(4, 0, bytes32(0));
        assertTrue(guard.rootRegistered(address(safe), root));

        // Another Safe may register the very same root.
        MockSafe other = new MockSafe(owner);
        assertFalse(guard.rootRegistered(address(other), root));
        _register(guard, other, 4);
        assertTrue(guard.rootRegistered(address(other), root));

        // The same Safe may not, even after its key was revoked.
        guard.requestKeyRevocation(address(safe), block.timestamp + 1 days, "owners-ok");
        vm.warp(block.timestamp + guard.EMERGENCY_ROTATION_TIMELOCK());
        guard.executeKeyRevocation(address(safe));

        (bytes32 sameRoot, bytes32 sameSeed,) = _xmss(4, 0, bytes32(0));
        uint256 n = guard.registryNonce(address(safe));
        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.RootAlreadyRegistered.selector, sameRoot));
        guard.registerQuantumKey(
            address(safe),
            admin,
            sameRoot,
            sameSeed,
            4,
            PARAM_SET,
            block.timestamp + 1 days,
            _attest(guard, address(safe), sameRoot, sameSeed, 4, n),
            "owners-ok"
        );

        // A different root is accepted.
        _register(guard, safe, 5);
        assertTrue(guard.safeToQuantumKey(address(safe)) != bytes32(0));
    }

    // fermionguard-module.md: "0. The gas-refund ban. It is a parameter of the signed
    // transaction, not Safe state, so it never blocks an escape call (re-sign with
    // gasPrice = 0); checked first" / "this check comes before the escape hatch, or an
    // owners-only escape call could pay the Safe's balance out as its refund"
    function test_Doc_GasRefundBanIsCheckedBeforeTheEscapeHatch() public {
        bytes memory escape = abi.encodeCall(guard.requestEmergencyDeGuard, ());

        // gasPrice == 0: the escape call is allowed (no approval, no enrollment check).
        vm.prank(address(safe));
        guard.checkTransaction(
            address(guard), 0, escape, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", stranger
        );
        vm.prank(address(safe));
        guard.checkAfterExecution(bytes32(0), true);

        // gasPrice != 0: refused, even for that same escape call.
        vm.prank(address(safe));
        vm.expectRevert(FermionGuard.GasRefundForbidden.selector);
        guard.checkTransaction(
            address(guard), 0, escape, Enum.Operation.Call, 0, 0, 1, address(0), payable(address(0)), "", stranger
        );
    }

    // ════════════════════ Authorization examples ═════════════════════════════

    // fermionguard-module.md: "Callable by the Safe or the key's quantumAdmin; also by
    // any single owner of the Safe directly — except ADMIN approvals"
    // ui-help.md (as corrected): revocation is sent from the Administrator's Ledger
    // address (`quantumAdmin`), from an owner's own address, or from the Safe itself.
    function test_Doc_RevokePreApprovalAcceptedFromAdminOwnerAndSafe_NotFromRelayer() public {
        // The Quantum Administrator's Ledger address.
        bytes32 a = _approveTransfer(1 ether, bytes32(0));
        vm.prank(admin);
        guard.revokePreApproval(a);
        assertTrue(guard.getPreApproval(a).revoked);

        // A single owner, from their own address.
        bytes32 b = _approveTransfer(2 ether, bytes32(0));
        vm.prank(owner);
        guard.revokePreApproval(b);
        assertTrue(guard.getPreApproval(b).revoked);

        // The Safe itself — neither an owner nor the Administrator, and accepted.
        bytes32 c = _approveTransfer(3 ether, bytes32(0));
        assertFalse(safe.isOwner(address(safe)));
        assertTrue(address(safe) != admin);
        safe.exec(address(guard), 0, abi.encodeCall(guard.revokePreApproval, (c)));
        assertTrue(guard.getPreApproval(c).revoked);

        // Nobody else — in particular not the gas relayer.
        bytes32 d = _approveTransfer(4 ether, bytes32(0));
        vm.prank(stranger);
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.revokePreApproval(d);
    }

    // ui-help.md: "A *single* owner can't revoke an admin approval alone — admin
    // approvals are how the threshold removes an owner ... Individual owners can still
    // revoke transfer and payload approvals directly"
    function test_Doc_SingleOwnerCannotRevokeAdminApproval_ButTheSafeCan() public {
        bytes32 id = _approveAdminRemoval();

        vm.prank(owner);
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.revokePreApproval(id);

        safe.exec(address(guard), 0, abi.encodeCall(guard.revokePreApproval, (id)));
        assertTrue(guard.getPreApproval(id).revoked);
    }

    // ════════════════════ Key registry examples ══════════════════════════════

    // quantum-key-registry.md: "quantumKeyId (`keccak256(abi.encodePacked(safe, xmssRoot,
    // registryNonce))`)"
    function test_Doc_QuantumKeyIdIsKeccakOfSafeRootAndRegistryNonce() public {
        MockSafe other = new MockSafe(owner);
        (bytes32 root,,) = _xmss(4, 0, bytes32(0));
        uint256 nonceAtRegistration = guard.registryNonce(address(other));

        bytes32 id = _register(guard, other, 4);
        assertEq(id, keccak256(abi.encodePacked(address(other), root, nonceAtRegistration)));
        assertEq(guard.getKey(id).xmssRoot, root);
        assertEq(guard.getKey(id).safe, address(other));
    }

    // quantum-key-registry.md: "`registryNonce` (OpenZeppelin `Nonces`) is consumed by
    // every registration, rotation, revocation request and revocation, so every
    // owner-signed registry message is single-use"
    function test_Doc_RegistryNonceConsumedByEveryOwnerSignedRegistryAction() public {
        MockSafe s = new MockSafe(owner);
        assertEq(guard.registryNonce(address(s)), 0);

        _register(guard, s, 4);
        assertEq(guard.registryNonce(address(s)), 1, "registration");

        _rotateOn(s, 4, 5);
        assertEq(guard.registryNonce(address(s)), 2, "rotation");

        guard.requestKeyRevocation(address(s), block.timestamp + 1 days, "owners-ok");
        assertEq(guard.registryNonce(address(s)), 3, "revocation request");

        // Cancelling is a Safe transaction, not an owner-signed registry message:
        // the doc does not list it, and it does not consume the nonce.
        s.setGuardDirect(address(guard));
        s.exec(address(guard), 0, abi.encodeCall(guard.cancelKeyRevocation, (address(s))));
        assertEq(guard.registryNonce(address(s)), 3, "cancel does not consume");

        guard.requestKeyRevocation(address(s), block.timestamp + 1 days, "owners-ok");
        assertEq(guard.registryNonce(address(s)), 4);
        vm.warp(block.timestamp + guard.EMERGENCY_ROTATION_TIMELOCK());
        guard.executeKeyRevocation(address(s));
        assertEq(guard.registryNonce(address(s)), 5, "revocation");
    }

    // quantum-key-registry.md: "new pre-approvals can only be created with the Safe's
    // `Active` key; approvals already created under a key that was later `Rotated` stay
    // executable, while a `Revoked` key's approvals do not"
    function test_Doc_RotatedKeysApprovalsStayExecutable_RevokedKeysDoNot() public {
        bytes32 survivor = _approveTransfer(11 ether, bytes32(0));
        bytes32 oldKeyId = keyId;

        _rotateOn(safe, treeHeight, 5);
        treeHeight = 5;
        nextLeaf = 0;
        keyId = guard.safeToQuantumKey(address(safe));

        assertEq(uint8(guard.getKey(oldKeyId).status), uint8(QuantumKeyRegistry.KeyStatus.Rotated));
        (bool valid,) = guard.validatePreApproval(survivor);
        assertTrue(valid, "a Rotated key's approvals stay executable");
        safe.exec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 11 ether)));
        assertEq(token.balanceOf(recipient), 11 ether);

        // Now an approval under the new key, whose key is then revoked. Its window
        // outlives the revocation timelock, so "revoked key" is the only thing
        // that can kill it.
        PreApprovalEngine.PreApprovalRequest memory req = _transferRequest(12 ether, bytes32(0));
        req.validTo = uint64(block.timestamp) + guard.EMERGENCY_ROTATION_TIMELOCK() + 30 days;
        (bytes memory e, bytes memory x) = _signRequest(req, 0);
        bytes32 doomed = guard.createPreApproval(req, e, x);
        guard.requestKeyRevocation(address(safe), block.timestamp + 1 days, "owners-ok");
        vm.warp(block.timestamp + guard.EMERGENCY_ROTATION_TIMELOCK());
        guard.executeKeyRevocation(address(safe));

        (bool stillValid, string memory reason) = guard.validatePreApproval(doomed);
        assertFalse(stillValid);
        assertEq(reason, "key revoked");
    }

    // pre-approval-engine.md: "the approval is marked used atomically with execution;
    // it stays used even if the call then fails"
    function test_Doc_ApprovalStaysUsedWhenTheInnerCallFails() public {
        _bumpSafeNonce();
        bytes32 id = _approveTransfer(9 ether, bytes32(0));

        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 9 ether));
        vm.prank(address(safe));
        guard.checkTransaction(
            address(token), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", stranger
        );
        assertTrue(guard.getPreApproval(id).used, "consumed inside checkTransaction");

        // The Safe reports the inner call reverted; the approval stays consumed.
        vm.prank(address(safe));
        guard.checkAfterExecution(bytes32(0), false);
        assertTrue(guard.getPreApproval(id).used, "still used after a failed call");

        (bool valid, string memory reason) = guard.validatePreApproval(id);
        assertFalse(valid);
        assertEq(reason, "used");
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    function _register(FermionGuard g, MockSafe s, uint32 h) internal returns (bytes32 id) {
        (bytes32 root, bytes32 seed,) = _xmss(h, 0, bytes32(0));
        uint256 regNonce = g.registryNonce(address(s));
        id = g.registerQuantumKey(
            address(s),
            admin,
            root,
            seed,
            h,
            PARAM_SET,
            block.timestamp + 1 days,
            _attest(g, address(s), root, seed, h, regNonce),
            "owners-ok"
        );
    }

    function _rotateOn(MockSafe s, uint32 oldHeight, uint32 newHeight) internal {
        (bytes32 newRoot, bytes32 newSeed,) = _xmss(newHeight, 0, bytes32(0));
        uint256 regNonce = guard.registryNonce(address(s));
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 oldId = guard.safeToQuantumKey(address(s));
        bytes32 digest = _typed(
            guard,
            keccak256(
                abi.encode(
                    ROTATE_KEY_TYPEHASH,
                    address(s),
                    oldId,
                    admin,
                    newRoot,
                    newSeed,
                    newHeight,
                    PARAM_SET,
                    regNonce,
                    validUntil
                )
            )
        );
        uint32 proofLeaf = address(s) == address(safe) ? nextLeaf++ : 0;
        (,, bytes memory oldProof) = _xmss(oldHeight, proofLeaf, digest);
        guard.rotateQuantumKey(
            address(s),
            admin,
            newRoot,
            newSeed,
            newHeight,
            PARAM_SET,
            validUntil,
            oldProof,
            _attest(guard, address(s), newRoot, newSeed, newHeight, regNonce),
            "owners-ok"
        );
    }

    function _attest(FermionGuard g, address s, bytes32 root, bytes32 seed, uint32 h, uint256 n)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 ss) =
            vm.sign(adminPk, _typed(g, keccak256(abi.encode(ATTEST_KEY_TYPEHASH, s, root, seed, h, PARAM_SET, n))));
        return abi.encodePacked(r, ss, v);
    }

    function _transferRequest(uint256 amount, bytes32 txHash)
        internal
        returns (PreApprovalEngine.PreApprovalRequest memory req)
    {
        req.safe = address(safe);
        req.token = address(token);
        req.recipient = recipient;
        req.amount = amount;
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 15 minutes;
        req.nonce = bytes32(++approvalNonce);
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = nextLeaf;
        req.txHash = txHash;
    }

    function _adminRequest(uint64 validFrom) internal returns (PreApprovalEngine.PreApprovalRequest memory req) {
        req.safe = address(safe);
        req.target = address(safe);
        req.dataHash = keccak256(abi.encodeWithSignature("setGuard(address)", address(0)));
        req.validFrom = validFrom;
        req.validTo = validFrom + 1 days;
        req.nonce = bytes32(++approvalNonce);
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = nextLeaf;
    }

    function _approveTransfer(uint256 amount, bytes32 txHash) internal returns (bytes32) {
        PreApprovalEngine.PreApprovalRequest memory req = _transferRequest(amount, txHash);
        (bytes memory e, bytes memory x) = _signRequest(req, 0);
        return guard.createPreApproval(req, e, x);
    }

    function _approveAdminRemoval() internal returns (bytes32) {
        PreApprovalEngine.PreApprovalRequest memory req = _adminRequest(uint64(block.timestamp) + guard.ADMIN_TIMELOCK());
        (bytes memory e, bytes memory x) = _signRequest(req, 2);
        return guard.createAdminPreApproval(req, e, x);
    }

    /// One identical-fields TRANSFER approval on `g` for `s` (same Tier-2 commitment).
    function _createIdentical(FermionGuard g, MockSafe s, bytes32 k, uint32 leaf, uint256 n) internal {
        PreApprovalEngine.PreApprovalRequest memory req;
        req.safe = address(s);
        req.token = address(token);
        req.recipient = recipient;
        req.amount = 1 ether;
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 1 days;
        req.nonce = keccak256(abi.encode("queue", n));
        req.quantumKeyId = k;
        req.xmssLeafIndex = leaf;

        bytes32 digest = _typed(g, _preApprovalStructHash(req, 0));
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(adminPk, digest);
        (,, bytes memory xmss) = _xmss(4, leaf, digest);
        g.createPreApproval(req, abi.encodePacked(r, ss, v), xmss);
    }

    /// The Tier-2 commitment of the identical approvals `_createIdentical` creates.
    function _commitmentOf(MockSafe s) internal view returns (bytes32) {
        return keccak256(
            abi.encode(address(s), PreApprovalEngine.ApprovalClass.TRANSFER, address(token), recipient, uint256(1 ether))
        );
    }

    function _signRequest(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_)
        internal
        returns (bytes memory ecdsa, bytes memory xmss)
    {
        bytes32 digest = _typed(guard, _preApprovalStructHash(req, class_));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPk, digest);
        ecdsa = abi.encodePacked(r, s, v);
        (,, xmss) = _xmss(treeHeight, nextLeaf++, digest);
    }

    function _preApprovalStructHash(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                PRE_APPROVAL_TYPEHASH,
                req.safe,
                class_,
                req.token,
                req.recipient,
                req.amount,
                req.target,
                req.value,
                req.dataHash,
                req.validFrom,
                req.validTo,
                req.nonce,
                req.quantumKeyId,
                req.xmssLeafIndex,
                req.policyHash,
                req.txHash
            )
        );
    }

    function _typed(FermionGuard g, bytes32 structHash) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("FermionGuard"),
                keccak256("1"),
                block.chainid,
                address(g)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    /// `checkTransaction` recomputes the safeTxHash from `nonce() - 1`, so the Safe must
    /// have executed at least one transaction before the Guard is called directly.
    function _bumpSafeNonce() internal {
        _approveTransfer(1 ether, bytes32(0));
        safe.exec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)));
    }

    function _expectBatchRevert(bytes memory txs, bytes memory err) internal {
        bytes memory data = abi.encodeWithSignature("multiSend(bytes)", txs);
        vm.expectRevert(err);
        vm.prank(address(safe));
        guard.checkTransaction(
            address(msco), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), "", stranger
        );
    }

    /// One packed MultiSend leg: uint8 op(0) | address to | uint256 value | uint256 len | data.
    function _leg(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    /// Sign `digest` at `leaf` with the deterministic height-`h` test key.
    function _xmss(uint32 h, uint32 leaf, bytes32 digest)
        internal
        returns (bytes32 root, bytes32 seed, bytes memory encoded)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "python3";
        cmd[1] = "lib/xmss-solidity/py/sign_digest.py";
        cmd[2] = vm.toString(h);
        cmd[3] = vm.toString(leaf);
        cmd[4] = vm.toString(digest);
        bytes memory out = vm.ffi(cmd);

        XMSS.Signature memory sig;
        sig.leafIdx = leaf;
        sig.authPath = new bytes32[](h);
        root = _word(out, 0);
        seed = _word(out, 1);
        sig.r = _word(out, 2);
        for (uint256 i = 0; i < 67; ++i) {
            sig.wotsSig[i] = _word(out, 3 + i);
        }
        for (uint256 i = 0; i < h; ++i) {
            sig.authPath[i] = _word(out, 70 + i);
        }
        encoded = abi.encode(sig);
    }

    function _word(bytes memory b, uint256 i) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), mul(i, 32)))
        }
    }
}
