// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";

import {FermionWalletGuard} from "../src/FermionWalletGuard.sol";
import {PreApprovalEngine} from "../src/PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "../src/QuantumKeyRegistry.sol";
import {XMSS} from "../src/XMSS.sol";

/// Malicious "token": its transfer() re-enters Safe.execTransaction with a fully
/// signed, pre-approved inner transaction. The Guard's transient depth flag must
/// kill the inner execution.
contract ReentrantToken {
    Safe internal immutable SAFE;
    address internal innerTo;
    bytes internal innerData;
    bytes internal innerSigs;

    constructor(Safe safe_) {
        SAFE = safe_;
    }

    function arm(address to, bytes calldata data, bytes calldata sigs) external {
        (innerTo, innerData, innerSigs) = (to, data, sigs);
    }

    function transfer(address, uint256) external returns (bool) {
        SAFE.execTransaction(
            innerTo, 0, innerData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), innerSigs
        );
        return true;
    }
}

/// End-to-end integration suite mandated by fermionwallet-guard-module.md, "Production
/// checklist": a REAL Safe v1.5.0 proxy (SafeProxyFactory + singleton), the real
/// MultiSendCallOnly, and XMSS signatures from the RFC 8391 reference implementation
/// via FFI (test key h = 4; rotation target h = 5). Exercises the nonce()-1 hash
/// recomputation, real checkSignatures threshold verification, the escape hatch under
/// pause, malformed-batch structure, and the full key lifecycle.
contract GuardIntegrationTest is Test {
    // ── Actors ──────────────────────────────────────────────────────────────
    uint256 internal constant OWNER1_PK = 0xA1;
    uint256 internal constant OWNER2_PK = 0xA2;
    uint256 internal constant OWNER3_PK = 0xA3;
    uint256 internal constant LEDGER_PK = 0x1ED6E4;
    address internal owner1 = vm.addr(OWNER1_PK);
    address internal owner2 = vm.addr(OWNER2_PK);
    address internal owner3 = vm.addr(OWNER3_PK);
    address internal ledger = vm.addr(LEDGER_PK);
    address internal deployer = makeAddr("deployer");
    address internal relayer = makeAddr("relayer");
    address internal recipient = makeAddr("recipient");

    // ── Parameters ──────────────────────────────────────────────────────────
    uint64 internal constant ADMIN_TIMELOCK = 2 days;
    uint64 internal constant EMERGENCY_TIMELOCK = 7 days;
    uint32 internal constant MAX_BATCH_LEGS = 4;
    uint32 internal constant MAX_QUEUE = 8;
    uint32 internal constant H = 4; //     primary test key height (16 leaves)
    uint32 internal constant H_NEW = 5; // rotation target key height (different root)
    bytes32 internal constant PARAM_SET = keccak256("XMSS-SHA2_4_256-TEST");

    // ── EIP-712 type hashes (must mirror the contracts verbatim) ────────────
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
    bytes32 internal constant PRE_APPROVAL_TYPEHASH = keccak256(
        "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    // ── Fixtures ────────────────────────────────────────────────────────────
    Safe internal safe;
    MultiSendCallOnly internal msco;
    FermionWalletGuard internal guard;
    MockToken internal token;
    bytes32 internal keyId;
    bytes32 internal xmssRoot;
    bytes32 internal xmssSeed;
    uint256 internal approvalNonce; // monotone salt for pre-approval ids

    function setUp() public {
        vm.warp(1_800_000_000);

        Safe singleton = new Safe();
        SafeProxyFactory factory = new SafeProxyFactory();
        msco = new MultiSendCallOnly();
        token = new MockToken();

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        bytes memory initializer = abi.encodeCall(
            Safe.setup, (owners, 2, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        safe = Safe(payable(factory.createProxyWithNonce(address(singleton), initializer, 0xF3E)));

        guard = new FermionWalletGuard(
            address(msco), ADMIN_TIMELOCK, EMERGENCY_TIMELOCK, MAX_BATCH_LEGS, MAX_QUEUE
        );

        token.mint(address(safe), 1_000_000 ether);
        vm.deal(address(safe), 100 ether);

        // Pre-guard no-op tx: guarantees safe.nonce() >= 1 so nonce()-1 never
        // underflows in direct checkTransaction tests (matches the real invariant:
        // the Guard only ever runs after execTransaction incremented the nonce).
        _safeExec(address(0xDEAD), 0, "", Enum.Operation.Call);

        // Ceremony: register the h=4 XMSS key, then wire the Guard.
        (xmssRoot, xmssSeed,) = _xmssSign(H, 0, bytes32(uint256(1))); // root/seed extraction only
        keyId = _registerKey();
        _safeExec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(guard)), Enum.Operation.Call);
    }

    // ═════════════════════════════ Registration ═════════════════════════════

    function test_RegistrationState() public view {
        assertEq(guard.safeToQuantumKey(address(safe)), keyId);
        assertTrue(guard.enrolledSafe(address(safe)));
        QuantumKeyRegistry.KeyRegistration memory k = guard.getKey(keyId);
        assertEq(k.xmssRoot, xmssRoot);
        assertEq(k.xmssSeed, xmssSeed);
        assertEq(k.quantumAdmin, ledger);
        assertEq(uint8(k.status), uint8(QuantumKeyRegistry.KeyStatus.Active));
        assertEq(guard.registryNonce(address(safe)), 1);
        // Enrollment hook: transfer allowed, approve not.
        assertTrue(guard.allowedSelectors(address(safe), IERC20.transfer.selector));
        assertFalse(guard.allowedSelectors(address(safe), IERC20.approve.selector));
    }

    function test_DoubleRegistrationReverts() public {
        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.SafeAlreadyEnrolled.selector, address(safe)));
        vm.prank(relayer);
        guard.registerQuantumKey(
            address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, block.timestamp + 1 days, "", ""
        );
    }

    // ══════════════════════ Tier 1 — pinned safeTxHash ══════════════════════

    /// The production-checklist integration test: pin the exact hash the Safe will
    /// compute, then verify the Guard's nonce()-1 recomputation matches it in-flight.
    function test_Tier1_PinnedTransfer_Executes() public {
        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 5 ether));
        bytes32 pin = safe.getTransactionHash(
            address(token), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
        bytes32 id = _createTransfer(recipient, 5 ether, 1, pin);

        _safeExec(address(token), 0, data, Enum.Operation.Call);

        assertEq(token.balanceOf(recipient), 5 ether);
        assertTrue(guard.getPreApproval(id).used);
        assertTrue(guard.isLeafUsed(keyId, 1));
    }

    // ═══════════════════════ Tier 2 — field-matched ═════════════════════════

    function test_Tier2_FieldMatchedTransfer_Executes() public {
        bytes32 id = _createTransfer(recipient, 7 ether, 1, bytes32(0));
        _safeExec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 7 ether)), Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 7 ether);
        assertTrue(guard.getPreApproval(id).used);
    }

    function test_Tier2_FifoOrder() public {
        bytes32 first = _createTransfer(recipient, 3 ether, 1, bytes32(0));
        bytes32 second = _createTransfer(recipient, 3 ether, 2, bytes32(0));
        _safeExec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 3 ether)), Enum.Operation.Call);
        assertTrue(guard.getPreApproval(first).used);
        assertFalse(guard.getPreApproval(second).used);
    }

    function test_NoApproval_Reverts() public {
        _expectExecRevert(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)));
    }

    function test_AmountMismatch_Reverts() public {
        _createTransfer(recipient, 5 ether, 1, bytes32(0));
        _expectExecRevert(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 6 ether)));
    }

    function test_ExpiredApproval_Reverts() public {
        _createTransfer(recipient, 5 ether, 1, bytes32(0));
        vm.warp(block.timestamp + 2 days + 1); // beyond validTo
        _expectExecRevert(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 5 ether)));
    }

    function test_RevokedApproval_Reverts() public {
        bytes32 id = _createTransfer(recipient, 5 ether, 1, bytes32(0));
        vm.prank(ledger);
        guard.revokePreApproval(id);
        _expectExecRevert(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 5 ether)));
    }

    // ═════════════════════════ Hybrid signature rules ═══════════════════════

    function test_LeafReuse_Reverts() public {
        _createTransfer(recipient, 1 ether, 3, bytes32(0));
        // Second approval attempting the same leaf must die inside the registry.
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 2 ether, 3, bytes32(0));
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.LeafAlreadyUsed.selector, keyId, uint32(3)));
        vm.prank(relayer);
        guard.createPreApproval(req, ecdsaSig, xmssSig);
    }

    function test_WrongEcdsaSigner_Reverts() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        (, bytes memory xmssSig) = _hybridSign(req, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER1_PK, _preApprovalDigest(req, 0)); // owner, not Ledger
        vm.expectRevert(PreApprovalEngine.InvalidEcdsaSignature.selector);
        vm.prank(relayer);
        guard.createPreApproval(req, abi.encodePacked(r, s, v), xmssSig);
    }

    function test_XmssOverWrongDigest_Reverts() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        (bytes memory ecdsaSig,) = _hybridSign(req, 0);
        (,, bytes memory wrongXmss) = _xmssSign(H, 1, keccak256("some other digest"));
        vm.expectRevert(QuantumKeyRegistry.InvalidXmssSignature.selector);
        vm.prank(relayer);
        guard.createPreApproval(req, ecdsaSig, wrongXmss);
    }

    function test_LeafIndexMismatch_Reverts() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 2, bytes32(0));
        bytes32 digest = _preApprovalDigest(req, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        (,, bytes memory xmssSig) = _xmssSign(H, 5, digest); // signature carries leaf 5, request says 2
        vm.expectRevert(
            abi.encodeWithSelector(PreApprovalEngine.LeafIndexDoesNotMatchSignature.selector, uint32(2), uint32(5))
        );
        vm.prank(relayer);
        guard.createPreApproval(req, abi.encodePacked(r, s, v), xmssSig);
    }

    // ═════════════════════════ Policy enforcement ═══════════════════════════

    function test_DeniedSelector_ApproveReverts() public {
        _expectExecRevertWith(
            address(token),
            0,
            abi.encodeCall(IERC20.approve, (recipient, 1 ether)),
            abi.encodeWithSelector(FermionWalletGuard.DeniedSelector.selector, IERC20.approve.selector)
        );
    }

    function test_UnlistedSelector_Reverts() public {
        _expectExecRevertWith(
            address(token),
            0,
            abi.encodeCall(MockToken.mint, (recipient, 1 ether)),
            abi.encodeWithSelector(
                FermionWalletGuard.SelectorNotAllowed.selector, address(safe), MockToken.mint.selector
            )
        );
    }

    function test_GasRefund_Reverts() public {
        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        bytes32 txHash = safe.getTransactionHash(
            address(token), 0, data, Enum.Operation.Call, 0, 0, 1, address(0), address(0), safe.nonce()
        );
        vm.expectRevert(FermionWalletGuard.GasRefundForbidden.selector);
        safe.execTransaction(
            address(token), 0, data, Enum.Operation.Call, 0, 0, 1, address(0), payable(address(0)), _ownerSigs(txHash)
        );
    }

    function test_DirectCheckTransaction_NonEnrolled_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(FermionWalletGuard.NotEnrolledSafe.selector, address(0xBAD)));
        vm.prank(address(0xBAD));
        guard.checkTransaction(
            address(token), 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", relayer
        );
    }

    function test_DelegateCallToArbitraryTarget_Reverts() public {
        _expectExecRevertOp(
            address(token),
            0,
            "",
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(FermionWalletGuard.DelegateCallForbidden.selector, address(token))
        );
    }

    /// A malicious call target re-enters execTransaction mid-flight with a fully
    /// signed, pre-approved inner transaction: the transient depth flag must kill it.
    function test_Reentrancy_NestedExecTransaction_Blocked() public {
        ReentrantToken attacker = new ReentrantToken(safe);

        // Outer: TRANSFER-class approval whose "token" is the attacker contract.
        _createTransfer2(address(attacker), recipient, 1 ether, 1, bytes32(0));
        // Inner: a legitimately approved real-token transfer the attacker will replay.
        _createTransfer(recipient, 2 ether, 2, bytes32(0));

        bytes memory innerData = abi.encodeCall(IERC20.transfer, (recipient, 2 ether));
        bytes32 innerHash = safe.getTransactionHash(
            address(token), 0, innerData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce() + 1
        );
        attacker.arm(address(token), innerData, _ownerSigs(innerHash));

        // The nested inner execTransaction reverts inside the Guard
        // (NestedSafeTransaction); with safeTxGas == 0 the outer Safe then reverts
        // the whole transaction — the attack is dead and no tokens move.
        bytes memory outerData = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        bytes32 outerHash = safe.getTransactionHash(
            address(attacker), 0, outerData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
        bytes memory sigs = _ownerSigs(outerHash);
        vm.expectRevert();
        safe.execTransaction(
            address(attacker), 0, outerData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sigs
        );

        assertEq(token.balanceOf(recipient), 0);
    }

    // ═══════════════════════ ADMIN class + timelock ═════════════════════════

    function test_AdminTimelock_TooEarly_Reverts() public {
        bytes memory call =
            abi.encodeCall(FermionWalletGuard.setSelectorPolicy, (address(safe), MockToken.mint.selector, true));
        PreApprovalEngine.PreApprovalRequest memory req = _adminReq(address(guard), keccak256(call), 1);
        req.validFrom = uint64(block.timestamp) + ADMIN_TIMELOCK - 1; // one second short
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 2);
        vm.expectRevert(
            abi.encodeWithSelector(
                PreApprovalEngine.AdminTimelockNotRespected.selector,
                req.validFrom,
                uint64(block.timestamp) + ADMIN_TIMELOCK
            )
        );
        vm.prank(relayer);
        guard.createAdminPreApproval(req, ecdsaSig, xmssSig);
    }

    /// Full governance round-trip: ADMIN pre-approval → timelock elapses → the Safe
    /// mutates its own selector permit-list through the Guard's ADMIN dispatch path.
    function test_AdminFlow_SetSelectorPolicy_EndToEnd() public {
        bytes memory call =
            abi.encodeCall(FermionWalletGuard.setSelectorPolicy, (address(safe), MockToken.mint.selector, true));
        _createAdmin(address(guard), keccak256(call), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(guard), 0, call, Enum.Operation.Call);
        assertTrue(guard.allowedSelectors(address(safe), MockToken.mint.selector));
    }

    function test_SetSelectorPolicy_DirectEOA_Reverts() public {
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        vm.prank(deployer);
        guard.setSelectorPolicy(address(safe), MockToken.mint.selector, true);
    }

    function test_SetSelectorPolicy_DenyListImmutable() public {
        vm.expectRevert(abi.encodeWithSelector(FermionWalletGuard.DeniedSelector.selector, IERC20.approve.selector));
        vm.prank(address(safe));
        guard.setSelectorPolicy(address(safe), IERC20.approve.selector, true);
    }

    // ═══════════════ Emergency de-guard — the no-brick invariant ════════════

    /// Production-checklist mandatory test: the escape hatch works WHILE PAUSED
    /// and with the quantum key presumed lost — request, wait out the timelock,
    /// detach the Guard with setGuard(0), and confirm the Safe is free. End to end.
    function test_EmergencyDeGuard_WorksWhilePaused_EndToEnd() public {
        _safeExec(
            address(guard), 0, abi.encodeCall(FermionWalletGuard.pauseSafe, (address(safe))), Enum.Operation.Call
        );

        // Any normal transaction is now dead…
        _expectExecRevertWith(
            address(token),
            0,
            abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            abi.encodeWithSelector(FermionWalletGuard.SafePausedError.selector, address(safe))
        );

        // …but the escape hatch is not (check-order rule #1).
        _safeExec(
            address(guard), 0, abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call
        );
        uint64 executableAt = guard.emergencyDeGuardExecutableAt(address(safe));
        assertEq(executableAt, uint64(block.timestamp) + EMERGENCY_TIMELOCK);

        // Premature setGuard(0): not escape-hatched yet, needs an ADMIN approval → dies.
        _expectExecRevert(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));

        vm.warp(executableAt + 1);
        _safeExec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)), Enum.Operation.Call);

        // The Safe is unguarded: plain owner-threshold transfers work again.
        _safeExec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 9 ether)), Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 9 ether);
    }

    function test_EmergencyDeGuard_SetNonZeroGuard_NotUnlocked() public {
        _safeExec(
            address(guard), 0, abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call
        );
        vm.warp(guard.emergencyDeGuardExecutableAt(address(safe)) + 1);
        // Swapping to a DIFFERENT guard is not part of the escape hatch → ADMIN path →
        // no approval → revert.
        _expectExecRevert(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0xBEEF)));
    }

    /// Per-Safe pause: one owner freezes instantly (direct call); unpause is Safe-
    /// governed, time-locked, and flows through the escape hatch while frozen.
    function test_SafePause_OwnerFreezes_TimelockedUnpause_EndToEnd() public {
        vm.prank(owner3);
        guard.pauseSafe(address(safe));
        assertTrue(guard.safePaused(address(safe)));

        _expectExecRevertWith(
            address(token),
            0,
            abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            abi.encodeWithSelector(FermionWalletGuard.SafePausedError.selector, address(safe))
        );

        // Unpause request passes THROUGH the guard while frozen (escape hatch).
        _safeExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.requestUnpauseSafe, ()), Enum.Operation.Call);
        uint64 executableAt = guard.safeUnpauseExecutableAt(address(safe));
        assertEq(executableAt, uint64(block.timestamp) + ADMIN_TIMELOCK);

        vm.warp(executableAt + 1);
        _safeExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.unpauseSafe, ()), Enum.Operation.Call);
        assertFalse(guard.safePaused(address(safe)));

        _createTransfer(recipient, 1 ether, 1, bytes32(0));
        _safeExec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)), Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    // ══════════════════════ Batch (MultiSendCallOnly) ═══════════════════════

    function test_Batch_TwoTransfers_Executes() public {
        bytes memory leg1 = abi.encodeCall(IERC20.transfer, (recipient, 2 ether));
        bytes memory leg2 = abi.encodeCall(IERC20.transfer, (owner3, 3 ether));
        bytes memory txs = bytes.concat(_leg(address(token), 0, leg1), _leg(address(token), 0, leg2));
        bytes memory data = abi.encodeWithSignature("multiSend(bytes)", txs);

        _createPayload(address(msco), 0, keccak256(data), 1);
        _safeExec(address(msco), 0, data, Enum.Operation.DelegateCall);

        assertEq(token.balanceOf(recipient), 2 ether);
        assertEq(token.balanceOf(owner3), 3 ether);
    }

    function test_Batch_TruncatedHeader_Reverts() public {
        bytes memory txs = new bytes(50); // < one 85-byte leg header
        _expectDirectBatchRevert(txs, abi.encodeWithSelector(FermionWalletGuard.MalformedBatch.selector));
    }

    function test_Batch_DataLengthOverrun_Reverts() public {
        // Header claims 1000 bytes of leg calldata; only 4 are present.
        bytes memory txs =
            abi.encodePacked(uint8(0), address(token), uint256(0), uint256(1000), IERC20.transfer.selector);
        _expectDirectBatchRevert(txs, abi.encodeWithSelector(FermionWalletGuard.MalformedBatch.selector));
    }

    function test_Batch_TrailingBytes_Reverts() public {
        bytes memory leg = _leg(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)));
        bytes memory txs = bytes.concat(leg, hex"deadbe"); // 3-byte smuggled suffix
        _expectDirectBatchRevert(txs, abi.encodeWithSelector(FermionWalletGuard.MalformedBatch.selector));
    }

    function test_Batch_TooManyLegs_Reverts() public {
        bytes memory leg = _leg(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)));
        bytes memory txs;
        for (uint256 i = 0; i <= MAX_BATCH_LEGS; ++i) {
            txs = bytes.concat(txs, leg);
        }
        _expectDirectBatchRevert(
            txs, abi.encodeWithSelector(FermionWalletGuard.BatchTooLarge.selector, MAX_BATCH_LEGS + 1, MAX_BATCH_LEGS)
        );
    }

    function test_Batch_LegTargetingSafe_Reverts() public {
        bytes memory txs = _leg(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
        _expectDirectBatchRevert(
            txs, abi.encodeWithSelector(FermionWalletGuard.ForbiddenBatchLegTarget.selector, address(safe))
        );
    }

    function test_Batch_LegWithDeniedSelector_Reverts() public {
        bytes memory txs = _leg(address(token), 0, abi.encodeCall(IERC20.approve, (recipient, 1 ether)));
        _expectDirectBatchRevert(
            txs, abi.encodeWithSelector(FermionWalletGuard.DeniedSelector.selector, IERC20.approve.selector)
        );
    }

    /// Fuzz the structural validator with arbitrary bytes: it must never accept —
    /// any acceptance would mean an unsigned batch got through.
    function testFuzz_Batch_GarbageNeverAccepted(bytes calldata garbage) public {
        vm.assume(garbage.length > 0 && garbage.length < 4096);
        bytes memory data = abi.encodeWithSignature("multiSend(bytes)", garbage);
        vm.prank(address(safe));
        (bool ok,) = address(guard).call(
            abi.encodeCall(
                guard.checkTransaction,
                (
                    address(msco),
                    0,
                    data,
                    Enum.Operation.DelegateCall,
                    0,
                    0,
                    0,
                    address(0),
                    payable(address(0)),
                    "",
                    relayer
                )
            )
        );
        // Without a matching PAYLOAD approval nothing may pass; structural garbage
        // must revert even earlier. Either way: never ok.
        assertFalse(ok);
    }

    // ═══════════════════════════ Key lifecycle ══════════════════════════════

    function test_Rotation_WithOldKeyProof() public {
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = block.timestamp + 1 days;

        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(
                    ROTATE_KEY_TYPEHASH,
                    address(safe),
                    keyId,
                    ledger,
                    newRoot,
                    newSeed,
                    H_NEW,
                    PARAM_SET,
                    nonce,
                    validUntil
                )
            )
        );
        (,, bytes memory oldKeyProof) = _xmssSign(H, 6, digest);

        vm.prank(relayer);
        bytes32 newKeyId = guard.rotateQuantumKey(
            address(safe),
            ledger,
            newRoot,
            newSeed,
            H_NEW,
            PARAM_SET,
            validUntil,
            oldKeyProof,
            _ledgerAttestation(newRoot, newSeed, H_NEW, nonce),
            _ownerSigs(digest)
        );

        assertEq(guard.safeToQuantumKey(address(safe)), newKeyId);
        assertEq(uint8(guard.getKey(keyId).status), uint8(QuantumKeyRegistry.KeyStatus.Rotated));
        assertEq(uint8(guard.getKey(newKeyId).status), uint8(QuantumKeyRegistry.KeyStatus.Active));
        assertTrue(guard.isLeafUsed(keyId, 6)); // rotation consumed one old-key leaf
    }

    function test_Rotation_WithoutOldKeyProof_Reverts() public {
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(
                    ROTATE_KEY_TYPEHASH,
                    address(safe),
                    keyId,
                    ledger,
                    newRoot,
                    newSeed,
                    H_NEW,
                    PARAM_SET,
                    nonce,
                    validUntil
                )
            )
        );
        (,, bytes memory wrongProof) = _xmssSign(H, 6, keccak256("not the rotation digest"));
        vm.expectRevert(QuantumKeyRegistry.InvalidXmssSignature.selector);
        vm.prank(relayer);
        guard.rotateQuantumKey(
            address(safe),
            ledger,
            newRoot,
            newSeed,
            H_NEW,
            PARAM_SET,
            validUntil,
            wrongProof,
            _ledgerAttestation(newRoot, newSeed, H_NEW, nonce),
            _ownerSigs(digest)
        );
    }

    function test_EmergencyRevocation_TimelockedLifecycle() public {
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(REVOKE_KEY_TYPEHASH, address(safe), keyId, guard.registryNonce(address(safe)), validUntil)
            )
        );
        vm.prank(relayer);
        guard.requestKeyRevocation(address(safe), validUntil, _ownerSigs(digest));

        uint64 executableAt = guard.keyRevocationExecutableAt(address(safe));
        assertEq(executableAt, uint64(block.timestamp) + EMERGENCY_TIMELOCK);

        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.RevocationTimelocked.selector, executableAt));
        guard.executeKeyRevocation(address(safe));

        vm.warp(executableAt + 1);
        guard.executeKeyRevocation(address(safe));

        assertEq(guard.safeToQuantumKey(address(safe)), bytes32(0));
        assertEq(uint8(guard.getKey(keyId).status), uint8(QuantumKeyRegistry.KeyStatus.Revoked));
        assertTrue(guard.enrolledSafe(address(safe))); // sticky: escape hatch stays reachable

        // No active key ⇒ normal transactions blocked ⇒ only the escape hatch remains.
        _expectExecRevertWith(
            address(token),
            0,
            abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            abi.encodeWithSelector(FermionWalletGuard.NotEnrolledSafe.selector, address(safe))
        );
        _safeExec(
            address(guard), 0, abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call
        );
    }

    /// A cancelled revocation request cannot be re-armed by replaying its owner
    /// signatures from chain history: the request consumed the registry nonce.
    function test_EmergencyRevocation_CancelledRequestCannotBeReplayed() public {
        uint256 validUntil = block.timestamp + 30 days;
        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(REVOKE_KEY_TYPEHASH, address(safe), keyId, guard.registryNonce(address(safe)), validUntil)
            )
        );
        bytes memory sigs = _ownerSigs(digest);
        vm.prank(relayer);
        guard.requestKeyRevocation(address(safe), validUntil, sigs);

        _safeExec(
            address(guard),
            0,
            abi.encodeCall(QuantumKeyRegistry.cancelKeyRevocation, (address(safe))),
            Enum.Operation.Call
        );
        assertEq(guard.keyRevocationExecutableAt(address(safe)), 0);

        vm.prank(relayer);
        vm.expectRevert(); // stale nonce ⇒ Safe's checkSignatures rejects the old signatures
        guard.requestKeyRevocation(address(safe), validUntil, sigs);
        assertEq(guard.keyRevocationExecutableAt(address(safe)), 0);
    }

    // ══════════════ Regressions: root squatting & ERC-1271 bypass ═══════════

    /// A mempool front-runner registering the victim's root under a fake "Safe"
    /// (self-authenticated checkSignatures) must NOT block the victim: root dedup
    /// is scoped per Safe, so the squat is inert.
    function test_RootSquatting_CannotBlockRotation() public {
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));

        FakeSafe fake = new FakeSafe();
        uint256 attackerPk = 0xBAD;
        address attacker = vm.addr(attackerPk);
        bytes32 attestDigest = _guardDigest(
            keccak256(
                abi.encode(
                    ATTEST_KEY_TYPEHASH, address(fake), newRoot, newSeed, H_NEW, PARAM_SET, guard.registryNonce(address(fake))
                )
            )
        );
        (uint8 av, bytes32 ar, bytes32 as_) = vm.sign(attackerPk, attestDigest);
        vm.prank(attacker);
        guard.registerQuantumKey(
            address(fake), attacker, newRoot, newSeed, H_NEW, PARAM_SET, block.timestamp + 1 days,
            abi.encodePacked(ar, as_, av), ""
        );

        // Victim's rotation to the squatted root still succeeds.
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(
                    ROTATE_KEY_TYPEHASH, address(safe), keyId, ledger, newRoot, newSeed, H_NEW, PARAM_SET, nonce, validUntil
                )
            )
        );
        (,, bytes memory oldKeyProof) = _xmssSign(H, 6, digest);
        vm.prank(relayer);
        bytes32 newKeyId = guard.rotateQuantumKey(
            address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, oldKeyProof,
            _ledgerAttestation(newRoot, newSeed, H_NEW, nonce), _ownerSigs(digest)
        );
        assertEq(guard.safeToQuantumKey(address(safe)), newKeyId);
        assertEq(uint8(guard.getKey(newKeyId).status), uint8(QuantumKeyRegistry.KeyStatus.Active));
    }

    /// Safe FallbackManager slot: keccak256("fallback_manager.handler.address").
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    /// A non-allowlisted fallback handler (ERC-1271 isValidSignature = Guard bypass)
    /// freezes all checked transactions until remediated.
    function test_FallbackHandler_BlocksCheckedTransactions() public {
        address evil = makeAddr("evilHandler");
        _createTransfer(recipient, 1 ether, 1, bytes32(0));
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(evil))));
        _expectExecRevertWith(
            address(token),
            0,
            abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            abi.encodeWithSelector(FermionWalletGuard.FallbackHandlerForbidden.selector, address(safe), evil)
        );
    }

    /// Even a matured, quantum-approved ADMIN action cannot install a handler that
    /// is not on the governance allowlist.
    function test_FallbackHandler_AdminInstallForbidden() public {
        address evil = makeAddr("evilHandler");
        bytes memory data = abi.encodeWithSignature("setFallbackHandler(address)", evil);
        _createAdmin(address(safe), keccak256(data), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _expectExecRevertWith(
            address(safe),
            0,
            data,
            abi.encodeWithSelector(FermionWalletGuard.FallbackHandlerForbidden.selector, address(safe), evil)
        );
    }

    /// The remediation path must work WHILE the posture is bad: quantum-approved
    /// setFallbackHandler(0) clears the handler, after which transfers flow again.
    function test_FallbackHandler_RemovalWorksWhilePostureBad() public {
        bytes memory clear = abi.encodeWithSignature("setFallbackHandler(address)", address(0));
        _createAdmin(address(safe), keccak256(clear), 1);
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(makeAddr("evilHandler")))));
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, clear, Enum.Operation.Call);

        _createTransfer(recipient, 2 ether, 2, bytes32(0));
        _safeExec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 2 ether)), Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 2 ether);
    }

    /// Module-posture deadlock prevention: an approved enableModule is rejected
    /// unless this Guard is already wired as the Safe's module guard — the Safe can
    /// never be steered into a state its own remediation transactions can't exit,
    /// and on Safe <= 1.4.1 (unguardable modules) it is rejected outright.
    function test_EnableModule_RejectedUntilModuleGuardWired() public {
        address module = makeAddr("module");
        bytes memory enable = abi.encodeWithSignature("enableModule(address)", module);
        _createAdmin(address(safe), keccak256(enable), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _expectExecRevertWith(
            address(safe),
            0,
            enable,
            abi.encodeWithSelector(FermionWalletGuard.ModuleGuardNotWired.selector, address(safe))
        );

        // Wire the module guard first (its own quantum-approved admin step)…
        bytes memory wire = abi.encodeWithSignature("setModuleGuard(address)", address(guard));
        _createAdmin(address(safe), keccak256(wire), 2);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, wire, Enum.Operation.Call);

        // …then the same enableModule approval executes, and the Safe stays usable.
        _createAdmin(address(safe), keccak256(enable), 3);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, enable, Enum.Operation.Call);

        _createTransfer(recipient, 1 ether, 4, bytes32(0));
        _safeExec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)), Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    // ═════════════════════════════ Helpers ══════════════════════════════════

    /// FFI to the RFC 8391 reference signer. Output: root|seed|r|wots[67]|auth[h].
    function _xmssSign(uint32 h, uint32 leaf, bytes32 digest)
        internal
        returns (bytes32 root, bytes32 seed, bytes memory encodedSig)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "python3";
        cmd[1] = "py/sign_digest.py";
        cmd[2] = vm.toString(uint256(h));
        cmd[3] = vm.toString(uint256(leaf));
        cmd[4] = vm.toString(digest);
        bytes memory blob = vm.ffi(cmd);
        require(blob.length == 32 * (3 + 67 + h), "ffi blob size");

        XMSS.Signature memory sig;
        sig.leafIdx = leaf;
        root = _word(blob, 0);
        seed = _word(blob, 1);
        sig.r = _word(blob, 2);
        for (uint256 i = 0; i < 67; ++i) {
            sig.wotsSig[i] = _word(blob, 3 + i);
        }
        sig.authPath = new bytes32[](h);
        for (uint256 i = 0; i < h; ++i) {
            sig.authPath[i] = _word(blob, 70 + i);
        }
        encodedSig = abi.encode(sig);
    }

    function _word(bytes memory blob, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(blob, 32), mul(i, 32)))
        }
    }

    /// Guard-domain EIP-712 digest (name "FermionWalletGuard", version "1").
    function _guardDigest(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("FermionWalletGuard"), keccak256("1"), block.chainid, address(guard))
        );
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    /// Threshold (2-of-3) owner signatures over `digest`, sorted by signer address
    /// ascending as the Safe requires.
    function _ownerSigs(bytes32 digest) internal view returns (bytes memory) {
        uint256[3] memory pks = [OWNER1_PK, OWNER2_PK, OWNER3_PK];
        address[3] memory addrs = [owner1, owner2, owner3];
        for (uint256 i = 0; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (addrs[j] < addrs[i]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pks[0], digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pks[1], digest);
        return abi.encodePacked(r1, s1, v1, r2, s2, v2);
    }

    /// Owner-signed execTransaction with zeroed gas params (refunds are Guard-banned).
    function _safeExec(address to, uint256 value, bytes memory data, Enum.Operation op) internal {
        bytes32 txHash = safe.getTransactionHash(to, value, data, op, 0, 0, 0, address(0), address(0), safe.nonce());
        safe.execTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), _ownerSigs(txHash));
    }

    function _expectExecRevert(address to, uint256 value, bytes memory data) internal {
        _expectExecRevertOp(to, value, data, Enum.Operation.Call, "");
    }

    function _expectExecRevertWith(address to, uint256 value, bytes memory data, bytes memory err) internal {
        _expectExecRevertOp(to, value, data, Enum.Operation.Call, err);
    }

    function _expectExecRevertOp(address to, uint256 value, bytes memory data, Enum.Operation op, bytes memory err)
        internal
    {
        bytes32 txHash = safe.getTransactionHash(to, value, data, op, 0, 0, 0, address(0), address(0), safe.nonce());
        bytes memory sigs = _ownerSigs(txHash);
        if (err.length > 0) vm.expectRevert(err);
        else vm.expectRevert();
        safe.execTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), sigs);
    }

    /// Direct-prank batch structural check (same code path as execTransaction; the
    /// Safe's nonce is >= 1 by construction — see setUp).
    function _expectDirectBatchRevert(bytes memory txs, bytes memory err) internal {
        bytes memory data = abi.encodeWithSignature("multiSend(bytes)", txs);
        vm.expectRevert(err);
        vm.prank(address(safe));
        guard.checkTransaction(
            address(msco), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), "", relayer
        );
    }

    /// One packed MultiSend leg: uint8 op(0) | address to | uint256 value | uint256 len | data.
    function _leg(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    // ── Registration / ceremony helpers ─────────────────────────────────────

    function _ledgerAttestation(bytes32 root, bytes32 seed, uint32 h, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest =
            _guardDigest(keccak256(abi.encode(ATTEST_KEY_TYPEHASH, address(safe), root, seed, h, PARAM_SET, nonce)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerKey() internal returns (bytes32) {
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(
                    APPROVE_KEY_TYPEHASH, address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, nonce, validUntil
                )
            )
        );
        vm.prank(relayer);
        return guard.registerQuantumKey(
            address(safe),
            ledger,
            xmssRoot,
            xmssSeed,
            H,
            PARAM_SET,
            validUntil,
            _ledgerAttestation(xmssRoot, xmssSeed, H, nonce),
            _ownerSigs(digest)
        );
    }

    // ── Pre-approval builders ────────────────────────────────────────────────
    // approvalClass values: 0 = TRANSFER, 1 = PAYLOAD, 2 = ADMIN (explicit, since the
    // request struct itself is class-free).

    function _transferReq(address to, uint256 amount, uint32 leaf, bytes32 txHash)
        internal
        returns (PreApprovalEngine.PreApprovalRequest memory req)
    {
        return _transferReq2(address(token), to, amount, leaf, txHash);
    }

    function _transferReq2(address token_, address to, uint256 amount, uint32 leaf, bytes32 txHash)
        internal
        returns (PreApprovalEngine.PreApprovalRequest memory req)
    {
        req.safe = address(safe);
        req.token = token_;
        req.recipient = to;
        req.amount = amount;
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 2 days;
        req.nonce = bytes32(++approvalNonce);
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = leaf;
        req.policyHash = keccak256("policy-v1");
        req.txHash = txHash;
    }

    function _payloadReq(address target, uint256 value, bytes32 dataHash, uint32 leaf)
        internal
        returns (PreApprovalEngine.PreApprovalRequest memory req)
    {
        req.safe = address(safe);
        req.target = target;
        req.value = value;
        req.dataHash = dataHash;
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 2 days;
        req.nonce = bytes32(++approvalNonce);
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = leaf;
        req.policyHash = keccak256("policy-v1");
    }

    function _adminReq(address target, bytes32 dataHash, uint32 leaf)
        internal
        returns (PreApprovalEngine.PreApprovalRequest memory req)
    {
        req = _payloadReq(target, 0, dataHash, leaf);
        req.validFrom = uint64(block.timestamp) + ADMIN_TIMELOCK;
        req.validTo = req.validFrom + 2 days;
    }

    function _preApprovalDigest(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_)
        internal
        view
        returns (bytes32)
    {
        return _guardDigest(
            keccak256(
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
            )
        );
    }

    /// Both hybrid halves over the same digest: Ledger ECDSA + XMSS leaf via FFI.
    function _hybridSign(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_)
        internal
        returns (bytes memory ecdsaSig, bytes memory xmssSig)
    {
        bytes32 digest = _preApprovalDigest(req, class_);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        ecdsaSig = abi.encodePacked(r, s, v);
        (,, xmssSig) = _xmssSign(H, req.xmssLeafIndex, digest);
    }

    function _createTransfer(address to, uint256 amount, uint32 leaf, bytes32 txHash) internal returns (bytes32 id) {
        return _createTransfer2(address(token), to, amount, leaf, txHash);
    }

    function _createTransfer2(address token_, address to, uint256 amount, uint32 leaf, bytes32 txHash)
        internal
        returns (bytes32 id)
    {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq2(token_, to, amount, leaf, txHash);
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        vm.prank(relayer);
        id = guard.createPreApproval(req, ecdsaSig, xmssSig);
    }

    function _createPayload(address target, uint256 value, bytes32 dataHash, uint32 leaf)
        internal
        returns (bytes32 id)
    {
        PreApprovalEngine.PreApprovalRequest memory req = _payloadReq(target, value, dataHash, leaf);
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 1);
        vm.prank(relayer);
        id = guard.createPayloadPreApproval(req, ecdsaSig, xmssSig);
    }

    function _createAdmin(address target, bytes32 dataHash, uint32 leaf) internal returns (bytes32 id) {
        PreApprovalEngine.PreApprovalRequest memory req = _adminReq(target, dataHash, leaf);
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 2);
        vm.prank(relayer);
        id = guard.createAdminPreApproval(req, ecdsaSig, xmssSig);
    }
}

/// Attacker-deployed "Safe" whose signature check accepts anything — used to prove
/// that root squatting through a fake Safe cannot block a real Safe's key lifecycle.
contract FakeSafe {
    function checkSignatures(bytes32, bytes calldata, bytes memory) external pure {}
}
