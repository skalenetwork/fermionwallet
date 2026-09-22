// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";
import {ITransactionGuard} from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import {IModuleGuard} from "@safe-global/safe-contracts/contracts/base/ModuleManager.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {FermionWalletGuard} from "../src/FermionWalletGuard.sol";
import {PreApprovalEngine, NO_MATCHING_PRE_APPROVAL} from "../src/PreApprovalEngine.sol";
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
    /// After an emergency key revocation, a Safe transaction that was pinned under the
    /// revoked key can be re-approved with the new key at once — the dead pin (its key
    /// is revoked) must not block the slot until its possibly far-off validTo.
    function test_EmergencyRevocation_PinnedTxCanBeReapprovedWithNewKey() public {
        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        bytes32 pin = safe.getTransactionHash(
            address(token), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        // Long-lived pinned approval under the current key.
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, pin);
        req.validTo = uint64(block.timestamp) + 60 days;
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        vm.prank(relayer);
        guard.createPreApproval(req, ecdsaSig, xmssSig);

        // Emergency revocation of that key.
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 revokeDigest = _guardDigest(
            keccak256(
                abi.encode(REVOKE_KEY_TYPEHASH, address(safe), keyId, guard.registryNonce(address(safe)), validUntil)
            )
        );
        vm.prank(relayer);
        guard.requestKeyRevocation(address(safe), validUntil, _ownerSigs(revokeDigest));
        vm.warp(guard.keyRevocationExecutableAt(address(safe)) + 1);
        guard.executeKeyRevocation(address(safe));

        // Fresh registration of a new key (h = H_NEW).
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        uint256 nonce = guard.registryNonce(address(safe));
        // vm.getBlockTimestamp(): via-IR may reuse the pre-warp block.timestamp.
        validUntil = vm.getBlockTimestamp() + 1 days;
        bytes32 regDigest = _guardDigest(
            keccak256(
                abi.encode(APPROVE_KEY_TYPEHASH, address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, nonce, validUntil)
            )
        );
        vm.prank(relayer);
        keyId = guard.registerQuantumKey(
            address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil,
            _ledgerAttestation(newRoot, newSeed, H_NEW, nonce), _ownerSigs(regDigest)
        );

        // Re-approve the SAME pinned Safe transaction with the new key, then execute it.
        req = _transferReq(recipient, 1 ether, 1, pin);
        bytes32 digest = _preApprovalDigest(req, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        (,, xmssSig) = _xmssSign(H_NEW, 1, digest);
        vm.prank(relayer);
        guard.createPreApproval(req, abi.encodePacked(r, s, v), xmssSig);

        _safeExec(address(token), 0, data, Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

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

    // ══════════════ Regression: single-owner veto over governance ═══════════

    /// One owner must not be able to veto the threshold: the ADMIN approval that
    /// removes that owner is revocable by the Safe (threshold) or the Administrator,
    /// never by an individual owner.
    function test_SingleOwnerCannotRevokeAdminApproval() public {
        bytes memory removeOwner =
            abi.encodeWithSignature("removeOwner(address,address,uint256)", owner1, owner2, uint256(2));
        bytes32 id = _createAdmin(address(safe), keccak256(removeOwner), 1);

        vm.prank(owner2);
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.revokePreApproval(id);

        _safeExec(address(guard), 0, abi.encodeCall(PreApprovalEngine.revokePreApproval, (id)), Enum.Operation.Call);
        assertTrue(guard.getPreApproval(id).revoked);
    }

    function _createAdmin(address target, bytes32 dataHash, uint32 leaf) internal returns (bytes32 id) {
        PreApprovalEngine.PreApprovalRequest memory req = _adminReq(target, dataHash, leaf);
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 2);
        vm.prank(relayer);
        id = guard.createAdminPreApproval(req, ecdsaSig, xmssSig);
    }

    // ══════════ Regression: escape hatch must not carry a gas refund ══════════

    /// The escape hatch returns before any other check — it must not also skip the
    /// refund ban. Otherwise owner-threshold signatures alone (the exact thing the
    /// quantum layer distrusts) drain any token as a "gas refund" of an escape call.
    function test_EscapeHatch_GasRefund_CannotDrain() public {
        address thief = makeAddr("thief");
        bytes memory data = abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ());
        uint256 baseGas = 100_000;
        uint256 gasPrice = 1 ether; // token units per gas → ~1e5 ether refund
        bytes32 txHash = safe.getTransactionHash(
            address(guard), 0, data, Enum.Operation.Call, 0, baseGas, gasPrice, address(token), thief, safe.nonce()
        );
        bytes memory sigs = _ownerSigs(txHash);
        vm.expectRevert(FermionWalletGuard.GasRefundForbidden.selector);
        safe.execTransaction(
            address(guard), 0, data, Enum.Operation.Call, 0, baseGas, gasPrice, address(token), payable(thief), sigs
        );
        assertEq(token.balanceOf(thief), 0);
    }

    // ══════ Regression: MultiSend leg `to == address(0)` is the Safe itself ══════

    /// MultiSendCallOnly rewrites a zero leg target to address(this) — the Safe, under
    /// delegatecall. A zero-target leg is therefore a Safe self-call smuggled into a
    /// PAYLOAD batch (no ADMIN class, no ADMIN_TIMELOCK), e.g. enableModule when the
    /// Safe permit-lists that selector for a Zodiac-style modifier contract.
    function test_Batch_LegZeroTarget_IsSafeSelfCall_Reverts() public {
        bytes memory policy = abi.encodeCall(
            FermionWalletGuard.setSelectorPolicy, (address(safe), bytes4(keccak256("enableModule(address)")), true)
        );
        _createAdmin(address(guard), keccak256(policy), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(guard), 0, policy, Enum.Operation.Call);

        address evilModule = makeAddr("evilModule");
        bytes memory leg = abi.encodeWithSignature("enableModule(address)", evilModule);
        bytes memory data = abi.encodeWithSignature("multiSend(bytes)", _leg(address(0), 0, leg));
        _createPayload(address(msco), 0, keccak256(data), 2);
        _expectExecRevertOp(
            address(msco),
            0,
            data,
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(FermionWalletGuard.ForbiddenBatchLegTarget.selector, address(0))
        );
        assertFalse(safe.isModuleEnabled(evilModule));
    }

    // ═══ Regression: dead Tier-2 entries behind a scheduled one jam the cap ═══

    /// Spec: dead entries "never count toward the cap and cannot jam the queue". A
    /// scheduled (future validFrom) approval at the head must not let used entries
    /// pile up behind it until identical recurring payouts can no longer be approved.
    function test_Tier2_DeadEntriesBehindScheduledApproval_DoNotFillQueue() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        req.validFrom = uint64(block.timestamp) + 1 days;
        req.validTo = req.validFrom + 2 days;
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        vm.prank(relayer);
        bytes32 scheduled = guard.createPreApproval(req, ecdsaSig, xmssSig);

        bytes memory pay = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        for (uint32 i = 0; i < MAX_QUEUE; ++i) {
            _createTransfer(recipient, 1 ether, 2 + i, bytes32(0)); // reverted CommitmentQueueFull before the fix
            _safeExec(address(token), 0, pay, Enum.Operation.Call);
        }
        assertEq(token.balanceOf(recipient), MAX_QUEUE * 1 ether);
        assertFalse(guard.getPreApproval(scheduled).used);

        vm.warp(block.timestamp + 1 days);
        _safeExec(address(token), 0, pay, Enum.Operation.Call);
        assertTrue(guard.getPreApproval(scheduled).used);
    }

    // ══ Regression: a nested escape call must not reset the reentrancy depth ══

    /// An escape-hatch transaction nested inside an approved one used to clear the
    /// depth flag in its checkAfterExecution, re-opening the door for a further
    /// nested (non-escape) Safe transaction within the same outer execution.
    function test_Reentrancy_NestedEscapeCallDoesNotResetDepth() public {
        EscapeThenReenterToken attacker = new EscapeThenReenterToken(safe);
        _createTransfer2(address(attacker), recipient, 1 ether, 1, bytes32(0));
        _createTransfer(recipient, 2 ether, 2, bytes32(0));

        uint256 n = safe.nonce();
        bytes memory escData = abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ());
        bytes32 escHash = safe.getTransactionHash(
            address(guard), 0, escData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), n + 1
        );
        bytes memory innerData = abi.encodeCall(IERC20.transfer, (recipient, 2 ether));
        bytes32 innerHash = safe.getTransactionHash(
            address(token), 0, innerData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), n + 2
        );
        attacker.arm(address(guard), escData, _ownerSigs(escHash), address(token), innerData, _ownerSigs(innerHash));

        bytes memory outerData = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        bytes32 outerHash = safe.getTransactionHash(
            address(attacker), 0, outerData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), n
        );
        bytes memory sigs = _ownerSigs(outerHash);
        vm.expectRevert();
        safe.execTransaction(
            address(attacker), 0, outerData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sigs
        );
        assertEq(token.balanceOf(recipient), 0);
    }

    // ═══ Regression: re-registration must not reset the owners' permit-list ═══

    /// Emergency-revoke the current key and register a fresh h = H_NEW key.
    function _revokeAndReregister() internal {
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 revokeDigest = _guardDigest(
            keccak256(
                abi.encode(REVOKE_KEY_TYPEHASH, address(safe), keyId, guard.registryNonce(address(safe)), validUntil)
            )
        );
        vm.prank(relayer);
        guard.requestKeyRevocation(address(safe), validUntil, _ownerSigs(revokeDigest));
        vm.warp(guard.keyRevocationExecutableAt(address(safe)) + 1);
        guard.executeKeyRevocation(address(safe));

        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        uint256 nonce = guard.registryNonce(address(safe));
        validUntil = vm.getBlockTimestamp() + 1 days;
        bytes32 regDigest = _guardDigest(
            keccak256(
                abi.encode(APPROVE_KEY_TYPEHASH, address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, nonce, validUntil)
            )
        );
        vm.prank(relayer);
        keyId = guard.registerQuantumKey(
            address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil,
            _ledgerAttestation(newRoot, newSeed, H_NEW, nonce), _ownerSigs(regDigest)
        );
    }

    function _disableTransferSelector() internal {
        bytes memory policy =
            abi.encodeCall(FermionWalletGuard.setSelectorPolicy, (address(safe), IERC20.transfer.selector, false));
        _createAdmin(address(guard), keccak256(policy), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(guard), 0, policy, Enum.Operation.Call);
        assertFalse(guard.allowedSelectors(address(safe), IERC20.transfer.selector));
    }

    /// The permit-list is initialised at FIRST enrollment only. Registering a new key
    /// after an emergency revocation (no owner vote on the permit-list) used to rerun
    /// the initialisation and silently re-enable `transfer` the owners had disabled.
    function test_Reregistration_DoesNotReenableDisabledTransfer() public {
        _disableTransferSelector();
        _revokeAndReregister();
        assertFalse(guard.allowedSelectors(address(safe), IERC20.transfer.selector));
    }

    /// Removing `transfer` from the permit-list must actually stop TRANSFER-class
    /// execution — directly and inside batches — even with a matching approval.
    function test_DisabledTransferSelector_BlocksTransfers() public {
        _disableTransferSelector();
        bytes memory pay = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        _createTransfer(recipient, 1 ether, 2, bytes32(0));
        _expectExecRevertWith(
            address(token),
            0,
            pay,
            abi.encodeWithSelector(FermionWalletGuard.SelectorNotAllowed.selector, address(safe), IERC20.transfer.selector)
        );

        bytes memory batch = abi.encodeWithSignature("multiSend(bytes)", _leg(address(token), 0, pay));
        _createPayload(address(msco), 0, keccak256(batch), 3);
        _expectExecRevertOp(
            address(msco),
            0,
            batch,
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(FermionWalletGuard.SelectorNotAllowed.selector, address(safe), IERC20.transfer.selector)
        );
        assertEq(token.balanceOf(recipient), 0);
    }

    // ═══ Coverage: escape hatch, depth counter, queue compaction (second review) ═══
    // Foundry clears transient storage between the test's top-level calls, so depth
    // leaks are only observable when several execTransactions share ONE call: the
    // SafeTxBatcher below runs them back to back inside a single EVM call frame.

    /// Sign the next `tos.length` Safe transactions (consecutive nonces).
    function _signedBatch(address[] memory tos, bytes[] memory datas, uint256[] memory safeTxGas)
        internal
        view
        returns (SafeTxBatcher.SafeCall[] memory calls)
    {
        calls = new SafeTxBatcher.SafeCall[](tos.length);
        uint256 n = safe.nonce();
        for (uint256 i = 0; i < tos.length; ++i) {
            bytes32 h = safe.getTransactionHash(
                tos[i], 0, datas[i], Enum.Operation.Call, safeTxGas[i], 0, 0, address(0), address(0), n + i
            );
            calls[i] = SafeTxBatcher.SafeCall(tos[i], datas[i], safeTxGas[i], _ownerSigs(h));
        }
    }

    /// Every owner safety call still goes through (gasPrice = 0) while the Safe is
    /// paused AND its posture is bad (fallback handler set) — and each one leaves the
    /// transient depth at zero: a quantum-approved transaction executed right after
    /// them in the SAME call frame is not mistaken for a nested one.
    function test_EscapeHatch_AllOwnerSafetyCallsPass_DepthReturnsToZero() public {
        bytes32 doomed = _createTransfer(recipient, 5 ether, 1, bytes32(0));
        bytes memory removeGuard = abi.encodeWithSignature("setGuard(address)", address(0));
        _createAdmin(address(safe), keccak256(removeGuard), 2);

        uint256 validUntil = block.timestamp + 1 days;
        bytes32 revokeDigest = _guardDigest(
            keccak256(
                abi.encode(REVOKE_KEY_TYPEHASH, address(safe), keyId, guard.registryNonce(address(safe)), validUntil)
            )
        );
        vm.prank(relayer);
        guard.requestKeyRevocation(address(safe), validUntil, _ownerSigs(revokeDigest));

        _safeExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.pauseSafe, (address(safe))), Enum.Operation.Call);
        _safeExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.requestUnpauseSafe, ()), Enum.Operation.Call);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1); // unpause + ADMIN approval mature
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(makeAddr("evilHandler")))));

        address[] memory tos = new address[](8);
        bytes[] memory datas = new bytes[](8);
        uint256[] memory gasArr = new uint256[](8);
        for (uint256 i = 0; i < 7; ++i) {
            tos[i] = address(guard);
        }
        datas[0] = abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ());
        datas[1] = abi.encodeCall(FermionWalletGuard.cancelEmergencyDeGuard, (address(safe)));
        datas[2] = abi.encodeCall(PreApprovalEngine.revokePreApproval, (doomed));
        datas[3] = abi.encodeCall(QuantumKeyRegistry.cancelKeyRevocation, (address(safe)));
        datas[4] = abi.encodeCall(FermionWalletGuard.unpauseSafe, ());
        datas[5] = abi.encodeCall(FermionWalletGuard.pauseSafe, (address(safe)));
        datas[6] = abi.encodeCall(FermionWalletGuard.requestUnpauseSafe, ());
        // Last: the quantum-approved Guard removal — a non-escape transaction that
        // passes the depth check (and works while paused with a bad posture).
        tos[7] = address(safe);
        datas[7] = removeGuard;

        SafeTxBatcher batcher = new SafeTxBatcher(safe);
        batcher.run(_signedBatch(tos, datas, gasArr));

        assertTrue(guard.getPreApproval(doomed).revoked);
        assertEq(guard.keyRevocationExecutableAt(address(safe)), 0);
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0);
        assertTrue(guard.safePaused(address(safe)));
        assertEq(uint256(vm.load(address(safe), GUARD_SLOT)), 0); // Guard detached
    }

    /// keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// Transactions whose inner call FAILS (safeTxGas != 0, so the Safe does not
    /// revert) still get checkAfterExecution and decrement the depth — both for an
    /// escape call and for an approved one — so the next one in the same frame runs.
    function test_Depth_FailedExecutionsStillUnwind() public {
        uint256 tooMuch = token.balanceOf(address(safe)) + 1;
        bytes32 failing = _createTransfer(recipient, tooMuch, 1, bytes32(0));
        _createTransfer(recipient, 1 ether, 2, bytes32(0));

        address[] memory tos = new address[](3);
        bytes[] memory datas = new bytes[](3);
        uint256[] memory gasArr = new uint256[](3);
        tos[0] = address(guard); // escape call reverting inside the Guard (nothing to cancel)
        datas[0] = abi.encodeCall(FermionWalletGuard.cancelEmergencyDeGuard, (address(safe)));
        gasArr[0] = 100_000;
        tos[1] = address(token); // approved transfer reverting inside the token
        datas[1] = abi.encodeCall(IERC20.transfer, (recipient, tooMuch));
        gasArr[1] = 100_000;
        tos[2] = address(token);
        datas[2] = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));

        SafeTxBatcher batcher = new SafeTxBatcher(safe);
        bool[] memory ok = batcher.run(_signedBatch(tos, datas, gasArr));
        assertFalse(ok[0]);
        assertFalse(ok[1]);
        assertTrue(ok[2]);
        assertTrue(guard.getPreApproval(failing).used); // consumed even though execution failed
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    /// Compaction at the cap keeps the survivors in FIFO order: live approvals queued
    /// behind a scheduled head and a run of used entries are consumed oldest-first.
    function test_Tier2_CompactionPreservesFifo() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        req.validFrom = uint64(block.timestamp) + 1 days;
        req.validTo = req.validFrom + 2 days;
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        vm.prank(relayer);
        bytes32 scheduled = guard.createPreApproval(req, ecdsaSig, xmssSig);

        bytes memory pay = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        uint32 leaf = 2;
        // Queue: [S, U1..U5] — five used entries stuck behind the scheduled head.
        for (uint256 i = 0; i < 5; ++i) {
            _createTransfer(recipient, 1 ether, leaf++, bytes32(0));
            _safeExec(address(token), 0, pay, Enum.Operation.Call);
        }
        // [S, U1..U5, L1, L2] fills the cap (8); L3 triggers compaction → [S, L1, L2, L3].
        bytes32[3] memory live;
        for (uint256 i = 0; i < 3; ++i) {
            live[i] = _createTransfer(recipient, 1 ether, leaf++, bytes32(0));
        }
        for (uint256 i = 0; i < 3; ++i) {
            _safeExec(address(token), 0, pay, Enum.Operation.Call);
            assertTrue(guard.getPreApproval(live[i]).used);
            if (i < 2) assertFalse(guard.getPreApproval(live[i + 1]).used);
        }
        assertFalse(guard.getPreApproval(scheduled).used);
    }

    // ═══ Regression: two bad-posture remediations must not block each other ═══

    /// A Safe can reach "fallback handler AND unguarded module" legitimately: enroll
    /// with a clean posture, install a handler and a module while still unguarded,
    /// then attach the Guard. Each remediation used to be exempt only from its own
    /// posture check, so disableModule died on the handler and setFallbackHandler(0)
    /// on the module — nothing but a full Guard removal could fix the posture.
    function test_PostureRemediations_DoNotDeadlockEachOther() public {
        address module = makeAddr("module");
        // Safe storage: slot 1 = modules linked list (SENTINEL → module → SENTINEL).
        vm.store(address(safe), keccak256(abi.encode(address(1), uint256(1))), bytes32(uint256(uint160(module))));
        vm.store(address(safe), keccak256(abi.encode(module, uint256(1))), bytes32(uint256(1)));
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(makeAddr("handler")))));
        assertTrue(safe.isModuleEnabled(module));

        bytes memory disable = abi.encodeWithSignature("disableModule(address,address)", address(1), module);
        bytes memory clear = abi.encodeWithSignature("setFallbackHandler(address)", address(0));
        _createAdmin(address(safe), keccak256(disable), 1);
        _createAdmin(address(safe), keccak256(clear), 2);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);

        _safeExec(address(safe), 0, disable, Enum.Operation.Call);
        _safeExec(address(safe), 0, clear, Enum.Operation.Call);
        assertFalse(safe.isModuleEnabled(module));

        _createTransfer(recipient, 1 ether, 3, bytes32(0));
        _safeExec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)), Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    // ═══════════════ Threat model (threat-model.md) — claim by claim ═════════════

    /// §2.1: "neither pausing nor key rotation stops the de-guard clock", and the
    /// matured owners-only removal works while paused. The Administrator pauses (its
    /// fast-pause right) and a routine rotation happens mid-window; the clock runs on.
    function test_TM_DeGuardClockSurvivesPauseAndRotation() public {
        _safeExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call);
        uint64 executableAt = guard.emergencyDeGuardExecutableAt(address(safe));
        assertEq(executableAt, uint64(block.timestamp) + EMERGENCY_TIMELOCK);

        vm.prank(ledger);
        guard.pauseSafe(address(safe));
        _rotateToNewKey(6);
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), executableAt);

        vm.warp(executableAt);
        _safeExec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)), Enum.Operation.Call);
        assertEq(address(uint160(uint256(vm.load(address(safe), GUARD_SLOT)))), address(0));
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0);
    }

    /// §2.3: owners clear-sign ApproveQuantumKey{safe, quantumAdmin, xmssRoot, ...,
    /// registryNonce, validUntil}: a swapped root, a swapped Administrator, or a stale
    /// (aborted-session) nonce invalidates every owner signature.
    function test_TM_CeremonySubstitutionAndStaleNonceRejected() public {
        _revokeKey();
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = vm.getBlockTimestamp() + 1 days;
        bytes memory sigs = _ownerSigs(_approveKeyDigest(ledger, newRoot, newSeed, nonce, validUntil));

        // Frontend swaps in the attacker's root (attested by the Ledger, even).
        (bytes32 evilRoot, bytes32 evilSeed,) = _xmssSign(3, 0, bytes32(uint256(1))); // a never-registered key
        bytes memory evilAttest = _ledgerAttestation(evilRoot, evilSeed, H_NEW, nonce);
        vm.expectRevert(bytes("GS026")); // Safe checkSignatures: the owners never signed this root
        guard.registerQuantumKey(address(safe), ledger, evilRoot, evilSeed, H_NEW, PARAM_SET, validUntil, evilAttest, sigs);

        // Frontend swaps in the attacker's Administrator address (with its attestation).
        uint256 attackerPk = 0xBAD;
        address attacker = vm.addr(attackerPk);
        bytes32 attestDigest = _guardDigest(
            keccak256(abi.encode(ATTEST_KEY_TYPEHASH, address(safe), newRoot, newSeed, H_NEW, PARAM_SET, nonce))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPk, attestDigest);
        vm.expectRevert(bytes("GS026"));
        guard.registerQuantumKey(
            address(safe), attacker, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, abi.encodePacked(r, s, v), sigs
        );

        // A ceremony signed before the nonce advanced (aborted session) is dead.
        bytes memory staleSigs = _ownerSigs(_approveKeyDigest(ledger, newRoot, newSeed, nonce - 1, validUntil));
        bytes memory attest = _ledgerAttestation(newRoot, newSeed, H_NEW, nonce);
        vm.expectRevert(bytes("GS026"));
        guard.registerQuantumKey(address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, attest, staleSigs);

        // Past its deadline, even the genuine ceremony is refused.
        uint256 deadline = vm.getBlockTimestamp() + 1 days;
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.SignatureExpired.selector, validUntil));
        guard.registerQuantumKey(address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, attest, sigs);
    }

    /// §2.9: a mempool copy of registerQuantumKey executes identically (the relayer
    /// has no authority; nothing is redirectable) and a second submission reverts.
    function test_TM_FrontRunRegistration_ExecutesIdentically() public {
        _revokeKey();
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = vm.getBlockTimestamp() + 1 days;
        bytes memory sigs = _ownerSigs(_approveKeyDigest(ledger, newRoot, newSeed, nonce, validUntil));
        bytes memory attest = _ledgerAttestation(newRoot, newSeed, H_NEW, nonce);

        vm.prank(makeAddr("frontRunner"));
        bytes32 id =
            guard.registerQuantumKey(address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, attest, sigs);
        QuantumKeyRegistry.KeyRegistration memory k = guard.getKey(id);
        assertEq(k.safe, address(safe));
        assertEq(k.quantumAdmin, ledger);
        assertEq(k.xmssRoot, newRoot);
        assertEq(guard.safeToQuantumKey(address(safe)), id);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.SafeAlreadyEnrolled.selector, address(safe)));
        guard.registerQuantumKey(address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, attest, sigs);
    }

    /// §2.9: a front-runner submitting the same createPreApproval calldata creates
    /// exactly the approval the Administrator signed; the relayer's copy reverts.
    function test_TM_FrontRunCreatePreApproval_SecondSubmissionReverts() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);

        vm.prank(makeAddr("frontRunner"));
        bytes32 id = guard.createPreApproval(req, ecdsaSig, xmssSig);
        PreApprovalEngine.PreApproval memory a = guard.getPreApproval(id);
        assertEq(a.safe, address(safe));
        assertEq(a.recipient, recipient);
        assertEq(a.amount, 1 ether);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(PreApprovalEngine.ApprovalExists.selector, id));
        guard.createPreApproval(req, ecdsaSig, xmssSig);
    }

    /// Guard spec, "Cross-chain replay": the EIP-712 domain binds block.chainid, so an
    /// approval signed for this chain verifies nowhere else — including on a fork.
    function test_TM_CrossChainReplayRejected() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        assertEq(block.chainid, 31337);
        vm.chainId(10); // (literals: via-IR may re-read block.chainid for a local copy)
        vm.prank(relayer);
        vm.expectRevert(PreApprovalEngine.InvalidEcdsaSignature.selector);
        guard.createPreApproval(req, ecdsaSig, xmssSig);
        vm.chainId(31337);
        vm.prank(relayer);
        guard.createPreApproval(req, ecdsaSig, xmssSig);
    }

    /// Registry invariants: after rotation the old key "can create nothing new", while
    /// every registration, rotation, revocation request and revocation consumes the
    /// registry nonce.
    function test_TM_RotatedKeyCreatesNothing_NonceConsumedByEveryStep() public {
        uint256 n0 = guard.registryNonce(address(safe));
        bytes32 oldKeyId = keyId;
        bytes32 newKeyId = _rotateToNewKey(6);
        assertEq(guard.registryNonce(address(safe)), n0 + 1);

        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        req.quantumKeyId = oldKeyId;
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(PreApprovalEngine.WrongQuantumKey.selector, newKeyId, oldKeyId));
        guard.createPreApproval(req, ecdsaSig, xmssSig);

        keyId = newKeyId;
        uint256 n1 = guard.registryNonce(address(safe));
        _revokeKey(); // request + execute
        assertEq(guard.registryNonce(address(safe)), n1 + 2);
    }

    /// pre-approval-engine.md, "At execution": a Revoked key's approvals are dead —
    /// also after a fresh key is registered for the same Safe.
    function test_TM_RevokedKeyApprovalsStayDeadAfterReregistration() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        req.validTo = uint64(block.timestamp) + 60 days; // outlives the revocation timelock
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        vm.prank(relayer);
        bytes32 id = guard.createPreApproval(req, ecdsaSig, xmssSig);
        _revokeAndReregister();
        (bool valid, string memory reason) = guard.validatePreApproval(id);
        assertFalse(valid);
        assertEq(reason, "key revoked");
        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        _expectExecRevertWith(address(token), 0, data, abi.encodeWithSignature("Error(string)", NO_MATCHING_PRE_APPROVAL));
    }

    /// quantum-key-registry.md: registration is refused while the Safe has a fallback
    /// handler or an unguarded enabled module (the enrollment posture check).
    function test_TM_RegistrationRefusedWithBadPosture() public {
        _revokeKey();
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = vm.getBlockTimestamp() + 1 days;
        bytes memory sigs = _ownerSigs(_approveKeyDigest(ledger, newRoot, newSeed, nonce, validUntil));
        bytes memory attest = _ledgerAttestation(newRoot, newSeed, H_NEW, nonce);

        address handler = makeAddr("handler");
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(handler))));
        vm.expectRevert(abi.encodeWithSelector(FermionWalletGuard.FallbackHandlerForbidden.selector, address(safe), handler));
        guard.registerQuantumKey(address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, attest, sigs);
        vm.store(address(safe), FALLBACK_SLOT, bytes32(0));

        address module = makeAddr("module");
        vm.store(address(safe), keccak256(abi.encode(address(1), uint256(1))), bytes32(uint256(uint160(module))));
        vm.store(address(safe), keccak256(abi.encode(module, uint256(1))), bytes32(uint256(1)));
        vm.expectRevert(
            abi.encodeWithSelector(FermionWalletGuard.ModulesEnabledWithoutModuleGuard.selector, address(safe))
        );
        guard.registerQuantumKey(address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, attest, sigs);
    }

    /// pre-approval-engine.md, "Validation rules" at creation: class-irrelevant fields
    /// must be zero, ADMIN targets only the Safe or this Guard, and TRANSFER/PAYLOAD
    /// reject zero addresses — all before any signature work.
    function test_TM_CreationShapeRules() public {
        PreApprovalEngine.PreApprovalRequest memory req = _transferReq(recipient, 1 ether, 1, bytes32(0));
        req.value = 1;
        vm.expectRevert(PreApprovalEngine.NonZeroClassFields.selector);
        guard.createPreApproval(req, "", "");
        req.value = 0;
        req.recipient = address(0);
        vm.expectRevert(QuantumKeyRegistry.ZeroAddress.selector);
        guard.createPreApproval(req, "", "");

        req = _payloadReq(recipient, 1 ether, bytes32(0), 1);
        req.amount = 1;
        vm.expectRevert(PreApprovalEngine.NonZeroClassFields.selector);
        guard.createPayloadPreApproval(req, "", "");
        req.amount = 0;
        req.target = address(0);
        vm.expectRevert(QuantumKeyRegistry.ZeroAddress.selector);
        guard.createPayloadPreApproval(req, "", "");

        req = _adminReq(address(token), bytes32(0), 1);
        vm.expectRevert(abi.encodeWithSelector(PreApprovalEngine.InvalidAdminTarget.selector, address(token)));
        guard.createAdminPreApproval(req, "", "");
        req = _adminReq(address(safe), bytes32(0), 1);
        req.token = address(token);
        vm.expectRevert(PreApprovalEngine.NonZeroClassFields.selector);
        guard.createAdminPreApproval(req, "", "");
    }

    /// Guard spec, "Required inheritance" + "Immutability and deployment hygiene":
    /// supportsInterface reports exactly Safe's ITransactionGuard / IModuleGuard IDs
    /// plus ERC-165, and the constructor validates its deployment parameters.
    function test_TM_InterfaceIdsAndConstructorValidation() public {
        assertTrue(guard.supportsInterface(type(ITransactionGuard).interfaceId));
        assertTrue(guard.supportsInterface(type(IModuleGuard).interfaceId));
        assertTrue(guard.supportsInterface(type(IERC165).interfaceId));
        assertFalse(guard.supportsInterface(0xffffffff));
        assertFalse(guard.supportsInterface(type(IERC20).interfaceId));

        vm.expectRevert(QuantumKeyRegistry.ZeroAddress.selector);
        new FermionWalletGuard(address(0), 2 days, 14 days, 4, 8);
        vm.expectRevert(QuantumKeyRegistry.InvalidKeyParams.selector);
        new FermionWalletGuard(makeAddr("noCode"), 2 days, 14 days, 4, 8);
        vm.expectRevert(bytes("EMERGENCY_TIMELOCK must exceed ADMIN_TIMELOCK"));
        new FermionWalletGuard(address(msco), 2 days, 2 days, 4, 8);
    }

    /// Residual risk documented in threat-model.md §2.1: once an emergency revocation
    /// executes, the next registration needs only classical signatures (owner
    /// threshold + an attestation by whatever quantumAdmin the owners signed). A
    /// quantum attacker holding the owner keys can therefore register ITS key in the
    /// same block the revocation matures and win the race against the honest owners'
    /// ceremony. The 14-day public countdown is the only on-chain protection.
    function test_TM_ResidualRisk_PostRevocationRegistrationIsClassicalOnly() public {
        _revokeKey();
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = vm.getBlockTimestamp() + 1 days;

        // Attacker: forged owner signatures (here: the real keys) over its own
        // Administrator address and XMSS root.
        uint256 attackerPk = 0xBAD;
        address attacker = vm.addr(attackerPk);
        (bytes32 evilRoot, bytes32 evilSeed,) = _xmssSign(3, 0, bytes32(uint256(1)));
        bytes32 attestDigest = _guardDigest(
            keccak256(abi.encode(ATTEST_KEY_TYPEHASH, address(safe), evilRoot, evilSeed, H_NEW, PARAM_SET, nonce))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPk, attestDigest);
        vm.prank(attacker);
        bytes32 evilKey = guard.registerQuantumKey(
            address(safe), attacker, evilRoot, evilSeed, H_NEW, PARAM_SET, validUntil, abi.encodePacked(r, s, v),
            _ownerSigs(_approveKeyDigest(attacker, evilRoot, evilSeed, nonce, validUntil))
        );
        assertEq(guard.safeToQuantumKey(address(safe)), evilKey);
        assertEq(guard.getKey(evilKey).quantumAdmin, attacker);

        // The honest ceremony, signed for the same nonce, now reverts.
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        bytes memory sigs = _ownerSigs(_approveKeyDigest(ledger, newRoot, newSeed, nonce, validUntil));
        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.SafeAlreadyEnrolled.selector, address(safe)));
        guard.registerQuantumKey(
            address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil,
            _ledgerAttestation(newRoot, newSeed, H_NEW, nonce), sigs
        );
    }

    // ── Module path (Safe >= 1.5, "Module bypass — mandatory mitigation") ────

    /// Wires the Guard as module guard, then enables `module` (leaves 1..3).
    function _enableModule() internal returns (address module) {
        module = makeAddr("module");
        bytes memory wire = abi.encodeWithSignature("setModuleGuard(address)", address(guard));
        _createAdmin(address(safe), keccak256(wire), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, wire, Enum.Operation.Call);
        bytes memory enable = abi.encodeWithSignature("enableModule(address)", module);
        _createAdmin(address(safe), keccak256(enable), 2);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, enable, Enum.Operation.Call);
        assertTrue(safe.isModuleEnabled(module));
    }

    /// A module transaction needs a Tier-2 approval like any owner transaction; a
    /// pinned (Tier-1) approval never matches it (no safeTxHash); the module address
    /// is logged.
    function test_TM_ModulePath_NeedsTier2Approval() public {
        address module = _enableModule();
        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));

        vm.prank(module);
        vm.expectRevert(bytes(NO_MATCHING_PRE_APPROVAL));
        safe.execTransactionFromModule(address(token), 0, data, Enum.Operation.Call);

        _createTransfer(recipient, 1 ether, 3, keccak256("some pinned safeTxHash"));
        vm.prank(module);
        vm.expectRevert(bytes(NO_MATCHING_PRE_APPROVAL));
        safe.execTransactionFromModule(address(token), 0, data, Enum.Operation.Call);

        bytes32 id = _createTransfer(recipient, 1 ether, 4, bytes32(0));
        vm.expectEmit(true, true, true, false, address(guard));
        emit FermionWalletGuard.ModuleTransactionChecked(address(safe), module, id);
        vm.prank(module);
        assertTrue(safe.execTransactionFromModule(address(token), 0, data, Enum.Operation.Call));
        assertEq(token.balanceOf(recipient), 1 ether);
        assertTrue(guard.getPreApproval(id).used);
    }

    /// Module-specific rules: DELEGATECALL is always rejected (no MultiSend exception),
    /// the Safe's pause applies, and a module can never install a fallback handler.
    function test_TM_ModulePath_DelegatecallPauseAndHandlerRules() public {
        address module = _enableModule();

        bytes memory batch = abi.encodeWithSignature(
            "multiSend(bytes)", _leg(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)))
        );
        vm.prank(module);
        vm.expectRevert(abi.encodeWithSelector(FermionWalletGuard.ModuleDelegateCallForbidden.selector, module));
        safe.execTransactionFromModule(address(msco), 0, batch, Enum.Operation.DelegateCall);

        address handler = makeAddr("handler");
        vm.prank(module);
        vm.expectRevert(abi.encodeWithSelector(FermionWalletGuard.FallbackHandlerForbidden.selector, address(safe), handler));
        safe.execTransactionFromModule(
            address(safe), 0, abi.encodeWithSignature("setFallbackHandler(address)", handler), Enum.Operation.Call
        );

        _createTransfer(recipient, 1 ether, 3, bytes32(0));
        vm.prank(owner1);
        guard.pauseSafe(address(safe));
        vm.prank(module);
        vm.expectRevert(abi.encodeWithSelector(FermionWalletGuard.SafePausedError.selector, address(safe)));
        safe.execTransactionFromModule(
            address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)), Enum.Operation.Call
        );
    }

    /// Emergency de-guard, step 4: a module-executed (ADMIN-approved) setGuard also
    /// ends the Guard's tenure and clears the pending emergency request.
    function test_TM_ModuleExecutedSetGuardClearsEmergencyRequest() public {
        address module = _enableModule();
        _safeExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call);
        assertGt(guard.emergencyDeGuardExecutableAt(address(safe)), 0);

        bytes memory remove = abi.encodeWithSignature("setGuard(address)", address(0));
        _createAdmin(address(safe), keccak256(remove), 3);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        vm.prank(module);
        assertTrue(safe.execTransactionFromModule(address(safe), 0, remove, Enum.Operation.Call));
        assertEq(address(uint160(uint256(vm.load(address(safe), GUARD_SLOT)))), address(0));
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0);
    }

    // ── Threat-model helpers ─────────────────────────────────────────────────

    function _approveKeyDigest(address admin, bytes32 root, bytes32 seed, uint256 nonce, uint256 validUntil)
        internal
        view
        returns (bytes32)
    {
        return _guardDigest(
            keccak256(abi.encode(APPROVE_KEY_TYPEHASH, address(safe), admin, root, seed, H_NEW, PARAM_SET, nonce, validUntil))
        );
    }

    /// Emergency revocation of the current key (request + timelock + execute).
    function _revokeKey() internal {
        uint256 validUntil = vm.getBlockTimestamp() + 1 days;
        bytes32 revokeDigest = _guardDigest(
            keccak256(
                abi.encode(REVOKE_KEY_TYPEHASH, address(safe), keyId, guard.registryNonce(address(safe)), validUntil)
            )
        );
        vm.prank(relayer);
        guard.requestKeyRevocation(address(safe), validUntil, _ownerSigs(revokeDigest));
        vm.warp(guard.keyRevocationExecutableAt(address(safe)) + 1);
        guard.executeKeyRevocation(address(safe));
        assertEq(guard.safeToQuantumKey(address(safe)), bytes32(0));
    }

    /// Routine rotation to a fresh h = H_NEW key, old-key proof at `oldLeaf`.
    function _rotateToNewKey(uint32 oldLeaf) internal returns (bytes32 newKeyId) {
        (bytes32 newRoot, bytes32 newSeed,) = _xmssSign(H_NEW, 0, bytes32(uint256(1)));
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = vm.getBlockTimestamp() + 1 days;
        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(
                    ROTATE_KEY_TYPEHASH, address(safe), keyId, ledger, newRoot, newSeed, H_NEW, PARAM_SET, nonce, validUntil
                )
            )
        );
        (,, bytes memory oldKeyProof) = _xmssSign(H, oldLeaf, digest);
        vm.prank(relayer);
        newKeyId = guard.rotateQuantumKey(
            address(safe), ledger, newRoot, newSeed, H_NEW, PARAM_SET, validUntil, oldKeyProof,
            _ledgerAttestation(newRoot, newSeed, H_NEW, nonce), _ownerSigs(digest)
        );
    }
}

/// Re-enters Safe.execTransaction twice from inside an approved outer transaction:
/// first an escape-hatch call, then a pre-approved transfer.
contract EscapeThenReenterToken {
    Safe internal immutable SAFE;
    address internal escTo;
    bytes internal escData;
    bytes internal escSigs;
    address internal innerTo;
    bytes internal innerData;
    bytes internal innerSigs;

    constructor(Safe safe_) {
        SAFE = safe_;
    }

    function arm(
        address escTo_,
        bytes calldata escData_,
        bytes calldata escSigs_,
        address innerTo_,
        bytes calldata innerData_,
        bytes calldata innerSigs_
    ) external {
        (escTo, escData, escSigs) = (escTo_, escData_, escSigs_);
        (innerTo, innerData, innerSigs) = (innerTo_, innerData_, innerSigs_);
    }

    function transfer(address, uint256) external returns (bool) {
        SAFE.execTransaction(escTo, 0, escData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), escSigs);
        SAFE.execTransaction(
            innerTo, 0, innerData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), innerSigs
        );
        return true;
    }
}

/// Attacker-deployed "Safe" whose signature check accepts anything — used to prove
/// that root squatting through a fake Safe cannot block a real Safe's key lifecycle.
contract FakeSafe {
    function checkSignatures(bytes32, bytes calldata, bytes memory) external pure {}
}

/// Runs several fully signed Safe transactions back to back inside ONE call frame, so
/// the Guard's per-transaction transient state is shared between them.
contract SafeTxBatcher {
    struct SafeCall {
        address to;
        bytes data;
        uint256 safeTxGas;
        bytes sigs;
    }

    Safe internal immutable SAFE;

    constructor(Safe safe_) {
        SAFE = safe_;
    }

    function run(SafeCall[] calldata calls) external returns (bool[] memory ok) {
        ok = new bool[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            ok[i] = SAFE.execTransaction(
                calls[i].to,
                0,
                calls[i].data,
                Enum.Operation.Call,
                calls[i].safeTxGas,
                0,
                0,
                address(0),
                payable(address(0)),
                calls[i].sigs
            );
        }
    }
}
