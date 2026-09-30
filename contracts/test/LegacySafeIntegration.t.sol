// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";

import {FermionGuard} from "../src/FermionGuard.sol";
import {PreApprovalEngine} from "../src/PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "../src/QuantumKeyRegistry.sol";
import {XMSS} from "xmss-solidity/XMSS.sol";

/// The Safe surface this suite drives — ABI-identical in v1.3.0, v1.4.1 and v1.5.0
/// (the repo's lib is v1.5.0, whose sources this repo compiles; legacy singletons
/// come from bytecode, so the suite talks to them through this interface only).
interface ILegacySafe {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);

    function execTransactionFromModule(address to, uint256 value, bytes memory data, Enum.Operation operation)
        external
        returns (bool success);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);

    function nonce() external view returns (uint256);
    function isModuleEnabled(address module) external view returns (bool);
    function VERSION() external view returns (string memory);
}

interface ILegacySafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

/// Setup-time delegatecall target (Safe.setup's `to`/`data`): writes the guard slot
/// directly, the way a deployment helper wires a guard before the Safe's first
/// transaction — so that first transaction (nonce 0) is already Guard-checked.
contract SetupGuardWriter {
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    function wire(address guard) external {
        assembly {
            sstore(GUARD_SLOT, guard)
        }
    }
}

/// Malicious "token": its transfer() re-enters execTransaction with a fully signed,
/// pre-approved inner transaction.
contract LegacyReentrantToken {
    ILegacySafe internal immutable SAFE;
    address internal innerTo;
    bytes internal innerData;
    bytes internal innerSigs;

    constructor(ILegacySafe safe_) {
        SAFE = safe_;
    }

    function arm(address to, bytes calldata data, bytes calldata sigs) external {
        (innerTo, innerData, innerSigs) = (to, data, sigs);
    }

    function transfer(address, uint256) external returns (bool) {
        SAFE.execTransaction(innerTo, 0, innerData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), innerSigs);
        return true;
    }
}

/// Runs several signed Safe transactions back to back inside ONE call frame, so the
/// Guard's per-transaction transient state (depth counter) is shared between them.
contract LegacySafeTxBatcher {
    struct SafeCall {
        address to;
        bytes data;
        uint256 safeTxGas;
        bytes sigs;
    }

    ILegacySafe internal immutable SAFE;

    constructor(ILegacySafe safe_) {
        SAFE = safe_;
    }

    function run(SafeCall[] calldata calls) external returns (bool[] memory ok) {
        ok = new bool[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            ok[i] = SAFE.execTransaction(
                calls[i].to, 0, calls[i].data, Enum.Operation.Call, calls[i].safeTxGas, 0, 0, address(0),
                payable(address(0)), calls[i].sigs
            );
        }
    }
}

/// Core Guard flows end to end on REAL legacy Safe singletons (v1.3.0 / v1.4.1, L1
/// and L2). The test bodies are version-agnostic; each concrete contract below only
/// supplies the Safe stack (singleton, proxy factory, MultiSendCallOnly, a canonical
/// CompatibilityFallbackHandler) for its version. The full v1.5.0 suite lives in
/// GuardIntegration.t.sol.
abstract contract LegacySafeIntegrationBase is Test {
    uint256 internal constant OWNER1_PK = 0xA1;
    uint256 internal constant OWNER2_PK = 0xA2;
    uint256 internal constant OWNER3_PK = 0xA3;
    uint256 internal constant LEDGER_PK = 0x1ED6E4;
    address internal owner1 = vm.addr(OWNER1_PK);
    address internal owner2 = vm.addr(OWNER2_PK);
    address internal owner3 = vm.addr(OWNER3_PK);
    address internal ledger = vm.addr(LEDGER_PK);
    address internal relayer = makeAddr("relayer");
    address internal recipient = makeAddr("recipient");

    uint64 internal constant ADMIN_TIMELOCK = 2 days;
    uint64 internal constant EMERGENCY_TIMELOCK = 7 days;
    uint32 internal constant MAX_BATCH_LEGS = 4;
    uint32 internal constant MAX_QUEUE = 8;
    uint32 internal constant H = 4;
    bytes32 internal constant PARAM_SET = keccak256("XMSS-SHA2_4_256-TEST");

    bytes32 internal constant APPROVE_KEY_TYPEHASH = keccak256(
        "ApproveQuantumKey(address safe,address quantumAdmin,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 internal constant ATTEST_KEY_TYPEHASH = keccak256(
        "QuantumKeyAttestation(address safe,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce)"
    );
    bytes32 internal constant PRE_APPROVAL_TYPEHASH = keccak256(
        "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    /// keccak256("fallback_manager.handler.address")
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    /// keccak256("module_manager.module_guard.address") — only Safe >= 1.5 reads it.
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    // Version stack (set by _deployStack).
    address internal singleton;
    ILegacySafeProxyFactory internal factory;
    address internal msco;
    address internal compatHandler;

    ILegacySafe internal safe;
    FermionGuard internal guard;
    MockToken internal token;
    bytes32 internal keyId;
    bytes32 internal xmssRoot;
    bytes32 internal xmssSeed;
    uint256 internal approvalNonce;
    uint256 internal saltNonce;

    /// Deploy (or etch) this version's singleton, proxy factory, MultiSendCallOnly and
    /// CompatibilityFallbackHandler.
    function _deployStack() internal virtual;

    /// Expected Safe.VERSION().
    function _version() internal pure virtual returns (string memory);

    /// The production onboarding order on a Safe created the way Safe{Wallet} creates
    /// it (default CompatibilityFallbackHandler installed): remove the handler, run
    /// the key ceremony, then setGuard — all with owner signatures only.
    function setUp() public {
        vm.warp(1_800_000_000);
        _deployStack();
        token = new MockToken();
        guard = new FermionGuard(msco, ADMIN_TIMELOCK, EMERGENCY_TIMELOCK, MAX_BATCH_LEGS, MAX_QUEUE);
        (xmssRoot, xmssSeed,) = _xmssSign(0, bytes32(uint256(1))); // root/seed extraction only

        safe = _newSafe(compatHandler, address(0), "");
        assertEq(safe.VERSION(), _version());
        token.mint(address(safe), 1_000_000 ether);
        vm.deal(address(safe), 100 ether);

        _safeExec(address(safe), 0, abi.encodeWithSignature("setFallbackHandler(address)", address(0)), Enum.Operation.Call);
        keyId = _registerKey();
        _safeExec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(guard)), Enum.Operation.Call);
    }

    // ═══════════════════════ Enrollment + setGuard ══════════════════════════

    function test_Enrollment_KeyRegisteredAndGuardWired() public view {
        assertEq(guard.safeToQuantumKey(address(safe)), keyId);
        assertTrue(guard.enrolledSafe(address(safe)));
        QuantumKeyRegistry.KeyRegistration memory k = guard.getKey(keyId);
        assertEq(k.xmssRoot, xmssRoot);
        assertEq(k.quantumAdmin, ledger);
        assertEq(uint8(k.status), uint8(QuantumKeyRegistry.KeyStatus.Active));
        assertTrue(guard.allowedSelectors(address(safe), IERC20.transfer.selector));
        assertEq(address(uint160(uint256(vm.load(address(safe), GUARD_SLOT)))), address(guard));
        assertEq(uint256(vm.load(address(safe), FALLBACK_SLOT)), 0);
    }

    /// The default Safe{Wallet} handler must be removed before the ceremony: a Safe
    /// still carrying it cannot enroll (ERC-1271 bypass).
    function test_Enrollment_RefusedWhileFallbackHandlerInstalled() public {
        safe = _newSafe(compatHandler, address(0), "");
        _expectRegistrationRevert(
            abi.encodeWithSelector(FermionGuard.FallbackHandlerForbidden.selector, address(safe), compatHandler)
        );
    }

    // ═══════════════════════════ Tier 2 / Tier 1 ════════════════════════════

    function test_Tier2Transfer_BlockedWithoutApproval_AllowedWithOne() public {
        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 7 ether));
        _expectExecRevert(address(token), 0, data, Enum.Operation.Call, "");

        bytes32 id = _createTransfer(recipient, 7 ether, 1, bytes32(0));
        _safeExec(address(token), 0, data, Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 7 ether);
        assertTrue(guard.getPreApproval(id).used);

        // Single use: the same transfer again is blocked.
        _expectExecRevert(address(token), 0, data, Enum.Operation.Call, "");
    }

    /// nonce() - 1: the Guard recomputes the safeTxHash with the Safe's own hasher
    /// after execTransaction incremented the nonce. A pin for the CURRENT nonce
    /// matches in-flight; a pin for the next nonce does not.
    function test_Tier1_PinnedTransfer_NonceMinusOne() public {
        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 5 ether));
        uint256 n = safe.nonce();
        bytes32 wrongPin = safe.getTransactionHash(address(token), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), n + 1);
        bytes32 stale = _createTransfer(recipient, 5 ether, 1, wrongPin);
        _expectExecRevert(address(token), 0, data, Enum.Operation.Call, "");
        assertFalse(guard.getPreApproval(stale).used);

        bytes32 pin = safe.getTransactionHash(address(token), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), n);
        bytes32 id = _createTransfer(recipient, 5 ether, 2, pin);
        _safeExec(address(token), 0, data, Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 5 ether);
        assertTrue(guard.getPreApproval(id).used);
        assertFalse(guard.getPreApproval(stale).used);
    }

    /// Edge of nonce() - 1: a Safe whose guard was wired at setup time has its very
    /// first transaction (nonce 0) checked; the recomputation must use nonce 0.
    function test_Tier1_FirstEverTransaction_NonceZero() public {
        SetupGuardWriter writer = new SetupGuardWriter();
        safe = _newSafe(address(0), address(writer), abi.encodeCall(SetupGuardWriter.wire, (address(guard))));
        assertEq(safe.nonce(), 0);
        token.mint(address(safe), 10 ether);
        keyId = _registerKey();

        bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, 3 ether));
        bytes32 pin = safe.getTransactionHash(address(token), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0);
        bytes32 id = _createTransfer(recipient, 3 ether, 1, pin);
        _safeExec(address(token), 0, data, Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 3 ether);
        assertTrue(guard.getPreApproval(id).used);
    }

    // ═════════════════════ Batch (MultiSendCallOnly) ═══════════════════════

    function test_Batch_MultiSendCallOnly_TwoTransfers() public {
        bytes memory txs = bytes.concat(
            _leg(address(token), abi.encodeCall(IERC20.transfer, (recipient, 2 ether))),
            _leg(address(token), abi.encodeCall(IERC20.transfer, (owner3, 3 ether)))
        );
        bytes memory data = abi.encodeWithSignature("multiSend(bytes)", txs);
        _expectExecRevert(msco, 0, data, Enum.Operation.DelegateCall, ""); // no approval

        bytes32 id = _createPayload(msco, 0, keccak256(data), 1);
        _safeExec(msco, 0, data, Enum.Operation.DelegateCall);
        assertEq(token.balanceOf(recipient), 2 ether);
        assertEq(token.balanceOf(owner3), 3 ether);
        assertTrue(guard.getPreApproval(id).used);
    }

    function test_Batch_LegTargetingSafe_Rejected() public {
        bytes memory txs = _leg(address(safe), abi.encodeWithSignature("setGuard(address)", address(0)));
        bytes memory data = abi.encodeWithSignature("multiSend(bytes)", txs);
        _createPayload(msco, 0, keccak256(data), 1);
        _expectExecRevert(
            msco,
            0,
            data,
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(FermionGuard.ForbiddenBatchLegTarget.selector, address(safe))
        );
    }

    // ═════════════════════ Escape hatch: pause + de-guard ═══════════════════

    function test_EscapeHatch_PauseThenEmergencyDeGuard() public {
        vm.prank(owner2); // any single owner (Safe.isOwner on the legacy Safe)
        guard.pauseSafe(address(safe));
        bytes memory pay = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        _createTransfer(recipient, 1 ether, 1, bytes32(0));
        _expectExecRevert(
            address(token), 0, pay, Enum.Operation.Call,
            abi.encodeWithSelector(FermionGuard.SafePausedError.selector, address(safe))
        );

        // Owner-signed escape calls go through while paused, no quantum approval.
        _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.pauseSafe, (address(safe))), Enum.Operation.Call);
        _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call);
        uint64 executableAt = guard.emergencyDeGuardExecutableAt(address(safe));
        assertEq(executableAt, uint64(block.timestamp) + EMERGENCY_TIMELOCK);

        bytes memory removeGuard = abi.encodeWithSignature("setGuard(address)", address(0));
        _expectExecRevert(address(safe), 0, removeGuard, Enum.Operation.Call, ""); // too early

        vm.warp(executableAt + 1);
        _safeExec(address(safe), 0, removeGuard, Enum.Operation.Call);
        assertEq(uint256(vm.load(address(safe), GUARD_SLOT)), 0);
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0); // cleared by checkAfterExecution

        _safeExec(address(token), 0, pay, Enum.Operation.Call); // owners alone again
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    function test_EscapeHatch_TimelockedUnpause() public {
        vm.prank(owner1);
        guard.pauseSafe(address(safe));
        _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.requestUnpauseSafe, ()), Enum.Operation.Call);
        vm.warp(guard.safeUnpauseExecutableAt(address(safe)) + 1);
        _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.unpauseSafe, ()), Enum.Operation.Call);
        assertFalse(guard.safePaused(address(safe)));

        _createTransfer(recipient, 1 ether, 1, bytes32(0));
        _safeExec(address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)), Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    // ═════════════════════════ Fallback-handler ban ═════════════════════════

    function test_FallbackHandler_AdminInstallForbidden_RemovalRemediates() public {
        bytes memory install = abi.encodeWithSignature("setFallbackHandler(address)", compatHandler);
        _createAdmin(address(safe), keccak256(install), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _expectExecRevert(
            address(safe), 0, install, Enum.Operation.Call,
            abi.encodeWithSelector(FermionGuard.FallbackHandlerForbidden.selector, address(safe), compatHandler)
        );

        // A handler that got in anyway (storage-level) freezes checked transactions…
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(compatHandler))));
        bytes memory pay = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        _expectExecRevert(
            address(token), 0, pay, Enum.Operation.Call,
            abi.encodeWithSelector(FermionGuard.FallbackHandlerForbidden.selector, address(safe), compatHandler)
        );

        // …until the quantum-approved removal, which works while the posture is bad.
        bytes memory clear = abi.encodeWithSignature("setFallbackHandler(address)", address(0));
        _createAdmin(address(safe), keccak256(clear), 3);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, clear, Enum.Operation.Call);
        _createTransfer(recipient, 1 ether, 2, bytes32(0));
        _safeExec(address(token), 0, pay, Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    // ══════════════ Modules — no module guard before Safe 1.5.0 ══════════════
    // Posture (spec, "Module bypass"): execTransactionFromModule never reaches a
    // guard on v1.3.0/v1.4.1, so the Guard keeps modules out entirely: enableModule
    // is refused even with a matured ADMIN approval, a Safe with modules cannot
    // enroll, and a guarded Safe that has one anyway fails closed until disableModule.

    function test_Module_EnableRejectedEvenWithAdminApproval() public {
        address module = makeAddr("module");
        bytes memory enable = abi.encodeWithSignature("enableModule(address)", module);
        _createAdmin(address(safe), keccak256(enable), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _expectExecRevert(
            address(safe), 0, enable, Enum.Operation.Call,
            abi.encodeWithSelector(FermionGuard.ModuleGuardNotWired.selector, address(safe))
        );

        // setModuleGuard does not exist before 1.5.0: the Safe's fallback swallows it
        // as a no-op, so it never unlocks enableModule.
        bytes memory wire = abi.encodeWithSignature("setModuleGuard(address)", address(guard));
        _createAdmin(address(safe), keccak256(wire), 2);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, wire, Enum.Operation.Call);
        _createAdmin(address(safe), keccak256(enable), 3);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _expectExecRevert(
            address(safe), 0, enable, Enum.Operation.Call,
            abi.encodeWithSelector(FermionGuard.ModuleGuardNotWired.selector, address(safe))
        );
        assertFalse(safe.isModuleEnabled(module));
    }

    /// The module-guard slot means nothing to a pre-1.5 Safe (e.g. left behind by a
    /// downgrade from 1.5.0, or planted before enrollment): holding this Guard's
    /// address there must not unlock enableModule — the module would bypass the
    /// Guard entirely.
    function test_Module_StaleModuleGuardSlotNotTrusted() public {
        vm.store(address(safe), MODULE_GUARD_SLOT, bytes32(uint256(uint160(address(guard)))));
        address module = makeAddr("module");
        bytes memory enable = abi.encodeWithSignature("enableModule(address)", module);
        _createAdmin(address(safe), keccak256(enable), 1);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _expectExecRevert(
            address(safe), 0, enable, Enum.Operation.Call,
            abi.encodeWithSelector(FermionGuard.ModuleGuardNotWired.selector, address(safe))
        );
        assertFalse(safe.isModuleEnabled(module));

        // Same at the enrollment door: a Safe with a module and a planted slot.
        safe = _newSafe(address(0), address(0), "");
        _safeExec(address(safe), 0, abi.encodeWithSignature("enableModule(address)", module), Enum.Operation.Call);
        vm.store(address(safe), MODULE_GUARD_SLOT, bytes32(uint256(uint160(address(guard)))));
        _expectRegistrationRevert(
            abi.encodeWithSelector(FermionGuard.ModulesEnabledWithoutModuleGuard.selector, address(safe))
        );
    }

    function test_Module_SafeWithModuleCannotEnroll() public {
        address module = makeAddr("module");
        safe = _newSafe(address(0), address(0), "");
        _safeExec(address(safe), 0, abi.encodeWithSignature("enableModule(address)", module), Enum.Operation.Call);
        _expectRegistrationRevert(
            abi.encodeWithSelector(FermionGuard.ModulesEnabledWithoutModuleGuard.selector, address(safe))
        );
    }

    /// A module enabled between enrollment and setGuard (the Guard cannot see that
    /// window): the module transaction itself never reaches the Guard on this Safe
    /// version, so the Guard fails closed on every owner transaction instead, until
    /// the ADMIN-approved disableModule remediation — which is never deadlocked.
    function test_Module_TransactionBypassesGuard_OwnerTxsFailClosedUntilDisabled() public {
        address module = makeAddr("module");
        safe = _newSafe(address(0), address(0), "");
        token.mint(address(safe), 10 ether);
        keyId = _registerKey();
        _safeExec(address(safe), 0, abi.encodeWithSignature("enableModule(address)", module), Enum.Operation.Call);
        _safeExec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(guard)), Enum.Operation.Call);

        // Module path: no checkModuleTransaction on this Safe version — unguarded.
        vm.recordLogs();
        vm.prank(module);
        assertTrue(
            safe.execTransactionFromModule(
                address(token), 0, abi.encodeCall(IERC20.transfer, (recipient, 1 ether)), Enum.Operation.Call
            )
        );
        assertEq(token.balanceOf(recipient), 1 ether);
        assertEq(_guardLogCount(), 0);

        // Owner path: refused while the module is enabled (posture check first).
        bytes memory pay = abi.encodeCall(IERC20.transfer, (recipient, 2 ether));
        _expectExecRevert(
            address(token), 0, pay, Enum.Operation.Call,
            abi.encodeWithSelector(FermionGuard.ModulesEnabledWithoutModuleGuard.selector, address(safe))
        );

        // Remediation (disableModule(prevModule = SENTINEL, module)) is exempt.
        bytes memory disable = abi.encodeWithSignature("disableModule(address,address)", address(1), module);
        _createAdmin(address(safe), keccak256(disable), 2);
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, disable, Enum.Operation.Call);
        assertFalse(safe.isModuleEnabled(module));

        _createTransfer(recipient, 2 ether, 1, bytes32(0));
        _safeExec(address(token), 0, pay, Enum.Operation.Call);
        assertEq(token.balanceOf(recipient), 3 ether);
    }

    // ═══════════════════ checkAfterExecution depth unwinding ═══════════════

    /// Failed executions (safeTxGas != 0, so the Safe does not revert) still get
    /// checkAfterExecution and unwind the depth — for an escape call and for an
    /// approved transaction — so the next transaction in the same frame runs.
    function test_Depth_UnwindsAcrossTransactionsInOneFrame() public {
        uint256 tooMuch = token.balanceOf(address(safe)) + 1;
        bytes32 failing = _createTransfer(recipient, tooMuch, 1, bytes32(0));
        _createTransfer(recipient, 1 ether, 2, bytes32(0));

        LegacySafeTxBatcher.SafeCall[] memory calls = new LegacySafeTxBatcher.SafeCall[](4);
        uint256 n = safe.nonce();
        calls[0] = _call(address(guard), abi.encodeCall(FermionGuard.cancelEmergencyDeGuard, (address(safe))), 100_000, n);
        calls[1] = _call(address(guard), abi.encodeCall(FermionGuard.requestEmergencyDeGuard, ()), 0, n + 1);
        calls[2] = _call(address(token), abi.encodeCall(IERC20.transfer, (recipient, tooMuch)), 100_000, n + 2);
        calls[3] = _call(address(token), abi.encodeCall(IERC20.transfer, (recipient, 1 ether)), 0, n + 3);

        bool[] memory ok = new LegacySafeTxBatcher(safe).run(calls);
        assertFalse(ok[0]); // escape call reverting inside the Guard (nothing to cancel)
        assertTrue(ok[1]);
        assertFalse(ok[2]); // approved transfer reverting inside the token
        assertTrue(ok[3]);
        assertTrue(guard.getPreApproval(failing).used);
        assertEq(token.balanceOf(recipient), 1 ether);
        assertGt(guard.emergencyDeGuardExecutableAt(address(safe)), 0);
    }

    /// A nested execTransaction from inside an approved one is rejected.
    function test_Depth_NestedExecTransactionBlocked() public {
        LegacyReentrantToken attacker = new LegacyReentrantToken(safe);
        _createTransfer2(address(attacker), recipient, 1 ether, 1, bytes32(0));
        _createTransfer(recipient, 2 ether, 2, bytes32(0));

        uint256 n = safe.nonce();
        bytes memory innerData = abi.encodeCall(IERC20.transfer, (recipient, 2 ether));
        attacker.arm(address(token), innerData, _ownerSigs(safe.getTransactionHash(address(token), 0, innerData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), n + 1)));

        bytes memory outer = abi.encodeCall(IERC20.transfer, (recipient, 1 ether));
        bytes memory sigs = _ownerSigs(safe.getTransactionHash(address(attacker), 0, outer, Enum.Operation.Call, 0, 0, 0, address(0), address(0), n));
        vm.expectRevert();
        safe.execTransaction(address(attacker), 0, outer, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sigs);
        assertEq(token.balanceOf(recipient), 0);
    }

    // ═════════════════════════════ Helpers ══════════════════════════════════

    function _newSafe(address handler, address setupTo, bytes memory setupData) internal returns (ILegacySafe s) {
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        bytes memory init = abi.encodeCall(
            ILegacySafe.setup, (owners, 2, setupTo, setupData, handler, address(0), 0, payable(address(0)))
        );
        s = ILegacySafe(factory.createProxyWithNonce(singleton, init, ++saltNonce));
        if (handler != address(0)) assertEq(address(uint160(uint256(vm.load(address(s), FALLBACK_SLOT)))), handler);
    }

    /// Creation bytecode from test/vectors (see the concrete contracts for provenance).
    function _deployBin(string memory path) internal returns (address a) {
        bytes memory code = vm.parseBytes(vm.trim(vm.readFile(path)));
        assembly {
            a := create(0, add(code, 32), mload(code))
        }
        require(a != address(0) && a.code.length > 0, "deploy failed");
    }

    /// Canonical mainnet runtime code, etched at its canonical address.
    function _etchMainnet(string memory json, string memory name) internal returns (address a) {
        a = vm.parseJsonAddress(json, string.concat(".", name, ".address"));
        vm.etch(a, vm.parseJsonBytes(json, string.concat(".", name, ".code")));
    }

    function _guardLogCount() internal returns (uint256 n) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == address(guard)) ++n;
        }
    }

    function _call(address to, bytes memory data, uint256 safeTxGas, uint256 n)
        internal
        view
        returns (LegacySafeTxBatcher.SafeCall memory)
    {
        bytes32 h = safe.getTransactionHash(to, 0, data, Enum.Operation.Call, safeTxGas, 0, 0, address(0), address(0), n);
        return LegacySafeTxBatcher.SafeCall(to, data, safeTxGas, _ownerSigs(h));
    }

    function _leg(address to, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, uint256(0), data.length, data);
    }

    function _safeExec(address to, uint256 value, bytes memory data, Enum.Operation op) internal {
        bytes32 h = safe.getTransactionHash(to, value, data, op, 0, 0, 0, address(0), address(0), safe.nonce());
        assertTrue(safe.execTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), _ownerSigs(h)));
    }

    function _expectExecRevert(address to, uint256 value, bytes memory data, Enum.Operation op, bytes memory err) internal {
        bytes32 h = safe.getTransactionHash(to, value, data, op, 0, 0, 0, address(0), address(0), safe.nonce());
        bytes memory sigs = _ownerSigs(h);
        if (err.length > 0) vm.expectRevert(err);
        else vm.expectRevert();
        safe.execTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), sigs);
    }

    /// 2-of-3 owner signatures, sorted by signer address.
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

    function _guardDigest(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("FermionGuard"), keccak256("1"), block.chainid, address(guard))
        );
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    function _approveKeyDigest(uint256 nonce, uint256 validUntil) internal view returns (bytes32) {
        return _guardDigest(
            keccak256(abi.encode(APPROVE_KEY_TYPEHASH, address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, nonce, validUntil))
        );
    }

    function _ledgerAttestation(uint256 nonce) internal view returns (bytes memory) {
        bytes32 digest =
            _guardDigest(keccak256(abi.encode(ATTEST_KEY_TYPEHASH, address(safe), xmssRoot, xmssSeed, H, PARAM_SET, nonce)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Key ceremony: owner-threshold co-signatures through the legacy Safe's own
    /// checkSignatures, plus the Ledger attestation.
    function _registerKey() internal returns (bytes32) {
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = block.timestamp + 1 days;
        bytes memory attestation = _ledgerAttestation(nonce);
        bytes memory sigs = _ownerSigs(_approveKeyDigest(nonce, validUntil));
        vm.prank(relayer);
        return guard.registerQuantumKey(address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, validUntil, attestation, sigs);
    }

    function _expectRegistrationRevert(bytes memory err) internal {
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = block.timestamp + 1 days;
        bytes memory attestation = _ledgerAttestation(nonce);
        bytes memory sigs = _ownerSigs(_approveKeyDigest(nonce, validUntil));
        vm.expectRevert(err);
        vm.prank(relayer);
        guard.registerQuantumKey(address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, validUntil, attestation, sigs);
    }

    /// FFI to the RFC 8391 reference signer (h = 4). Output: root|seed|r|wots[67]|auth[h].
    function _xmssSign(uint32 leaf, bytes32 digest) internal returns (bytes32 root, bytes32 seed, bytes memory encodedSig) {
        string[] memory cmd = new string[](5);
        cmd[0] = "python3";
        cmd[1] = "lib/xmss-solidity/py/sign_digest.py";
        cmd[2] = vm.toString(uint256(H));
        cmd[3] = vm.toString(uint256(leaf));
        cmd[4] = vm.toString(digest);
        bytes memory blob = vm.ffi(cmd);
        require(blob.length == 32 * (3 + 67 + H), "ffi blob size");
        XMSS.Signature memory sig;
        sig.leafIdx = leaf;
        root = _word(blob, 0);
        seed = _word(blob, 1);
        sig.r = _word(blob, 2);
        for (uint256 i = 0; i < 67; ++i) {
            sig.wotsSig[i] = _word(blob, 3 + i);
        }
        sig.authPath = new bytes32[](H);
        for (uint256 i = 0; i < H; ++i) {
            sig.authPath[i] = _word(blob, 70 + i);
        }
        encodedSig = abi.encode(sig);
    }

    function _word(bytes memory blob, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(blob, 32), mul(i, 32)))
        }
    }

    function _baseReq(uint32 leaf) internal returns (PreApprovalEngine.PreApprovalRequest memory req) {
        req.safe = address(safe);
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 2 days;
        req.nonce = bytes32(++approvalNonce);
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = leaf;
        req.policyHash = keccak256("policy-v1");
    }

    function _preApprovalDigest(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_)
        internal
        view
        returns (bytes32)
    {
        return _guardDigest(
            // All-static fields: two concatenated encodings == one abi.encode (split
            // only to stay under the stack limit).
            keccak256(
                bytes.concat(
                    abi.encode(
                        PRE_APPROVAL_TYPEHASH, req.safe, class_, req.token, req.recipient, req.amount, req.target,
                        req.value
                    ),
                    abi.encode(
                        req.dataHash, req.validFrom, req.validTo, req.nonce, req.quantumKeyId, req.xmssLeafIndex,
                        req.policyHash, req.txHash
                    )
                )
            )
        );
    }

    function _hybridSign(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_)
        internal
        returns (bytes memory ecdsaSig, bytes memory xmssSig)
    {
        bytes32 digest = _preApprovalDigest(req, class_);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        ecdsaSig = abi.encodePacked(r, s, v);
        (,, xmssSig) = _xmssSign(req.xmssLeafIndex, digest);
    }

    function _createTransfer(address to, uint256 amount, uint32 leaf, bytes32 txHash) internal returns (bytes32) {
        return _createTransfer2(address(token), to, amount, leaf, txHash);
    }

    function _createTransfer2(address token_, address to, uint256 amount, uint32 leaf, bytes32 txHash)
        internal
        returns (bytes32 id)
    {
        PreApprovalEngine.PreApprovalRequest memory req = _baseReq(leaf);
        req.token = token_;
        req.recipient = to;
        req.amount = amount;
        req.txHash = txHash;
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 0);
        vm.prank(relayer);
        id = guard.createPreApproval(req, ecdsaSig, xmssSig);
    }

    function _createPayload(address target, uint256 value, bytes32 dataHash, uint32 leaf) internal returns (bytes32 id) {
        PreApprovalEngine.PreApprovalRequest memory req = _baseReq(leaf);
        req.target = target;
        req.value = value;
        req.dataHash = dataHash;
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 1);
        vm.prank(relayer);
        id = guard.createPayloadPreApproval(req, ecdsaSig, xmssSig);
    }

    function _createAdmin(address target, bytes32 dataHash, uint32 leaf) internal returns (bytes32 id) {
        PreApprovalEngine.PreApprovalRequest memory req = _baseReq(leaf);
        req.target = target;
        req.dataHash = dataHash;
        req.validFrom = uint64(block.timestamp) + ADMIN_TIMELOCK;
        req.validTo = req.validFrom + 2 days;
        (bytes memory ecdsaSig, bytes memory xmssSig) = _hybridSign(req, 2);
        vm.prank(relayer);
        id = guard.createAdminPreApproval(req, ecdsaSig, xmssSig);
    }
}

// ═════════════════════════════ Version stacks ═════════════════════════════
//
// Provenance of test/vectors used here:
//   safe-v1.3.0/Safe.bin, SafeProxyFactory.bin, MultiSendCallOnly.bin — creation
//     bytecode of GnosisSafe.sol, proxies/GnosisSafeProxyFactory.sol and
//     libraries/MultiSendCallOnly.sol at github.com/safe-global/safe-smart-account
//     tag v1.3.0 (186a21a7), unmodified source, solc 0.8.20, optimizer 200 runs, no
//     via-IR (`solc --optimize --optimize-runs 200 --bin <file>`; Safe.bin and
//     SafeProxyFactory.bin reproduce byte-for-byte with that command).
//   safe-v1.4.1/Safe.bin, SafeProxyFactory.bin — see LegacySafeSignatures.t.sol
//     (tag v1.4.1, bf943f80, solc 0.8.37, optimizer 200, no via-IR).
//   safe-v*/mainnet-runtime.json — deployed runtime code (`cast code <address>`
//     against Ethereum mainnet) of the canonical singleton-factory deployments, keyed
//     by contract name with its canonical address. v1.4.1 entries are identical to
//     demo/wallet/safe-1.4.1-code.json. Etched at the canonical address; none of these
//     contracts has immutables, so the runtime code is position-independent.

/// Safe v1.3.0 L1 — GnosisSafe built from the upstream tag.
contract LegacySafe130IntegrationTest is LegacySafeIntegrationBase {
    function _version() internal pure override returns (string memory) {
        return "1.3.0";
    }

    function _deployStack() internal override {
        singleton = _deployBin("test/vectors/safe-v1.3.0/Safe.bin");
        factory = ILegacySafeProxyFactory(_deployBin("test/vectors/safe-v1.3.0/SafeProxyFactory.bin"));
        msco = _deployBin("test/vectors/safe-v1.3.0/MultiSendCallOnly.bin");
        compatHandler = _etchMainnet(vm.readFile("test/vectors/safe-v1.3.0/mainnet-runtime.json"), "CompatibilityFallbackHandler");
    }
}

/// Safe v1.3.0 L2 — mainnet GnosisSafeL2 (0x3E5c…D36E), factory and MultiSendCallOnly.
contract LegacySafe130L2IntegrationTest is LegacySafeIntegrationBase {
    function _version() internal pure override returns (string memory) {
        return "1.3.0";
    }

    function _deployStack() internal override {
        string memory json = vm.readFile("test/vectors/safe-v1.3.0/mainnet-runtime.json");
        singleton = _etchMainnet(json, "SafeL2");
        factory = ILegacySafeProxyFactory(_etchMainnet(json, "SafeProxyFactory"));
        msco = _etchMainnet(json, "MultiSendCallOnly");
        compatHandler = _etchMainnet(json, "CompatibilityFallbackHandler");
    }
}

/// Safe v1.4.1 L1 — Safe built from the upstream tag; mainnet MultiSendCallOnly.
contract LegacySafe141IntegrationTest is LegacySafeIntegrationBase {
    function _version() internal pure override returns (string memory) {
        return "1.4.1";
    }

    function _deployStack() internal override {
        string memory json = vm.readFile("test/vectors/safe-v1.4.1/mainnet-runtime.json");
        singleton = _deployBin("test/vectors/safe-v1.4.1/Safe.bin");
        factory = ILegacySafeProxyFactory(_deployBin("test/vectors/safe-v1.4.1/SafeProxyFactory.bin"));
        msco = _etchMainnet(json, "MultiSendCallOnly");
        compatHandler = _etchMainnet(json, "CompatibilityFallbackHandler");
    }
}

/// Safe v1.4.1 L2 — mainnet SafeL2 (0x29fc…C762), factory and MultiSendCallOnly: the
/// exact stack demo/wallet runs.
contract LegacySafe141L2IntegrationTest is LegacySafeIntegrationBase {
    function _version() internal pure override returns (string memory) {
        return "1.4.1";
    }

    function _deployStack() internal override {
        string memory json = vm.readFile("test/vectors/safe-v1.4.1/mainnet-runtime.json");
        singleton = _etchMainnet(json, "SafeL2");
        factory = ILegacySafeProxyFactory(_etchMainnet(json, "SafeProxyFactory"));
        msco = _etchMainnet(json, "MultiSendCallOnly");
        compatHandler = _etchMainnet(json, "CompatibilityFallbackHandler");
    }
}
