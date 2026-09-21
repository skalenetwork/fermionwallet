// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {BaseTransactionGuard, ITransactionGuard} from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import {BaseModuleGuard, IModuleGuard} from "@safe-global/safe-contracts/contracts/base/ModuleManager.sol";
import {IGuardManager} from "@safe-global/safe-contracts/contracts/interfaces/IGuardManager.sol";
import {ISafe} from "@safe-global/safe-contracts/contracts/interfaces/ISafe.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {TransientSlot} from "@openzeppelin/contracts/utils/TransientSlot.sol";

import {PreApprovalEngine} from "./PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "./QuantumKeyRegistry.sol";

/// @title FermionWalletGuard — quantum second-authorization Guard for Gnosis Safe
/// @notice The enforcement layer per fermionwallet-guard-module.md. One contract serves
///         both hook families (BaseTransactionGuard + BaseModuleGuard — one storage, one
///         address for `setGuard` and `setModuleGuard`) and embeds the QuantumKeyRegistry
///         and PreApprovalEngine, so the Guard can only ever enforce what it can read
///         on-chain at execution time.
///
///         `checkTransaction` check order is NORMATIVE (spec, "Emergency de-guard path"):
///           1. emergency escape hatch — may never be blocked by any other state;
///           2. pause (deny-all circuit breaker);
///           3. enrollment, reentrancy depth, refund policy, class dispatch, consumption.
/// @dev    Non-upgradeable by design; a fix is a new deployment set via Safe governance.
contract FermionWalletGuard is
    PreApprovalEngine,
    BaseTransactionGuard,
    BaseModuleGuard,
    Pausable,
    AccessControl
{
    using TransientSlot for *;

    // ── Errors ──────────────────────────────────────────────────────────────

    error GuardPausedError();
    error NotEnrolledSafe(address caller);
    error NestedSafeTransaction(address safe);
    error DelegateCallForbidden(address to);
    error GasRefundForbidden();
    error DeniedSelector(bytes4 selector);
    error SelectorNotAllowed(address safe, bytes4 selector);
    error MalformedTransferCalldata();
    error MalformedBatch();
    error BatchTooLarge(uint256 legs, uint32 maxLegs);
    error ForbiddenBatchLegTarget(address target);
    error ModuleDelegateCallForbidden(address module);
    error ModulesEnabledWithoutModuleGuard(address safe);
    error EmergencyDeGuardNotRequested(address safe);
    error UnpauseTimelocked(uint64 executableAt);
    error UnpauseNotRequested();
    error SafePausedError(address safe);
    error SafeNotPaused(address safe);

    // ── Events ──────────────────────────────────────────────────────────────

    event GuardPaused(address indexed by);
    event GuardUnpauseRequested(address indexed by, uint64 executableAt);
    event GuardUnpaused(address indexed by);
    event EmergencyDeGuardRequested(address indexed safe, uint64 executableAt);
    event EmergencyDeGuardCancelled(address indexed safe, address indexed by);
    event EmergencyDeGuardCleared(address indexed safe);
    event SafePaused(address indexed safe, address indexed by);
    event SafeUnpauseRequested(address indexed safe, uint64 executableAt);
    event SafeUnpaused(address indexed safe);
    event SelectorPolicyChanged(address indexed safe, bytes4 indexed selector, bool allowed);
    event TransactionChecked(address indexed safe, bytes32 indexed safeTxHash, bytes32 indexed preApprovalId);
    event ModuleTransactionChecked(address indexed safe, address indexed module, bytes32 indexed preApprovalId);

    // ── Roles / immutables / constants ──────────────────────────────────────

    /// Fast, low-privilege pause (guardian); unpause is slow and high-privilege.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// The sole permitted delegatecall target: canonical MultiSendCallOnly, pinned at
    /// deployment. Delegatecall-capable MultiSend stays banned forever.
    address public immutable MULTISEND_CALL_ONLY;
    /// Emergency de-guard delay — materially longer than ADMIN_TIMELOCK by construction.
    uint64 public immutable EMERGENCY_TIMELOCK;
    /// Batch decode bound: adversarial input costs at most this many O(1) header reads.
    uint32 public immutable MAX_BATCH_LEGS;

    // Hardcoded deny-list — never re-enableable by any governance action, only by a
    // new Guard deployment. Allowance grants are stealth-drain paths.
    bytes4 private constant SEL_TRANSFER = IERC20.transfer.selector; //          0xa9059cbb
    bytes4 private constant SEL_APPROVE = IERC20.approve.selector; //            0x095ea7b3
    bytes4 private constant SEL_TRANSFER_FROM = IERC20.transferFrom.selector; // 0x23b872dd
    bytes4 private constant SEL_INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));
    bytes4 private constant SEL_PERMIT =
        bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"));
    bytes4 private constant SEL_SET_GUARD = IGuardManager.setGuard.selector;

    /// MultiSendCallOnly packed leg header: uint8 op + address to + uint256 value + uint256 dataLength.
    uint256 private constant LEG_HEADER = 85;

    // ── Storage ─────────────────────────────────────────────────────────────

    /// Per-Safe selector permit-list ({transfer} at enrollment; ADMIN-governed mutation only).
    mapping(address safe => mapping(bytes4 selector => bool)) public allowedSelectors;
    /// Pending emergency de-guards: safe => executableAt (0 = none).
    mapping(address safe => uint64) public emergencyDeGuardExecutableAt;
    /// Time-locked unpause request (0 = none).
    uint64 public unpauseExecutableAt;
    /// Per-Safe deny-all pause: any owner of the Safe (or the Safe, or its Quantum
    /// Administrator) pauses instantly; only the Safe unpauses, after ADMIN_TIMELOCK.
    mapping(address safe => bool) public safePaused;
    mapping(address safe => uint64) public safeUnpauseExecutableAt;

    constructor(
        address multiSendCallOnly,
        uint64 adminTimelock,
        uint64 emergencyTimelock,
        uint32 maxBatchLegs,
        uint32 maxCommitmentQueue,
        address admin,
        address guardian
    )
        QuantumKeyRegistry(emergencyTimelock)
        PreApprovalEngine(adminTimelock, maxCommitmentQueue)
        EIP712("FermionWalletGuard", "1")
    {
        if (multiSendCallOnly == address(0) || admin == address(0) || guardian == address(0)) revert ZeroAddress();
        if (multiSendCallOnly.code.length == 0) revert InvalidKeyParams();
        require(emergencyTimelock > adminTimelock, "EMERGENCY_TIMELOCK must exceed ADMIN_TIMELOCK");
        MULTISEND_CALL_ONLY = multiSendCallOnly;
        EMERGENCY_TIMELOCK = emergencyTimelock;
        MAX_BATCH_LEGS = maxBatchLegs;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, guardian);
    }

    // ── ERC165 (Safe checks this in setGuard/setModuleGuard — GS300 otherwise) ──

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(BaseTransactionGuard, BaseModuleGuard, AccessControl)
        returns (bool)
    {
        return interfaceId == type(ITransactionGuard).interfaceId || interfaceId == type(IModuleGuard).interfaceId
            || AccessControl.supportsInterface(interfaceId);
    }

    // ── ITransactionGuard ───────────────────────────────────────────────────

    /// @inheritdoc ITransactionGuard
    /// @dev `msg.sender` IS the Safe proxy (external CALL from execTransaction, after
    ///      signature validation and nonce increment). The `msgSender` parameter is the
    ///      relayer EOA — informational only, never a trust anchor.
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory, /* signatures — already validated by the Safe */
        address /* msgSender */
    ) external override {
        address safe = msg.sender;
        (bool isSetGuard, address newGuard) = _setGuardCall(safe, to, value, data, operation);

        // 1. FIRST — before pause, before enrollment, before everything: the
        //    emergency escape hatch and the owner safety calls may never be blocked
        //    by any other state.
        if (_isEmergencyEscapeCall(safe, to, value, data, operation)) {
            if (isSetGuard) _clearEmergencySlot(safe).asBoolean().tstore(true);
            return;
        }

        // 2. Only THEN the deny-all circuit breaker — which never blocks the quantum-
        //    approved Guard removal (no-brick path 1 must work while paused; it still
        //    needs a matching, timelock-elapsed ADMIN approval below).
        if (!(isSetGuard && newGuard == address(0))) {
            if (paused()) revert GuardPausedError();
            if (safePaused[safe]) revert SafePausedError(safe);
        }

        // 3. Enrollment: stops attacker-controlled contracts from burning another
        //    Safe's approvals (the consumption path takes `safe` from msg.sender only).
        _requireEnrolledActive(safe);

        // 4. Reentrancy depth: nested Safe transactions are rejected for the MVP.
        TransientSlot.BooleanSlot depth = _depthSlot(safe).asBoolean();
        if (depth.tload()) revert NestedSafeTransaction(safe);
        depth.tstore(true);

        // 5. Module-bypass mitigation: no enabled modules, or this contract wired
        //    as the module guard (Safe >= 1.5).
        _checkModulePosture(safe);

        // 6. Gas-refund drain protection (MVP: no refunds at all).
        if (gasPrice != 0) revert GasRefundForbidden();

        // 7. Tier-1 pin: recompute the safeTxHash with the Safe's own hasher.
        //    nonce() - 1 because execTransaction increments before calling us;
        //    cannot underflow in this call path (nonce >= 1 here).
        bytes32 safeTxHash = ISafe(payable(safe)).getTransactionHash(
            to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, ISafe(payable(safe)).nonce() - 1
        );

        // 8. Class dispatch + consumption (marks the approval used — atomic with execution).
        bytes32 id = _dispatch(safe, to, value, data, operation, safeTxHash);
        // Any executed setGuard ends this Guard's tenure on the Safe: a pending or
        // matured emergency request must not outlive it (checkAfterExecution clears it).
        if (isSetGuard) _clearEmergencySlot(safe).asBoolean().tstore(true);
        emit TransactionChecked(safe, safeTxHash, id);
    }

    /// @inheritdoc ITransactionGuard
    /// @dev Post-execution bookkeeping only — never an authorization gate. A consumed
    ///      approval stays consumed even if `success == false`. Safe calls this on the
    ///      Guard it checked with, even when that transaction just removed the Guard.
    function checkAfterExecution(bytes32, bool success) external override {
        address safe = msg.sender;
        _depthSlot(safe).asBoolean().tstore(false);

        TransientSlot.BooleanSlot clearEmergency = _clearEmergencySlot(safe).asBoolean();
        if (clearEmergency.tload()) {
            clearEmergency.tstore(false);
            // "Exactly one" removal per request: a later re-enabled Guard starts clean.
            if (success && emergencyDeGuardExecutableAt[safe] != 0) {
                emergencyDeGuardExecutableAt[safe] = 0;
                emit EmergencyDeGuardCleared(safe);
            }
        }
    }

    // ── IModuleGuard (Safe >= 1.5) ──────────────────────────────────────────

    /// @inheritdoc IModuleGuard
    /// @dev Same class-dispatch pipeline, two module-specific rules: delegatecall from
    ///      a module is ALWAYS rejected (no MultiSend exception), and the module address
    ///      is logged. Tier-1 pinning is unavailable (module txs have no safeTxHash), so
    ///      matching is Tier-2 only.
    function checkModuleTransaction(address to, uint256 value, bytes memory data, Enum.Operation operation, address module)
        external
        override
        returns (bytes32 moduleTxHash)
    {
        address safe = msg.sender;
        if (paused()) revert GuardPausedError();
        if (safePaused[safe]) revert SafePausedError(safe);
        _requireEnrolledActive(safe);
        if (operation != Enum.Operation.Call) revert ModuleDelegateCallForbidden(module);

        moduleTxHash = keccak256(abi.encode(safe, to, value, keccak256(data), module));
        bytes32 id = _dispatch(safe, to, value, data, operation, bytes32(0));
        emit ModuleTransactionChecked(safe, module, id);
    }

    /// @inheritdoc IModuleGuard
    function checkAfterModuleExecution(bytes32, bool) external override {}

    // ── Emergency de-guard (the no-brick invariant, path 2) ─────────────────

    /// @notice Start the time-locked, quantum-key-independent Guard removal. Callable
    ///         only via an owner-threshold Safe transaction (msg.sender == safe); the
    ///         escape-hatch allow in checkTransaction guarantees this call can never be
    ///         blocked — including while paused or after key loss.
    function requestEmergencyDeGuard() external {
        if (!enrolledSafe[msg.sender]) revert NotEnrolledSafe(msg.sender);
        uint64 executableAt = uint64(block.timestamp) + EMERGENCY_TIMELOCK;
        emergencyDeGuardExecutableAt[msg.sender] = executableAt;
        emit EmergencyDeGuardRequested(msg.sender, executableAt);
    }

    /// @notice Cancel a pending emergency de-guard. Only the Safe itself — i.e. an
    ///         owner-threshold Safe transaction, with or without a quantum ADMIN approval
    ///         (spec, "Emergency de-guard path", step 3). The Quantum Administrator's key
    ///         alone must NOT be able to cancel: a stolen Ledger could then veto every
    ///         emergency removal forever and brick the Safe.
    function cancelEmergencyDeGuard(address safe) external {
        if (msg.sender != safe) revert NotAuthorized();
        if (emergencyDeGuardExecutableAt[safe] == 0) revert EmergencyDeGuardNotRequested(safe);
        emergencyDeGuardExecutableAt[safe] = 0;
        emit EmergencyDeGuardCancelled(safe, msg.sender);
    }

    /// @dev The one family of transactions the Guard may never block — no quantum
    ///      approval, no pause, no enrollment requirement. Matches:
    ///        a) safe → guard: the owner safety calls — requestEmergencyDeGuard(),
    ///           cancelEmergencyDeGuard(safe), pauseSafe(safe), requestUnpauseSafe(),
    ///           unpauseSafe(), revokePreApproval(id), cancelKeyRevocation(safe).
    ///           Each re-checks its own authority; none can move funds or weaken
    ///           enforcement (unpausing is itself time-locked);
    ///        b) safe → safe: setGuard(address(0)), only after the emergency timelock.
    ///      All must be plain CALLs with zero value.
    function _isEmergencyEscapeCall(address safe, address to, uint256 value, bytes memory data, Enum.Operation operation)
        internal
        view
        returns (bool)
    {
        if (operation != Enum.Operation.Call || value != 0 || data.length < 4) return false;
        bytes4 selector = bytes4(data);

        if (to == address(this)) {
            if (data.length == 4) {
                return selector == this.requestEmergencyDeGuard.selector
                    || selector == this.requestUnpauseSafe.selector || selector == this.unpauseSafe.selector;
            }
            if (data.length == 36) {
                return selector == this.cancelEmergencyDeGuard.selector || selector == this.pauseSafe.selector
                    || selector == this.revokePreApproval.selector || selector == this.cancelKeyRevocation.selector;
            }
            return false;
        }

        (bool isSetGuard, address newGuard) = _setGuardCall(safe, to, value, data, operation);
        if (isSetGuard && newGuard == address(0)) {
            uint64 executableAt = emergencyDeGuardExecutableAt[safe];
            return executableAt != 0 && block.timestamp >= executableAt; // nothing else is unlocked
        }
        return false;
    }

    /// @dev Is this a Safe self-call to setGuard(newGuard)?
    function _setGuardCall(address safe, address to, uint256 value, bytes memory data, Enum.Operation operation)
        private
        pure
        returns (bool isSetGuard, address newGuard)
    {
        if (to != safe || operation != Enum.Operation.Call || value != 0 || data.length != 36) return (false, address(0));
        if (bytes4(data) != SEL_SET_GUARD) return (false, address(0));
        assembly ("memory-safe") {
            newGuard := mload(add(data, 36))
        }
        return (true, newGuard);
    }

    // ── Per-Safe pause (fast, any owner) / unpause (slow, Safe governance) ──

    /// @notice Freeze all Guard-checked activity of one Safe, instantly. Callable by
    ///         any single owner of the Safe, the Safe itself, or its Quantum
    ///         Administrator — fast and low-privilege so a compromised key holder
    ///         cannot front-run revocations. The emergency de-guard and the quantum-
    ///         approved Guard removal both keep working while paused (no-brick).
    function pauseSafe(address safe) external {
        if (!enrolledSafe[safe]) revert NotEnrolledSafe(safe);
        if (msg.sender != safe && !_isSafeOwner(safe, msg.sender)) {
            bytes32 keyId = safeToQuantumKey[safe];
            if (keyId == bytes32(0) || msg.sender != _keys[keyId].quantumAdmin) revert NotAuthorized();
        }
        safePaused[safe] = true;
        safeUnpauseExecutableAt[safe] = 0; // a fresh pause cancels any pending unpause
        emit SafePaused(safe, msg.sender);
    }

    /// @notice Start the unpause delay. Only the Safe (owner-threshold transaction).
    function requestUnpauseSafe() external {
        address safe = msg.sender;
        if (!safePaused[safe]) revert SafeNotPaused(safe);
        uint64 executableAt = uint64(block.timestamp) + ADMIN_TIMELOCK;
        safeUnpauseExecutableAt[safe] = executableAt;
        emit SafeUnpauseRequested(safe, executableAt);
    }

    /// @notice Complete an unpause after ADMIN_TIMELOCK. Only the Safe.
    function unpauseSafe() external {
        address safe = msg.sender;
        uint64 executableAt = safeUnpauseExecutableAt[safe];
        if (executableAt == 0) revert UnpauseNotRequested();
        if (block.timestamp < executableAt) revert UnpauseTimelocked(executableAt);
        safeUnpauseExecutableAt[safe] = 0;
        safePaused[safe] = false;
        emit SafeUnpaused(safe);
    }

    // ── Pause (fast) / unpause (slow, time-locked) ──────────────────────────

    /// @notice Global deny-all circuit breaker, for incidents affecting every Safe
    ///         (e.g. a verifier bug). Guardian only: on a shared singleton, letting any
    ///         enrolled Safe pause would let one Safe freeze all others. Individual
    ///         Safes use `pauseSafe`.
    function pause() external {
        if (!hasRole(PAUSER_ROLE, msg.sender)) revert NotAuthorized();
        _pause();
        emit GuardPaused(msg.sender);
    }

    /// @notice Unpausing is slow and high-privilege: governance role + time lock.
    function requestUnpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        unpauseExecutableAt = uint64(block.timestamp) + ADMIN_TIMELOCK;
        emit GuardUnpauseRequested(msg.sender, unpauseExecutableAt);
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint64 executableAt = unpauseExecutableAt;
        if (executableAt == 0) revert UnpauseNotRequested();
        if (block.timestamp < executableAt) revert UnpauseTimelocked(executableAt);
        unpauseExecutableAt = 0;
        _unpause();
        emit GuardUnpaused(msg.sender);
    }

    // ── Selector policy (deny-list hardcoded; permit-list ADMIN-governed) ───

    /// @notice Mutate a Safe's selector permit-list. Only callable by the Safe itself —
    ///         which forces the call through checkTransaction's ADMIN path (this Guard is
    ///         an ADMIN target): hybrid dual signature + owner threshold + ADMIN_TIMELOCK.
    ///         No EOA, guardian, or deployer can modify any Safe's allowlist.
    function setSelectorPolicy(address safe, bytes4 selector, bool allowed) external {
        if (msg.sender != safe) revert NotAuthorized();
        if (_isDeniedSelector(selector)) revert DeniedSelector(selector); // never re-enableable
        allowedSelectors[safe][selector] = allowed;
        emit SelectorPolicyChanged(safe, selector, allowed);
    }

    /// Enrollment hook: permit-list initialized to {transfer} only.
    function _afterEnrollment(address safe) internal override {
        allowedSelectors[safe][SEL_TRANSFER] = true;
        emit SelectorPolicyChanged(safe, SEL_TRANSFER, true);
    }

    // ── Class dispatch ──────────────────────────────────────────────────────

    /// @dev Spec dispatch order:
    ///        1. delegatecall → only the pinned MultiSendCallOnly (batch path);
    ///        2. to == safe or to == guard → ADMIN;
    ///        3. bare native send → PAYLOAD;
    ///        4. ERC-20 transfer → TRANSFER;
    ///        5. anything else → PAYLOAD + selector permit-list (deny-list first).
    function _dispatch(
        address safe,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        bytes32 safeTxHash
    ) private returns (bytes32 id) {
        PreApproval memory expected;
        expected.safe = safe;

        if (operation == Enum.Operation.DelegateCall) {
            if (to != MULTISEND_CALL_ONLY) revert DelegateCallForbidden(to);
            _checkBatchLegs(safe, data);
            expected.class_ = ApprovalClass.PAYLOAD;
            expected.target = to;
            expected.value = value;
            expected.dataHash = keccak256(data); // binds every leg: order, targets, values, calldata
            return _consumeMatching(safe, safeTxHash, expected);
        }

        if (to == safe || to == address(this)) {
            // Restricted administrative action: setGuard/setModuleGuard/enableModule/
            // disableModule/owner/threshold changes (self-call) or Guard policy mutation.
            expected.class_ = ApprovalClass.ADMIN;
            expected.target = to;
            expected.value = value;
            expected.dataHash = keccak256(data);
            return _consumeMatching(safe, safeTxHash, expected);
        }

        if (data.length == 0) {
            // Native currency send (value == 0 with empty data is a no-op ping — still
            // requires an exact PAYLOAD approval rather than a silent allow).
            expected.class_ = ApprovalClass.PAYLOAD;
            expected.target = to;
            expected.value = value;
            expected.dataHash = keccak256(data);
            return _consumeMatching(safe, safeTxHash, expected);
        }

        if (data.length < 4) revert MalformedTransferCalldata();
        bytes4 selector = bytes4(data);
        if (_isDeniedSelector(selector)) revert DeniedSelector(selector);

        if (selector == SEL_TRANSFER) {
            (address recipient, uint256 amount) = _decodeTransfer(data);
            expected.class_ = ApprovalClass.TRANSFER;
            expected.token = to;
            expected.recipient = recipient;
            expected.amount = amount;
            return _consumeMatching(safe, safeTxHash, expected);
        }

        if (!allowedSelectors[safe][selector]) revert SelectorNotAllowed(safe, selector);
        expected.class_ = ApprovalClass.PAYLOAD;
        expected.target = to;
        expected.value = value;
        expected.dataHash = keccak256(data);
        return _consumeMatching(safe, safeTxHash, expected);
    }

    // ── Batch (MultiSendCallOnly) structural checks ─────────────────────────

    /// @dev Strict decode of `multiSend(bytes transactions)` calldata. The PAYLOAD hash
    ///      already binds the batch; these per-leg checks are the on-chain backstop that
    ///      holds even if the host lies about the legs. Every check is O(1) per leg;
    ///      the leg cap is enforced BEFORE decoding further legs, so adversarial input
    ///      costs at most MAX_BATCH_LEGS header reads.
    function _checkBatchLegs(address safe, bytes memory data) private view {
        // Outer calldata: multiSend(bytes) — selector + abi-encoded bytes.
        if (data.length < 4 + 64 || bytes4(data) != bytes4(keccak256("multiSend(bytes)"))) revert MalformedBatch();

        uint256 txsOffset;
        uint256 txsLen;
        assembly ("memory-safe") {
            txsOffset := mload(add(data, 36)) // offset word of the bytes argument (rel. to arg area at data+36)
            txsLen := mload(add(add(data, 36), txsOffset)) // length word of the bytes argument
        }
        if (txsOffset != 0x20) revert MalformedBatch(); // canonical head-encoding only
        // The packed transactions blob must sit exactly inside the (padded) calldata.
        if (68 + txsLen > data.length) revert MalformedBatch();

        uint256 base;
        assembly ("memory-safe") {
            base := add(add(data, 68), txsOffset) // first packed leg (length word + 32)
        }

        uint256 offset = 0;
        uint256 legs = 0;
        while (offset < txsLen) {
            unchecked {
                ++legs;
            }
            if (legs > MAX_BATCH_LEGS) revert BatchTooLarge(legs, MAX_BATCH_LEGS); // before decoding further
            if (txsLen - offset < LEG_HEADER) revert MalformedBatch(); // truncated header

            uint8 op;
            address legTo;
            uint256 dataLength;
            assembly ("memory-safe") {
                let p := add(base, offset)
                op := shr(248, mload(p))
                legTo := shr(96, mload(add(p, 1)))
                dataLength := mload(add(p, 53))
            }
            if (op != 0) revert MalformedBatch(); // CALL only (redundant with MultiSendCallOnly, checked anyway)
            if (dataLength > txsLen - offset - LEG_HEADER) revert MalformedBatch(); // overrun / truncation
            // No admin ops smuggled inside batches — those go through ADMIN alone.
            if (legTo == safe || legTo == address(this) || legTo == MULTISEND_CALL_ONLY) {
                revert ForbiddenBatchLegTarget(legTo);
            }
            if (dataLength >= 4) {
                bytes4 legSelector;
                assembly ("memory-safe") {
                    legSelector := mload(add(add(base, offset), LEG_HEADER))
                }
                if (_isDeniedSelector(legSelector)) revert DeniedSelector(legSelector);
                if (legSelector != SEL_TRANSFER && !allowedSelectors[safe][legSelector]) {
                    revert SelectorNotAllowed(safe, legSelector);
                }
            } else if (dataLength != 0) {
                revert MalformedBatch(); // 1–3 byte calldata is never a valid call
            }
            offset += LEG_HEADER + dataLength;
        }
        if (offset != txsLen) revert MalformedBatch(); // no smuggled suffix
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    function _requireEnrolledActive(address safe) private view {
        bytes32 keyId = safeToQuantumKey[safe];
        if (keyId == bytes32(0) || _keys[keyId].status != KeyStatus.Active) revert NotEnrolledSafe(safe);
    }

    /// Module-bypass re-check: the tx guard is skipped by execTransactionFromModule
    /// pre-1.5, so either no modules are enabled or this contract is the module guard.
    function _checkModulePosture(address safe) private view {
        (bool ok, bytes memory ret) =
            safe.staticcall(abi.encodeWithSignature("getModulesPaginated(address,uint256)", address(0x1), 1));
        if (!ok || ret.length < 64) return; // pre-module-manager Safe: nothing to bypass with
        (address[] memory modules,) = abi.decode(ret, (address[], address));
        if (modules.length == 0) return;

        // Safe >= 1.5: acceptable iff this contract is wired as the module guard.
        (bool ok2, bytes memory slot) = safe.staticcall(
            abi.encodeWithSignature(
                "getStorageAt(uint256,uint256)",
                uint256(0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947), // MODULE_GUARD_STORAGE_SLOT
                1
            )
        );
        if (ok2 && slot.length >= 96) {
            address moduleGuard = abi.decode(abi.decode(slot, (bytes)), (address));
            if (moduleGuard == address(this)) return;
        }
        revert ModulesEnabledWithoutModuleGuard(safe);
    }

    function _isDeniedSelector(bytes4 selector) private pure returns (bool) {
        return selector == SEL_APPROVE || selector == SEL_TRANSFER_FROM || selector == SEL_INCREASE_ALLOWANCE
            || selector == SEL_PERMIT;
    }

    function _decodeTransfer(bytes memory data) private pure returns (address recipient, uint256 amount) {
        if (data.length != 68) revert MalformedTransferCalldata();
        assembly ("memory-safe") {
            recipient := mload(add(data, 36))
            amount := mload(add(data, 68))
        }
        if (uint256(uint160(recipient)) != uint256(bytes32(uint256(uint160(recipient))))) revert MalformedTransferCalldata();
    }

    function _depthSlot(address safe) private pure returns (bytes32) {
        return keccak256(abi.encode("fermionwallet.guard.depth", safe));
    }

    function _clearEmergencySlot(address safe) private pure returns (bytes32) {
        return keccak256(abi.encode("fermionwallet.guard.clearEmergency", safe));
    }
}
