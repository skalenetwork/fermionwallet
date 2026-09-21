// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {DoubleEndedQueue} from "@openzeppelin/contracts/utils/structs/DoubleEndedQueue.sol";
import {QuantumKeyRegistry} from "./QuantumKeyRegistry.sol";

/// @title PreApprovalEngine — hybrid (ECDSA + XMSS) time-bound pre-approvals
/// @notice Creates, indexes, revokes, and (for the Guard) consumes pre-approvals per
///         pre-approval-engine.md. Every creation verifies BOTH hybrid halves over the
///         same EIP-712 digest: the classical half against the registered Ledger EOA
///         (`quantumAdmin`) via SignatureChecker, and the post-quantum half against the
///         registered XMSS root with on-chain leaf consumption. Full signature bytes
///         are never stored — only `signatureHash` (gas-grief / storage-bloat vector).
///
///         Execution-time lookup is O(1)-bounded, two tiers:
///           Tier 1 (pinned): approvalByTxHash[safe][safeTxHash] — exact-transaction pin.
///           Tier 2 (field-matched): bounded FIFO queue per field commitment, lazy head
///           advance past expired/revoked entries so stale approvals never block live ones.
/// @dev    Abstract: deployed only as part of `FermionWalletGuard`.
abstract contract PreApprovalEngine is QuantumKeyRegistry {
    using SignatureChecker for address;
    using DoubleEndedQueue for DoubleEndedQueue.Bytes32Deque;

    // ── Types ───────────────────────────────────────────────────────────────

    enum ApprovalClass {
        TRANSFER, // ERC-20 transfer: token/recipient/amount binding, no timelock
        PAYLOAD, // exact payload: native ETH or policy-allowlisted call
        ADMIN // exact payload, target == safe (or this Guard); mandatory ADMIN_TIMELOCK
    }

    struct PreApproval {
        bytes32 id;
        address safe;
        ApprovalClass class_;
        // TRANSFER class fields (zero for other classes)
        address token;
        address recipient;
        uint256 amount;
        // PAYLOAD / ADMIN class fields (zero for TRANSFER)
        address target;
        uint256 value;
        bytes32 dataHash; // keccak256 of the exact calldata
        // common
        uint64 validFrom;
        uint64 validTo;
        bytes32 nonce;
        bytes32 quantumKeyId;
        uint32 xmssLeafIndex;
        bytes32 policyHash;
        bytes32 txHash; // exact safeTxHash pin (Tier 1); bytes32(0) = Tier 2
        bytes32 signatureHash; // keccak256 of the XMSS signature bytes (audit anchor)
        bool used;
        bool revoked;
    }

    /// Calldata request mirroring the EIP-712 PreApproval struct (minus the id and
    /// verification-derived fields). Class-irrelevant fields must be zero.
    struct PreApprovalRequest {
        address safe;
        address token; //     TRANSFER only
        address recipient; // TRANSFER only
        uint256 amount; //    TRANSFER only
        address target; //    PAYLOAD / ADMIN only
        uint256 value; //     PAYLOAD / ADMIN only
        bytes32 dataHash; //  PAYLOAD / ADMIN only
        uint64 validFrom;
        uint64 validTo;
        bytes32 nonce;
        bytes32 quantumKeyId;
        uint32 xmssLeafIndex;
        bytes32 policyHash;
        bytes32 txHash; //    Tier-1 pin; bytes32(0) = Tier-2 field queue
    }

    // ── Errors ──────────────────────────────────────────────────────────────

    error ApprovalExists(bytes32 id);
    error InvalidWindow(uint64 validFrom, uint64 validTo);
    error AdminTimelockNotRespected(uint64 validFrom, uint64 earliest);
    error InvalidAdminTarget(address target);
    error InvalidEcdsaSignature();
    error WrongQuantumKey(bytes32 expected, bytes32 actual);
    error LeafIndexDoesNotMatchSignature(uint32 declared, uint32 inSignature);
    error TxHashAlreadyPinned(address safe, bytes32 txHash);
    error CommitmentQueueFull(bytes32 commitment);
    error UnknownApproval(bytes32 id);
    error NotRevocable(bytes32 id);
    error NoMatchingPreApproval(address safe, bytes32 commitment, bytes32 safeTxHash);

    // ── Events ──────────────────────────────────────────────────────────────

    event PreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed token, uint256 amount);
    event PayloadPreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed target, bytes32 dataHash);
    event AdminPreApprovalCreated(
        bytes32 indexed id, address indexed safe, address indexed target, bytes32 dataHash, uint64 executableAt
    );
    event PreApprovalUsed(bytes32 indexed id, address indexed safe, address indexed recipient, uint256 amount);
    event PreApprovalRevoked(bytes32 indexed id, address indexed safe);

    // ── Constants / immutables ──────────────────────────────────────────────

    /// Minimum validity-window length: block.timestamp is validator-skewable by
    /// seconds, so windows must never be a sub-minute security boundary.
    uint64 public constant MIN_WINDOW = 15 minutes;
    /// Mandatory delay for ADMIN-class approvals (guard removal, owner changes,
    /// policy mutation) — the watch-and-revoke window. Immutable by design.
    uint64 public immutable ADMIN_TIMELOCK;
    /// Tier-2 per-commitment queue bound: caps consumption-time traversal gas.
    uint32 public immutable MAX_COMMITMENT_QUEUE;

    /// EIP-712 struct both hybrid halves sign. Binds safe + chainid (via the domain)
    /// + class + every class field + validity + nonce + leaf index + policyHash +
    /// optional txHash pin — neither half is replayable across Safes, chains, or payloads.
    bytes32 internal constant PRE_APPROVAL_TYPEHASH = keccak256(
        "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
    );

    // ── Storage ─────────────────────────────────────────────────────────────

    mapping(bytes32 id => PreApproval) internal _approvals;
    /// Tier 1: exact safeTxHash pin. Pinned approvals never collide — Safe nonces differ.
    mapping(address safe => mapping(bytes32 safeTxHash => bytes32 id)) public approvalByTxHash;
    /// Tier 2: FIFO queue per field commitment (recurring identical payouts queue naturally).
    /// Permanently dead entries are popped from the front on every create and consume.
    mapping(bytes32 commitment => DoubleEndedQueue.Bytes32Deque) internal _queue;

    constructor(uint64 adminTimelock, uint32 maxCommitmentQueue) {
        ADMIN_TIMELOCK = adminTimelock;
        MAX_COMMITMENT_QUEUE = maxCommitmentQueue;
    }

    // ── Creation (relayer-called; `req.safe` is explicit, msg.sender is never trusted) ──

    error NonZeroClassFields();

    function createPreApproval(
        PreApprovalRequest calldata req,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature
    ) external returns (bytes32 preApprovalId) {
        if (req.token == address(0) || req.recipient == address(0)) revert ZeroAddress();
        if (req.target != address(0) || req.value != 0 || req.dataHash != bytes32(0)) revert NonZeroClassFields();
        preApprovalId = _create(_toApproval(req, ApprovalClass.TRANSFER), ecdsaSignature, xmssSignature);
        emit PreApprovalCreated(preApprovalId, req.safe, req.token, req.amount);
    }

    function createPayloadPreApproval(
        PreApprovalRequest calldata req,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature
    ) external returns (bytes32 preApprovalId) {
        if (req.target == address(0)) revert ZeroAddress();
        if (req.token != address(0) || req.recipient != address(0) || req.amount != 0) revert NonZeroClassFields();
        preApprovalId = _create(_toApproval(req, ApprovalClass.PAYLOAD), ecdsaSignature, xmssSignature);
        emit PayloadPreApprovalCreated(preApprovalId, req.safe, req.target, req.dataHash);
    }

    /// @notice ADMIN class: self-calls on the Safe (setGuard incl. address(0),
    ///         setModuleGuard, enable/disableModule, owner/threshold changes) and policy
    ///         mutations on this Guard (setSelectorPolicy). Reverts unless
    ///         `req.validFrom >= block.timestamp + ADMIN_TIMELOCK`. Emits a distinct, loud
    ///         event so watchers can revoke during the delay. The sanctioned unbrick path.
    function createAdminPreApproval(
        PreApprovalRequest calldata req,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature
    ) external returns (bytes32 preApprovalId) {
        if (req.target != req.safe && req.target != address(this)) revert InvalidAdminTarget(req.target);
        if (req.token != address(0) || req.recipient != address(0) || req.amount != 0) revert NonZeroClassFields();
        if (req.validFrom < block.timestamp + ADMIN_TIMELOCK) {
            revert AdminTimelockNotRespected(req.validFrom, uint64(block.timestamp) + ADMIN_TIMELOCK);
        }
        preApprovalId = _create(_toApproval(req, ApprovalClass.ADMIN), ecdsaSignature, xmssSignature);
        emit AdminPreApprovalCreated(preApprovalId, req.safe, req.target, req.dataHash, req.validFrom);
    }

    function _toApproval(PreApprovalRequest calldata req, ApprovalClass class_)
        private
        pure
        returns (PreApproval memory a)
    {
        a.safe = req.safe;
        a.class_ = class_;
        a.token = req.token;
        a.recipient = req.recipient;
        a.amount = req.amount;
        a.target = req.target;
        a.value = req.value;
        a.dataHash = req.dataHash;
        a.validFrom = req.validFrom;
        a.validTo = req.validTo;
        a.nonce = req.nonce;
        a.quantumKeyId = req.quantumKeyId;
        a.xmssLeafIndex = req.xmssLeafIndex;
        a.policyHash = req.policyHash;
        a.txHash = req.txHash;
    }

    // ── Revocation / validation ─────────────────────────────────────────────

    /// @notice Revoke a live approval. Callable by the Safe, the Quantum Administrator
    ///         whose key created it, or ANY single owner of the Safe, directly from the
    ///         owner's own address. Revocation is deliberately cheaper than approval: a
    ///         false alarm costs one re-approval, a missed alarm can cost the Safe.
    ///         Damage control, not undo — the consumed leaf is not recoverable.
    function revokePreApproval(bytes32 preApprovalId) external returns (bool) {
        PreApproval storage a = _approvals[preApprovalId];
        if (a.id == bytes32(0)) revert UnknownApproval(preApprovalId);
        if (
            msg.sender != a.safe && msg.sender != _keys[a.quantumKeyId].quantumAdmin
                && !_isSafeOwner(a.safe, msg.sender)
        ) revert NotAuthorized();
        if (a.used || a.revoked) revert NotRevocable(preApprovalId);
        a.revoked = true;
        emit PreApprovalRevoked(preApprovalId, a.safe);
        return true;
    }

    /// @notice Off-chain convenience only — never the consumption mechanism.
    function validatePreApproval(bytes32 preApprovalId) external view returns (bool valid, string memory reason) {
        PreApproval storage a = _approvals[preApprovalId];
        if (a.id == bytes32(0)) return (false, "unknown");
        if (a.used) return (false, "used");
        if (a.revoked) return (false, "revoked");
        if (block.timestamp < a.validFrom) return (false, "not yet valid");
        if (block.timestamp > a.validTo) return (false, "expired");
        if (!_keyUsable(a.quantumKeyId)) return (false, "key revoked");
        return (true, "");
    }

    function getPreApproval(bytes32 preApprovalId) external view returns (PreApproval memory) {
        return _approvals[preApprovalId];
    }

    // ── Creation internals ──────────────────────────────────────────────────

    function _create(PreApproval memory a, bytes calldata ecdsaSignature, bytes calldata xmssSignature)
        private
        returns (bytes32 id)
    {
        // Key must be the Safe's one Active key.
        KeyRegistration storage k = _activeKey(a.safe);
        if (a.quantumKeyId != k.quantumKeyId) revert WrongQuantumKey(k.quantumKeyId, a.quantumKeyId);

        // Window sanity: minimum granularity, not yet expired.
        if (a.validTo <= a.validFrom || a.validTo - a.validFrom < MIN_WINDOW || a.validTo <= block.timestamp) {
            revert InvalidWindow(a.validFrom, a.validTo);
        }

        // Nonce uniqueness == id uniqueness: the id IS the (safe, nonce) binding.
        id = keccak256(abi.encodePacked(a.safe, a.nonce));
        if (_approvals[id].id != bytes32(0)) revert ApprovalExists(id);
        a.id = id;

        // Both hybrid halves over the same EIP-712 digest. ECDSA first (cheap):
        // a valid XMSS half with a missing Ledger anchor must revert — checked
        // regardless of order, but failing early saves ~1M gas of hashing.
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    PRE_APPROVAL_TYPEHASH,
                    a.safe,
                    uint8(a.class_),
                    a.token,
                    a.recipient,
                    a.amount,
                    a.target,
                    a.value,
                    a.dataHash,
                    a.validFrom,
                    a.validTo,
                    a.nonce,
                    a.quantumKeyId,
                    a.xmssLeafIndex,
                    a.policyHash,
                    a.txHash
                )
            )
        );
        if (!k.quantumAdmin.isValidSignatureNow(digest, ecdsaSignature)) revert InvalidEcdsaSignature();

        uint32 leafInSig = _verifyAndConsumeXmss(a.quantumKeyId, digest, xmssSignature);
        if (leafInSig != a.xmssLeafIndex) revert LeafIndexDoesNotMatchSignature(a.xmssLeafIndex, leafInSig);

        a.signatureHash = keccak256(xmssSignature); // hash only — bytes are never persisted
        _approvals[id] = a;

        // Index for O(1) execution-time lookup.
        if (a.txHash != bytes32(0)) {
            // A pin may be replaced only when its approval can never execute (expired
            // or revoked) — the documented recovery for "approval expired before
            // execution" is to re-approve the same Safe transaction. A live pin, or a
            // used one (that Safe transaction already executed), is never overwritten.
            bytes32 prev = approvalByTxHash[a.safe][a.txHash];
            if (prev != bytes32(0)) {
                PreApproval storage p = _approvals[prev];
                if (p.used || (!p.revoked && block.timestamp <= p.validTo)) revert TxHashAlreadyPinned(a.safe, a.txHash);
            }
            approvalByTxHash[a.safe][a.txHash] = id;
        } else {
            // Prune first: dead entries must never count toward the cap, or a queue of
            // expired/revoked approvals would lock this commitment out forever.
            bytes32 c = _commitment(a);
            DoubleEndedQueue.Bytes32Deque storage q = _queue[c];
            _pruneDead(q);
            if (q.length() >= MAX_COMMITMENT_QUEUE) revert CommitmentQueueFull(c);
            q.pushBack(id);
        }
    }

    /// Field commitment for Tier-2 matching — includes `safe` so one Safe's approvals
    /// can never satisfy another's transactions.
    function _commitment(PreApproval memory a) internal pure returns (bytes32) {
        if (a.class_ == ApprovalClass.TRANSFER) {
            return keccak256(abi.encode(a.safe, a.class_, a.token, a.recipient, a.amount));
        }
        return keccak256(abi.encode(a.safe, a.class_, a.target, a.value, a.dataHash));
    }

    // ── Consumption internals (Guard-only; called from checkTransaction) ────

    /// @dev Consume a matching approval for `safe`. Tier 1 (safeTxHash pin) first,
    ///      then the Tier-2 field queue. Marks `used` inside checkTransaction —
    ///      the only place consumption is atomic with execution. Reverts if nothing
    ///      matches; the expected-fields check on the Tier-1 hit is defense in depth
    ///      (the pin already binds the payload via the Safe tx hash).
    function _consumeMatching(address safe, bytes32 safeTxHash, PreApproval memory expected)
        internal
        returns (bytes32 id)
    {
        // Tier 1 — pinned.
        id = approvalByTxHash[safe][safeTxHash];
        if (id != bytes32(0)) {
            PreApproval storage a = _approvals[id];
            if (_isConsumable(a) && _fieldsMatch(a, expected)) {
                _markUsed(a);
                return id;
            }
            id = bytes32(0); // pinned but dead (expired/revoked/mismatched) — fall through
        }

        // Tier 2 — field-matched FIFO. Only permanently dead entries (used / revoked /
        // expired / revoked key) are ever popped; a merely not-yet-valid entry (future
        // validFrom) stays queued even when a later entry is consumed over it —
        // otherwise a scheduled approval would be silently lost and its leaf wasted.
        bytes32 c = _commitment(expected);
        DoubleEndedQueue.Bytes32Deque storage q = _queue[c];
        _pruneDead(q);
        uint256 len = q.length();
        for (uint256 i = 0; i < len; ++i) {
            PreApproval storage a = _approvals[q.at(i)];
            if (_isConsumable(a)) {
                _markUsed(a);
                _pruneDead(q);
                return a.id;
            }
        }
        revert NoMatchingPreApproval(safe, c, safeTxHash);
    }

    /// Pop permanently dead entries off the front of a Tier-2 queue (bounded by its cap).
    function _pruneDead(DoubleEndedQueue.Bytes32Deque storage q) private {
        while (!q.empty() && _isDead(_approvals[q.front()])) q.popFront();
    }

    function _isConsumable(PreApproval storage a) private view returns (bool) {
        return a.id != bytes32(0) && !a.used && !a.revoked && block.timestamp >= a.validFrom
            && block.timestamp <= a.validTo && _keyUsable(a.quantumKeyId);
    }

    /// Can never become consumable again (as opposed to merely not-yet-valid).
    function _isDead(PreApproval storage a) private view returns (bool) {
        return a.used || a.revoked || block.timestamp > a.validTo || !_keyUsable(a.quantumKeyId);
    }

    /// Approvals created under a key stay executable after routine rotation — they
    /// were fully verified at creation, and rotation only stops NEW creations
    /// (quantum-key-registry.md, "Invariants"). Only revocation, the response to
    /// compromise, kills them.
    function _keyUsable(bytes32 quantumKeyId) private view returns (bool) {
        KeyStatus s = _keys[quantumKeyId].status;
        return s == KeyStatus.Active || s == KeyStatus.Rotated;
    }

    function _fieldsMatch(PreApproval storage a, PreApproval memory e) private view returns (bool) {
        if (a.class_ != e.class_ || a.safe != e.safe) return false;
        if (a.class_ == ApprovalClass.TRANSFER) {
            return a.token == e.token && a.recipient == e.recipient && a.amount == e.amount;
        }
        return a.target == e.target && a.value == e.value && a.dataHash == e.dataHash;
    }

    function _markUsed(PreApproval storage a) private {
        a.used = true;
        emit PreApprovalUsed(
            a.id, a.safe, a.class_ == ApprovalClass.TRANSFER ? a.recipient : a.target, a.class_ == ApprovalClass.TRANSFER ? a.amount : a.value
        );
    }
}
