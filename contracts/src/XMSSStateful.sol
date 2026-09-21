// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {XMSS} from "./XMSS.sol";

/// @title Stateful XMSS verifier with mandatory leaf-index consumption
/// @notice Wraps the stateless XMSS library with the one piece of state that XMSS
///         security requires: a used-leaf bitmap. `verifyAndConsume` atomically
///         checks the leaf, verifies the signature, and marks the leaf used —
///         reverting on any reuse. This is the reference enforcement point the
///         FermionWallet Guard builds on (fermionwallet-guard-module.md, "State
///         management"); the raw library must never be exposed to callers that
///         do not consume leaves.
/// @author FermionWallet — MIT licensed.
contract XMSSStateful {
    error LeafAlreadyUsed(uint32 leafIndex);
    error LeafIndexMismatch(uint32 expected, uint32 actual);
    error InvalidSignature();
    error InvalidKey();

    event LeafConsumed(uint32 indexed leafIndex, bytes32 messageDigest);

    bytes32 public immutable root;
    bytes32 public immutable seed;
    uint32 public immutable treeHeight;

    /// Used-leaf bitmap: word index => 256 leaf flags.
    mapping(uint256 => uint256) private usedLeaves;
    uint256 public usedCount;

    constructor(bytes32 root_, bytes32 seed_, uint32 treeHeight_) {
        if (root_ == bytes32(0) || seed_ == bytes32(0)) revert InvalidKey();
        if (treeHeight_ == 0 || treeHeight_ > XMSS.MAX_HEIGHT) revert InvalidKey();
        root = root_;
        seed = seed_;
        treeHeight = treeHeight_;
    }

    function isLeafUsed(uint32 leafIndex) public view returns (bool) {
        return usedLeaves[leafIndex >> 8] & (1 << (leafIndex & 0xff)) != 0;
    }

    /// @notice Verify `sig` over `messageDigest` and consume its leaf index.
    /// @dev Reverts (never returns false): a failed verification must abort the
    ///      surrounding transaction, and a reused leaf must be loud.
    function verifyAndConsume(bytes32 messageDigest, XMSS.Signature memory sig) external {
        // Height binding: an auth path of any other length is malformed for this key.
        if (sig.authPath.length != treeHeight) {
            revert LeafIndexMismatch(treeHeight, uint32(sig.authPath.length));
        }

        uint32 leaf = sig.leafIdx;
        uint256 word = usedLeaves[leaf >> 8];
        uint256 bit = 1 << (leaf & 0xff);
        if (word & bit != 0) revert LeafAlreadyUsed(leaf);

        // Verify before marking used — mirrors the Ledger app's ordering guarantee
        // (state committed only around a valid signature). XMSS.verify is a pure
        // internal library call (its only external touch is the SHA-256 precompile
        // via staticcall), so there is no reentrancy window between the check and
        // the effect below.
        if (!XMSS.verify(messageDigest, sig, XMSS.PublicKey({root: root, seed: seed}))) {
            revert InvalidSignature();
        }

        usedLeaves[leaf >> 8] = word | bit;
        unchecked {
            ++usedCount;
        }

        emit LeafConsumed(leaf, messageDigest);
    }
}
