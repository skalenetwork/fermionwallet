// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {XMSS} from "xmss-solidity/XMSS.sol";

/// @title Stateless XMSS verification, callable from any contract or off-chain client
/// @notice The external interface of `eips/erc-draft-xmss-verification.md`: one view
///         function over the ABI-encoded signature structure that standard defines.
/// @dev    Verification alone grants no authority. XMSS is a ONE-TIME-signature scheme:
///         a caller that derives authority from a valid signature MUST also record the
///         consumed leaf index — keyed by `root`, never by its own registration record —
///         and refuse a repeat. See `QuantumKeyRegistry._verifyAndConsumeXmss` for the
///         enforcing caller, and the standard's "Leaf-index accounting" clauses.
interface IXmssVerifier {
    /// @notice Verify an RFC 8391 XMSS signature over a 32-byte digest.
    /// @param messageDigest the signed 32-byte message digest
    /// @param root          the XMSS public root of the signing key
    /// @param seed          the XMSS public SEED of the signing key
    /// @param treeHeight    the height the key was generated with (1..20); binds the
    ///                      parameter set the way RFC 8391's public-key OID does
    /// @param signature     `abi.encode(XMSS.Signature)` — 2304 + 32 * treeHeight bytes
    /// @return valid true iff the signature is valid for (root, seed) at `treeHeight`
    function verifyXmssSignature(
        bytes32 messageDigest,
        bytes32 root,
        bytes32 seed,
        uint256 treeHeight,
        bytes calldata signature
    ) external view returns (bool valid);
}

/// @title XmssVerifier — the reference implementation of `IXmssVerifier`
/// @notice Stateless and immutable: no storage, no owner, no upgrade path.
contract XmssVerifier is IXmssVerifier, IERC165 {
    /// Wire length of `abi.encode(XMSS.Signature)` at tree height 0, i.e. everything
    /// except the authentication path's elements: a leading offset word, the head
    /// (leafIdx, r, wotsSig[67] inline, authPath offset) and the authPath length word.
    uint256 internal constant ENCODED_SIGNATURE_BASE_LENGTH = 2304;

    /// @inheritdoc IXmssVerifier
    function verifyXmssSignature(
        bytes32 messageDigest,
        bytes32 root,
        bytes32 seed,
        uint256 treeHeight,
        bytes calldata signature
    ) external view returns (bool) {
        if (treeHeight == 0 || treeHeight > XMSS.MAX_HEIGHT) return false;
        if (signature.length != ENCODED_SIGNATURE_BASE_LENGTH + 32 * treeHeight) return false;
        XMSS.Signature memory sig = abi.decode(signature, (XMSS.Signature));
        return XMSS.verify(messageDigest, sig, XMSS.PublicKey({root: root, seed: seed}), treeHeight);
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IXmssVerifier).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
