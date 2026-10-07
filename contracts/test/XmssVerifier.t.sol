// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {XMSS} from "xmss-solidity/XMSS.sol";
import {IXmssVerifier, XmssVerifier} from "../src/XmssVerifier.sol";

/// Every normative claim `eips/erc-draft-xmss-verification.md` makes about the wire
/// format and the accept/reject behaviour of a conforming verifier, executed.
///
/// The standard states an exact encoded length; a spec that states a number nobody
/// runs is a number that drifts.
contract XmssVerifierTest is Test {
    XmssVerifier verifier;

    function setUp() public {
        verifier = new XmssVerifier();
    }

    /// `abi.encode(XMSS.Signature)` is 2304 + 32 * h bytes — the standard's formula.
    function test_encodedSignatureLength() public pure {
        assertEq(_encodedLength(10), 2624, "XMSS-SHA2_10_256");
        assertEq(_encodedLength(16), 2816, "XMSS-SHA2_16_256");
        assertEq(_encodedLength(20), 2944, "XMSS-SHA2_20_256");
        for (uint32 h = 1; h <= 20; ++h) {
            assertEq(_encodedLength(h), 2304 + 32 * uint256(h), "2304 + 32h");
        }
    }

    function test_verifiesAGenuineSignature() public {
        bytes32 digest = keccak256("erc-xmss test vector");
        (bytes32 root, bytes32 seed, bytes memory sig) = _sign(10, 7, digest);
        assertTrue(verifier.verifyXmssSignature(digest, root, seed, 10, sig), "genuine signature accepted");
    }

    function test_rejectsAFlippedBit() public {
        bytes32 digest = keccak256("erc-xmss test vector");
        (bytes32 root, bytes32 seed, bytes memory sig) = _sign(10, 7, digest);
        sig[2000] = bytes1(uint8(sig[2000]) ^ 0x01); // inside the WOTS+ signature
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 10, sig), "mutated signature rejected");
    }

    function test_rejectsAnotherDigest() public {
        bytes32 digest = keccak256("erc-xmss test vector");
        (bytes32 root, bytes32 seed, bytes memory sig) = _sign(10, 7, digest);
        assertFalse(
            verifier.verifyXmssSignature(keccak256("a different message"), root, seed, 10, sig), "digest is bound"
        );
    }

    /// The height is an input, not a field of the signature: a signature under a
    /// height-10 key must not verify when the caller claims another height.
    function test_rejectsAHeightThatIsNotTheKeysHeight() public {
        bytes32 digest = keccak256("erc-xmss test vector");
        (bytes32 root, bytes32 seed, bytes memory sig) = _sign(10, 7, digest);
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 9, sig), "height 9 rejected");
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 11, sig), "height 11 rejected");
    }

    function test_rejectsOutOfDomainParameters() public {
        bytes32 digest = keccak256("erc-xmss test vector");
        (bytes32 root, bytes32 seed, bytes memory sig) = _sign(10, 7, digest);
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 0, sig), "height 0");
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 21, sig), "height above MAX_HEIGHT");
        assertFalse(verifier.verifyXmssSignature(digest, bytes32(0), seed, 10, sig), "zero root");
        assertFalse(verifier.verifyXmssSignature(digest, root, bytes32(0), 10, sig), "zero seed");
    }

    /// A wrong-length blob is refused without reverting, so a caller cannot be griefed
    /// into a revert by a malformed third-party signature.
    function test_rejectsAWrongLengthEncoding() public {
        bytes32 digest = keccak256("erc-xmss test vector");
        (bytes32 root, bytes32 seed, bytes memory sig) = _sign(10, 7, digest);
        bytes memory short_ = new bytes(sig.length - 1);
        for (uint256 i = 0; i < short_.length; ++i) {
            short_[i] = sig[i];
        }
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 10, short_), "truncated");
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 10, ""), "empty");
    }

    function test_advertisesItsInterface() public view {
        // The standard quotes this identifier as a literal; a signature change here would
        // silently invalidate it ([XV-16]).
        assertEq(type(IXmssVerifier).interfaceId, bytes4(0x5867b896), "the identifier the ERC states");
        assertTrue(verifier.supportsInterface(type(IXmssVerifier).interfaceId), "IXmssVerifier");
        assertTrue(verifier.supportsInterface(type(IERC165).interfaceId), "IERC165");
        assertFalse(verifier.supportsInterface(0xffffffff), "the ERC-165 invalid id");
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _encodedLength(uint32 h) private pure returns (uint256) {
        XMSS.Signature memory sig;
        sig.authPath = new bytes32[](h);
        return abi.encode(sig).length;
    }

    /// Sign `digest` at `leaf` with the deterministic height-`h` test key.
    function _sign(uint32 h, uint32 leaf, bytes32 digest)
        private
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

    function _word(bytes memory b, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), mul(i, 32)))
        }
    }
}
