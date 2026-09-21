// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {XMSS} from "../src/XMSS.sol";
import {XMSSStateful} from "../src/XMSSStateful.sol";

contract XMSSStatefulTest is Test {
    XMSSStateful verifier;
    bytes32 root;
    bytes32 seed;

    function setUp() public {
        string memory json = vm.readFile("test/vectors/xmss_h10.json");
        root = vm.parseJsonBytes32(json, ".root");
        seed = vm.parseJsonBytes32(json, ".seed");
        verifier = new XMSSStateful(root, seed, 10);
    }

    function loadSig(uint256 i) internal view returns (bytes32 m, XMSS.Signature memory sig) {
        string memory json = vm.readFile("test/vectors/xmss_h10.json");
        string memory base = string.concat(".vectors[", vm.toString(i), "]");
        sig.leafIdx = uint32(vm.parseJsonUint(json, string.concat(base, ".idx")));
        sig.r = vm.parseJsonBytes32(json, string.concat(base, ".r"));
        m = vm.parseJsonBytes32(json, string.concat(base, ".msg"));
        bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(base, ".wotsSig"));
        for (uint256 k = 0; k < 67; ++k) sig.wotsSig[k] = w[k];
        sig.authPath = vm.parseJsonBytes32Array(json, string.concat(base, ".auth"));
    }

    function test_consumesLeaf() public {
        (bytes32 m, XMSS.Signature memory sig) = loadSig(0);
        assertFalse(verifier.isLeafUsed(sig.leafIdx));
        verifier.verifyAndConsume(m, sig);
        assertTrue(verifier.isLeafUsed(sig.leafIdx));
        assertEq(verifier.usedCount(), 1);
    }

    /// The catastrophic XMSS failure mode: leaf reuse must be impossible.
    function test_revertOnLeafReuse() public {
        (bytes32 m, XMSS.Signature memory sig) = loadSig(0);
        verifier.verifyAndConsume(m, sig);
        vm.expectRevert(abi.encodeWithSelector(XMSSStateful.LeafAlreadyUsed.selector, sig.leafIdx));
        verifier.verifyAndConsume(m, sig);
    }

    function test_distinctLeavesBothConsumable() public {
        (bytes32 m0, XMSS.Signature memory s0) = loadSig(0);
        (bytes32 m1, XMSS.Signature memory s1) = loadSig(1);
        verifier.verifyAndConsume(m0, s0);
        verifier.verifyAndConsume(m1, s1);
        assertEq(verifier.usedCount(), 2);
    }

    function test_revertOnInvalidSignature_leafNotBurned() public {
        (bytes32 m, XMSS.Signature memory sig) = loadSig(0);
        sig.wotsSig[7] ^= bytes32(uint256(1));
        vm.expectRevert(XMSSStateful.InvalidSignature.selector);
        verifier.verifyAndConsume(m, sig);
        // the revert rolled the bitmap back — the honest signature still works
        (bytes32 m2, XMSS.Signature memory sig2) = loadSig(0);
        verifier.verifyAndConsume(m2, sig2);
    }

    function test_revertOnWrongHeight() public {
        (bytes32 m, XMSS.Signature memory sig) = loadSig(0);
        sig.authPath = new bytes32[](4); // h=4 shape against an h=10 key
        vm.expectRevert(
            abi.encodeWithSelector(XMSSStateful.LeafIndexMismatch.selector, uint32(10), uint32(4))
        );
        verifier.verifyAndConsume(m, sig);
    }

    function test_revertOnZeroKeyAtDeploy() public {
        vm.expectRevert(XMSSStateful.InvalidKey.selector);
        new XMSSStateful(bytes32(0), seed, 10);
        vm.expectRevert(XMSSStateful.InvalidKey.selector);
        new XMSSStateful(root, bytes32(0), 10);
        vm.expectRevert(XMSSStateful.InvalidKey.selector);
        new XMSSStateful(root, seed, 0);
        vm.expectRevert(XMSSStateful.InvalidKey.selector);
        new XMSSStateful(root, seed, 21); // > XMSS.MAX_HEIGHT (20)
    }
}
