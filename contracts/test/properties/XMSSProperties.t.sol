// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {XMSS} from "../../src/XMSS.sol";

contract XMSSVerifier {
    function verify(bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) external view returns (bool) {
        return XMSS.verify(m, sig, pk);
    }

    /// Exactly the registry's path: ABI-decode the raw signature bytes, then verify.
    function decodeAndVerify(bytes32 m, bytes calldata blob, XMSS.PublicKey memory pk)
        external
        view
        returns (bool ok, bytes32 decodedHash)
    {
        XMSS.Signature memory sig = abi.decode(blob, (XMSS.Signature));
        return (XMSS.verify(m, sig, pk), keccak256(abi.encode(sig)));
    }
}

/// XMSS verifier properties over the RFC 8391 reference vectors (no FFI):
///  - any single-byte mutation of a valid signature (leaf index, r, any WOTS+ chain
///    value, any auth-path node) is rejected;
///  - any single-byte mutation of the ABI-encoded signature bytes the registry decodes
///    either fails to decode, fails to verify, or decodes to the identical signature;
///  - a signature over one digest never verifies another digest (vectors cross-checked,
///    and arbitrary digests), nor under another key.
contract XMSSPropertiesTest is Test {
    XMSSVerifier internal v;
    bytes32[4] internal msgs;
    bytes[4] internal sigs; // abi.encode(XMSS.Signature)
    bytes32 internal root;
    bytes32 internal seed;
    bytes32 internal root10;
    bytes32 internal seed10;
    bytes internal sig10;
    bytes32 internal msg10;

    uint256 internal constant H = 4;
    uint256 internal constant PACKED_LEN = 4 + 32 + 67 * 32 + H * 32; // leafIdx | r | wots | auth

    function setUp() public {
        v = new XMSSVerifier();
        string memory json = vm.readFile("test/vectors/xmss_h4.json");
        root = vm.parseJsonBytes32(json, ".root");
        seed = vm.parseJsonBytes32(json, ".seed");
        for (uint256 i = 0; i < 4; ++i) {
            (msgs[i], sigs[i]) = _load(json, i);
        }
        string memory json10 = vm.readFile("test/vectors/xmss_h10.json");
        root10 = vm.parseJsonBytes32(json10, ".root");
        seed10 = vm.parseJsonBytes32(json10, ".seed");
        (msg10, sig10) = _load(json10, 0);
    }

    function _load(string memory json, uint256 i) internal pure returns (bytes32 m, bytes memory encoded) {
        string memory base = string.concat(".vectors[", vm.toString(i), "]");
        XMSS.Signature memory sig;
        sig.leafIdx = uint32(vm.parseJsonUint(json, string.concat(base, ".idx")));
        sig.r = vm.parseJsonBytes32(json, string.concat(base, ".r"));
        m = vm.parseJsonBytes32(json, string.concat(base, ".msg"));
        bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(base, ".wotsSig"));
        for (uint256 k = 0; k < 67; ++k) {
            sig.wotsSig[k] = w[k];
        }
        sig.authPath = vm.parseJsonBytes32Array(json, string.concat(base, ".auth"));
        encoded = abi.encode(sig);
    }

    function _pk() internal view returns (XMSS.PublicKey memory) {
        return XMSS.PublicKey({root: root, seed: seed});
    }

    function _sig(uint256 i) internal view returns (XMSS.Signature memory) {
        return abi.decode(sigs[i], (XMSS.Signature));
    }

    function test_vectorsVerify() public view {
        for (uint256 i = 0; i < 4; ++i) {
            assertTrue(v.verify(msgs[i], _sig(i), _pk()));
        }
    }

    /// forge-config: default.fuzz.runs = 1024
    function testFuzz_anySingleByteMutationRejected(uint8 vec, uint256 pos, uint8 mask) public view {
        uint256 i = vec % 4;
        XMSS.Signature memory sig = _sig(i);
        pos = pos % PACKED_LEN;
        uint8 x = mask == 0 ? 1 : mask;
        if (pos < 4) {
            sig.leafIdx ^= uint32(x) << uint32(8 * (3 - pos));
        } else if (pos < 36) {
            sig.r ^= bytes32(uint256(x) << (8 * (31 - (pos - 4))));
        } else if (pos < 36 + 67 * 32) {
            uint256 off = pos - 36;
            sig.wotsSig[off / 32] ^= bytes32(uint256(x) << (8 * (31 - off % 32)));
        } else {
            uint256 off = pos - 36 - 67 * 32;
            sig.authPath[off / 32] ^= bytes32(uint256(x) << (8 * (31 - off % 32)));
        }
        assertFalse(v.verify(msgs[i], sig, _pk()), "mutated signature verified");
    }

    /// forge-config: default.fuzz.runs = 1024
    function testFuzz_abiBlobMutationNeverYieldsANewValidSignature(uint8 vec, uint256 pos, uint8 mask) public view {
        uint256 i = vec % 4;
        bytes memory blob = sigs[i];
        pos = pos % blob.length;
        blob[pos] = bytes1(uint8(blob[pos]) ^ (mask == 0 ? 1 : mask));
        try v.decodeAndVerify(msgs[i], blob, _pk()) returns (bool ok, bytes32 decodedHash) {
            if (ok) assertEq(decodedHash, keccak256(sigs[i]), "mutated bytes decoded to a different valid signature");
        } catch {
            // malformed ABI: rejected before verification
        }
    }

    /// forge-config: default.fuzz.runs = 256
    function testFuzz_signatureBindsItsDigest(uint8 a, uint8 b, bytes32 other) public view {
        uint256 i = a % 4;
        uint256 j = b % 4;
        if (i != j) assertFalse(v.verify(msgs[j], _sig(i), _pk()), "vector i verified vector j's digest");
        if (other != msgs[i]) assertFalse(v.verify(other, _sig(i), _pk()), "signature verified another digest");
    }

    /// A signature never verifies under another key (root or seed), and a tall-tree
    /// signature never verifies against a short-tree key or vice versa.
    /// forge-config: default.fuzz.runs = 256
    function testFuzz_signatureBindsItsKey(uint8 a, bytes32 otherRoot, bytes32 otherSeed) public view {
        uint256 i = a % 4;
        if (otherRoot != root) assertFalse(v.verify(msgs[i], _sig(i), XMSS.PublicKey(otherRoot, seed)));
        if (otherSeed != seed) assertFalse(v.verify(msgs[i], _sig(i), XMSS.PublicKey(root, otherSeed)));
        XMSS.Signature memory s10 = abi.decode(sig10, (XMSS.Signature));
        assertFalse(v.verify(msg10, s10, _pk()));
        assertFalse(v.verify(msgs[i], _sig(i), XMSS.PublicKey(root10, seed10)));
    }
}
