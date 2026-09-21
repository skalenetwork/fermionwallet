// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {XMSS} from "../src/XMSS.sol";

contract XMSSWrapper {
    function verify(
        bytes32 messageDigest,
        XMSS.Signature memory sig,
        XMSS.PublicKey memory pk
    ) external view returns (bool) {
        return XMSS.verify(messageDigest, sig, pk);
    }
}

contract XMSSTest is Test {
    XMSSWrapper wrapper;

    function setUp() public {
        wrapper = new XMSSWrapper();
    }

    // ------------------------------------------------------------------
    // Vector loading
    // ------------------------------------------------------------------

    function loadVector(string memory file, uint256 i)
        internal
        view
        returns (bytes32 msgDigest, XMSS.Signature memory sig, XMSS.PublicKey memory pk)
    {
        string memory json = vm.readFile(string.concat("test/vectors/", file));
        pk.root = vm.parseJsonBytes32(json, ".root");
        pk.seed = vm.parseJsonBytes32(json, ".seed");
        string memory base = string.concat(".vectors[", vm.toString(i), "]");
        sig.leafIdx = uint32(vm.parseJsonUint(json, string.concat(base, ".idx")));
        sig.r = vm.parseJsonBytes32(json, string.concat(base, ".r"));
        msgDigest = vm.parseJsonBytes32(json, string.concat(base, ".msg"));
        bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(base, ".wotsSig"));
        for (uint256 k = 0; k < 67; ++k) sig.wotsSig[k] = w[k];
        sig.authPath = vm.parseJsonBytes32Array(json, string.concat(base, ".auth"));
    }

    function runAll(string memory file) internal view {
        for (uint256 i = 0; i < 4; ++i) {
            (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
                loadVector(file, i);
            assertTrue(wrapper.verify(m, sig, pk), "valid vector rejected");
        }
    }

    // ------------------------------------------------------------------
    // Positive tests
    // ------------------------------------------------------------------

    function test_verify_h4_allVectors() public view {
        runAll("xmss_h4.json");
    }

    function test_verify_h10_allVectors() public view {
        runAll("xmss_h10.json");
    }

    /// h=20 is the production parameter set (XMSS-SHA2_20_256).
    function test_verify_h20_allVectors() public view {
        runAll("xmss_h20.json");
    }

    // ------------------------------------------------------------------
    // Input validation
    // ------------------------------------------------------------------

    function test_reject_zeroRoot() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        pk.root = bytes32(0);
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function test_reject_zeroSeed() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        pk.seed = bytes32(0);
        assertFalse(wrapper.verify(m, sig, pk));
    }

    /// A signature for one tree height must not verify against a key of another.
    function test_reject_crossHeight() public view {
        (bytes32 m4, XMSS.Signature memory sig4,) = loadVector("xmss_h4.json", 0);
        (bytes32 m10, XMSS.Signature memory sig10, XMSS.PublicKey memory pk10) =
            loadVector("xmss_h10.json", 0);
        (,, XMSS.PublicKey memory pk4) = loadVector("xmss_h4.json", 0);
        assertFalse(wrapper.verify(m4, sig4, pk10));
        assertFalse(wrapper.verify(m10, sig10, pk4));
    }

    /// Tampering specifically with the WOTS+ checksum chains (indices 64..66).
    function test_reject_tamperedChecksumChain() public view {
        for (uint256 i = 64; i < 67; ++i) {
            (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
                loadVector("xmss_h10.json", 0);
            sig.wotsSig[i] ^= bytes32(uint256(1));
            assertFalse(wrapper.verify(m, sig, pk));
        }
    }

    // ------------------------------------------------------------------
    // Fuzz tests (h=4 vectors keep the fuzz loop affordable)
    // ------------------------------------------------------------------

    function testFuzz_reject_anyOtherMessage(bytes32 forged) public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h4.json", 0);
        vm.assume(forged != m);
        assertFalse(wrapper.verify(forged, sig, pk));
    }

    function testFuzz_reject_bitflippedWotsSig(uint8 element, uint8 bit) public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h4.json", 0);
        sig.wotsSig[element % 67] ^= bytes32(uint256(1) << bit);
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function testFuzz_reject_bitflippedAuthPath(uint8 level, uint8 bit) public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h4.json", 0);
        sig.authPath[level % sig.authPath.length] ^= bytes32(uint256(1) << bit);
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function testFuzz_reject_randomGarbageSignature(
        bytes32 r,
        bytes32 fill,
        uint32 leafIdx
    ) public view {
        (bytes32 m,, XMSS.PublicKey memory pk) = loadVector("xmss_h4.json", 0);
        XMSS.Signature memory sig;
        sig.leafIdx = leafIdx % 16;
        sig.r = r;
        for (uint256 i = 0; i < 67; ++i) {
            sig.wotsSig[i] = keccak256(abi.encodePacked(fill, i));
        }
        sig.authPath = new bytes32[](4);
        for (uint256 i = 0; i < 4; ++i) {
            sig.authPath[i] = keccak256(abi.encodePacked(fill, "auth", i));
        }
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function testFuzz_reject_wrongLeafIndexAnyValue(uint32 idx) public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h4.json", 0);
        vm.assume(idx != sig.leafIdx);
        sig.leafIdx = idx;
        assertFalse(wrapper.verify(m, sig, pk));
    }

    // ------------------------------------------------------------------
    // Negative tests (h=10 vector 0)
    // ------------------------------------------------------------------

    function test_reject_wrongMessage() public view {
        (, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        assertFalse(wrapper.verify(keccak256("forged"), sig, pk));
    }

    function test_reject_flippedMessageBit() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        assertFalse(wrapper.verify(m ^ bytes32(uint256(1)), sig, pk));
    }

    function test_reject_tamperedWotsSig() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        sig.wotsSig[33] ^= bytes32(uint256(1));
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function test_reject_tamperedAuthPath() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        sig.authPath[3] ^= bytes32(uint256(1));
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function test_reject_wrongLeafIndex() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        sig.leafIdx += 1;
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function test_reject_wrongRoot() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        pk.root ^= bytes32(uint256(1));
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function test_reject_wrongSeed() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        pk.seed ^= bytes32(uint256(1));
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function test_reject_wrongR() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        sig.r ^= bytes32(uint256(1));
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function test_reject_outOfRangeIndex() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        sig.leafIdx = 1024; // 2^10 — out of range
        assertFalse(wrapper.verify(m, sig, pk));
    }

    function test_reject_emptyAuthPath() public view {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        sig.authPath = new bytes32[](0);
        assertFalse(wrapper.verify(m, sig, pk));
    }

    // ------------------------------------------------------------------
    // Gas benchmark
    // ------------------------------------------------------------------

    function test_gas_verify_h10() public {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h10.json", 0);
        uint256 g0 = gasleft();
        bool ok = wrapper.verify(m, sig, pk);
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        emit log_named_uint("XMSS verify gas (h=10)", used);
    }

    function test_gas_verify_h20() public {
        (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk) =
            loadVector("xmss_h20.json", 0);
        uint256 g0 = gasleft();
        bool ok = wrapper.verify(m, sig, pk);
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        emit log_named_uint("XMSS verify gas (h=20, measured)", used);
        assertLt(used, 1_100_000, "h=20 verification exceeds gas budget");
    }
}
