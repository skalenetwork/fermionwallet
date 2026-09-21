// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title XMSS signature verification (RFC 8391, XMSS-SHA2_*_256 parameter family)
/// @notice Clean-room implementation from RFC 8391 / NIST SP 800-208. Verifies a
///         single-tree XMSS signature over a 32-byte message digest using the
///         SHA-256 precompile. Parameters: n = 32, w = 16, len = 67; tree height
///         is taken from the auth-path length, capped at the largest standardized
///         single-tree height (20, XMSS-SHA2_20_256).
/// @dev    Stateless and storage-free. Leaf-index reuse protection (mandatory for
///         XMSS security) is enforced by XMSSStateful.sol / the FermionWallet
///         Guard — never expose this library to callers that do not consume
///         leaf indices, as specified in fermionwallet-guard-module.md.
/// @author FermionWallet — MIT licensed.
library XMSS {
    /// Winternitz parameter w = 16: 4 bits per chain, 64 message chains,
    /// 3 checksum chains, chain length w - 1 = 15.
    uint256 internal constant LEN = 67;
    uint256 internal constant LEN1 = 64;
    uint256 internal constant W_MINUS_1 = 15;

    /// Largest RFC 8391 single-tree height (XMSS-SHA2_20_256). Anything taller
    /// is not a standardized parameter set and is rejected outright.
    uint256 internal constant MAX_HEIGHT = 20;

    /// Gas stipend for SHA-256 precompile calls. The precompile costs
    /// 60 + 12*ceil(len/32) = 96..108 gas for our 96/128-byte inputs; a fixed
    /// bound fails fast under gas starvation instead of forwarding gas().
    uint256 private constant SHA256_GAS = 1000;

    struct PublicKey {
        bytes32 root; // Merkle tree root
        bytes32 seed; // public SEED for hash-function bitmasks/keys
    }

    struct Signature {
        uint32 leafIdx;         // idx_sig — the (one-time!) leaf index
        bytes32 r;              // randomizer for H_msg
        bytes32[LEN] wotsSig;   // WOTS+ signature, 67 x 32 bytes
        bytes32[] authPath;     // Merkle authentication path, h x 32 bytes
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// @notice Verify an XMSS signature over `messageDigest`.
    /// @param messageDigest 32-byte message digest (e.g. an EIP-712 struct hash).
    /// @return true iff the signature is valid for `pk`.
    function verify(
        bytes32 messageDigest,
        Signature memory sig,
        PublicKey memory pk
    ) internal view returns (bool) {
        // A zero SEED collapses every PRF-derived key/bitmask to a function of
        // the ADRS alone; a zero root can never be a real tree root. Both are
        // unconditionally rejected as malformed keys.
        if (pk.root == bytes32(0) || pk.seed == bytes32(0)) return false;

        uint256 h = sig.authPath.length;
        if (h == 0 || h > MAX_HEIGHT) return false;
        if (uint256(sig.leafIdx) >= (1 << h)) return false;

        // M' = H_msg(r || root || toByte(idx, 32), M)      (RFC 8391 §4.1.9)
        bytes32 mPrime = sha256(
            abi.encodePacked(
                uint256(2), sig.r, pk.root, uint256(sig.leafIdx), messageDigest
            )
        );

        // One 160-byte hash buffer, allocated once and reused by every prf/F/H
        // call below: bytes [0..127] hold the hash input, bytes [128..159] the
        // output. No reliance on Solidity scratch space or the free-memory
        // pointer — the assembly hashing is strictly memory-safe.
        bytes memory scratchBuf = new bytes(160);
        uint256 scratch;
        assembly ("memory-safe") {
            scratch := add(scratchBuf, 32)
        }

        bytes32 node = rootFromSig(mPrime, sig, pk.seed, scratch);
        return node == pk.root;
    }

    // ------------------------------------------------------------------
    // RFC 8391 Algorithm 13: XMSS_rootFromSig
    // ------------------------------------------------------------------

    function rootFromSig(
        bytes32 mPrime,
        Signature memory sig,
        bytes32 seed,
        uint256 scratch
    ) private view returns (bytes32) {
        uint32 idx = sig.leafIdx;

        // WOTS+ public key from signature, then L-tree compression to the leaf.
        bytes32[LEN] memory wotsPk = wotsPkFromSig(mPrime, sig.wotsSig, idx, seed, scratch);
        bytes32 node = ltree(wotsPk, idx, seed, scratch);

        // Climb the Merkle tree with the authentication path (type-2 ADRS).
        uint256 h = sig.authPath.length;
        uint32 treeIdx = idx;
        for (uint256 k = 0; k < h; ++k) {
            treeIdx >>= 1;
            if ((idx >> k) & 1 == 0) {
                node = randHash(node, sig.authPath[k], seed, adrs(2, 0, uint32(k), treeIdx, 0), scratch);
            } else {
                node = randHash(sig.authPath[k], node, seed, adrs(2, 0, uint32(k), treeIdx, 0), scratch);
            }
        }
        return node;
    }

    // ------------------------------------------------------------------
    // WOTS+ (RFC 8391 §3.1) — public key recovery from a signature
    // ------------------------------------------------------------------

    function wotsPkFromSig(
        bytes32 mPrime,
        bytes32[LEN] memory sigOts,
        uint32 otsAddr,
        bytes32 seed,
        uint256 scratch
    ) private view returns (bytes32[LEN] memory pk) {
        // base_w(M', 16) — 64 nibbles, big-endian — plus 3 checksum nibbles.
        uint256 m = uint256(mPrime);
        uint256 csum = 0;

        for (uint256 i = 0; i < LEN1; ++i) {
            uint256 d = (m >> (252 - 4 * i)) & 0xf;
            csum += W_MINUS_1 - d;
            pk[i] = chain(sigOts[i], otsAddr, uint32(i), uint32(d), uint32(W_MINUS_1 - d), seed, scratch);
        }

        // csum <= 960 (10 bits); left-shift 4 into a 16-bit field, take 3 nibbles.
        csum <<= 4;
        for (uint256 i = 0; i < 3; ++i) {
            uint256 d = (csum >> (12 - 4 * i)) & 0xf;
            pk[LEN1 + i] = chain(
                sigOts[LEN1 + i], otsAddr, uint32(LEN1 + i), uint32(d), uint32(W_MINUS_1 - d), seed, scratch
            );
        }
    }

    /// RFC 8391 Algorithm 2: chain — iterate F with per-step PRF key and bitmask.
    function chain(
        bytes32 x,
        uint32 otsAddr,
        uint32 chainAddr,
        uint32 start,
        uint32 steps,
        bytes32 seed,
        uint256 scratch
    ) private view returns (bytes32) {
        for (uint32 j = start; j < start + steps; ++j) {
            bytes32 key = prf(seed, adrs(0, otsAddr, chainAddr, j, 0), scratch);
            bytes32 bm = prf(seed, adrs(0, otsAddr, chainAddr, j, 1), scratch);
            // F(KEY, M) = SHA-256(toByte(0, 32) || KEY || M)
            x = fHash(key, x ^ bm, scratch);
        }
        return x;
    }

    // ------------------------------------------------------------------
    // L-tree (RFC 8391 Algorithm 8)
    // ------------------------------------------------------------------

    function ltree(
        bytes32[LEN] memory nodes,
        uint32 ltreeAddr,
        bytes32 seed,
        uint256 scratch
    ) private view returns (bytes32) {
        uint256 l = LEN;
        uint32 height = 0;
        while (l > 1) {
            uint256 half = l >> 1;
            for (uint256 i = 0; i < half; ++i) {
                nodes[i] = randHash(
                    nodes[2 * i], nodes[2 * i + 1], seed, adrs(1, ltreeAddr, height, uint32(i), 0), scratch
                );
            }
            if (l & 1 == 1) {
                nodes[half] = nodes[l - 1];
                l = half + 1;
            } else {
                l = half;
            }
            ++height;
        }
        return nodes[0];
    }

    // ------------------------------------------------------------------
    // Keyed hash primitives (RFC 8391 §5.1, SHA-256 instantiation)
    // ------------------------------------------------------------------

    /// RAND_HASH (Algorithm 1): H with PRF-derived key and two bitmasks.
    /// The `a` argument carries words 3..6 of the ADRS. The keyAndMask word
    /// (lowest 4 bytes) is explicitly cleared before being set to 0/1/2, so the
    /// result is correct regardless of what the caller left in that field.
    function randHash(
        bytes32 left,
        bytes32 right,
        bytes32 seed,
        bytes32 a,
        uint256 scratch
    ) private view returns (bytes32) {
        bytes32 base = bytes32(uint256(a) & ~uint256(0xffffffff)); // keyAndMask := 0
        bytes32 key = prf(seed, base, scratch);
        bytes32 bm0 = prf(seed, base | bytes32(uint256(1)), scratch);
        bytes32 bm1 = prf(seed, base | bytes32(uint256(2)), scratch);
        // H(KEY, M) = SHA-256(toByte(1, 32) || KEY || M), |M| = 2n
        return hHash(key, left ^ bm0, right ^ bm1, scratch);
    }

    /// PRF(SEED, ADRS) = SHA-256(toByte(3, 32) || SEED || ADRS)
    /// @dev `scratch` points into a caller-allocated 160-byte buffer: input is
    ///      written at [scratch..], output at [scratch+128..scratch+160). Fully
    ///      memory-safe — only caller-allocated memory is touched.
    function prf(bytes32 seed, bytes32 a, uint256 scratch) private view returns (bytes32 out) {
        assembly ("memory-safe") {
            mstore(scratch, 3)
            mstore(add(scratch, 32), seed)
            mstore(add(scratch, 64), a)
            if iszero(staticcall(SHA256_GAS, 2, scratch, 96, add(scratch, 128), 32)) { revert(0, 0) }
            out := mload(add(scratch, 128))
        }
    }

    /// F(KEY, M) = SHA-256(toByte(0, 32) || KEY || M), |M| = n
    function fHash(bytes32 key, bytes32 m32, uint256 scratch) private view returns (bytes32 out) {
        assembly ("memory-safe") {
            mstore(scratch, 0)
            mstore(add(scratch, 32), key)
            mstore(add(scratch, 64), m32)
            if iszero(staticcall(SHA256_GAS, 2, scratch, 96, add(scratch, 128), 32)) { revert(0, 0) }
            out := mload(add(scratch, 128))
        }
    }

    /// H(KEY, M) = SHA-256(toByte(1, 32) || KEY || M), |M| = 2n
    function hHash(bytes32 key, bytes32 l, bytes32 r, uint256 scratch) private view returns (bytes32 out) {
        assembly ("memory-safe") {
            mstore(scratch, 1)
            mstore(add(scratch, 32), key)
            mstore(add(scratch, 64), l)
            mstore(add(scratch, 96), r)
            if iszero(staticcall(SHA256_GAS, 2, scratch, 128, add(scratch, 128), 32)) { revert(0, 0) }
            out := mload(add(scratch, 128))
        }
    }

    /// Pack an RFC 8391 §2.5 hash-function address into bytes32.
    /// Layout (big-endian 4-byte words): layer | tree(8B) | type | w4 | w5 | w6 | keyAndMask.
    /// Layer and tree address are always 0 for single-tree XMSS.
    function adrs(
        uint32 typ,
        uint32 word4,
        uint32 word5,
        uint32 word6,
        uint32 keyAndMask
    ) private pure returns (bytes32) {
        return bytes32(
            (uint256(typ) << 128) | (uint256(word4) << 96) | (uint256(word5) << 64)
                | (uint256(word6) << 32) | uint256(keyAndMask)
        );
    }
}
