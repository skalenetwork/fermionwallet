#!/usr/bin/env python3
"""Foundry FFI helper: sign MANY 32-byte digests with the deterministic test XMSS
key in one process (the tree is built once), for property/invariant fixtures that
pre-generate a pool of signatures in setUp.

Usage:  sign_batch.py <h> <leaf_idx>:<digest_hex> [<leaf_idx>:<digest_hex> ...]

Prints one hex blob (no 0x): root | seed, then per request r | wotsSig[67] | authPath[h]
— all fixed 32-byte words. Same key derivation as sign_digest.py. MIT licensed.
Test-only.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "lib", "xmss-solidity", "py"))
import xmss_ref as x  # noqa: E402
from sign_digest import keypair  # noqa: E402


def main() -> None:
    h = int(sys.argv[1])
    seed, sk_seed, sk_prf, levels = keypair(h)
    root = levels[h][0]
    out = [root, seed]
    for item in sys.argv[2:]:
        idx_s, dig_s = item.split(":")
        idx = int(idx_s)
        digest = bytes.fromhex(dig_s.removeprefix("0x"))
        assert len(digest) == 32 and 0 <= idx < (1 << h)
        r, sig_ots, auth = x.sign(digest, idx, levels, sk_seed, sk_prf, seed)
        out.append(r + b"".join(sig_ots) + b"".join(auth))
    sys.stdout.write(b"".join(out).hex())


if __name__ == "__main__":
    main()
