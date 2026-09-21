#!/usr/bin/env python3
"""Foundry FFI helper: sign an arbitrary 32-byte digest with the deterministic
test XMSS key (RFC 8391 reference implementation, xmss_ref.py).

Usage:  sign_digest.py <h> <leaf_idx> <digest_hex>

Prints a single hex blob (no 0x) laid out as fixed 32-byte words:
    root | seed | r | wotsSig[67] | authPath[h]
The Foundry test parses this layout directly. MIT licensed. Test-only —
production signing happens exclusively inside the Ledger secure element.
"""
import functools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xmss_ref as x  # noqa: E402


@functools.lru_cache(maxsize=None)
def keypair(h: int):
    seed = x.sha(b"fermionwallet/test-signer/public-seed/%d" % h)
    sk_seed = x.sha(b"fermionwallet/test-signer/sk-seed/%d" % h)
    sk_prf = x.sha(b"fermionwallet/test-signer/sk-prf/%d" % h)
    levels = x.build_tree(h, sk_seed, seed)
    return seed, sk_seed, sk_prf, levels


def main() -> None:
    h = int(sys.argv[1])
    idx = int(sys.argv[2])
    digest = bytes.fromhex(sys.argv[3].removeprefix("0x"))
    assert len(digest) == 32 and 0 <= idx < (1 << h)

    seed, sk_seed, sk_prf, levels = keypair(h)
    root = levels[h][0]
    r, sig_ots, auth = x.sign(digest, idx, levels, sk_seed, sk_prf, seed)
    assert x.verify(digest, idx, r, sig_ots, auth, root, seed)

    out = root + seed + r + b"".join(sig_ots) + b"".join(auth)
    sys.stdout.write(out.hex())


if __name__ == "__main__":
    main()
