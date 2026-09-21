#!/usr/bin/env python3
"""Generate the h=20 (production-parameter XMSS-SHA2_20_256) test vectors.

Separate from xmss_ref.main() because the 2^20-leaf tree needs multiprocessing
(~3-4 min on 20 cores, ~70 min single-core). MIT licensed.
"""
import json
import multiprocessing as mp
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import xmss_ref as x  # noqa: E402

H = 20
_seed = x.sha(b"fermionwallet/public-seed/%d" % H)
_sk_seed = x.sha(b"fermionwallet/sk-seed/%d" % H)
_sk_prf = x.sha(b"fermionwallet/sk-prf/%d" % H)


def leaf(i: int) -> bytes:
    return x.ltree(x.wots_pk(_sk_seed, i, _seed), i, _seed)


def leaf_range(args):
    lo, hi = args
    return b"".join(leaf(i) for i in range(lo, hi))


def main():
    t0 = time.time()
    n = 1 << H
    chunk = 4096
    ranges = [(i, min(i + chunk, n)) for i in range(0, n, chunk)]
    with mp.Pool() as pool:
        blobs = pool.map(leaf_range, ranges)
    raw = b"".join(blobs)
    leaves = [raw[32 * i:32 * (i + 1)] for i in range(n)]
    print(f"leaves done in {time.time() - t0:.0f}s", flush=True)

    levels = [leaves]
    for k in range(H):
        cur = levels[-1]
        levels.append([x.rand_hash(cur[2 * i], cur[2 * i + 1], _seed,
                                   x.adrs(2, 0, k, i, 0))
                       for i in range(len(cur) // 2)])
    root = levels[H][0]

    vectors = []
    for idx in (0, 1, n - 1, n // 2):
        msg = x.sha(b"fermionwallet/msg/%d/%d" % (H, idx))
        r, sig_ots, auth = x.sign(msg, idx, levels, _sk_seed, _sk_prf, _seed)
        assert x.verify(msg, idx, r, sig_ots, auth, root, _seed)
        assert not x.verify(x.sha(b"x"), idx, r, sig_ots, auth, root, _seed)
        vectors.append({
            "idx": idx,
            "msg": x.hx(msg),
            "r": x.hx(r),
            "wotsSig": [x.hx(s) for s in sig_ots],
            "auth": [x.hx(a) for a in auth],
        })

    out = os.path.join(os.path.dirname(__file__), "..", "test", "vectors",
                       f"xmss_h{H}.json")
    with open(out, "w") as f:
        json.dump({"h": H, "seed": x.hx(_seed), "root": x.hx(root),
                   "vectors": vectors}, f, indent=1)
    print(f"h={H}: root={x.hx(root)} total {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
