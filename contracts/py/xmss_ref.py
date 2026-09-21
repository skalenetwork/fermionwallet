#!/usr/bin/env python3
"""Clean-room XMSS reference (RFC 8391, SHA-256, n=32, w=16, len=67).

Generates test vectors for the Solidity verifier in contracts/src/XMSS.sol.
Signer-side private-key derivation is implementation-defined (verifier never
sees it); everything the verifier checks follows RFC 8391 exactly.

MIT licensed.
"""
import hashlib
import json
import os
import sys

N = 32
W = 16
LEN1 = 64
LEN2 = 3
LEN = LEN1 + LEN2


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def to_byte(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")


# --- keyed hash primitives (RFC 8391 §5.1, SHA-256 instantiation) ---

def F(key: bytes, m: bytes) -> bytes:
    return sha(to_byte(0, 32) + key + m)


def H(key: bytes, m: bytes) -> bytes:
    return sha(to_byte(1, 32) + key + m)


def H_msg(key: bytes, m: bytes) -> bytes:
    return sha(to_byte(2, 32) + key + m)


def PRF(seed: bytes, adrs: bytes) -> bytes:
    return sha(to_byte(3, 32) + seed + adrs)


def adrs(typ: int, w4: int, w5: int, w6: int, kam: int) -> bytes:
    # layer(4) | tree(8) | type(4) | w4 | w5 | w6 | keyAndMask — zero layer/tree
    return to_byte(0, 12) + to_byte(typ, 4) + to_byte(w4, 4) + to_byte(w5, 4) \
        + to_byte(w6, 4) + to_byte(kam, 4)


def rand_hash(left: bytes, right: bytes, seed: bytes, a: bytes) -> bytes:
    base = a[:28]
    key = PRF(seed, base + to_byte(0, 4))
    bm0 = PRF(seed, base + to_byte(1, 4))
    bm1 = PRF(seed, base + to_byte(2, 4))
    return H(key, bytes(x ^ y for x, y in zip(left, bm0))
             + bytes(x ^ y for x, y in zip(right, bm1)))


# --- WOTS+ ---

def chain(x: bytes, ots: int, cadr: int, start: int, steps: int, seed: bytes) -> bytes:
    for j in range(start, start + steps):
        key = PRF(seed, adrs(0, ots, cadr, j, 0))
        bm = PRF(seed, adrs(0, ots, cadr, j, 1))
        x = F(key, bytes(a ^ b for a, b in zip(x, bm)))
    return x


def base_w_with_csum(digest: bytes):
    vals = []
    for b in digest:
        vals += [b >> 4, b & 0xF]
    csum = sum(W - 1 - v for v in vals) << 4
    cb = to_byte(csum, 2)
    vals += [cb[0] >> 4, cb[0] & 0xF, cb[1] >> 4]
    assert len(vals) == LEN
    return vals


def wots_sk(sk_seed: bytes, leaf: int):
    return [sha(sk_seed + to_byte(leaf, 4) + to_byte(i, 4)) for i in range(LEN)]


def wots_pk(sk_seed: bytes, leaf: int, seed: bytes):
    sk = wots_sk(sk_seed, leaf)
    return [chain(sk[i], leaf, i, 0, W - 1, seed) for i in range(LEN)]


def wots_sign(digest: bytes, sk_seed: bytes, leaf: int, seed: bytes):
    sk = wots_sk(sk_seed, leaf)
    vals = base_w_with_csum(digest)
    return [chain(sk[i], leaf, i, 0, vals[i], seed) for i in range(LEN)]


# --- L-tree and Merkle tree ---

def ltree(pk, leaf: int, seed: bytes) -> bytes:
    nodes, height = list(pk), 0
    while len(nodes) > 1:
        nxt = [rand_hash(nodes[2 * i], nodes[2 * i + 1], seed,
                         adrs(1, leaf, height, i, 0))
               for i in range(len(nodes) // 2)]
        if len(nodes) & 1:
            nxt.append(nodes[-1])
        nodes, height = nxt, height + 1
    return nodes[0]


def build_tree(h: int, sk_seed: bytes, seed: bytes):
    leaves = [ltree(wots_pk(sk_seed, i, seed), i, seed) for i in range(1 << h)]
    levels = [leaves]
    for k in range(h):
        cur = levels[-1]
        levels.append([rand_hash(cur[2 * i], cur[2 * i + 1], seed,
                                 adrs(2, 0, k, i, 0))
                       for i in range(len(cur) // 2)])
    return levels  # levels[h][0] is the root


def sign(msg32: bytes, idx: int, levels, sk_seed, sk_prf, seed):
    h = len(levels) - 1
    root = levels[h][0]
    r = sha(sk_prf + to_byte(idx, 32))
    m_prime = H_msg(r + root + to_byte(idx, 32), msg32)
    sig_ots = wots_sign(m_prime, sk_seed, idx, seed)
    auth = [levels[k][(idx >> k) ^ 1] for k in range(h)]
    return r, sig_ots, auth


def verify(msg32, idx, r, sig_ots, auth, root, seed):
    h = len(auth)
    m_prime = H_msg(r + root + to_byte(idx, 32), msg32)
    vals = base_w_with_csum(m_prime)
    pk = [chain(sig_ots[i], idx, i, vals[i], W - 1 - vals[i], seed)
          for i in range(LEN)]
    node = ltree(pk, idx, seed)
    ti = idx
    for k in range(h):
        ti >>= 1
        pair = (node, auth[k]) if (idx >> k) & 1 == 0 else (auth[k], node)
        node = rand_hash(pair[0], pair[1], seed, adrs(2, 0, k, ti, 0))
    return node == root


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "test", "vectors")
    os.makedirs(out_dir, exist_ok=True)
    for h in (4, 10):
        # deterministic vectors
        seed = sha(b"fermionwallet/public-seed/%d" % h)
        sk_seed = sha(b"fermionwallet/sk-seed/%d" % h)
        sk_prf = sha(b"fermionwallet/sk-prf/%d" % h)
        levels = build_tree(h, sk_seed, seed)
        root = levels[h][0]
        vectors = []
        for idx in (0, 1, (1 << h) - 1, (1 << h) // 2):
            msg = sha(b"fermionwallet/msg/%d/%d" % (h, idx))
            r, sig_ots, auth = sign(msg, idx, levels, sk_seed, sk_prf, seed)
            assert verify(msg, idx, r, sig_ots, auth, root, seed)
            assert not verify(sha(b"x"), idx, r, sig_ots, auth, root, seed)
            vectors.append({
                "idx": idx,
                "msg": hx(msg),
                "r": hx(r),
                "wotsSig": [hx(s) for s in sig_ots],
                "auth": [hx(a) for a in auth],
            })
        with open(os.path.join(out_dir, f"xmss_h{h}.json"), "w") as f:
            json.dump({"h": h, "seed": hx(seed), "root": hx(root),
                       "vectors": vectors}, f, indent=1)
        print(f"h={h}: root={hx(root)} ({len(vectors)} vectors)")


if __name__ == "__main__":
    sys.exit(main())
