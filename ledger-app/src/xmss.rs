//! XMSS-SHA2_h_256 signing (RFC 8391), n = 32, w = 16, len = 67.
//!
//! A line-for-line port of `contracts/lib/xmss-solidity/py/xmss_ref.py`, which is
//! the reference this project's Solidity verifier is proven against and which
//! agrees with the RFC authors' own C implementation on 40/40 differential-fuzzing
//! cases. Porting that file rather than the RFC prose is deliberate: a signer that
//! disagrees with the verifier by one domain byte produces signatures the Guard
//! silently refuses, and the fuzzed reference is the only artefact in the repo
//! known to match it.
//!
//! Signer-side private-key derivation is implementation-defined in RFC 8391 (the
//! verifier never sees it); everything a verifier checks follows the reference.

use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::hash::HashInit;

pub const N: usize = 32;
const W: usize = 16;
pub const LEN: usize = 67; // len_1 (64) + len_2 (3)

/// Tree height of the key this app holds: 2^4 = 16 one-time signatures.
pub const HEIGHT: usize = 4;
const LEAVES: usize = 1 << HEIGHT;

/// `r ‖ wotsSig[67] ‖ authPath[HEIGHT]`, the part of the blob that XMSS produces.
pub const SIG_WORDS: usize = 1 + LEN + HEIGHT;
pub const SIG_LEN: usize = SIG_WORDS * N;

/// The secrets of one key. `sk_seed` and `sk_prf` never leave the device; `seed` is
/// the public SEED an RFC 8391 verifier needs (registered on-chain as `xmssSeed`).
pub struct Key {
    pub sk_seed: [u8; N],
    pub sk_prf: [u8; N],
    pub seed: [u8; N],
}

// Working buffers. Static rather than stack: 2.6 KB of locals would overflow the
// Nano's stack, and the app is single-threaded with one signing session at a time.
static mut WOTS: [[u8; N]; LEN] = [[0; N]; LEN];
static mut NODES: [[u8; N]; LEAVES] = [[0; N]; LEAVES];

// ── RFC 8391 §5.1: the four keyed hashes, distinguished by a domain word ──────

fn sha(parts: &[&[u8]]) -> [u8; N] {
    let mut ctx = Sha2_256::new();
    for p in parts {
        // The SDK's hash calls fail only on a malformed context, which cannot
        // happen here; a panic would be a device fault, not a host error.
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; N];
    ctx.finalize(&mut out).unwrap();
    out
}

/// `toByte(t, 32)`, the domain separator of each hash function.
const fn dom(t: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = t;
    w
}
const DOM_F: [u8; 32] = dom(0);
const DOM_H: [u8; 32] = dom(1);
const DOM_H_MSG: [u8; 32] = dom(2);
const DOM_PRF: [u8; 32] = dom(3);

fn f(key: &[u8; N], m: &[u8; N]) -> [u8; N] {
    sha(&[&DOM_F, key, m])
}

fn h(key: &[u8; N], left: &[u8; N], right: &[u8; N]) -> [u8; N] {
    sha(&[&DOM_H, key, left, right])
}

fn h_msg(r: &[u8; N], root: &[u8; N], idx: u32, m: &[u8; N]) -> [u8; N] {
    sha(&[&DOM_H_MSG, r, root, &word32(idx), m])
}

fn prf(seed: &[u8; N], adrs: &[u8; N]) -> [u8; N] {
    sha(&[&DOM_PRF, seed, adrs])
}

/// `toByte(x, 32)`.
fn word32(x: u32) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[28..32].copy_from_slice(&x.to_be_bytes());
    w
}

// ── RFC 8391 §2.5: the hash address ──────────────────────────────────────────

/// `layer(4) ‖ tree(8) ‖ type(4) ‖ w4 ‖ w5 ‖ w6 ‖ keyAndMask`, layer and tree zero
/// (this is a single-tree XMSS, not XMSS^MT).
fn adrs(typ: u32, w4: u32, w5: u32, w6: u32, key_and_mask: u32) -> [u8; N] {
    let mut a = [0u8; N];
    a[12..16].copy_from_slice(&typ.to_be_bytes());
    a[16..20].copy_from_slice(&w4.to_be_bytes());
    a[20..24].copy_from_slice(&w5.to_be_bytes());
    a[24..28].copy_from_slice(&w6.to_be_bytes());
    a[28..32].copy_from_slice(&key_and_mask.to_be_bytes());
    a
}

/// RFC 8391 Algorithm 7: RAND_HASH.
fn rand_hash(left: &[u8; N], right: &[u8; N], seed: &[u8; N], a: &[u8; N]) -> [u8; N] {
    let mut base = *a;
    base[28..32].copy_from_slice(&0u32.to_be_bytes());
    let key = prf(seed, &base);
    base[28..32].copy_from_slice(&1u32.to_be_bytes());
    let bm0 = prf(seed, &base);
    base[28..32].copy_from_slice(&2u32.to_be_bytes());
    let bm1 = prf(seed, &base);

    let mut l = *left;
    let mut r = *right;
    for i in 0..N {
        l[i] ^= bm0[i];
        r[i] ^= bm1[i];
    }
    h(&key, &l, &r)
}

// ── WOTS+ ────────────────────────────────────────────────────────────────────

/// RFC 8391 Algorithm 2: the hash chain, `steps` applications of F from `start`.
fn chain(x: &[u8; N], ots: u32, cadr: u32, start: u32, steps: u32, seed: &[u8; N]) -> [u8; N] {
    let mut acc = *x;
    for j in start..start + steps {
        let key = prf(seed, &adrs(0, ots, cadr, j, 0));
        let bm = prf(seed, &adrs(0, ots, cadr, j, 1));
        for i in 0..N {
            acc[i] ^= bm[i];
        }
        acc = f(&key, &acc);
    }
    acc
}

/// base_w(M, 16) of a 32-byte digest, followed by its 3-digit checksum
/// (RFC 8391 §3.1.5, Algorithm 5 steps 1-6).
fn base_w_with_csum(digest: &[u8; N]) -> [u8; LEN] {
    let mut vals = [0u8; LEN];
    for (i, &b) in digest.iter().enumerate() {
        vals[2 * i] = b >> 4;
        vals[2 * i + 1] = b & 0x0f;
    }
    let mut csum = 0u32;
    for v in vals[..2 * N].iter() {
        csum += (W - 1) as u32 - *v as u32;
    }
    // csum << 4 so its 12 significant bits sit at the top of two bytes.
    let cb = ((csum << 4) as u16).to_be_bytes();
    vals[64] = cb[0] >> 4;
    vals[65] = cb[0] & 0x0f;
    vals[66] = cb[1] >> 4;
    vals
}

/// The WOTS+ secret key of one chain. Implementation-defined; matches the
/// reference so device and reference produce identical signatures for one key.
fn wots_sk(sk_seed: &[u8; N], leaf: u32, i: u32) -> [u8; N] {
    sha(&[sk_seed, &leaf.to_be_bytes(), &i.to_be_bytes()])
}

// ── Leaves, L-tree and the Merkle tree ───────────────────────────────────────

#[allow(static_mut_refs)]
fn wots_buf() -> &'static mut [[u8; N]; LEN] {
    unsafe { &mut WOTS }
}

#[allow(static_mut_refs)]
fn nodes_buf() -> &'static mut [[u8; N]; LEAVES] {
    unsafe { &mut NODES }
}

/// RFC 8391 Algorithm 8: compress a WOTS+ public key (in `WOTS`) to one node.
fn ltree(leaf: u32, seed: &[u8; N]) -> [u8; N] {
    let pk = wots_buf();
    let mut len = LEN;
    let mut height = 0u32;
    while len > 1 {
        let pairs = len / 2;
        for i in 0..pairs {
            pk[i] = rand_hash(&pk[2 * i], &pk[2 * i + 1], seed, &adrs(1, leaf, height, i as u32, 0));
        }
        if len & 1 == 1 {
            pk[pairs] = pk[len - 1];
            len = pairs + 1;
        } else {
            len = pairs;
        }
        height += 1;
    }
    pk[0]
}

/// The Merkle leaf for one one-time key: L-tree of its WOTS+ public key.
fn leaf_node(key: &Key, leaf: u32) -> [u8; N] {
    {
        let pk = wots_buf();
        for i in 0..LEN {
            let sk = wots_sk(&key.sk_seed, leaf, i as u32);
            pk[i] = chain(&sk, leaf, i as u32, 0, (W - 1) as u32, &key.seed);
        }
    }
    ltree(leaf, &key.seed)
}

/// Build the whole tree, returning the root and, if `auth` is given, the
/// authentication path of `leaf`. The tree is rebuilt from the seeds every time —
/// 16 leaves is cheap enough that no traversal state has to be kept (and kept
/// correct) across signatures.
fn tree(key: &Key, leaf: u32, mut auth: Option<&mut [[u8; N]; HEIGHT]>) -> [u8; N] {
    let nodes = nodes_buf();
    for i in 0..LEAVES {
        nodes[i] = leaf_node(key, i as u32);
    }
    let mut count = LEAVES;
    let mut level = 0usize;
    while count > 1 {
        if let Some(a) = auth.as_deref_mut() {
            // The sibling of this leaf's ancestor at this level, read before the
            // level is folded over.
            a[level] = nodes[((leaf as usize) >> level) ^ 1];
        }
        for i in 0..count / 2 {
            nodes[i] = rand_hash(
                &nodes[2 * i],
                &nodes[2 * i + 1],
                &key.seed,
                &adrs(2, 0, level as u32, i as u32, 0),
            );
        }
        count /= 2;
        level += 1;
    }
    nodes[0]
}

/// Derive this build's key from the device's BIP-32 node at the app's XMSS path.
///
/// RFC 8391 leaves signer-side derivation open, so the three secrets are just
/// domain-separated hashes of the node. Note what this means and what README.md
/// says about it: a key derived this way is restorable from the recovery phrase,
/// which the spec forbids for a stateful key holding real funds.
pub fn derive(node: &[u8; N]) -> Key {
    Key {
        sk_seed: sha(&[b"FermionGuard/xmss/sk-seed/v1", node]),
        sk_prf: sha(&[b"FermionGuard/xmss/sk-prf/v1", node]),
        seed: sha(&[b"FermionGuard/xmss/pub-seed/v1", node]),
    }
}

/// The public root of the key: what the registry stores as `xmssRoot`.
pub fn public_root(key: &Key) -> [u8; N] {
    tree(key, 0, None)
}

/// Sign `msg` with the one-time leaf the counter has just committed, writing
/// `r ‖ wotsSig ‖ authPath` into `out` (`SIG_LEN` bytes). Returns the key's root — the
/// signature is valid only under that root, which the verifier already has from
/// registration, so the device does not put it on the wire.
///
/// The index arrives as [`session::Signing`](crate::session::Signing) rather than a
/// `u32`, and that is the point: this function has no way to tell whether a leaf is
/// fresh, a leaf used twice makes WOTS+ forgeable, and the only `Signing` token that
/// exists is the one `session::publish` mints from a leaf it has already committed.
/// So the caller cannot reach this function with an index the counter did not consume,
/// and `xmss::sign(&key, 0, …)` is a type error rather than a forgeable pair of
/// signatures. `session.rs`'s module documentation has the whole argument.
pub fn sign(
    key: &Key,
    leaf: crate::session::Signing,
    msg: &[u8; N],
    out: &mut [u8],
) -> [u8; N] {
    let leaf = leaf.index();
    let mut auth = [[0u8; N]; HEIGHT];
    let root = tree(key, leaf, Some(&mut auth));

    let r = sha(&[&key.sk_prf, &word32(leaf)]);
    let m_prime = h_msg(&r, &root, leaf, msg);
    let vals = base_w_with_csum(&m_prime);

    out[..N].copy_from_slice(&r);
    for i in 0..LEN {
        let sk = wots_sk(&key.sk_seed, leaf, i as u32);
        let sig = chain(&sk, leaf, i as u32, 0, vals[i] as u32, &key.seed);
        out[(1 + i) * N..(2 + i) * N].copy_from_slice(&sig);
    }
    for (k, node) in auth.iter().enumerate() {
        out[(1 + LEN + k) * N..(2 + LEN + k) * N].copy_from_slice(node);
    }
    root
}
