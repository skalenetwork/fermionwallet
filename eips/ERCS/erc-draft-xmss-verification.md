---
eip: <to be assigned>
title: On-Chain XMSS Signature Verification
description: Encoding, verification rules and leaf-index accounting for RFC 8391 XMSS signatures verified inside the EVM
author: Konstantin Kladko (@kladkogex)
discussions-to: <URL>
status: Draft
type: Standards Track
category: ERC
created: 2026-09-30
requires: 165, 712, 4337
---

## Abstract

This ERC specifies how a contract verifies an XMSS signature (RFC 8391, `XMSS-SHA2_h_256`
family) over a 32-byte message digest: the canonical ABI encoding of an XMSS public key and
signature, the exact hash instantiation, the domain checks a verifier performs, an
[ERC-165](./eip-165.md)-identified verification interface, and — because XMSS is a *stateful one-time* scheme — the
leaf-index accounting that any contract deriving authority from such a signature is required
to perform. It defines no key generation and no signing: those stay off-chain, on the signer's
device.

## Motivation

ECDSA and BLS, the signature schemes the EVM supports natively, are broken by a
cryptographically relevant quantum computer. A smart account that wants to keep authorising
transfers after that point needs a signature scheme whose security rests on hash functions
alone. XMSS is the conservative choice: it is standardised (RFC 8391, NIST SP 800-208),
stateless in its verifier, and needs only SHA-256 — available on every EVM chain as
precompile `0x02`.

What has been missing is agreement on the parts that are not in RFC 8391 because they are
specific to a public blockchain:

1. **How the signature is encoded on the wire.** RFC 8391 §4.1.8 defines a byte-string
   format for `XMSS_signature`; contracts and wallets exchange ABI-encoded structures.
   Without one encoding, every wallet, relayer, indexer and verifier re-invents a
   serialisation, and a signature produced for one contract cannot be replayed into another
   even when both are correct.
2. **Who binds the tree height.** In RFC 8391 the public key carries an OID that fixes the
   parameter set and therefore the height (§4.1.7, §5.3). An ABI-encoded public key has no
   OID, so if the height is read from the signature the *signer* chooses it. That is a real
   attack surface (see Security Considerations), and the fix has to be stated normatively.
3. **Where the one-time state lives.** XMSS security collapses if one leaf index signs two
   different messages: two WOTS+ signatures under one chain leak enough chain positions to
   forge. Off-chain counters are advisory — an attacker with the private key ignores them.
   On a blockchain the only counter that cannot be rewound is on-chain, and this ERC states
   exactly what has to be recorded and what it has to be keyed by. The reference
   implementation shipped a bug here (leaves counted per *registration* instead of per
   *key*, so the same key enrolled by two accounts got two fresh counters) — the kind of
   mistake a normative clause prevents.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in RFC 2119 and RFC 8174.

Normative statements are labelled `[XV-nn]` for reference.

### 1. Parameters

This ERC covers the single-tree `XMSS-SHA2_h_256` parameter family of RFC 8391 §5.3:

| parameter | value | meaning |
| --- | --- | --- |
| `n` | 32 | hash output and node size, in bytes |
| `w` | 16 | Winternitz parameter |
| `len1` | 64 | WOTS+ message chains |
| `len2` | 3 | WOTS+ checksum chains |
| `len` | 67 | `len1 + len2`, total WOTS+ chains |
| `h` | 10, 16 or 20 | tree height; `2^h` one-time signatures per key |

The standardised parameter sets and their RFC 8391 OIDs are `XMSS-SHA2_10_256` (`0x00000001`),
`XMSS-SHA2_16_256` (`0x00000002`) and `XMSS-SHA2_20_256` (`0x00000003`).

- **[XV-01]** A verifier MUST reject any signature whose tree height is `0` or greater
  than `20`. Height 20 is the tallest standardised single tree; taller trees are not a
  standardised parameter set.
- **[XV-02]** A verifier MUST support the three standardised heights `10`, `16` and `20`: a
  valid signature at any of them, under a key of that height, MUST be accepted. It MAY also
  accept other heights in `1..20` (used by test vectors and by deployments that deliberately
  choose a smaller tree); a deployment that does SHOULD document which ones, and applications
  SHOULD register only keys of a standardised height.
- **[XV-03]** Multi-tree XMSS^MT (RFC 8391 §4.2) is out of scope of this ERC. A verifier
  conforming to this ERC MUST NOT accept an XMSS^MT signature as an XMSS signature.

### 2. Hash instantiation

With `toByte(x, y)` the `y`-byte big-endian encoding of `x` and `‖` concatenation, all
hashing is SHA-256 (RFC 8391 §5.1):

```text
PRF(SEED, ADRS) = SHA-256( toByte(3, 32) ‖ SEED ‖ ADRS )      ADRS is 32 bytes
F(KEY, M)       = SHA-256( toByte(0, 32) ‖ KEY  ‖ M )         |M| = 32
H(KEY, M)       = SHA-256( toByte(1, 32) ‖ KEY  ‖ M )         |M| = 64
H_msg(KEY, M)   = SHA-256( toByte(2, 32) ‖ KEY  ‖ M )
```

- **[XV-04]** The randomised message digest MUST be computed as
  `M' = H_msg(r ‖ root ‖ toByte(leafIdx, 32), messageDigest)`, i.e.
  `SHA-256(toByte(2,32) ‖ r ‖ root ‖ toByte(leafIdx,32) ‖ messageDigest)`, where
  `messageDigest` is the 32-byte digest being verified.

`ADRS` is the 32-byte hash-function address of RFC 8391 §2.5, in this layout (each field
big-endian):

| bytes | field | value for single-tree XMSS |
| --- | --- | --- |
| 0–3 | layer address | `0` |
| 4–11 | tree address | `0` |
| 12–15 | type | `0` OTS hash, `1` L-tree, `2` hash tree |
| 16–19 | word 4 | OTS address / L-tree address / padding `0` |
| 20–23 | word 5 | chain address / tree height |
| 24–27 | word 6 | hash address / tree index |
| 28–31 | keyAndMask | `0` key, `1` first bitmask, `2` second bitmask |

- **[XV-05]** Every `ADRS` a verifier constructs MUST have `layer address = 0` and
  `tree address = 0`. These fields are not carried in the wire format ([XV-06]) — there is
  nothing to validate, and nothing a signer can choose. They are fixed because a non-zero
  value would compute the hashes of a *different* subtree of an XMSS^MT key, and this ERC
  covers single trees only ([XV-03]).

### 3. Data types and wire encoding

```solidity
struct PublicKey {
    bytes32 root; // Merkle tree root
    bytes32 seed; // public SEED, the PRF input for keys and bitmasks
}

struct Signature {
    uint32 leafIdx;       // idx_sig: the one-time leaf index
    bytes32 r;            // randomizer for H_msg
    bytes32[67] wotsSig;  // WOTS+ signature, len = 67 chains
    bytes32[] authPath;   // Merkle authentication path, h nodes, leaf level first
}
```

- **[XV-06]** The wire form of a signature MUST be `abi.encode(Signature)` — the standard
  ABI encoding of that single tuple, `Signature` being a dynamic type because of `authPath`,
  so the encoding begins with an offset word pointing at the tuple. The canonical encoding is
  exactly this, every field 32-byte aligned and big-endian, at height `h`:

| word | byte offset | content |
| --- | --- | --- |
| 0 | 0x0000 | `0x20` — offset of the tuple from the start of the blob |
| 1 | 0x0020 | `leafIdx`, left-padded to 32 bytes |
| 2 | 0x0040 | `r` |
| 3 … 69 | 0x0060 … 0x08a0 | `wotsSig[0]` … `wotsSig[66]`, inline (a static array of 67) |
| 70 | 0x08c0 | `0x8c0` — offset of `authPath` from the start of the tuple (word 1), i.e. `70 * 32` |
| 71 | 0x08e0 | `h` — `authPath.length` |
| 72 … 71+h | 0x0900 … | `authPath[0]` … `authPath[h-1]` |

  Element `k` of `authPath` is the sibling node at tree level `k`; level `0` is the leaf's
  sibling. The blob is therefore `72 + h` words — exactly `2304 + 32 * h` bytes: 2624 at
  `h = 10`, 2816 at `h = 16`, 2944 at `h = 20`.
- **[XV-07]** A verifier MUST reject a blob whose length is not `2304 + 32 * h` for the height
  it was given, and MUST reject one whose decoded `authPath.length` is not that height
  ([XV-08]). It MAY signal such a blob either by returning `false` or by reverting; a verifier
  that is called with third-party data SHOULD return `false` rather than revert, so that a
  malformed signature cannot grief the caller's transaction. A verifier is NOT REQUIRED to
  check word 0 and word 70 against the table in [XV-06]: at the required length an encoding
  that sets them differently is harmless, for the reason given in the Rationale. Producers
  MUST emit the canonical encoding.
- **[XV-08]** `authPath.length` MUST equal the tree height supplied by the caller
  (see [XV-24]); it MUST NOT be used as the height.
- **[XV-09]** A verifier MUST reject `root == 0` and `seed == 0`. This goes beyond RFC 8391:
  a zero SEED collapses every PRF-derived key and bitmask to a function of `ADRS` alone, and
  a zero root is never a real tree root, so both indicate an uninitialised or forged key
  record rather than a signature worth verifying.
- **[XV-10]** A verifier MUST reject `leafIdx >= 2^h`: no such leaf exists, and the index is
  hashed into `M'`, so an out-of-range index would otherwise be verified against an
  authentication path it cannot correspond to.

### 4. Verification

```text
verify(messageDigest, root, seed, h, sig) -> bool

 1. reject unless 1 <= h <= 20                                          [XV-01]
 2. reject unless sig decodes canonically and |authPath| == h            [XV-06..08]
 3. reject if root == 0 or seed == 0                                     [XV-09]
 4. reject if sig.leafIdx >= 2^h                                        [XV-10]
 5. M'   = H_msg(sig.r ‖ root ‖ toByte(sig.leafIdx, 32), messageDigest)  [XV-04]
 6. pk   = WOTS_pkFromSig(M', sig.wotsSig, sig.leafIdx, seed)            § 4.1
 7. node = L_tree(pk, sig.leafIdx, seed)                                § 4.2
 8. for k in 0 .. h-1: node = climb(node, sig.authPath[k], sig.leafIdx, k, seed)  § 4.3
 9. accept iff node == root
```

This is RFC 8391 Algorithm 13 (`XMSS_rootFromSig`) followed by the root comparison of
Algorithm 14, with the domain checks of §3 added.

#### 4.1 WOTS+ public key from the signature

Let `m` be `M'` read as a big-endian 256-bit integer. The base-`w` digits are

```text
d_i = (m >> (252 - 4*i)) & 0xf                       for i in 0 .. 63
csum = ( sum_{i=0..63} (15 - d_i) ) << 4
d_i = (csum >> (12 - 4*(i - 64))) & 0xf              for i in 64 .. 66
```

- **[XV-11]** For each chain `i in 0..66` the verifier MUST compute
  `pk[i] = chain(wotsSig[i], start = d_i, steps = 15 - d_i, ADRS(type = 0, word4 = leafIdx, word5 = i))`,
  where `chain` starts from `x = wotsSig[i]` and applies, for
  `j = start, start + 1, …, start + steps - 1` in that order (RFC 8391 Algorithm 2; no step at
  all when `steps == 0`),
  `x <- F(PRF(seed, ADRS(keyAndMask = 0, word6 = j)), x XOR PRF(seed, ADRS(keyAndMask = 1, word6 = j)))`.
  `j` is the absolute chain position, not a counter from zero: at `start = d_i` the first step
  uses `word6 = d_i`. Since `start + steps = 15` for every `i`, `j` runs over `d_i .. 14`.

The `<< 4` on `csum` is RFC 8391's `toByte(csum, 2)` with `w = 16` and `len2 = 3`: the
checksum occupies the top 12 bits of the two-byte encoding.

#### 4.2 L-tree

- **[XV-12]** The verifier MUST compress the 67 WOTS+ public-key nodes with the L-tree of
  RFC 8391 Algorithm 8, using `ADRS(type = 1, word4 = leafIdx, word5 = level, word6 = i)`,
  and MUST carry an odd trailing node up unchanged to the next level (the "lonely leaf"
  rule) rather than duplicating or dropping it.

#### 4.3 Tree climb

- **[XV-13]** For each level `k` the verifier MUST combine the current node with
  `authPath[k]` using `RAND_HASH` of RFC 8391 Algorithm 7 with
  `ADRS(type = 2, word5 = k, word6 = leafIdx >> (k+1))`, placing the current node on the
  left iff bit `k` of `leafIdx` is `0`:

```text
RAND_HASH(left, right, seed, ADRS) =
    H( PRF(seed, ADRS[keyAndMask=0]),
       (left XOR PRF(seed, ADRS[keyAndMask=1])) ‖ (right XOR PRF(seed, ADRS[keyAndMask=2])) )
```

- **[XV-14]** The verifier MUST set the `keyAndMask` field explicitly before each `PRF` call
  — `0` for the key, `1` for the first bitmask, `2` for the second — rather than relying on
  whatever value the field already holds, so that the result never depends on residue left in
  it by an earlier call.

### 5. Verification interface

- **[XV-15]** A contract that offers XMSS verification to other contracts MUST expose it under
  this exact signature, so that callers are portable between verifiers:

```solidity
interface IXmssVerifier {
    /// @return valid true iff `signature` is a valid XMSS signature on `messageDigest`
    ///         under the key (`root`, `seed`) of height `treeHeight`.
    function verifyXmssSignature(
        bytes32 messageDigest,
        bytes32 root,
        bytes32 seed,
        uint256 treeHeight,
        bytes calldata signature
    ) external view returns (bool valid);
}
```

- **[XV-16]** Such a contract SHOULD implement ERC-165 and return `true` for
  `interfaceId == 0x5867b896` (`type(IXmssVerifier).interfaceId`) and for the ERC-165
  identifier itself.
- **[XV-17]** `verifyXmssSignature` MUST be `view` and MUST NOT depend on any mutable
  storage: verification is a pure function of its arguments, and a verifier whose answer can
  change is not one a second implementation can reproduce.
- **[XV-18]** `messageDigest` is opaque to the verifier. When the signed object is a
  structured message, applications SHOULD use an [EIP-712](./eip-712.md)
  `hashTypedDataV4` digest, so that
  the signed bytes are bound to a domain (chain id and verifying contract) and can be
  displayed on the signing device.

### 6. Leaf-index accounting (mandatory for authority)

A valid XMSS signature says only "the holder of this key signed this digest at this leaf".
It becomes an authorisation when a contract acts on it, and at that moment the one-time
property must be enforced on-chain.

- **[XV-19]** A contract that grants any authority on the strength of an XMSS signature MUST
  record the consumed `leafIdx` in storage and MUST reject a second use of the same
  `leafIdx` for the same key, permanently.
- **[XV-20]** That record MUST be keyed by the XMSS public `root` (equivalently, by a
  collision-resistant hash of `(root, seed)`), and MUST NOT be keyed by a per-account,
  per-registration or per-application identifier. One physical key registered by two
  accounts, two applications or two chains-of-custody is one key: if each registration keeps
  its own counter, one leaf can sign two different digests, which is exactly the condition
  that makes WOTS+ forgeable.
- **[XV-21]** Consumption MUST happen in the same transaction as the authority grant, and
  MUST persist even if the authorised action later fails: a leaf offered to the chain is
  spent whatever the outcome.
- **[XV-22]** The reuse check SHOULD be performed *before* the verification itself, which
  costs on the order of `10^6` gas; rejecting a replayed leaf early is materially cheaper.
- **[XV-23]** A contract MAY additionally require leaf indices to be monotonically
  increasing. This ERC does not require it: a relayed, concurrently prepared batch of
  approvals can legitimately arrive out of order, and monotonicity would silently burn the
  skipped leaves.
- **[XV-24]** The tree height used in verification MUST be the height recorded with the key
  when it was registered, and MUST NOT be taken from the signature (see [XV-08] and
  Security Considerations).
- **[XV-25]** A key's `root` SHOULD be one-shot per registry: re-registering a root that
  the registry has seen before MUST NOT reset its consumed-leaf record.

### 7. Events

- **[XV-26]** A contract that consumes leaves MUST emit, for each consumed leaf, an event
  carrying the leaf index and the signed digest, whose indexed topics let an indexer aggregate
  the consumed set *per key* — so that the log can be reconciled with a signing device's own
  counter. It MUST therefore either index the XMSS public `root` itself, or index an identifier
  of its own **together with** a public view that resolves that identifier to the `root` the
  leaf was recorded under ([XV-20]). An event that indexes only an identifier whose relation to
  `root` is not readable on-chain does not satisfy this clause: the consumed set of a key
  registered twice cannot then be reconstructed from the log at all.

This ERC does not name the event, because the contract that emits it is the one holding the key
records, not the verifier. The companion ERC on stateful hash-based key registries fixes a
concrete event for registries, indexed by a registration identifier that the registry's own
`getKey` view resolves to the root.

## Rationale

**Why the height is an argument, not a field.** RFC 8391's OID fixes the parameter set, and a
verifier that trusts the signature's own height loses that binding. The concrete danger is not
that a wrong height verifies — it does not — but that a *shorter* tree is a different key with
a different leaf space: a signer who can choose `h` at signing time can present the same
`root` as a key with `2^k` leaves for any `k`, multiplying the one-time indices available for
one recorded key. Taking the height from the registration re-establishes what the OID does in
RFC 8391. `[XV-08]`, `[XV-24]`.

**Why the leaf record is keyed by the root.** Any other key — an account address, a
registration identifier, an application namespace — makes the counter local to a view of the
key rather than to the key. The reference implementation initially keyed it by a
per-registration `quantumKeyId`; because the same device key is legitimately registered by
several accounts, each account began with an empty counter, and one leaf could sign two
digests. Keying by `root` is the only choice that tracks the object whose state is at stake.
`[XV-20]`.

**Why `abi.encode` and not RFC 8391 §4.1.8 bytes.** The RFC's packed format has to be parsed
by hand in the EVM, which means hand-written offset arithmetic in every implementation, while
`abi.decode` is a single audited decoder that bounds-checks every offset it reads. The fixed
length `2304 + 32h` gives a cheap structural pre-check before that decode. Clients that hold
RFC-format signatures convert by reading the fields in order.

**Why [XV-07] does not require the offset words to be checked.** `abi.decode` bounds-checks;
it does not require an encoding to be canonical. At the exact length of [XV-06] a blob can set
word 70 to, say, `0x40` instead of `0x8c0`, so that `authPath` aliases the head of `wotsSig`
(with `wotsSig[0]` read as the length) and the canonical tail becomes dead padding; `abi.decode`
accepts it and reports `authPath.length == wotsSig[0]`. Such an encoding is harmless: whichever
words the decoder hands to §4, they still have to hash to `root` for the signature to be
accepted, and the aliasing gives an attacker no control it did not already have over the bytes
it supplied. Requiring verifiers to reject it would cost every implementation two extra
comparisons and rule out `abi.decode` as a conforming decoder, for no security gain — so
[XV-06] pins the encoding for producers and [XV-07] asks verifiers only for the two checks
that are load-bearing: the length, and `authPath.length == h`.

**Why a `view` function returning `bool` rather than a reverting `require`-style check.** A
verifier is frequently called speculatively (a wallet asking "would this be accepted?") and
with third-party data. A `bool` composes; a revert forces `try`/`catch` and makes malformed
input a griefing vector. `[XV-07]`, `[XV-17]`.

**Why zero root and zero seed are rejected although RFC 8391 does not say so.** In the EVM the
default value of a storage slot is zero, so `root == 0` is the signature of an *absent* key
record, and the most likely way to reach a verifier with a zero key is a lookup that missed.
`seed == 0` is worse: every bitmask and chain key becomes a function of `ADRS` alone, i.e.
public. Rejecting both turns a class of integration bug into a refusal. `[XV-09]`.

**Why SHA-256 and not keccak256.** RFC 8391 and NIST SP 800-208 specify SHA-256 for this
family; deviating would produce signatures no standard tool can generate or audit, and forfeit
the conservative security argument that motivates hash-based signatures. SHA-256 is precompile
`0x02` on every EVM chain, at 60 + 12·⌈len/32⌉ gas, and a height-10 verification costs
approximately 800,000 gas in the reference implementation.

## Backwards Compatibility

This ERC adds an interface and an encoding; it changes no existing behaviour and requires no
consensus change. It is independent of [ERC-4337](./eip-4337.md) and of any particular account
implementation: an XMSS signature is verified by ordinary contract code.

`IXmssVerifier` is a new interface, so nothing can already claim its ERC-165 identifier.
Contracts that already verify XMSS with a different encoding are unaffected but do not conform
to this ERC.

## Test Cases

The reference implementation is tested against three key sets (`h = 4`, `h = 10`, `h = 20`)
with four signatures each, generated by a separate Python implementation of RFC 8391 written
for the same project. The `h = 10` and `h = 20` sets are additionally cross-checked against the
RFC authors' own C implementation (`github.com/XMSS/xmss-reference`), which accepts all eight
genuine signatures and rejects all eight when the message is tampered with; the `h = 4` set is
not cross-checked against it.

A complete `XMSS-SHA2_10_256` case set — the public key, four genuine signatures and one
single-bit mutation of the first, each with its expected verdict — is in [`vector-xmss-sha2_10_256.json`](../assets/erc-draft-xmss-verification/vector-xmss-sha2_10_256.json).
Abridged (full values in the asset):

```json
{
  "h": 10,
  "root": "0x368489f616a32acf1d63f8e8b6bb21cc03b7444d95ab8412dde78106c80bccc8",
  "seed": "0x7df9bb119a1b957115c751443f5cdbd321436df22c9ac457376637cb4effe30f",
  "vectors": [
    {
      "idx": 0,
      "msg": "0x0fd2d3a29e153801039c3efb1b196115f6b9fe81aee617bed229d405cbd269d4",
      "r": "0x0e05f4d8b489ea1882ee51af9875337160f5d603ab6917530497df25a52f21da",
      "wotsSig": ["0x…", "… 67 words …"],
      "auth": ["0x…", "… 10 words …"],
      "expect": "accept"
    }
  ]
}
```

Required behaviour on that vector, each case a separate test:

| case | expected |
| --- | --- |
| the vector as given | accept |
| any single bit flipped in `wotsSig` | reject |
| any single bit flipped in `auth` | reject |
| any single bit flipped in `r` or `msg` | reject |
| two `wotsSig` words swapped | reject |
| `idx` changed, everything else kept | reject |
| `treeHeight` passed as 9 or 11 | reject |
| `root` or `seed` set to zero | reject |
| encoding truncated by one byte, or empty | reject |
| the same `idx` used a second time by an authority-granting caller | reject ([XV-19]) |

## Reference Implementation

An implementation of §2–§4 as a Solidity library is published as `xmss-solidity`. Its
primitives are machine-checked against an executable, line-by-line transcription of RFC 8391
with the Halmos symbolic execution engine: the WOTS+ chain, `RAND_HASH`, the base-`w` message
encoding, the L-tree, one level of the tree climb, `H_msg`, and the input-validation rejections
of `[XV-01]`, `[XV-08]`, `[XV-09]` and `[XV-10]` are each proved equal to the transcription for
all inputs. What is *not* machine-checked for general `h` is the composition of those
primitives into the final comparison of the recomputed root with `root` — the step that both
accepts a genuine signature and rejects a forgery. That argument is by hand, symbolic only at
`h = 2` with one fixed `M'`, and pinned by concrete vectors at `h = 4`, `h = 10` and `h = 20`.
SHA-256 is modelled as an uninterpreted function throughout, so the proofs say nothing about
SHA-256 itself. The conforming external interface of §5 is:

```solidity
contract XmssVerifier is IXmssVerifier, IERC165 {
    uint256 internal constant ENCODED_SIGNATURE_BASE_LENGTH = 2304;

    function verifyXmssSignature(
        bytes32 messageDigest,
        bytes32 root,
        bytes32 seed,
        uint256 treeHeight,
        bytes calldata signature
    ) external view returns (bool) {
        if (treeHeight == 0 || treeHeight > 20) return false;
        if (signature.length != ENCODED_SIGNATURE_BASE_LENGTH + 32 * treeHeight) return false;
        XMSS.Signature memory sig = abi.decode(signature, (XMSS.Signature));
        return XMSS.verify(messageDigest, sig, XMSS.PublicKey({root: root, seed: seed}), treeHeight);
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IXmssVerifier).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
```

The leaf-index accounting of §6 is deliberately *not* part of the verifier: it is state, it
belongs to whoever grants authority, and a stateless verifier can be shared. A registry
implementing §6 is specified in the companion ERC on stateful hash-based key registries.

## Security Considerations

**Leaf reuse is total failure, not degradation.** Two WOTS+ signatures at one leaf index
reveal, for each chain, two positions of that chain; a forger can then sign any message whose
base-`w` digits are pointwise no smaller (including, with the checksum, a usable set of
messages). There is no partial security: a single reused leaf can hand an attacker the key's
signing power for that leaf, and in practice for chosen messages. Everything in §6 exists for
this reason, and `[XV-20]` is the clause that a straightforward implementation gets wrong.

**Height substitution.** Without `[XV-24]`, the leaf space of a key is chosen by the signer:
the same `root` presented at height `k < h` has `2^k` leaves, and the indices a registry has
already recorded as consumed at height `h` do not cover the low indices of the shallower view
in the way the operator expects. Bind the height at registration, and reject a signature whose
`authPath` has any other length.

**The digest must bind the context.** A bare 32-byte digest is replayable anywhere the same
digest is meaningful. `[XV-18]` is the clause: sign an EIP-712 digest that includes the chain
id, the verifying contract, the account and a nonce, because otherwise a signature captured on
one chain or one account authorises the same action on another.

**Gas and denial of service.** A verification is on the order of `10^6` gas at `h = 10`
(dominated by roughly two thousand SHA-256 precompile calls). A contract that verifies before checking
cheap preconditions (leaf reuse, key status, window) can be made to burn that gas by anyone;
order the checks as in `[XV-22]`. Verification cost grows only with `h` in the tree climb, so
`h = 20` is a few percent more expensive than `h = 10`, not 1000×.

**Key exhaustion is a liveness matter.** A key has `2^h` signatures and no more. At `h = 10` a
key that signs ten times a day is exhausted in under three months. Monitor consumption and
rotate before exhaustion, and make rotation possible without the old key — behind a delay — so
that exhaustion or device loss is not a lockout. The companion registry ERC specifies that
path; a deployment without one has traded a compromise risk for a lockout risk.

**Randomiser reuse.** `r` is generated by the signer; a signer that reuses `r` across
different messages at the same leaf has already violated the one-time rule. The verifier
cannot detect a reused `r` from a single signature, which is another reason the on-chain leaf
record, not the randomiser, is the enforcement point.

**The verifier is not an oracle for key validity.** A valid signature under a key says nothing
about whether that key *should* authorise anything. Key status (active, rotated, revoked),
ownership and policy are the registry's business, and a caller that treats
`verifyXmssSignature == true` as authorisation has skipped every one of those checks.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
