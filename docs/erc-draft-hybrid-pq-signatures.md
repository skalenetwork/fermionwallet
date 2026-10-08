---
eip: <to be assigned>
title: Hybrid ECDSA and ML-DSA Signatures
description: One classical and one post-quantum signature over one EIP-712 digest, with a fixed encoding and ERC-1271 wrapping
author: Stan Kladko (@kladkogex)
discussions-to: <URL>
status: Draft
type: Standards Track
category: ERC
created: 2026-10-08
requires: 191, 712, 1271, 7702, 7825
---

## Abstract

This ERC specifies a hybrid signature for smart contracts: an ECDSA (secp256k1) signature and
an ML-DSA (FIPS 204) signature, both over the same 32-byte [EIP-712](./eip-712.md) digest, both
required. It fixes what each half signs, the ML-DSA signing mode and context, the byte encoding
of the pair, the validity window of at most 24 hours that every signature carries, how the
ML-DSA parameter set is identified, and how a contract holding a hybrid key
answers [ERC-1271](./eip-1271.md) `isValidSignature` for a hash it did not produce. The on-chain
ML-DSA verifier interface and the algorithm identifiers are not specified here; they are taken by
reference from `pq-verifier-interface`.

## Motivation

ECDSA over secp256k1 is expected to fall to a cryptographically relevant quantum computer.
ML-DSA is the NIST post-quantum signature standard. Contracts that want quantum resistance today
cannot drop ECDSA: wallets, hardware signers and users' habits are built around it, and a new
scheme has had less scrutiny. Requiring **both** signatures keeps today's security if ML-DSA or
its implementation turns out to be weak, and keeps post-quantum security if ECDSA breaks.

Without a shared format, every such contract invents its own: which half signs what, whether
ML-DSA signs a hash or a message, with which context string, in which order the bytes go, and how
ERC-1271 hashes are bound to the contract. Hardware signers then need one code path per contract.
This ERC fixes those choices so one signer implementation serves every conforming contract.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in RFC 2119 and RFC 8174.

### Terms

- **Hybrid key:** a triple `(admin, algorithm, pk)`: `admin` is the address of a secp256k1 key,
  `algorithm` is an ML-DSA algorithm identifier, `pk` is an ML-DSA public key of that parameter set.
- **Hybrid-key contract:** a contract that grants authority to a hybrid key.
- **Digest `d`:** the 32-byte EIP-712 digest
  `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct(message))`.

### Algorithm identifiers

`algorithm` MUST be an identifier assigned to an ML-DSA parameter set by the `PQAlgorithms`
registry of `pq-verifier-interface` (skalenetwork/pq-verifier-interface, commit `6efa8e3`). This
ERC does not assign identifiers and does not restate that registry. A hybrid-key contract MUST
reject any identifier that the registry does not assign to ML-DSA.

A hybrid-key contract MUST fix `algorithm` when the hybrid key is set and MUST NOT accept a
signature under a different identifier for that key.

### What is signed

1. Both halves MUST sign the same digest `d`.
2. The EIP-712 domain MUST include `chainId` and `verifyingContract`, and `verifyingContract`
   MUST be the hybrid-key contract.
3. **ECDSA half.** A secp256k1 ECDSA signature over `d` itself, with no [EIP-191](./eip-191.md)
   prefix and no further hashing.
4. **ML-DSA half.** `ML-DSA.Sign(sk, M, ctx)` as defined in FIPS 204 (the "pure" external
   interface, not HashML-DSA), with `M = d` (exactly 32 bytes) and `ctx` the empty string. The
   message the internal algorithm signs is therefore `M' = 0x00 ‖ 0x00 ‖ d`.
5. Signers SHOULD use hedged signing (fresh randomness, the FIPS 204 default). Verifiers cannot
   tell hedged from deterministic signatures and MUST NOT depend on either.

### Verification

A hybrid signature `(σ_ecdsa, σ_mldsa)` is valid for `d` under `(admin, algorithm, pk)` if and
only if **both** of the following hold:

1. ECDSA recovery of `σ_ecdsa` over `d` succeeds and yields `admin`. Recovery MUST reject
   signatures with `s` in the upper half of the curve order and `v` other than 27 or 28.
2. ML-DSA verification of `σ_mldsa` over `M = d`, `ctx` empty, under `pk` and `algorithm`
   succeeds. A contract that verifies on chain SHOULD do so through the `IPQVerifier.verify`
   function of `pq-verifier-interface`, passing `d` as a 32-byte `bytes` message.

The contract MUST evaluate both checks and MUST NOT accept on either alone.

`admin` MUST be the address of an externally owned key. A hybrid-key contract MUST refuse to set
an `admin` that has code at the time it is set, and MUST check the classical half only by ECDSA
recovery, never by calling ERC-1271 on `admin`.

### Validity window

Every message a hybrid key signs MUST carry a validity window `(validFrom, validUntil)`, both
`uint64` Unix timestamps in seconds, inside the signed EIP-712 struct. A verifier MUST reject the
signature unless `validFrom <= block.timestamp <= validUntil` and
`validUntil - validFrom <= 86400` (24 hours). This applies to every path, including ERC-1271.

### ERC-1271 wrapping

A hybrid-key contract that answers ERC-1271 for a hash `h` produced by another protocol (for
example a Safe transaction hash) MUST NOT have the hybrid key sign `h` directly. It MUST instead
compute `d` as the EIP-712 digest, under the hybrid-key contract's own domain (rule 2 above), of

```
SignedHash(bytes32 hash,uint64 validFrom,uint64 validUntil)

hashStruct = keccak256(abi.encode(
    keccak256("SignedHash(bytes32 hash,uint64 validFrom,uint64 validUntil)"),
    h, validFrom, validUntil))
```

with `hash = h`, and verify the hybrid signature over that `d`.

- `isValidSignature(bytes32 h, bytes signature)` returns `0x1626ba7e` when `signature` is a valid
  signed-hash encoding (below) for `h`.
- A contract that also implements the legacy form `isValidSignature(bytes data, bytes signature)`
  MUST take `h = keccak256(data)`, wrap it the same way, and return `0x20c13b0b` when valid.
- On any failure, including a malformed `signature`, both forms MUST return a value other than
  their magic value, SHOULD return `0xffffffff`, and SHOULD NOT revert.

### Encoding

Where a single `bytes` value carries a hybrid signature over a `SignedHash` (the ERC-1271
`signature` argument, or a signature appended to another protocol's signature list), it MUST be
encoded as

```
signature = validFrom ‖ validUntil ‖ r ‖ s ‖ v ‖ σ_mldsa
```

| Field | Size | Encoding |
|---|---|---|
| `validFrom` | 8 bytes | `uint64`, big-endian |
| `validUntil` | 8 bytes | `uint64`, big-endian |
| `r`, `s` | 32 bytes each | big-endian |
| `v` | 1 byte | 27 or 28 |
| `σ_mldsa` | fixed by `algorithm` | FIPS 204 signature encoding |

There is no length prefix and no algorithm tag: the length of `σ_mldsa` is fixed by `algorithm`,
which the verifying contract already holds. The total length is 81 plus the ML-DSA signature
length of `algorithm`: **2,501 bytes for ML-DSA-44, 3,390 for ML-DSA-65 and 4,708 for
ML-DSA-87**. A verifier MUST reject a `signature` of any other length.

The verifier reads `validFrom` and `validUntil` from the encoding, builds the `SignedHash` from
them and `h`, checks the window, and then verifies both halves over the resulting `d`.

Where a contract's own signed struct already contains the window (for example a transfer), it MAY
take the two halves as separate arguments.

### Signers

A signer that produces hybrid signatures SHOULD display the fields of the EIP-712 message to its
user and compute `d` itself from the displayed fields, rather than sign a digest supplied by a
host. For ERC-1271 wrapping, it SHOULD receive the fields that produce `h` (for example the Safe
transaction) rather than `h` itself. Display and refusal rules are out of scope for this ERC.

## Rationale

**Both halves over one digest.** Signing the same digest with both schemes means one user
confirmation authorizes exactly one message, and neither half can be replayed under the other's
message. AND-composition keeps the stronger of the two: the classical scheme's track record today,
the post-quantum scheme's resistance tomorrow.

**Pure ML-DSA over the 32-byte digest, empty context.** The digest is already a collision-resistant
hash with EIP-712 domain separation, so HashML-DSA would add a second hash with no gain, and a
second hash identifier to agree on. A non-empty context would be one more string for every signer
to get exactly right, while the EIP-712 domain already separates uses.

**Algorithm identifiers by reference.** The on-chain verifier interface and its identifier registry
already exist as a separate MIT-licensed specification used by several verifier libraries.
Restating them here would create two sources of truth that could drift. This ERC only constrains
which identifiers apply (ML-DSA) and that they are fixed per key.

**No length prefix, no tag.** The verifying contract stores the algorithm with the key, so the
signature length is known. A tag in the signature would be a second, possibly conflicting,
statement of something the contract already knows.

**Fixed-size fields first.** The window and the ECDSA half have fixed sizes, so every field
starts at a constant offset (0, 8, 16, 81) for every parameter set; only the ML-DSA signature's
length varies.

**A validity window on ERC-1271 signatures.** ML-DSA is stateless and `isValidSignature` is a view,
so without a window a hybrid ERC-1271 signature would be valid forever. Protocols that consume
ERC-1271 signatures do not all carry their own expiry or nonce (a sign-in message, an off-chain
order), and a signature leaked or stockpiled by a compromised host could be used years later,
possibly after the key holder believed the key retired. The window bounds every signature's life
to at most 24 hours, the same rule the reference implementation applies to its own messages. It
travels in the signature, not in `h`, because `h` belongs to the other protocol and cannot be
changed; it is signed because it is inside the `SignedHash` struct. Signers have no trusted
clock, so the bound is enforced by the verifier on `block.timestamp`; a signer only refuses to
sign a window longer than 24 hours.

**EOA-only classical half.** Checking the classical half through ERC-1271 would make its validity
depend on arbitrary code, which can change, and would put a second contract's logic inside the
hybrid check. ECDSA recovery is simple, has no external call, and is what the hardware signers this
format targets produce. An [EIP-7702](./eip-7702.md) delegation set on `admin` later does not matter, because only
recovery is used.

**ERC-1271 wrapping.** Signing a foreign hash directly would let one hybrid signature answer for
every contract that shares the key and would let a signer be asked to sign an opaque hash. Wrapping
the hash in the hybrid-key contract's domain binds the signature to that contract and chain.

## Backwards Compatibility

This ERC introduces a new signature format; it changes nothing existing. A hybrid-key contract is an
ordinary ERC-1271 signer to the protocols that query it, such as Safe, which accept its `bytes`
signature without knowing its contents. Contracts that pass signatures through fixed-size buffers
or assume 65-byte signatures will not accept a hybrid signature.

## Test Cases

To be added: digests, keys and signatures for ML-DSA-44 and ML-DSA-65, valid and invalid (each half
tampered, wrong length, wrong algorithm, high-`s`, window not yet started, expired, longer than
24 hours), and ERC-1271 `SignedHash` digests and encodings for both forms.

## Reference Implementation

Fermion (skalenetwork/fermionwallet, branch `ml-dsa-v2`): the Fermion Wallet and Fermion Guard
contracts and the Fermion Ledger app. ML-DSA verification: skalenetwork/mldsa-solidity, through
`IPQVerifier` from skalenetwork/pq-verifier-interface.

## Security Considerations

**What the classical half buys.** Against a quantum adversary who can recover ECDSA keys, the
ECDSA half provides nothing and the security is ML-DSA's alone. Its value is against classical
failures: a weakness in ML-DSA or in its implementation, and a host that would otherwise need to
compromise only one signing path.

**Key derivation.** When both keys come from one seed, the ML-DSA key MUST NOT be derivable from the
ECDSA private key or from any value a quantum adversary can obtain from the ECDSA public key.
Deriving them from separate hardened children of a common parent satisfies this; deriving the
ML-DSA seed from the ECDSA key's own node does not, because a quantum break of the ECDSA public
key would then yield the ML-DSA key.

**Key reuse.** The empty context means the ML-DSA key gives no protocol separation of its own. A
hybrid key SHOULD be used for one hybrid-key contract only, and MUST NOT be used outside this
format.

**Signature malleability.** Neither half is unique: ML-DSA signatures are randomized and ECDSA
signatures have more than one encoding unless `s` is restricted. Contracts MUST NOT use signature
bytes as a replay identifier; replay protection belongs in the signed message (a nonce, a validity
window).

**Verifier correctness.** A defect in the on-chain ML-DSA verifier that accepts forgeries silently
reduces the hybrid to ECDSA, which is exactly the scheme the format exists to back up. Verifiers
should be tested against FIPS 204 test vectors and independent implementations. The reference
verifier is unaudited at the time of writing.

**Side channels.** Signers running ML-DSA on constrained hardware should document their side-channel
countermeasures. Hedged signing limits some fault and side-channel attacks on deterministic signing
but is not a substitute for a hardened implementation.

**Gas and the per-transaction cap.** On-chain ML-DSA verification costs millions of gas. In the
reference implementation, verification through `IPQVerifier` measures 2.68M (ML-DSA-44), 3.66M
(ML-DSA-65) and 5.53M (ML-DSA-87) gas with per-key precomputation, and 5.75M, 9.13M and 14.23M
without it. With the [EIP-7825](./eip-7825.md) per-transaction cap of 16,777,216 gas, a transaction
can verify only a few hybrid signatures, and some key-setup steps must be split across
transactions. Gas schedules change; these numbers will.

**Displayed content.** A hybrid signature is only as good as what the human approved. A signer that
signs host-supplied digests reduces both halves to the security of the host.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
