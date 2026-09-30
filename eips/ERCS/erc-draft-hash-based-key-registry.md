---
eip: <to be assigned>
title: Stateful Hash-Based Key Registry
description: Registration, rotation and time-locked revocation of one-time-signature keys held by a device, for smart accounts
author: Konstantin Kladko (@kladkogex)
discussions-to: <URL>
status: Draft
type: Standards Track
category: ERC
created: 2026-09-30
requires: 165, 712, 1271
---

## Abstract

This ERC specifies an on-chain registry that binds a stateful hash-based public key — an XMSS
root (RFC 8391) held on a hardware device — to a smart account, and governs that key's whole
life: a co-signed one-shot registration, a rotation that proves possession of the outgoing
key, and a time-locked revocation that works when the key is lost. It fixes the key states and
every permitted transition, the [EIP-712](./eip-712.md) messages the account's owners and
the device sign, the
per-account ceremony nonce, and the consumed-leaf record that makes a one-time-signature key
safe to use more than once. It does not specify what the key authorises; that is the companion
ERC on hybrid pre-approvals.

## Motivation

A post-quantum second factor for a smart account is only as good as the lifecycle around it.
The signature scheme is standardised (RFC 8391) and its verification is specified in the
companion ERC on on-chain XMSS verification, but the operational questions are where
deployments diverge and where they get hurt:

- **Activation.** If the device alone can register a key, a compromised or malicious device
  captures the account. If the owners alone can register, they can install a key nobody holds.
  Activation has to require both, in one transaction, over a message that names the root
  itself — not an opaque identifier that a relayer chose.
- **Rotation.** A key with `2^h` one-time signatures will be exhausted, and devices are
  replaced. Rotation must leave no window in which the account has two active keys (two
  independent authorisers) or none (no second factor).
- **Loss.** A hash-based key on a device that is lost cannot sign its own replacement. Without
  a path that does not need the old key, the account is stuck with a dead second factor
  forever — and if that path is instant, whoever stole the device uses it first. A delay that
  the account's owners can cancel is the only shape that survives both cases.
- **One-time state.** The consumed-leaf record belongs to the key, not to any authorisation
  built on top of it, and not to any one account that registered it.

Each of these has exactly one safe answer and several plausible unsafe ones, which is what a
standard is for.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in RFC 2119 and RFC 8174.

Normative statements are labelled `[KR-nn]`.

### 1. Roles

| role | who | authority |
| --- | --- | --- |
| account | the smart account (`account`) | decides owner authorisation for itself; the only canceller of a pending revocation |
| owners | whoever the account's own signature check accepts at threshold | co-sign registration, rotation and revocation requests |
| administrator | the EOA or [ERC-1271](./eip-1271.md) signer that holds the device (`quantumAdmin`) | attests each key at registration; signs authorisations with the device's classical key |
| device | the hardware that holds the hash-based private key | generates the key, signs, keeps its own leaf counter |
| relayer | anyone | submits ceremony transactions; holds no authority |

- **[KR-01]** The registry MUST take the account address from an explicit argument, never from
  `msg.sender`, for every ceremony function, and MUST NOT grant the caller any authority by
  virtue of being the caller. The authorisation is carried entirely by the signatures.
- **[KR-02]** The registry MUST decide owner authorisation by delegating to the account: it
  MUST call the account's own signature-verification entry point, and MUST treat both a
  revert and a negative answer as a refusal. The registry MUST NOT maintain its own notion of
  who the owners are, or of what threshold applies. Which entry point that is belongs to the
  account implementation; an account that answers ERC-1271 `isValidSignature` satisfies this
  clause, and an account implementation with its own threshold-checking entry point satisfies
  it through that (see Rationale for the Safe family, whose entry point is not ERC-1271).
- **[KR-03]** The registry MUST verify the administrator's attestation with an ERC-1271-aware
  check (accepting both an EOA signature and a contract signer), and MUST NOT use raw
  `ecrecover`.
- **[KR-04]** There MUST be no registry-wide administrator, guardian, pauser, owner or
  upgrade authority. Every control this ERC defines is scoped to one account and held by that
  account's owners or its administrator.
- **[KR-42]** The administrator MUST NOT be a signer the account's own signature check
  accepts, and MUST NOT be controlled by a secret that also controls such a signer. The
  registry cannot enforce this — `[KR-02]` denies it any knowledge of the owner set — so it
  binds the deployment and whatever flow registers a key, which SHOULD verify it before the
  ceremony is assembled. It is nevertheless normative: if one party can produce both halves of
  a ceremony, the two-party property the rest of this ERC builds has already failed, and no
  clause below restores it.

### 2. Key record and identity

```solidity
enum KeyStatus { None, Active, Rotated, Revoked }

struct KeyRegistration {
    bytes32 quantumKeyId; // keccak256(abi.encodePacked(safe, xmssRoot, nonce))
    address safe;         // the account this registration serves (see §7 on the name)
    address quantumAdmin; // classical co-signer that attested this key
    bytes32 xmssRoot;     // XMSS public root
    bytes32 xmssSeed;     // XMSS public SEED
    uint32  treeHeight;   // binds the parameter set; 1..20
    bytes32 parameterSet; // e.g. keccak256("XMSS-SHA2_20_256")
    KeyStatus status;
    uint64  createdAt;
    uint64  rotatedAt;    // 0 until rotated
    uint256 useCounter;   // leaves consumed under this registration
}
```

- **[KR-05]** A key's registry identity MUST be
  `quantumKeyId = keccak256(abi.encodePacked(safe, xmssRoot, nonce))`, where `safe` is the
  20-byte account address, `xmssRoot` the 32-byte root, and `nonce` is the
  account's ceremony nonce consumed by the registration. The identity therefore binds the
  account, the root and the ceremony, and a re-registration of the same root by the same
  account (after a revocation) yields a different identity.
- **[KR-06]** An account MUST have at most one key in state `Active` at any time.
- **[KR-07]** The registry MUST record, per account, whether it has *ever* registered a key
  ("enrolled"), and MUST NOT clear that flag on revocation. Recovery paths that exist only for
  enrolled accounts must stay reachable after the key is gone.
- **[KR-08]** The registry MUST reject registration or rotation parameters in which
  `account`, `quantumAdmin`, `xmssRoot`, `xmssSeed` or `parameterSet` is zero, or
  `treeHeight` is `0` or greater than the maximum height of the signature scheme (20 for
  single-tree XMSS).
- **[KR-09]** `treeHeight` MUST be the height used for every later verification under this
  key (see the XMSS ERC, `[XV-24]`). `parameterSet` SHOULD be checked for consistency with
  `treeHeight` where the implementation knows the mapping; the reference implementation
  records `parameterSet` without cross-checking it, and clients therefore MUST NOT rely on it
  as a verified statement about the key.
- **[KR-10]** The registry MUST record every root an account has registered, in any status,
  and MUST reject re-registration of such a root by that account. Re-registering a root would
  otherwise start a new registration whose per-registration counters are empty.
- **[KR-11]** That root record MUST be scoped per account, not globally. A global one-shot
  root record is a denial-of-service vector: the root is public calldata in the mempool and
  the account address is only self-authenticated, so an attacker contract that accepts any
  signature could claim a victim's root first and permanently block enrollment. Cross-account
  reuse of a root harms only the reuser, because the consumed-leaf record is shared
  (`[KR-12]`) and every authorisation digest binds the account.
- **[KR-12]** The consumed-leaf record MUST be keyed by `xmssRoot` and MUST be shared by all
  registrations of that root, as required by `[XV-19]`–`[XV-21]` of the XMSS ERC. It MUST NOT
  be keyed by `quantumKeyId`.

### 3. Ceremony nonce

- **[KR-13]** The registry MUST keep a per-account monotonically increasing ceremony nonce,
  readable as `registryNonce(account)`, MUST include it in every owner-signed and
  device-signed ceremony message, and MUST consume exactly one nonce per successful
  registration, rotation, revocation request and revocation execution.
- **[KR-14]** Consuming the nonce MUST invalidate every other ceremony message prepared at
  that nonce. This is the mechanism by which a cancelled revocation cannot be re-armed from
  chain history, and by which stale concurrent ceremonies die; implementations MUST accept
  that in-flight ceremonies are invalidated as a consequence.

### 4. Signed messages

All ceremony messages are EIP-712 typed data hashed with `hashTypedDataV4` under the
registry's own domain (the registry is the `verifyingContract`, so the chain id and the
registry address are bound). The domain `name` and `version` are chosen by the implementation.

- **[KR-15]** Implementations MUST use these type strings verbatim, since their `keccak256` is
  the type hash a device and an owner wallet must reproduce:

```text
ApproveQuantumKey(address safe,address quantumAdmin,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)

RotateQuantumKey(address safe,bytes32 oldQuantumKeyId,address newQuantumAdmin,bytes32 newXmssRoot,bytes32 newXmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)

QuantumKeyAttestation(address safe,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce)

RequestKeyRevocation(address safe,bytes32 quantumKeyId,uint256 registryNonce,uint256 validUntil)
```

The member named `safe` is the account address; the name is part of the frozen type string and
is retained for compatibility with deployed verifiers and signing devices.

- **[KR-16]** The owner-signed messages MUST name the public key material itself
  (`xmssRoot`, `xmssSeed`, `treeHeight`, `parameterSet`), never only a derived identifier.
  Owners approve the key they were shown; an identifier can be computed from material they
  never saw.
- **[KR-17]** Every owner-signed ceremony message MUST carry a `validUntil` deadline, and the
  registry MUST reject it once `block.timestamp > validUntil`.
- **[KR-18]** Some account implementations' signature checks take the signed *preimage*
  rather than the digest, and some additionally require that the digest they were given is
  the hash of that preimage. A registry MUST therefore pass the full EIP-712 preimage
  `0x1901 ‖ domainSeparator ‖ structHash` wherever the account's entry point accepts a
  preimage argument, and MUST NOT pass the digest there, or the bare struct hash, or empty
  bytes. The digest itself remains `keccak256` of that preimage. (Concrete account versions
  that make this necessary are in the Rationale.)
- **[KR-19]** The attestation message MUST NOT include `validUntil`: it is bound by the
  ceremony nonce, and the device signs it before the owners have finished collecting
  signatures.

### 5. State machine

State per account: `activeKeyId`, `enrolled`, `revocationExecutableAt`, `revocationKeyId`,
`nonce`. The transitions below are complete and normative: an implementation MUST make exactly
these transitions and no others.

| transition | preconditions (all required) | effects |
| --- | --- | --- |
| `register` | no `Active` key; parameters valid `[KR-08]`; root not registered by this account `[KR-10]`; `now <= validUntil`; owner threshold over `ApproveQuantumKey`; attestation by `quantumAdmin` over `QuantumKeyAttestation` | new key `Active`; `activeKeyId = keyId`; `enrolled = true`; root recorded; `nonce += 1`; a pending revocation is left untouched |
| `rotate` | an `Active` key exists; parameters valid; new root not registered by this account; `now <= validUntil`; owner threshold over `RotateQuantumKey`; attestation by the new `quantumAdmin` over `QuantumKeyAttestation`; a valid XMSS signature by the **old** key over the *same digest the owners signed*, consuming one old leaf | old key → `Rotated`, `rotatedAt = now`; new key `Active`; `nonce += 1`; any pending revocation cleared |
| `requestRevocation` | an `Active` key exists; `now <= validUntil`; owner threshold over `RequestKeyRevocation` | `revocationExecutableAt = now + TIMELOCK`; `revocationKeyId = activeKeyId`; `nonce += 1` |
| `cancelRevocation` | caller is the account itself; an `Active` key exists; a revocation is pending | `revocationExecutableAt = 0`; `revocationKeyId = 0` |
| `executeRevocation` | a revocation is pending; `now >= revocationExecutableAt`; `revocationKeyId == activeKeyId` | named key → `Revoked`; `activeKeyId = 0`; pending state cleared; `nonce += 1`; `enrolled` unchanged |

- **[KR-20]** `register` MUST fail while the account has an `Active` key. Replacing a live key
  is `rotate`; replacing a lost one is `executeRevocation` followed by `register`.
- **[KR-21]** `rotate` MUST make both changes in one transaction: there MUST be no state in
  which an account has two `Active` keys or, transiently, none.
- **[KR-22]** `rotate` MUST require an XMSS signature by the outgoing key over the same
  digest the owners signed, and MUST consume that leaf. This proves the outgoing device is
  present and consenting, which is what distinguishes a rotation from a recovery.
- **[KR-23]** `requestRevocation` MUST arm the delay from the current timestamp. A second
  request MUST therefore never move an existing deadline earlier.
- **[KR-24]** `cancelRevocation` MUST be callable only by the account itself (i.e. by an
  owner-threshold transaction), and MUST NOT be callable by the administrator alone. The
  revocation path is the owners' remedy against a stolen device; a thief holding the device
  must not be able to veto it.
- **[KR-25]** `executeRevocation` MUST be permissionless once the delay has elapsed: the
  authorisation is the owner-signed request plus the passage of time.
- **[KR-26]** `executeRevocation` MUST revoke exactly the key the request named, and MUST
  fail if the account's `Active` key is no longer that key. A rotation that happened while the
  request matured is owner-co-signed and supersedes it; revoking "whatever is active" would
  destroy the successor key.
- **[KR-27]** `rotate` MUST clear a pending revocation of the rotated-away key, and SHOULD
  emit the cancellation event when it does.
- **[KR-28]** After `executeRevocation` the account MUST have no `Active` key, and the
  registry MUST accept a fresh `register` for it (`enrolled` stays `true`, `[KR-07]`).
- **[KR-29]** The revocation delay MUST be immutable after deployment and SHOULD be at least
  one week; it is the window in which owners notice and cancel an unauthorised request.

### 6. Key status semantics

- **[KR-30]** Only an `Active` key MAY authorise the creation of new authorisations.
- **[KR-31]** Authorisations already created under a key that later becomes `Rotated` MUST
  remain usable. They were fully verified when created, each consumed its own leaf, and
  routine rotation is not a statement that anything was compromised.
- **[KR-32]** A key in state `Revoked` MUST invalidate every authorisation created under it,
  used or unused. Revocation is the response to compromise, and it must reach authorisations
  the compromised key already produced.
- **[KR-33]** A key MUST NOT return to `Active` from `Rotated` or `Revoked`.

### 7. Interface

- **[KR-34]** A conforming registry MUST expose these functions under exactly these names,
  with these parameter types in this order and this mutability. Function *parameter* names are
  informative — they do not enter the selector — but the function names do, so they are
  normative: a caller compiled against this interface must be able to call any conforming
  registry.

```solidity
interface IHashBasedKeyRegistry {
    // ── ceremonies ──
    function registerQuantumKey(
        address account,
        address quantumAdmin,
        bytes32 xmssRoot,
        bytes32 xmssSeed,
        uint32  treeHeight,
        bytes32 parameterSet,
        uint256 validUntil,
        bytes calldata deviceAttestation,
        bytes calldata ownerSignatures
    ) external returns (bytes32 quantumKeyId);

    function rotateQuantumKey(
        address account,
        address newQuantumAdmin,
        bytes32 newXmssRoot,
        bytes32 newXmssSeed,
        uint32  treeHeight,
        bytes32 parameterSet,
        uint256 validUntil,
        bytes calldata oldKeyXmssProof,
        bytes calldata deviceAttestation,
        bytes calldata ownerSignatures
    ) external returns (bytes32 newQuantumKeyId);

    function requestKeyRevocation(address account, uint256 validUntil, bytes calldata ownerSignatures) external;
    function cancelKeyRevocation(address account) external;
    function executeKeyRevocation(address account) external;

    // ── views ──
    function getKey(bytes32 quantumKeyId) external view returns (KeyRegistration memory);
    function isLeafUsed(bytes32 quantumKeyId, uint32 leafIndex) external view returns (bool);
    function registryNonce(address account) external view returns (uint256);
    function safeToQuantumKey(address account) external view returns (bytes32);
    function enrolledSafe(address account) external view returns (bool);
    function keyRevocationExecutableAt(address account) external view returns (uint64);
    function keyRevocationKeyId(address account) external view returns (bytes32);
    function rootRegistered(address account, bytes32 xmssRoot) external view returns (bool);
}
```

The views `safeToQuantumKey` and `enrolledSafe` read "the account's active key" and "has this
account ever enrolled". The word `safe` in these names, in the `safe` member of every type
string of §4, in the `KeyRegistration.safe` field and in the event and error parameters of §8
is historical: the first implementation served Safe accounts, and those spellings are now
frozen because deployed verifiers, indexers and signing devices reproduce them. They mean
"account" throughout, and this ERC keeps one spelling rather than two.

- **[KR-35]** `isLeafUsed(quantumKeyId, leafIndex)` MUST answer for the *key*, not the
  registration: two registrations of the same root MUST give the same answer. It MUST return
  `false` for an unknown `quantumKeyId` rather than revert.
- **[KR-36]** A conforming registry SHOULD advertise this interface through
  [ERC-165](./eip-165.md). The
  reference implementation does not, because it is deployed as part of a Safe guard whose
  `supportsInterface` answers for the guard interfaces the account checks; a registry deployed
  standalone SHOULD advertise it.

### 8. Events and errors

- **[KR-37]** A conforming registry MUST emit:

```solidity
event QuantumKeyRegistered(bytes32 indexed quantumKeyId, address indexed safe, bytes32 xmssRoot, uint32 treeHeight);
event QuantumKeyRotated(bytes32 indexed oldKeyId, bytes32 indexed newKeyId, address indexed safe);
event KeyRevocationRequested(address indexed safe, bytes32 indexed quantumKeyId, uint64 executableAt);
event KeyRevocationCancelled(address indexed safe, bytes32 indexed quantumKeyId);
event QuantumKeyRevoked(bytes32 indexed quantumKeyId, address indexed safe);
event LeafConsumed(bytes32 indexed quantumKeyId, uint32 indexed leafIndex, bytes32 digest);
```

- **[KR-38]** `LeafConsumed` MUST be emitted for every consumed leaf, including the leaf a
  rotation consumes, so that the on-chain record can be reconciled with the device's counter.
- **[KR-39]** Failures SHOULD be reported with these custom errors, so that clients can
  distinguish them without string matching:

```solidity
error ZeroAddress();
error InvalidKeyParams();
error SafeAlreadyEnrolled(address safe);
error NoActiveKey(address safe);
error SignatureExpired(uint256 validUntil);
error InvalidAttestation();
error LeafAlreadyUsed(bytes32 quantumKeyId, uint32 leafIndex);
error InvalidXmssSignature();
error LeafIndexMismatch(uint32 expected, uint32 actual);
error RevocationNotRequested(address safe);
error RevocationTimelocked(uint64 executableAt);
error RevocationSuperseded(address safe, bytes32 requestedKeyId);
error NotAuthorized();
error RootAlreadyRegistered(bytes32 xmssRoot);
```

### 9. Verification and consumption order

- **[KR-40]** When verifying a hash-based signature the registry MUST, in this order: check
  that the declared height matches the registered height; check that the leaf is unconsumed;
  verify the signature; then mark the leaf consumed and increment the key's use counter. The
  reuse check precedes verification because verification costs on the order of `10^6` gas
  (`[XV-22]`).
- **[KR-41]** Between the reuse check and the consumption the registry MUST NOT make any call
  that can re-enter it. Hash precompiles are the only external interaction the verification
  itself needs.

## Rationale

**Why registration takes both signatures in one transaction.** Two separate transactions —
owners approve, device attests later — create a window in which one half is committed and the
other can be substituted, and they double the number of states an implementation must reason
about. One transaction makes the ceremony atomic: either the account has the key both parties
agreed on, or nothing changed. `[KR-02]`, `[KR-03]`.

**Why the entry point and the preimage are left to the account (`[KR-02]`, `[KR-18]`).** The
accounts these registries serve do not agree on how to be asked. The Safe family exposes
`checkSignatures`, not ERC-1271, and its overloads differ by version: v1.3.0 and v1.4.1 pass
`data` — the signed preimage — rather than the digest to contract owners, and v1.4.1
additionally requires `keccak256(data) == dataHash`, so a registry that hands them the digest
in the preimage argument is rejected by some owners and accepted by others. v1.5.0 changes the
shape again. Naming one of those in normative text would bind every implementer to one account
family and one release; naming none of them would leave `[KR-18]`'s trap open. So the clause
states the property — pass the full `0x1901 ‖ domainSeparator ‖ structHash` preimage wherever
a preimage is accepted — and the reference implementation picks the version-portable
`checkSignatures(bytes32,bytes,bytes)` overload to satisfy it.

**Why the owners sign the root and not an identifier.** An identifier is a hash of material
the owners may never have seen; the substitution attack is then invisible to them. Signing
`xmssRoot`, `xmssSeed`, `treeHeight` and `parameterSet` means the device's screen and the
owners' wallets show the same object. `[KR-16]`.

**Why rotation consumes an old-key leaf.** Without it, "rotation" is indistinguishable from
recovery, and the outgoing device — which may be in an attacker's hands — has no say. With it,
a rotation is proof that the current key still exists and consents, which is why rotation may
be instant while recovery must not be. `[KR-22]`.

**Why revocation is a delay the account can cancel, rather than a threshold action.** The case
that matters is a stolen device. The thief holds the classical key and the hash-based key; the
owners hold the threshold. If revocation were instant, the *owners* could silently swap the
second factor, weakening the two-party model. If the device could cancel, the thief would veto
every recovery. A delay that only the account can cancel gives the owners a guaranteed path
and gives everyone else time to notice. `[KR-23]`–`[KR-25]`, `[KR-29]`.

**Why a matured revocation is permissionless but key-specific.** Permissionless, because the
authorisation is already on-chain and waiting for a privileged executor is another liveness
dependency. Key-specific, because the request names a key and a rotation in the meantime is a
*newer* owner-co-signed decision; executing against "whatever is active" would let a stale
request destroy a healthy successor. `[KR-25]`, `[KR-26]`.

**Why enrollment is sticky.** Emergency recovery paths (including detaching the enforcement
layer entirely) are gated on "this account is enrolled". Clearing the flag on revocation would
remove the recovery path exactly when it is needed: after the key is gone. `[KR-07]`.

**Why the root record is per account but the leaf record is global.** They protect different
things. The root record stops an account from re-registering a root and getting a fresh set of
per-registration counters; scoping it globally would let anyone squat a victim's root from the
mempool. The leaf record protects the key's one-time property, which is a property of the key
wherever it is used, so it must be global. `[KR-11]`, `[KR-12]`.

**Why `Rotated` keeps existing authorisations alive but `Revoked` does not.** Rotation is
routine hygiene: invalidating outstanding authorisations would burn their leaves and make
rotation operationally expensive, discouraging it. Revocation is the compromise response, and
must reach everything the key touched. `[KR-31]`, `[KR-32]`.

## Backwards Compatibility

No consensus or account changes are required. The registry is an ordinary contract, and it
learns what "owner threshold" means by asking the account (`[KR-02]`), so it works with any
account implementation that can answer a signature check — including Safe v1.3.0, v1.4.1 and
v1.5.0, whose differing `checkSignatures` overloads motivate `[KR-18]`.

The registry deliberately holds no upgrade authority (`[KR-04]`); a change to its rules is a
new deployment that accounts adopt by re-enrolling.

## Test Cases

The reference implementation's state machine is transcribed as an executable specification and
checked against the contract with the Halmos symbolic execution engine: for *all* callers,
timestamps, key parameters and prior states satisfying the specification's invariant, the
transitions below succeed exactly when the specification allows and leave exactly the state it
describes. Two things are abstracted, and the lemmas are conditional on them. The owner
threshold and the administrator's attestation are stubbed to accept every signature, so
"succeeds when allowed" means "given that both authorisations succeeded". And a valid XMSS
signature is out of reach of the solver, so `rotate` is proved only to *reach* its possession
proof exactly when the state preconditions hold; the post-state of a succeeding rotation is not
proved symbolically and is covered by concrete-vector tests instead. The proved lemmas are

1. `register` succeeds iff allowed, and the resulting state matches (including that the new key
   is `Active` and the height is recorded);
2. `requestRevocation` succeeds iff allowed, with matching state;
3. a re-request never moves an armed deadline earlier (`[KR-23]`);
4. `cancelRevocation` succeeds iff the caller is the account and a request is pending
   (`[KR-24]`);
5. `executeRevocation` succeeds iff matured and not superseded, and then the named key is
   `Revoked`, the account has no active key, and enrollment is unchanged (`[KR-26]`, `[KR-28]`);
6. a root is one-shot: a second registration under a root the account already used fails and
   leaves the active key unchanged (`[KR-10]`).

Additional cases worth covering in any implementation:

| case | expected |
| --- | --- |
| `register` with an `Active` key present | revert `SafeAlreadyEnrolled` |
| `register` with `treeHeight = 0` or `21` | revert `InvalidKeyParams` |
| `register` with a zero root, seed, admin or parameter set | revert `InvalidKeyParams` / `ZeroAddress` |
| `register` past `validUntil` | revert `SignatureExpired` |
| `register` with owner signatures for a different root | revert (account's check) |
| `register` with an attestation by another signer | revert `InvalidAttestation` |
| `register` replaying a previous ceremony's signatures | revert (nonce consumed, `[KR-14]`) |
| `rotate` without an old-key proof, or with a proof at a consumed leaf | revert `InvalidXmssSignature` / `LeafAlreadyUsed` |
| `rotate` with an old-key proof whose auth path length ≠ registered height | revert `LeafIndexMismatch` |
| `rotate` while a revocation is pending | succeeds; pending revocation cleared (`[KR-27]`) |
| `cancelKeyRevocation` called by the administrator | revert `NotAuthorized` (`[KR-24]`) |
| `executeKeyRevocation` before the deadline | revert `RevocationTimelocked` |
| `executeKeyRevocation` after a rotation | revert `RevocationSuperseded` (`[KR-26]`) |
| `register` after a completed revocation | succeeds; `enrolled` still `true` |
| the same root registered by two accounts, one leaf spent on one | `isLeafUsed` true for both (`[KR-12]`) |

## Reference Implementation

`QuantumKeyRegistry`, the registry half of an immutable Safe transaction guard, implements
this ERC: `registerQuantumKey`, `rotateQuantumKey`, `requestKeyRevocation`,
`cancelKeyRevocation`, `executeKeyRevocation`, the five per-account storage fields of §5, the
per-root leaf bitmap of `[KR-12]`, and the Halmos-proved state machine of the Test Cases
section. Owner authorisation is delegated to the account through the version-portable
`checkSignatures(bytes32,bytes,bytes)` overload with the digest preimage (`[KR-18]`), and the
attestation is checked with an ERC-1271-aware signature checker (`[KR-03]`).

The consumption routine, which is where `[KR-40]` and `[KR-41]` live:

```solidity
function _verifyAndConsumeXmss(bytes32 keyId, bytes32 digest, bytes calldata xmssSignature)
    internal
    returns (uint32 leafIndex)
{
    KeyRegistration storage k = _keys[keyId];
    XMSS.Signature memory sig = abi.decode(xmssSignature, (XMSS.Signature));

    if (sig.authPath.length != k.treeHeight) {
        revert LeafIndexMismatch(k.treeHeight, SafeCast.toUint32(sig.authPath.length));
    }
    leafIndex = sig.leafIdx;

    BitMaps.BitMap storage used = _usedLeaves[k.xmssRoot]; // per ROOT, not per registration
    if (used.get(leafIndex)) revert LeafAlreadyUsed(keyId, leafIndex);

    if (!XMSS.verify(digest, sig, XMSS.PublicKey({root: k.xmssRoot, seed: k.xmssSeed}), k.treeHeight)) {
        revert InvalidXmssSignature();
    }

    used.set(leafIndex);
    unchecked { ++k.useCounter; }
    emit LeafConsumed(keyId, leafIndex, digest);
}
```

## Security Considerations

**The two halves must be independent.** The security claim is that no single party can install
or replace a key: the owners cannot, because the device must attest; the device cannot, because
the owners must co-sign. That claim fails if the same secret can produce both halves — for
example if the administrator is also an owner of the account, or if the device and an owner key
live on the same machine. `[KR-42]` forbids exactly that overlap; because no clause of this
ERC can be enforced by the registry, an onboarding flow that does not check it is the single
most likely way to deploy this scheme and get none of its benefit.

**Ceremony front-running.** The root is public in the mempool before the ceremony lands.
`[KR-11]` (per-account root records) removes the denial-of-service; the digest's binding of the
account, the registry address and the chain id removes redirection; the nonce and `validUntil`
remove replay. An implementation that globalises the root record, or omits the nonce from the
digest, reintroduces one of these.

**Revocation races.** A thief who holds the device will try to rotate to a key they control
before the owners' revocation matures — but rotation needs the owner threshold too, so the
thief cannot. The reverse race matters more: owners who request revocation and then rotate
legitimately must not have their successor key destroyed when the stale request matures, which
is `[KR-26]`. Implementations that clear the pending request on rotation (`[KR-27]`) *and*
check the named key on execution are safe against both orderings.

**Nonce invalidation is a liveness cost.** `[KR-14]` means a revocation request invalidates
in-flight ceremony signatures. That is intended — stale ceremonies must die — but it means an
owner who repeatedly requests revocation can stall other ceremonies. The request itself needs
the owner threshold, so this is a threshold-level griefing concern, not a single-key one.

**Leaf exhaustion and the rotation leaf.** Every rotation consumes one leaf of the outgoing
key, so a policy of frequent rotation shortens the useful life of each key. At `h = 10`
(1024 leaves) this is negligible; at very small heights it is not.

**Device counter versus chain counter.** The device's own counter is a usability feature; the
chain's record is the security boundary. A device restored from backup may have a stale counter
and will happily re-sign a spent leaf. `[KR-12]` and `[XV-19]` are what make the registry
refuse it; a deployment is well advised to treat such a refusal as a possible
restore-from-backup incident rather than a transient error.

**Status is not authority by itself.** `Active` means "this key may authorise new
authorisations", not "this key's holder may do anything". What an authorisation permits, and
how it is consumed, is the companion ERC's subject; a registry that is integrated into a
system which skips those checks provides no protection.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
