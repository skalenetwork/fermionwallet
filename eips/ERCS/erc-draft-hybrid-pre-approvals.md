---
eip: <to be assigned>
title: Hybrid post-quantum pre-approvals
description: Transaction authorisations signed by both a classical and a hash-based key, matched and consumed atomically at execution
author: Konstantin Kladko (@kladkogex)
discussions-to: <URL>
status: Draft
type: Standards Track
category: ERC
created: 2026-09-30
requires: 165, 712, 1271
---

## Abstract

This ERC specifies *pre-approvals*: authorisation objects a smart account creates before a
transaction is executed, each carrying two independent signatures over one EIP-712 digest — one
classical (ECDSA or ERC-1271) and one post-quantum (a stateful hash-based signature) — and each
consumed exactly once, atomically, at execution time. It defines the three approval classes and
what each one binds, the EIP-712 message both signers sign, the creation and validity rules, the
two-tier matching that lets an enforcement hook find the right approval in constant bounded
work, revocation authority, and the consumption semantics. It is the authorisation layer above
the companion ERCs on on-chain XMSS verification and stateful hash-based key registries.

## Motivation

A quantum-capable adversary who can forge the classical signatures of a smart account's owners
can move its funds. Migrating the account to a post-quantum scheme is the eventual answer, but
it requires the account implementation, the wallet, the hardware and the ecosystem to move
together. A *second* authorisation — one the account's own signature scheme cannot produce and
a quantum adversary cannot forge — can be added now, to accounts that already exist, without
changing the account's own signing.

That arrangement needs an authorisation object, and the object needs to be specified rather
than invented per deployment, because the details are where the money leaks:

- **Two signatures over one digest, or two signatures over two messages?** One digest, or the
  halves can be recombined across contexts.
- **What does an approval bind?** "This account may transfer 100 USDC" and "this account may
  execute exactly these bytes" are different promises, and mixing them silently widens the
  second into the first.
- **How does the enforcement hook find the approval at execution time?** It runs inside the
  transaction, with a gas budget, and it MUST NOT be possible to make matching unbounded or to
  starve a live approval with dead ones.
- **What happens to an approval whose key was later rotated, or revoked?** Rotation is
  routine; revocation is an incident. Treating them alike either burns leaves needlessly or
  leaves a compromised key's authorisations standing.
- **Who may cancel an approval?** Approval must be expensive and revocation cheap, but a single
  owner able to revoke *anything* can veto their own removal from the account.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in
RFC 2119 and RFC 8174.

Normative statements are labelled `[PA-nn]`.

### 1. Model and roles

```text
   owners (classical threshold)        administrator + device (classical + hash-based)
             │                                          │
             │  account transaction                     │  pre-approval, created in advance
             ▼                                          ▼
      ┌──────────────────┐   checks   ┌─────────────────────────────────────┐
      │ smart account    │───────────▶│ enforcement hook + pre-approvals    │
      └──────────────────┘            └─────────────────────────────────────┘
                                       consumes exactly one matching approval
```

- **[PA-01]** A pre-approval MUST carry two signatures over one digest: a *classical* half by
  the administrator (`quantumAdmin` of the key record), verified in an ERC-1271-aware way, and
  a *post-quantum* half by the hash-based key registered to the account. Both MUST be
  verified at creation; neither half alone MUST be sufficient.
- **[PA-02]** An account's own owner authorisation is independent of, and additional to, a
  pre-approval: the account still authorises its transaction its own way. A pre-approval is a
  *second* authorisation and MUST NOT be usable as a substitute for the first.
- **[PA-03]** Creation MUST be callable by anyone (a relayer): the authority is in the
  signatures. The account address MUST be taken from the signed request, never from
  `msg.sender`.
- **[PA-04]** Consumption MUST take the account address from `msg.sender` (the account
  executing the transaction), so that one account's approvals can never satisfy another's
  transaction.

### 2. Approval classes

| class | value | binds | timelock |
| --- | --- | --- | --- |
| `TRANSFER` | 0 | `token`, `recipient`, `amount` | none |
| `PAYLOAD` | 1 | `target`, `value`, `keccak256(calldata)` | none |
| `ADMIN` | 2 | `target` (the account or the enforcement contract), `value`, `keccak256(calldata)` | mandatory |

- **[PA-05]** The class MUST be part of the signed digest. An implementation MUST NOT infer it
  at consumption time from anything other than the executed transaction's own shape.
- **[PA-06]** Fields that a class does not bind MUST be zero in the request, and a creation
  call MUST reject a request that sets them. Otherwise two distinct signed objects could map to
  one approval, or a field the signer ignored could carry meaning later.
- **[PA-07]** A `TRANSFER` approval MUST NOT authorise native value: an implementation MUST
  reject an execution that carries non-zero `value` against a `TRANSFER` approval. Native value
  moves only under `PAYLOAD`.
- **[PA-08]** An `ADMIN` approval MUST have `target` equal to the account itself or to the
  enforcement contract, and MUST NOT be created with `validFrom < block.timestamp + ADMIN_TIMELOCK`.
- **[PA-09]** `ADMIN` is the class for every action that changes the enforcement posture or the
  account's governance — attaching or detaching the enforcement hook, changing owners or the
  threshold, enabling or disabling modules, changing the enforcement policy. An implementation
  MUST classify such an action as `ADMIN` and MUST NOT allow it to be smuggled through
  `PAYLOAD` or through a batch.
- **[PA-10]** Implementations MUST emit a distinct event for `ADMIN` creation that includes the
  earliest execution time, so that watchers can act during the delay.

### 3. The signed message

```solidity
struct PreApprovalRequest {
    address account;       // `safe` in the type string
    address token;         // TRANSFER only
    address recipient;     // TRANSFER only
    uint256 amount;        // TRANSFER only
    address target;        // PAYLOAD / ADMIN only
    uint256 value;         // PAYLOAD / ADMIN only
    bytes32 dataHash;      // PAYLOAD / ADMIN only: keccak256 of the exact calldata
    uint64  validFrom;
    uint64  validTo;
    bytes32 nonce;         // caller-chosen; unique per account
    bytes32 quantumKeyId;  // the key that must be the account's Active key
    uint32  xmssLeafIndex; // the leaf the post-quantum half consumes
    bytes32 policyHash;    // optional binding to an off-chain policy document
    bytes32 txHash;        // optional exact-transaction pin; 0 = field matching
}
```

- **[PA-11]** Both halves MUST sign the EIP-712 digest of this type string, verbatim:

```text
PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)
```

whose type hash is
`0x5468891f128cc5ac3b167339395b9b79f129564c2b0b0e766beb737fa6422e19`. The member named `safe`
is the account address; the name is part of the frozen type string.

- **[PA-12]** The digest MUST be `hashTypedDataV4` under the domain of the contract that
  verifies it, so that the chain id and that contract's address are bound. `name` and `version`
  are implementation-chosen.
- **[PA-13]** The digest MUST bind the account, the class, every field the class uses, the
  validity window, the nonce, the key identity, the leaf index, the policy hash and the
  optional transaction pin — i.e. all of the members above. A half-signature MUST NOT be
  replayable across accounts, chains, classes, payloads or leaves.
- **[PA-14]** `xmssLeafIndex` MUST equal the leaf index inside the post-quantum signature, and
  the implementation MUST reject a mismatch. The signer states the leaf in the signed message
  so the device's screen and the chain agree on which one-time key was spent.

### 4. Creation

- **[PA-15]** Creation MUST reject the request unless `quantumKeyId` is the account's single
  `Active` key at that moment (see the registry ERC, `[KR-06]`, `[KR-30]`).
- **[PA-16]** Creation MUST verify the classical half against the `quantumAdmin` recorded in
  that key's registration, with an ERC-1271-aware check, and SHOULD verify it *before* the
  post-quantum half: the classical check costs thousands of gas and the post-quantum one
  millions, and a valid post-quantum half with a missing classical anchor must fail either way.
- **[PA-17]** Creation MUST verify the post-quantum half and consume its leaf as specified in
  the registry ERC `[KR-40]`.
- **[PA-18]** The approval identity MUST be `keccak256(abi.encodePacked(account, nonce))`, and
  creation MUST reject an identity that already exists. The nonce is therefore the
  replay-protection and the identity in one.
- **[PA-19]** Creation MUST reject a window that is empty (`validTo <= validFrom`), already
  expired (`validTo <= block.timestamp`), or shorter than the minimum granularity
  `MIN_WINDOW`. `MIN_WINDOW` MUST be at least 15 minutes and MUST be immutable after
  deployment: block timestamps are validator-skewable by seconds, so a sub-minute window is
  not a boundary any implementation can honour, and a mutable floor is not a floor.
- **[PA-20]** An implementation MUST NOT store the signature bytes. It SHOULD store
  `keccak256(postQuantumSignature)` as an audit anchor. Storing multi-kilobyte signatures per
  approval is a storage-bloat and gas-griefing vector, and the signature has no further
  on-chain use once verified.
- **[PA-21]** Creation MUST emit an event identifying the approval, the account and the bound
  fields of its class.

### 5. Matching and consumption

An approval is consumed by the enforcement hook while the account's transaction executes. Two
matching tiers are specified; an implementation MUST support both.

**Tier 1 — exact-transaction pin.** If `txHash != 0`, the approval is indexed by
`(account, txHash)`, where `txHash` is the account's own transaction hash.

- **[PA-22]** A Tier-1 hit MUST be verified against the executing transaction's fields as well
  as the pin before it is consumed.
- **[PA-23]** A pin MUST NOT be overwritten while the pinned approval is still live, or after
  it has been used. It MAY be replaced when the pinned approval can never execute again
  (expired, revoked, or created under a revoked key) — that is the sanctioned way to re-approve
  a transaction whose approval expired.

**Tier 2 — field commitment queue.** If `txHash == 0`, the approval joins a FIFO queue keyed by
a commitment to its bound fields:

```text
TRANSFER: keccak256(abi.encode(account, class, token, recipient, amount))
other:    keccak256(abi.encode(account, class, target, value, dataHash))
```

- **[PA-24]** The commitment MUST include the account address, so one account's approvals can
  never be matched against another's transaction.
- **[PA-25]** Consumption MUST try Tier 1 first, then Tier 2, and MUST consume at most one
  approval per execution.
- **[PA-26]** An implementation MUST bound the per-commitment queue length, and MUST bound the
  work consumption performs, so that an adversary cannot make matching unboundedly expensive.
- **[PA-27]** Entries that can never become consumable again — used, revoked, expired, or
  created under a revoked key — MUST NOT count toward that bound: they MUST be removable, and
  an implementation MUST remove them before rejecting a creation for a full queue. Otherwise a
  queue of dead approvals locks a commitment out permanently.
- **[PA-28]** An entry that is merely *not yet valid* (a future `validFrom`) MUST NOT be
  discarded when a later entry is consumed over it. Discarding it would silently destroy a
  scheduled approval and waste its one-time leaf.
- **[PA-29]** Consumption MUST mark the approval used in the same transaction as the
  execution, and the approval MUST stay used even if the executed transaction fails. A leaf and
  an approval offered to the chain are spent whatever the outcome.
- **[PA-30]** Post-execution hooks MUST NOT be authorisation gates: all checks happen before
  execution.
- **[PA-31]** When nothing matches, the enforcement hook MUST revert. It SHOULD revert with a
  plain `Error(string)` reason rather than a custom error, because widely deployed account
  front-ends decode only string reasons, and this revert is the message a legitimate owner sees
  when they forgot to approve. The reference reason is:

```text
FermionGuard: no quantum pre-approval for this transaction. Approve it in the FermionGuard app first.
```

- **[PA-32]** An approval MUST be consumable only while `validFrom <= block.timestamp <= validTo`
  and its key is usable (`[PA-34]`).

### 6. Key status interaction

- **[PA-33]** Creation MUST require the key to be `Active`.
- **[PA-34]** Consumption MUST accept an approval whose key is `Active` or `Rotated`, and MUST
  reject one whose key is `Revoked` — matching `[KR-31]` and `[KR-32]`: routine rotation does
  not invalidate already-verified authorisations, revocation does.

### 7. Revocation

- **[PA-35]** A live approval MUST be revocable by the account itself and by the administrator
  whose key created it.
- **[PA-36]** A live approval of class `TRANSFER` or `PAYLOAD` MUST also be revocable by any
  single owner of the account, acting from their own address. Approval requires two parties and
  a threshold; revocation must be cheap, because a false alarm costs one re-approval while a
  missed alarm can cost the account's balance.
- **[PA-37]** An approval of class `ADMIN` MUST NOT be revocable by a single owner. `ADMIN`
  approvals are how the owner threshold changes governance, including removing a rogue owner; a
  single-owner veto would let that owner block their own removal indefinitely.
- **[PA-38]** Revocation MUST fail for an approval that is already used or revoked, and MUST
  emit an event. Revocation is damage control, not undo: the consumed one-time leaf is not
  recovered.

### 8. Interface

- **[PA-39]** A conforming implementation MUST expose these functions (types, order and
  mutability normative; names informative):

```solidity
interface IHybridPreApprovals {
    enum ApprovalClass { TRANSFER, PAYLOAD, ADMIN }

    function createPreApproval(
        PreApprovalRequest calldata req,
        bytes calldata classicalSignature,
        bytes calldata postQuantumSignature
    ) external returns (bytes32 preApprovalId);

    function createPayloadPreApproval(
        PreApprovalRequest calldata req,
        bytes calldata classicalSignature,
        bytes calldata postQuantumSignature
    ) external returns (bytes32 preApprovalId);

    function createAdminPreApproval(
        PreApprovalRequest calldata req,
        bytes calldata classicalSignature,
        bytes calldata postQuantumSignature
    ) external returns (bytes32 preApprovalId);

    function revokePreApproval(bytes32 preApprovalId) external returns (bool);

    function validatePreApproval(bytes32 preApprovalId) external view returns (bool valid, string memory reason);
    function getPreApproval(bytes32 preApprovalId) external view returns (PreApproval memory);
    function approvalByTxHash(address account, bytes32 txHash) external view returns (bytes32 preApprovalId);

    function MIN_WINDOW() external view returns (uint64);
    function ADMIN_TIMELOCK() external view returns (uint64);
}
```

- **[PA-40]** `validatePreApproval` is a convenience view and MUST NOT be the consumption
  mechanism: an implementation MUST NOT accept its result in place of the checks of §5. Its
  `reason` string is informative.
- **[PA-41]** `ADMIN_TIMELOCK` MUST be immutable after deployment. A system that also offers a
  key-independent way to detach the enforcement hook MUST make that delay strictly longer than
  `ADMIN_TIMELOCK`, so that the fast path is always the co-signed one.
- **[PA-42]** The stored approval record MUST contain at least the fields of
  `PreApprovalRequest` plus `id`, `approvalClass`, a hash of the post-quantum signature, and
  the `used` and `revoked` flags, and MUST be readable through `getPreApproval`.

### 9. Events and errors

- **[PA-43]** A conforming implementation MUST emit:

```solidity
event PreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed token, uint256 amount);
event PayloadPreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed target, bytes32 dataHash);
event AdminPreApprovalCreated(bytes32 indexed id, address indexed safe, address indexed target, bytes32 dataHash, uint64 executableAt);
event PreApprovalUsed(bytes32 indexed id, address indexed safe, address indexed recipient, uint256 amount);
event PreApprovalRevoked(bytes32 indexed id, address indexed safe);
```

- **[PA-44]** Failures SHOULD be reported with these custom errors (the no-match revert of
  `[PA-31]` excepted):

```solidity
error ApprovalExists(bytes32 id);
error InvalidWindow(uint64 validFrom, uint64 validTo);
error AdminTimelockNotRespected(uint64 validFrom, uint64 earliest);
error InvalidAdminTarget(address target);
error InvalidEcdsaSignature();
error WrongQuantumKey(bytes32 expected, bytes32 actual);
error LeafIndexDoesNotMatchSignature(uint32 declared, uint32 inSignature);
error TxHashAlreadyPinned(address safe, bytes32 txHash);
error CommitmentQueueFull(bytes32 commitment);
error UnknownApproval(bytes32 id);
error NotRevocable(bytes32 id);
error NonZeroClassFields();
```

### 10. Enforcement hook (informative)

This ERC specifies the authorisation object, not the hook that enforces it; the hook is
necessarily specific to the account implementation (for Safe accounts, a transaction guard and
a module guard). A conforming enforcement hook is expected to:

1. classify the executing transaction into exactly one class — self-calls and calls to the
   enforcement contract are `ADMIN`; a bare native send is `PAYLOAD`; a token `transfer` is
   `TRANSFER`; anything else is `PAYLOAD`;
2. recompute the account's own transaction hash itself for Tier-1 matching, rather than trusting
   a caller-supplied hash;
3. refuse `delegatecall` except to a pinned, call-only batching library, and bind the whole
   batch by hashing its calldata;
4. refuse transactions whose parameters can pay out balances as "gas refunds";
5. refuse the account-level constructs that would let a transaction bypass the hook entirely —
   for Safe accounts: an installed fallback handler (which can answer ERC-1271 signature checks
   with no transaction at all), and enabled modules on versions where module execution is not
   guarded;
6. keep a key-independent, time-locked path to detach itself (`[PA-41]`), so that a lost device
   or an exhausted key can never permanently freeze the account.

Items 4 and 5 are not decoration: each closes a path by which value leaves the account without
any pre-approval being consumed.

## Rationale

**Why pre-approvals rather than a co-signing scheme at execution time.** The post-quantum
signature is produced on a hardware device, takes a human interaction, and costs on the order
of `10^6` gas to verify. Doing that inside the execution path would put a multi-second device
interaction and a million gas on the critical path of every transaction, and would make the
hook's gas cost depend on the signature. Separating creation from consumption lets the
expensive verification happen once, in its own transaction, before the account's owners even
assemble their signatures — and gives watchers a window in which to revoke.

**Why one digest for both halves.** With two messages, the two halves are separate artefacts
that can be captured and recombined with a *different* counterpart — a classical signature for
one payload with a post-quantum signature for another, if any field is not common to both. One
digest makes "both parties agreed to exactly this" a single, checkable statement. `[PA-01]`,
`[PA-13]`.

**Why three classes instead of one.** A single "exact payload" class would be safe but
unusable for the common case: a recurring payment has a natural identity (token, recipient,
amount) and its account-level transaction hash is not known until the transaction is assembled.
A single "fields" class would be unsafe: arbitrary calldata has no meaningful field projection,
so it must be bound by hash. `ADMIN` exists because a third kind of action — one that changes
who may authorise, or whether enforcement happens at all — needs a delay rather than a
different binding. `[PA-05]`–`[PA-09]`.

**Why two matching tiers.** Tier 1 is exact and is what a careful wallet uses: it pins one
approval to one account transaction. Tier 2 exists because the account's transaction hash
depends on its nonce, which is not known when the approval is created for a queue of recurring
payouts, and because a strict pin would force re-approval (and another one-time leaf) whenever
an unrelated transaction changed the nonce. `[PA-22]`–`[PA-25]`.

**Why dead entries must not count toward the queue bound.** A bound is necessary to keep
consumption's work finite; a bound that counts entries which can never be consumed is a
permanent denial of service against that exact (token, recipient, amount) tuple, reachable by
anyone who can create approvals and let them expire. `[PA-27]`.

**Why a not-yet-valid entry survives consumption over it.** Scheduled approvals ("payable from
Monday") legitimately sit in front of live ones. Popping them would destroy an authorisation
the signer paid a one-time leaf for. `[PA-28]`.

**Why the no-match revert is a string.** Custom errors are better engineering and worse
product: the account front-ends people actually use render `Error(string)` and show a bare
selector for anything else. This particular revert is the one a legitimate owner hits, and a
bare selector there turns a recoverable mistake into a support incident. `[PA-31]`.

**Why any single owner may revoke, except `ADMIN`.** Revocation is a safety valve; requiring
the threshold to pull it means the valve is unavailable exactly when owners disagree about
whether there is an emergency. The `ADMIN` exception exists because `ADMIN` approvals are the
mechanism for removing an owner, and a universal single-owner veto makes a rogue owner
irremovable without falling back to the slow key-independent path. `[PA-36]`, `[PA-37]`.

**Why the signature bytes are not stored.** A hash-based signature is 2.6–2.9 kB. Storing it
per approval would cost hundreds of thousands of gas, could be used to bloat state cheaply, and
serves no on-chain purpose after verification; its hash is enough to prove later which
signature was presented. `[PA-20]`.

## Backwards Compatibility

No consensus change and no change to any existing account implementation is required. The
scheme is additive: an account adopts it by attaching an enforcement hook and enrolling a key,
and abandons it through the hook's own detach path.

The classical half is verified with an ERC-1271-aware check, so the administrator may be an EOA
today and a contract signer later. The post-quantum half is specified by the companion XMSS
ERC; another stateful hash-based scheme could be substituted without changing this document's
structure, provided its one-time state is accounted for as that ERC requires.

Pre-approvals are orthogonal to ERC-4337: an approval is consumed by the account's own
execution path, whatever assembles that execution.

## Test Cases

Behaviour every implementation SHOULD cover; the reference implementation's suite covers each
of these:

| case | expected |
| --- | --- |
| both halves valid, window valid, key `Active` | approval created, leaf consumed |
| classical half by another signer | revert `InvalidEcdsaSignature` |
| post-quantum half over a different digest | revert `InvalidXmssSignature` |
| post-quantum half at an already consumed leaf | revert `LeafAlreadyUsed` |
| `xmssLeafIndex` ≠ the leaf in the signature | revert `LeafIndexDoesNotMatchSignature` |
| `quantumKeyId` not the account's `Active` key | revert `WrongQuantumKey` |
| window shorter than `MIN_WINDOW`, or already expired | revert `InvalidWindow` |
| the same `nonce` reused for one account | revert `ApprovalExists` |
| `TRANSFER` request with non-zero `target`/`value`/`dataHash` | revert `NonZeroClassFields` |
| `ADMIN` request with `validFrom` earlier than `now + ADMIN_TIMELOCK` | revert `AdminTimelockNotRespected` |
| `ADMIN` request whose `target` is neither the account nor the enforcement contract | revert `InvalidAdminTarget` |
| execution matching a Tier-1 pin | approval consumed, marked used |
| execution matching a Tier-2 commitment, FIFO order | oldest consumable approval consumed |
| execution with no matching approval | revert with the string of `[PA-31]` |
| second execution of the same transaction | revert (approval already used) |
| execution while the approval's key is `Rotated` | succeeds (`[PA-34]`) |
| execution while the approval's key is `Revoked` | revert |
| execution before `validFrom` or after `validTo` | revert |
| ERC-20 `transfer` execution carrying non-zero native value | revert (`[PA-07]`) |
| Tier-2 queue full of expired entries, new creation | succeeds after pruning (`[PA-27]`) |
| a not-yet-valid entry at the queue head, a live entry behind it | the live entry is consumed, the scheduled one remains (`[PA-28]`) |
| pin replacement while the pinned approval is live | revert `TxHashAlreadyPinned` |
| pin replacement after the pinned approval expired | succeeds (`[PA-23]`) |
| single owner revoking a `TRANSFER` approval | succeeds |
| single owner revoking an `ADMIN` approval | revert `NotAuthorized` (`[PA-37]`) |
| administrator revoking an approval created under their key | succeeds |
| revoking a used approval | revert `NotRevocable` |
| executed transaction that reverts after a consumed approval | approval stays used (`[PA-29]`) |

## Reference Implementation

`PreApprovalEngine` and the `FermionGuard` Safe transaction guard implement this ERC together:
the engine holds creation, indexing, revocation and the two-tier consumption; the guard is the
enforcement hook of §10 for Safe v1.3.0, v1.4.1 and v1.5.0 accounts, implementing both
`ITransactionGuard` and `IModuleGuard` at one address. Creation verifies both halves over one
`hashTypedDataV4` digest, the classical half first:

```solidity
bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
    PRE_APPROVAL_TYPEHASH, a.safe, uint8(a.class_), a.token, a.recipient, a.amount,
    a.target, a.value, a.dataHash, a.validFrom, a.validTo, a.nonce,
    a.quantumKeyId, a.xmssLeafIndex, a.policyHash, a.txHash
)));
if (!k.quantumAdmin.isValidSignatureNow(digest, ecdsaSignature)) revert InvalidEcdsaSignature();

uint32 leafInSig = _verifyAndConsumeXmss(a.quantumKeyId, digest, xmssSignature);
if (leafInSig != a.xmssLeafIndex) revert LeafIndexDoesNotMatchSignature(a.xmssLeafIndex, leafInSig);

a.signatureHash = keccak256(xmssSignature); // hash only — bytes are never persisted
```

Consumption is Tier 1 then Tier 2, with dead-entry pruning on both creation and consumption,
and the string revert of `[PA-31]` when nothing matches.

## Security Considerations

**The hook is the whole security boundary.** A pre-approval scheme protects an account only if
every path by which value can leave passes through the hook. The paths that do not, and must be
closed (§10), are: an installed fallback handler answering ERC-1271 signature checks off-chain
(Permit, Permit2 and order protocols then move tokens with no transaction at all); modules
executing on account versions that do not consult a module guard; `delegatecall` to arbitrary
code; token allowances granted before enrollment or through `approve`/`increaseAllowance`/
`permit`; and gas-refund parameters that pay an attacker-chosen receiver in an
attacker-chosen token. A deployment that leaves any of these open has a second factor in name
only.

**Approval granularity is a risk decision.** A `TRANSFER` approval for (token, recipient,
amount) is matched by *any* transaction with those fields, once. That is what makes recurring
payments usable and also what a careless integration gets wrong: an approval for a large amount
sitting in a queue is a bearer instrument for exactly one transfer of that amount to that
recipient. Deployments SHOULD prefer Tier-1 pins when the transaction is already known, and
SHOULD keep windows short (`[PA-19]` is a floor, not a recommendation).

**Windows and validator skew.** `block.timestamp` is manipulable within seconds; `MIN_WINDOW`
exists so that no implementation depends on finer resolution. A window is not a rate limit: two
approvals with overlapping windows can both be consumed.

**Revocation is a race, not a guarantee.** Revoking a pre-approval is a transaction, and it can
lose to the execution it was meant to stop. The `ADMIN_TIMELOCK` is the only mechanism here
that *guarantees* a reaction window, and only for `ADMIN` actions. Deployments SHOULD monitor
`PreApprovalCreated` and `AdminPreApprovalCreated` events and alert immediately, and SHOULD
treat the pause/freeze facilities of §10 as the primary response.

**A consumed leaf is spent even on failure.** `[PA-29]` is deliberate — it is what makes leaf
accounting sound — but it means a transaction that fails for an unrelated reason (slippage, a
token's own revert) costs a one-time signature. Clients SHOULD simulate before consuming, and
key heights SHOULD be chosen with a margin for failed executions.

**The administrator is a single point of compromise for *creating* approvals, not for
executing them.** An attacker who holds both the device and the administrator's classical key
can create approvals, but the account's own owner threshold is still required to execute a
transaction. The corresponding rule in the other direction is the reason for `[PA-02]`: an
implementation that let a pre-approval stand in for owner authorisation would have turned two
factors into one.

**Class confusion.** If an enforcement hook classifies a transaction differently from the way
the signer's client did, an approval for a benign-looking object can be consumed by a different
action. Implementations MUST derive the class from the executing transaction alone, deterministically
(`[PA-05]`), MUST refuse administrative selectors inside batches (`[PA-09]`), and SHOULD have a
test for each dispatch branch — including the boundary cases: empty calldata, calldata shorter
than four bytes, a self-call, a call to the enforcement contract, and a batch whose legs target
the account.

**Queue griefing.** `[PA-26]`–`[PA-28]` together are what stop an adversary from making
consumption expensive or a commitment unusable. Note that only the administrator's key can
create approvals, so queue griefing presupposes a compromised or careless administrator; the
bound matters anyway, because consumption runs inside someone else's transaction.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
