# Fermion Wallet

**Status: specification for v2. Not implemented yet, not deployed, and unaudited.** Nothing in this
document, in the verifier library it calls or in the key factory it relies on has had an external
audit. This document is normative for the Fermion Wallet contract; every normative sentence carries
an `[FW-###]` tag, defined once in the [requirement index](#requirement-index).

Fermion Wallet is a post-quantum cold vault. It is one small contract per holder that receives anything
and sends only what one hybrid signature — ECDSA and ML-DSA over the same digest — authorizes. Its
sibling product, [Fermion Guard](./fermion-guard.md), protects an existing Safe instead.

| | Fermion Wallet | Fermion Guard |
|---|---|---|
| What it protects | its own balance | an existing Safe |
| Authorization | one hybrid signature | Safe owners **and** one hybrid approval |
| Governance | none | the Safe's owners |
| Recovery if the key is lost | **none** | owners remove the Guard after 14 days |
| Outbound calls | ETH, ERC-20, ERC-721, ERC-1155 transfers only | any Safe transaction |

## Contents

- [What it does](#what-it-does)
- [Non-goals](#non-goals)
- [Keys](#keys)
- [Interface](#interface)
- [Hybrid signature](#hybrid-signature)
- [Signed messages](#signed-messages)
- [Replay and validity window](#replay-and-validity-window)
- [Transfers](#transfers)
- [Receiving](#receiving)
- [Safe owner (ERC-1271)](#safe-owner-erc-1271)
- [Deployment](#deployment)
- [Gas](#gas)
- [What can go wrong](#what-can-go-wrong)
- [Residual risks](#residual-risks)
- [Requirement index](#requirement-index)

## What it does

1. The holder's signer derives one key pair for this wallet: an ECDSA (secp256k1) key whose address is the
   wallet's **admin**, and an ML-DSA key of the chosen parameter set. [FW-001]
2. One transaction creates the wallet through the wallet factory: it registers the key's precomputation,
   stores the public key as contract code, and deploys a clone at an address fixed by the key. [FW-002]
3. Anybody sends ETH, ERC-20 tokens, ERC-721 and ERC-1155 tokens to that address. Receiving needs no
   signature and no gas from the holder. [FW-003]
4. To move assets out, the signer produces one hybrid signature over an EIP-712 `Transfer` of up to 8
   legs. Anybody may relay it. The wallet checks the window, the nonce and both signature halves, then
   executes every leg or none. [FW-004]
5. The wallet can also act as an owner of a Safe, and can prove control of its address to a dApp, through
   ERC-1271. Both are views: they move nothing by themselves. [FW-005]

There is no other way for assets to leave. [FW-006]

## Non-goals

Each of these is what keeps the contract small:

- **No owner, admin role, pause or upgrade.** "Admin" names the ECDSA half of the key, not a privileged
  caller. The implementation is not upgradeable and a clone cannot be re-pointed. [FW-007]
- **No recovery.** Lose the recovery phrase and the balance is unreachable forever. A holder who needs
  recovery should use [Fermion Guard](./fermion-guard.md) on a Safe. [FW-008]
- **No `approve`, no arbitrary call, no delegatecall, no modules, no ERC-4337.** The only outbound calls are
  the four transfer kinds in [Transfers](#transfers). An allowance would let a spender move assets with no
  post-quantum signature at all. [FW-009]
- **No arbitrary EIP-712 signing, no permits.** Through ERC-1271 the wallet vouches only for a Safe
  transaction hash or a plain-text message, as set out in [Safe owner (ERC-1271)](#safe-owner-erc-1271). [FW-010]
- **No gas reimbursement.** The holder's own EOA or any relayer pays gas; the wallet never pays anyone
  from its balance. [FW-011]
- **No key rotation.** To change keys, transfer the balance to a new wallet, which only the current key
  can authorize. [FW-012]
- **No verifier switching.** The verifier address is fixed when the implementation is deployed. A new
  verifier means a new implementation and new wallets. [FW-013]

## Keys

- **One key per contract.** Each wallet has its own derivation slot; a key used by one wallet is never
  used by another wallet or by a Safe. The derivation path, the split into an ECDSA child and an ML-DSA
  seed child, and the passphrase advice are specified in [the Ledger app](./ledger-app.md#key-derivation)
  and [the signer requirements](./signer-requirements.md#key-generation-and-backup). [FW-014]
- **Parameter set.** ML-DSA-44 is the default; ML-DSA-65 is chosen at creation; ML-DSA-87 is accepted by
  the contract but no v2 signer produces it (see [Residual risks](#residual-risks)). The set is fixed for
  the life of the wallet. [FW-015]
- **Algorithm ids.** The wallet stores the set as an `IPQVerifier` algorithm id from
  [pq-verifier-interface](https://github.com/skalenetwork/pq-verifier-interface) (pinned 6efa8e3) and
  accepts exactly these three: [FW-016]

| Set | Algorithm id | Public key | Signature |
|---|---|---|---|
| ML-DSA-44 | `0x0101` | 1312 bytes | 2420 bytes |
| ML-DSA-65 | `0x0102` | 1952 bytes | 3309 bytes |
| ML-DSA-87 | `0x0103` | 2592 bytes | 4627 bytes |

- **The admin is an EOA.** The factory refuses an admin address that has code at creation, and the
  wallet checks the ECDSA half only by recovery, never through ERC-1271. Code that later appears at
  the admin address (an EIP-7702 delegation, say) changes nothing, because recovery never consults
  it. [FW-017]
- **One secret.** Both halves come from the same recovery phrase. Whoever holds the phrase holds the
  wallet; whoever loses it loses the wallet. The phrase is the key control; see
  [security](./security.md). [FW-018]

## Interface

The wallet is a clone of one implementation contract. Per-wallet values are clone immutable arguments;
the verifier and key factory are immutables of the implementation, shared by every clone. The whole
external interface is: [FW-019]

```solidity
interface IFermionWallet is IERC1271, IERC721Receiver, IERC1155Receiver /* IERC165 */ {
    // One leg of a transfer batch. `kind`: 0 = ETH, 1 = ERC-20, 2 = ERC-721, 3 = ERC-1155.
    struct Leg {
        uint8 kind;
        address token;   // address(0) for ETH
        address to;
        uint256 id;      // token id for ERC-721 / ERC-1155; 0 otherwise
        uint256 amount;  // wei, token units, 1 for ERC-721, units for ERC-1155
    }

    // Implementation immutables (shared by all clones)
    function VERIFIER() external view returns (address);     // IPQVerifier
    function KEY_FACTORY() external view returns (address);  // MLDSAKeyFactory
    function MAX_LEGS() external pure returns (uint256);     // 8
    function MAX_WINDOW() external pure returns (uint64);    // 24 hours

    // Per-wallet values (clone immutable arguments)
    function admin() external view returns (address);              // ECDSA half: an EOA
    function algorithm() external view returns (uint256);          // 0x0101 | 0x0102 | 0x0103
    function publicKeyHash() external view returns (bytes32);      // keccak256(ML-DSA public key)
    function publicKeyPointer() external view returns (address);   // the public key, stored as code
    function publicKey() external view returns (bytes memory);     // read from publicKeyPointer

    // The only mutable state
    function nonce() external view returns (uint256);

    // ERC-5267
    function eip712Domain() external view returns (
        bytes1 fields, string memory name, string memory version, uint256 chainId,
        address verifyingContract, bytes32 salt, uint256[] memory extensions);

    // The only state-changing function
    function transfer(
        Leg[] calldata legs,
        uint256 nonce,
        uint64 validFrom,
        uint64 validUntil,
        bytes calldata ecdsaSignature,  // 65 bytes: r ‖ s ‖ v
        bytes calldata pqSignature,     // ML-DSA signature, length fixed by algorithm()
        bytes calldata aHat             // empty, or the key's precomputed A (first transfer, 44/65 only)
    ) external;

    // ERC-1271, inbound only (see "Safe owner (ERC-1271)")
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4); // 0x1626ba7e
    function isValidSignature(bytes calldata data, bytes calldata signature) external view returns (bytes4); // 0x20c13b0b

    // Receiving
    receive() external payable;
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4);
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external returns (bytes4);
    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    event Transferred(uint256 indexed nonce, bytes32 indexed digest, uint256 legCount);

    error NotAClone();
    error InvalidLegs();
    error OutsideWindow();
    error WindowTooLong();
    error WrongNonce(uint256 expected);
    error InvalidEcdsaSignature();
    error InvalidPqSignature();
    error UnexpectedAHat();
    error EthTransferFailed(uint256 leg);
}
```

The `nonce` argument repeats a value that is also in the signed struct; it lets a stale signature fail
before any verification. The wallet rebuilds the digest from its own stored nonce after checking that the
two agree. [FW-020]

Calls that reach the implementation contract directly, rather than through a clone, revert with
`NotAClone` (the implementation records its own address at construction and compares). The implementation
therefore never holds or moves anything. [FW-021]

`supportsInterface` returns true for exactly ERC-165, ERC-1271 (`0x1626ba7e`), `IERC721Receiver` and
`IERC1155Receiver`. [FW-022]

## Hybrid signature

Every authorization the wallet accepts is a **hybrid signature**: an ECDSA signature and an ML-DSA
signature over the same 32-byte EIP-712 digest. Both halves are always required. A quantum adversary who
breaks ECDSA still faces ML-DSA; a flaw in the young ML-DSA verifier still leaves ECDSA. [FW-023]

- **ECDSA half:** 65 bytes `r ‖ s ‖ v` over the digest, checked with OpenZeppelin `ECDSA.tryRecover`
  (which rejects a high `s` and a `v` other than 27 or 28). The recovered address must equal `admin()`.
  [FW-024]
- **ML-DSA half:** FIPS 204 pure ML-DSA (not HashML-DSA) with an empty context string, over the message
  `M` = the 32 digest bytes. The wallet calls
  `IPQVerifier(VERIFIER).verify(algorithm(), publicKey(), abi.encodePacked(digest), pqSignature)` and
  requires `true`. The interface itself is specified by pq-verifier-interface, not here. [FW-025]
- **The verifier decides the path, not the wallet.** If the key's precomputation is registered in the
  key factory, the verifier takes the fast path; otherwise it runs full verification. Both compute the
  same function; registration changes only the gas. [FW-026]

### Check order

Every path that accepts a hybrid signature checks, in this order, and stops at the first failure: [FW-027]

1. **Shape.** Inputs that need no cryptography: for `transfer`, the legs (see [Transfers](#transfers)); for
   ERC-1271, the signature length.
2. **Validity window.** `validFrom <= block.timestamp <= validUntil` and `validUntil - validFrom <= 24 hours`.
3. **Nonce** (transfers only). The argument equals `nonce()`.
4. **ECDSA recovery** against `admin()` over the digest rebuilt on-chain from the arguments.
5. **ML-DSA** through `IPQVerifier` with the stored algorithm id and public key.

Cheap checks come first, so a stale, expired or wrong-key signature is refused without the multi-million
gas ML-DSA verification. `msg.sender` is never consulted; any address may relay a valid signature, and no
address can do anything without one. [FW-028]

## Signed messages

All digests use one EIP-712 domain: [FW-029]

```
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
name              = "FermionWallet"
version           = "2"
chainId           = block.chainid
verifyingContract = the wallet (the clone's address, never the implementation's)
```

The domain binds the chain and the wallet. A signature for one wallet never verifies on another wallet,
and a signature for one chain never verifies on another chain, even though the wallet has the same address
on every chain. [FW-030]

The digest is `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct(message))`, exactly as EIP-712
defines it. The signer computes it from the fields it displays and never signs a digest handed to it by a
host. [FW-031]

The wallet defines exactly two signed types. [FW-032]

### Transfer

```
Leg(uint8 kind,address token,address to,uint256 id,uint256 amount)
Transfer(Leg[] legs,uint256 nonce,uint64 validFrom,uint64 validUntil)Leg(uint8 kind,address token,address to,uint256 id,uint256 amount)
```

```
LEG_TYPEHASH      = keccak256("Leg(uint8 kind,address token,address to,uint256 id,uint256 amount)")
TRANSFER_TYPEHASH = keccak256("Transfer(Leg[] legs,uint256 nonce,uint64 validFrom,uint64 validUntil)Leg(uint8 kind,address token,address to,uint256 id,uint256 amount)")

hashStruct(leg)      = keccak256(abi.encode(LEG_TYPEHASH, leg.kind, leg.token, leg.to, leg.id, leg.amount))
hashStruct(transfer) = keccak256(abi.encode(
                           TRANSFER_TYPEHASH,
                           keccak256(abi.encodePacked(hashStruct(legs[0]), ..., hashStruct(legs[n-1]))),
                           nonce, validFrom, validUntil))
```

The array is encoded as EIP-712 requires for an array of structs: the keccak256 of the concatenated
struct hashes, in order. Leg order is signed; reordering the legs changes the digest. [FW-033]

### SignedHash

```
SignedHash(bytes32 hash,uint64 validFrom,uint64 validUntil)

SIGNED_HASH_TYPEHASH = keccak256("SignedHash(bytes32 hash,uint64 validFrom,uint64 validUntil)")
hashStruct(s)        = keccak256(abi.encode(SIGNED_HASH_TYPEHASH, s.hash, s.validFrom, s.validUntil))
```

`SignedHash` is the wrapper for everything the wallet vouches for through ERC-1271. The wallet sees only
the 32-byte `hash`; what it stands for is fixed by how the signer computed it from what it displayed: [FW-034]

| Content the signer shows | `hash` the signer wraps |
|---|---|
| A Safe transaction: the Safe address, the chain, the Safe nonce and every SafeTx field | the Safe's own `safeTxHash` (the Safe's EIP-712 digest of the SafeTx struct) |
| A plain-text message (SIWE, an ownership proof), shown in full | the EIP-191 hash `keccak256("\x19Ethereum Signed Message:\n" ‖ decimal byte length ‖ text)` |

The two content kinds cannot collide: a `safeTxHash` is the keccak256 of a `0x1901`-prefixed preimage and
an EIP-191 hash the keccak256 of a `0x19 0x45`-prefixed one. One wrapper type suffices because the contract
could not tell the two apart anyway — it never sees anything but the hash. Which screens a signer must show
for each, and what it must refuse, is in [the signer requirements](./signer-requirements.md#display-and-refusal-rules).
[FW-035]

## Replay and validity window

- **Sequential nonce.** `nonce()` starts at 0. A `Transfer` is valid only for the current nonce, and a
  successful transfer increments it by one. One nonce covers a whole batch. [FW-036]
- **Increment before calls.** The nonce is incremented after all checks and before the first outbound
  call, so a recipient that re-enters `transfer` faces the next nonce and needs another valid
  signature. [FW-037]
- **Validity window.** Every signed struct carries `validFrom` and `validUntil` (Unix seconds). The wallet
  requires `validFrom <= block.timestamp <= validUntil` and `validUntil - validFrom <= 24 hours`, on every
  path, transfers and ERC-1271 alike. A signer has no trusted clock, so the 24-hour cap is enforced
  on-chain; the signer only refuses to sign a window longer than 24 hours and shows both times in UTC.
  [FW-038]
- **No cancel function.** A signed transfer stays relayable by anyone until `validUntil`. To kill one
  early, sign and relay any other transfer at the same nonce; the cheapest is a single ETH leg of amount 0
  to the admin address. [FW-039]
- **A reverted transfer consumes nothing.** If any leg fails, the whole transaction reverts, the nonce is
  not incremented, and the same signature stays valid until `validUntil`. [FW-040]
- **ERC-1271 has no nonce.** `isValidSignature` is a view and records nothing. Replay protection is the
  consumer's: a Safe transaction hash contains the Safe's nonce, and a SIWE message carries its own nonce
  and expiry. The window still bounds every ERC-1271 signature to at most 24 hours. [FW-041]
- **Timestamps are coarse.** Validators can skew `block.timestamp` by seconds; windows are never a
  sub-minute security boundary. [FW-042]

## Transfers

`transfer` executes a batch of 1 to 8 legs, atomically: every leg succeeds or the whole transaction
reverts. [FW-043]

Leg shape, checked before any signature (`InvalidLegs` otherwise): [FW-044]

| `kind` | Asset | `token` | `id` | `amount` | Call made by the wallet |
|---|---|---|---|---|---|
| 0 | ETH | `address(0)` | 0 | any, 0 allowed | `to.call{value: amount}("")`, all remaining gas forwarded; failure reverts with `EthTransferFailed` |
| 1 | ERC-20 | the token, non-zero | 0 | any | `SafeERC20.safeTransfer(token, to, amount)` |
| 2 | ERC-721 | the collection, non-zero | token id | exactly 1 | `IERC721(token).safeTransferFrom(wallet, to, id)` |
| 3 | ERC-1155 | the collection, non-zero | token id | any | `IERC1155(token).safeTransferFrom(wallet, to, id, amount, "")` |

For every leg, `to` is neither `address(0)` nor the wallet itself; any other `kind` is refused. [FW-045]

`transfer` runs the [check order](#check-order), then: [FW-046]

1. if `aHat` is non-empty, calls the key factory's `storeA(set, publicKeyHash(), aHat)` (permissionless and
   idempotent; it accepts only bytes that hash to the commitment recorded at creation). For ML-DSA-87
   `aHat` must be empty (`UnexpectedAHat`): its A is stored ahead, in two parts, directly through the
   factory. This step sits between the ECDSA check and the ML-DSA check, so the verification that follows
   takes the fast path;
2. verifies the ML-DSA half;
3. increments the nonce;
4. executes the legs in signed order;
5. emits `Transferred(nonce, digest, legs.length)` with the nonce that was consumed.

ERC-721 and ERC-1155 legs use the `safe` transfer functions, so a recipient contract that cannot handle
the token makes the batch revert instead of locking the token. [FW-047]

A token with transfer fees, rebasing or blocklists behaves as its own `transfer` does: the signed amount
is what is sent, not necessarily what is received, and a token call that reverts reverts the batch.
[FW-048]

## Receiving

- `receive()` accepts ETH from anyone, with no event and no logic. ETH also arrives without a call (a
  self-destructing contract, a block reward); the wallet can send it all. [FW-049]
- ERC-20 tokens arrive as an ordinary transfer to an address; the wallet does nothing. [FW-050]
- `onERC721Received`, `onERC1155Received` and `onERC1155BatchReceived` accept unconditionally and return
  their selectors. Unwanted tokens are harmless: they sit in the wallet until the holder chooses to send
  them. [FW-051]
- The wallet has no `fallback` function; any call with an unknown selector reverts. [FW-052]

## Safe owner (ERC-1271)

The wallet can be an owner of a Safe, and can sign a plain-text message for a dApp, by answering ERC-1271.
This is **inbound** ERC-1271 only: the wallet answers it; it never asks a contract whether a signature is
valid. [FW-053]

Both forms are implemented, because Safe versions differ: [FW-054]

| Form | Magic value | Caller | `hash` used |
|---|---|---|---|
| `isValidSignature(bytes32 hash, bytes signature)` | `0x1626ba7e` | Safe 1.5.0; any ERC-1271 consumer (SIWE) | `hash` as given |
| `isValidSignature(bytes data, bytes signature)` | `0x20c13b0b` | Safe 1.3.0 and 1.4.1 (legacy `ISignatureValidator`) | `keccak256(data)` |

Safe 1.3.0 and 1.4.1 pass the SafeTx preimage (`0x19 0x01 ‖ domainSeparator ‖ safeTxStructHash`) as
`data`, and `keccak256(data)` is exactly the `safeTxHash` that Safe 1.5.0 passes as `hash`. Both forms
therefore reach the same `SignedHash` digest, and one device signature serves all three Safe versions.
[FW-055]

The `signature` argument is, byte for byte: [FW-056]

```
validFrom (uint64, 8 bytes big-endian) ‖ validUntil (uint64, 8 bytes big-endian) ‖ ecdsa (65: r ‖ s ‖ v) ‖ mldsa (signature bytes of algorithm())
```

Its length is exactly 81 + the ML-DSA signature size: 2501 bytes for ML-DSA-44, 3390 for ML-DSA-65 and
4708 for ML-DSA-87. Fermion Guard's inline approval uses the same layout
([inline and stored approvals](./fermion-guard.md#inline-and-stored-approvals)).

`isValidSignature` builds `SignedHash(hash, validFrom, validUntil)`, runs the [check order](#check-order)
(length, window, ECDSA, ML-DSA), and returns the magic value of the form called if everything passes. On
any failure, including a malformed signature, it returns `0xffffffff` and does not revert. [FW-057]

`isValidSignature` is a view. It needs no nonce because ML-DSA is stateless: answering the same question
twice spends nothing. [FW-058]

**What the contract cannot check.** The wallet sees a hash, not a transaction. Whether that hash stands for
a delegatecall, a gas-refund drain or an unlimited approval is invisible to it. On a Safe **without** Fermion
Guard the signer is therefore the only gate. The signer must refuse, before any screen, a SafeTx that is a
`DelegateCall` to anything but the canonical `MultiSendCallOnly` deployment of the Safe's version (a batch,
whose legs must each be a `Call` and are decoded, checked under the same rules as a single transaction and
shown one by one), whose `gasPrice`, `gasToken` or `refundReceiver` is non-zero, or which grants an
unlimited approval; must show named Safe admin functions on their own screen; and may allow a call it cannot
decode only after a strong warning showing target, selector, value and the full calldata. Those rules are
specified in [the signer requirements](./signer-requirements.md#display-and-refusal-rules). [FW-059]

A plain-text message is signed only through the `bytes32` form with its EIP-191 hash. A legacy caller that
passes the raw text as `data` gets `keccak256(text)`, which no conforming signer wraps, so it gets
`0xffffffff`. [FW-060]

## Deployment

### Shared contracts

These are deployed through the Arachnid deterministic deployer
`0x4e59b44847b379578588920cA78FbF26c0B4956C` with fixed salts, so each has the same address on every chain
(Ethereum mainnet, Base, Arbitrum, Optimism). Each has no owner and no initialization; anyone may deploy
them on a new chain and gets the same addresses. [FW-061]

| Contract | Constructor arguments | Source |
|---|---|---|
| `MLDSAKeyFactory` | none | mldsa-solidity (v1.0.0 pending) |
| `MLDSAVerifier` (implements `IPQVerifier`) | the key factory | mldsa-solidity (v1.0.0 pending) |
| `FermionWallet` (the implementation) | the verifier, the key factory | this repository |
| `FermionWalletFactory` | the implementation, the key factory | this repository |

### The wallet factory

```solidity
interface IFermionWalletFactory {
    function IMPLEMENTATION() external view returns (address);
    function KEY_FACTORY() external view returns (address);

    // One transaction: key registration + public key as code + clone. Idempotent:
    // returns the existing wallet if it is already deployed.
    function createWallet(uint256 algorithm, address admin, bytes calldata publicKey)
        external returns (address wallet);

    // The address createWallet deploys to, on any chain, before or after deployment.
    function walletAddress(uint256 algorithm, address admin, bytes calldata publicKey)
        external view returns (address wallet);

    event WalletCreated(address indexed wallet, address indexed admin, uint256 algorithm, bytes32 publicKeyHash);
}
```

`createWallet` is permissionless and does, in one transaction: [FW-062]

1. Checks that `algorithm` is one of `0x0101`, `0x0102`, `0x0103`, that `publicKey` has that set's length,
   and that `admin` is non-zero and has no code. [FW-063]
2. Calls the key factory's `commitA` (computes A on-chain from the public key and records its keccak256;
   for ML-DSA-87 the commitment covers both A parts) and `registerT` (computes and stores `tr ‖ NTT(t1·2^d)`
   as code). Both skip work already done. [FW-064]
3. Stores the public key as contract code, with CREATE2 from the wallet factory and salt `publicKeyHash`,
   so the pointer's address is a function of the factory and the key only. The wallet reads it with
   `EXTCODECOPY`. [FW-065]
4. Deploys the wallet as a clone of the implementation with immutable arguments (OpenZeppelin
   `Clones.cloneDeterministicWithImmutableArgs`), arguments
   `abi.encodePacked(admin, publicKeyPointer, publicKeyHash, algorithm)` and salt
   `keccak256(abi.encode(algorithm, admin, publicKeyHash))`. [FW-066]

**The address pins the key.** CREATE2 hashes the clone's init code, which contains the immutable
arguments, so one address can only ever hold the wallet built for exactly that `(algorithm, admin,
public key)`. Nobody, the holder included, can deploy a different wallet there. [FW-067]

**Same address on every chain.** Because the factory has the same address everywhere and the address
depends only on the key, a wallet's address is known before it exists on any chain. Assets sent to it on a
chain where it has not been created yet are not lost: running `createWallet` there, which anyone may do,
deploys the same wallet. Setup is paid once per chain. [FW-068]

**Created up front.** The client runs `createWallet` when the wallet is made, before any asset arrives, so
ERC-1271 and the NFT receiver hooks work from the first block. [FW-069]

### The first transfer stores A

`commitA` records only the hash of A, because computing and storing A in the same transaction does not fit
the per-transaction gas cap for every set. The first transfer supplies A (computed off-chain from the public
key) in `aHat`; the factory's `storeA` checks it against the commitment and stores it as code. Every later
transfer takes the fast path. Until A is stored, verification falls back to the full path and still gives
the same answer. [FW-070]

For ML-DSA-87, a first transfer that also stores A measures 16.30M gas against the 16,777,216 cap
(EIP-7825), which leaves too little headroom. The client stores the two A parts ahead, in separate
transactions straight to the key factory (`storeAPart`), and the wallet refuses a non-empty `aHat` for
ML-DSA-87. [FW-071]

## Gas

From the measured table in the decision record. These are whole-transaction figures on a local chain, before
the Glamsterdam repricing; re-measure after it. [FW-072]

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| One-transaction wallet setup | 5.55M | 9.53M | 14.99M |
| First transfer (stores A) | 5.90M | 9.56M | 16.30M — store the A parts ahead instead |
| Later transfer | 2.82M | 3.83M | 5.60M |
| ML-DSA verify, key registered (through `IPQVerifier`) | 2.68M | 3.66M | 5.53M |
| ML-DSA verify, from scratch | 5.75M | 9.13M | 14.23M |
| ERC-1271 `signature` length | 2501 B | 3390 B | 4708 B |

Not measured: a batch of more than one leg, ERC-721 and ERC-1155 legs, `isValidSignature` end to end, and a
Safe execution with a Fermion Wallet owner. Each ERC-1271 answer costs at least the registered-key verify
above, inside the Safe transaction that asks. A Safe transaction with one Fermion Wallet owner and a Fermion
Guard inline approval runs two verifications; both must fit the 16,777,216 per-transaction cap together.
[FW-073]

ML-DSA verification is expensive on Ethereum mainnet and comfortable on L2s. That stays true until an
ML-DSA precompile ships. [FW-074]

## What can go wrong

| Situation | Outcome |
|---|---|
| Quantum adversary breaks ECDSA | Still needs the ML-DSA half; assets safe |
| Flaw in the ML-DSA verifier | Still needs the ECDSA half; assets safe |
| Compromised host or phishing front end | The signer shows every leg and signs only what it shows ([FW-031]) |
| Relayer censors or front-runs | Anyone else can relay the same signature; it binds every field, so a front-runner can only submit what the holder authorized |
| Replayed transfer | The nonce has moved; refused before verification ([FW-027]) |
| Signature for another wallet or chain | Different domain; ECDSA recovers a different address ([FW-030]) |
| Recovery phrase lost | **Assets unrecoverable.** The accepted cost of the design ([FW-008]) |
| Recovery phrase stolen | **Full compromise.** Both halves come from the phrase ([FW-018]) |
| The admin address later gets code (EIP-7702) | Nothing changes; recovery never consults it ([FW-017]) |
| A token call reverts (paused, blocklisted) | The batch reverts; the nonce does not move; the signature stays valid until `validUntil` ([FW-040]) |
| …and the token unpauses | The same signature is relayable by anyone until `validUntil`; sign a zero-value ETH leg at the same nonce to kill it ([FW-039]) |
| An ERC-721 or ERC-1155 recipient cannot receive | The batch reverts ([FW-047]) |
| Assets sent on a chain where the wallet does not exist yet | Anyone runs `createWallet` there; same address ([FW-068]) |
| The wallet signs a Safe transaction that is a delegatecall to anything but a `MultiSendCallOnly` batch | Possible only if the signer breaks its refusal rules; the contract cannot see it ([FW-059]) |
| A signed transfer sits unrelayed | It expires at `validUntil`, at most 24 hours after `validFrom` ([FW-038]) |

## Residual risks

Stated plainly; none of these has a contract-side fix in v2.

- **Unaudited.** The wallet, the factory, mldsa-solidity and the key factory have had no external audit.
  [FW-075]
- **One secret.** The recovery phrase is the single secret behind both halves. Phrase compromise is full
  compromise; phrase loss is total loss. [FW-076]
- **ML-DSA-87 has no v2 signer.** The contract accepts it, but the Ledger app ships ML-DSA-44 and ML-DSA-65
  only and the nShield signer is a design document. A wallet created with ML-DSA-87 needs a signer that does
  not ship with v2. [FW-077]
- **Signer side channels.** The Ledger SDK documents no side-channel hardening for ML-DSA; treat it as
  unhardened. See [security](./security.md). [FW-078]
- **The signer is the only gate for ERC-1271.** On a Safe without Fermion Guard, nothing on-chain stops a
  hash the signer should have refused ([FW-059]). [FW-079]
- **Gas headroom.** ML-DSA-87 sits close to the per-transaction cap; a repricing could push its operations
  over it. Behaviour of the cap on each L2 is not verified on live networks before release. [FW-080]
- **Fixed verifier.** A verifier bug cannot be patched in place; it needs a new implementation and a
  transfer to a new wallet, which the old wallet's ECDSA half still protects. [FW-081]

## Requirement index

| ID | Requirement |
|---|---|
| FW-001 | Each wallet has one ECDSA key, whose address is the admin, and one ML-DSA key of a chosen parameter set. |
| FW-002 | One factory transaction registers the key's precomputation, stores the public key as code and deploys the wallet at a key-determined address. |
| FW-003 | Receiving ETH, ERC-20, ERC-721 and ERC-1155 needs no signature and no gas from the holder. |
| FW-004 | Assets leave only through a hybrid-signed `Transfer` of up to 8 legs, relayable by anyone, executed all or nothing. |
| FW-005 | ERC-1271 answers are views and move nothing. |
| FW-006 | There is no other outbound path for assets. |
| FW-007 | No owner, admin role, pause or upgrade exists; the admin is the ECDSA half, not a privileged caller. |
| FW-008 | There is no recovery path; losing the phrase loses the balance. |
| FW-009 | No `approve`, arbitrary call, delegatecall, module or ERC-4337 path exists. |
| FW-010 | Through ERC-1271 the wallet vouches only for a Safe transaction hash or a plain-text message, never arbitrary EIP-712 or a permit. |
| FW-011 | The wallet never reimburses gas from its balance. |
| FW-012 | Rotation is a transfer to a new wallet, authorized by the current key. |
| FW-013 | The verifier address is fixed in the implementation; a new verifier means new wallets. |
| FW-014 | A key is used by exactly one contract. |
| FW-015 | ML-DSA-44 is the default, ML-DSA-65 is opt-in at creation, ML-DSA-87 is accepted; the set never changes for a wallet. |
| FW-016 | The wallet stores an `IPQVerifier` algorithm id and accepts only `0x0101`, `0x0102` and `0x0103`. |
| FW-017 | The admin must have no code at creation and is checked only by ECDSA recovery, never ERC-1271. |
| FW-018 | Both halves derive from one recovery phrase; the phrase is the key control. |
| FW-019 | The external interface is exactly the one listed, with `transfer` as the only state-changing function. |
| FW-020 | `transfer` takes the nonce as an argument, checks it equals the stored nonce, and rebuilds the digest from the stored value. |
| FW-021 | Calls to the implementation itself revert with `NotAClone`. |
| FW-022 | `supportsInterface` reports exactly ERC-165, ERC-1271, `IERC721Receiver` and `IERC1155Receiver`. |
| FW-023 | Every authorization needs both an ECDSA and an ML-DSA signature over the same digest. |
| FW-024 | The ECDSA half is 65 bytes, checked with `ECDSA.tryRecover`, and must recover to the admin. |
| FW-025 | The ML-DSA half is pure ML-DSA with empty context over the 32-byte digest, checked through `IPQVerifier.verify` with the stored algorithm id and key. |
| FW-026 | Whether the fast or full verification path runs depends only on key registration and never changes the answer. |
| FW-027 | Checks run in the order shape, window, nonce, ECDSA, ML-DSA, stopping at the first failure. |
| FW-028 | `msg.sender` carries no authority. |
| FW-029 | The EIP-712 domain is name "FermionWallet", version "2", the chain id and the wallet's address. |
| FW-030 | A signature never verifies on another wallet or another chain. |
| FW-031 | The signer computes the digest from displayed fields and never signs a host-supplied digest. |
| FW-032 | The wallet defines exactly two signed types, `Transfer` (with `Leg`) and `SignedHash`. |
| FW-033 | The `Transfer` type string, typehashes and leg-array encoding are exactly as specified; leg order is signed. |
| FW-034 | `SignedHash(bytes32 hash,uint64 validFrom,uint64 validUntil)` wraps every ERC-1271 answer. |
| FW-035 | The wrapped hash is a Safe `safeTxHash` or the EIP-191 hash of a fully displayed text. |
| FW-036 | The nonce starts at 0, is valid only at its current value, and increments by one per successful batch. |
| FW-037 | The nonce is incremented after all checks and before the first outbound call. |
| FW-038 | Every path enforces `validFrom <= block.timestamp <= validUntil` and a window of at most 24 hours. |
| FW-039 | There is no cancel function; a transfer at the same nonce (a zero-value ETH leg suffices) kills a pending signature. |
| FW-040 | A reverted transfer leaves the nonce unchanged and the signature valid until `validUntil`. |
| FW-041 | ERC-1271 records nothing; replay protection belongs to the consumer, bounded by the window. |
| FW-042 | Validity windows are never a sub-minute security boundary. |
| FW-043 | A batch has 1 to 8 legs and executes atomically. |
| FW-044 | Leg shapes are exactly the four kinds in the table and are checked before any signature. |
| FW-045 | No leg may send to `address(0)` or to the wallet itself; unknown kinds are refused. |
| FW-046 | `transfer` runs the check order, optionally stores A between the ECDSA and ML-DSA checks, then increments the nonce, executes the legs in order and emits `Transferred`. |
| FW-047 | NFT legs use the `safeTransferFrom` functions. |
| FW-048 | The signed amount is what is sent; a reverting token call reverts the batch. |
| FW-049 | `receive()` accepts ETH from anyone with no logic. |
| FW-050 | Receiving ERC-20 involves no wallet code. |
| FW-051 | The NFT receiver hooks accept unconditionally. |
| FW-052 | There is no `fallback` function. |
| FW-053 | ERC-1271 is inbound only: the wallet answers it and never calls it. |
| FW-054 | Both the `bytes32` form (`0x1626ba7e`) and the legacy `bytes` form (`0x20c13b0b`, hash = `keccak256(data)`) are implemented. |
| FW-055 | Both forms reach the same `SignedHash` digest for a Safe transaction on Safe 1.3.0, 1.4.1 and 1.5.0. |
| FW-056 | The ERC-1271 signature is `validFrom ‖ validUntil ‖ ecdsa ‖ mldsa`, of exact length 81 + the ML-DSA signature size. |
| FW-057 | `isValidSignature` returns the form's magic value only if every check passes, and `0xffffffff` on any failure without reverting. |
| FW-058 | `isValidSignature` is a view and records nothing. |
| FW-059 | The contract cannot see what a wrapped hash stands for; the signer's refusal rules are the only gate on a Safe without Fermion Guard. |
| FW-060 | Plain-text messages are answered only through the `bytes32` form with their EIP-191 hash. |
| FW-061 | Shared contracts are deployed through the Arachnid deterministic deployer with fixed salts, with no owner or initialization. |
| FW-062 | `createWallet` is permissionless, does all setup in one transaction and is idempotent. |
| FW-063 | `createWallet` checks the algorithm id, the public-key length and that the admin is non-zero with no code. |
| FW-064 | `createWallet` calls the key factory's `commitA` and `registerT`, skipping work already done. |
| FW-065 | The public key is stored as code at a CREATE2 address determined by the factory and the key. |
| FW-066 | The wallet is a clone with immutable arguments `(admin, publicKeyPointer, publicKeyHash, algorithm)` and salt `keccak256(abi.encode(algorithm, admin, publicKeyHash))`. |
| FW-067 | One address can only ever hold the wallet built for one `(algorithm, admin, public key)`. |
| FW-068 | A wallet has the same address on every chain and can be created on any chain by anyone. |
| FW-069 | The client creates the wallet before any asset arrives. |
| FW-070 | The first transfer may supply A, which the key factory stores only if it matches the commitment. |
| FW-071 | For ML-DSA-87 the A parts are stored ahead through the key factory and `transfer` refuses a non-empty `aHat`. |
| FW-072 | Gas figures are taken from the measured table and are re-measured after the Glamsterdam repricing. |
| FW-073 | Unmeasured costs are labelled as not measured; a Safe transaction's verifications must fit the per-transaction cap together. |
| FW-074 | ML-DSA verification stays expensive on mainnet until a precompile ships. |
| FW-075 | The wallet and everything it calls are unaudited, and the documentation says so. |
| FW-076 | Phrase compromise is full compromise and phrase loss is total loss. |
| FW-077 | ML-DSA-87 is accepted by the contract but has no v2 signer. |
| FW-078 | The Ledger's ML-DSA is treated as side-channel unhardened. |
| FW-079 | On a Safe without Fermion Guard, nothing on-chain stops a hash the signer should have refused. |
| FW-080 | ML-DSA-87 operations sit close to the per-transaction cap, and L2 cap behaviour is unverified on live networks. |
| FW-081 | A verifier bug requires a new implementation and a transfer to a new wallet. |
