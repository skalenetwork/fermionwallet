# FermionWallet — the smallest possible post-quantum ERC-20 wallet

**Status: implemented.** [`contracts/src/FermionWallet.sol`](./contracts/src/FermionWallet.sol)
and its test suite. Not audited, not deployed on any network, and the device support it needs
is only partly built — see [FWL-033](#requirements).

FermionWallet is a *second* product in this repository, separate from [FermionGuard](./fermionguard-module.md). Where FermionGuard adds a post-quantum second authorization to an existing Gnosis Safe — owners, threshold, policies, timelocks, recovery paths — FermionWallet throws all of that away and keeps one thing: **an address that holds ERC-20 tokens and releases them only against a signature from the Fermion Ledger app.**

It is deliberately the simplest contract that can be called a wallet: one immutable key, one operation, one piece of state.

| | FermionGuard | FermionWallet |
|---|---|---|
| What it protects | an existing Safe | its own balance |
| Authorization | Safe owners **and** the Ledger's hybrid approval | the Ledger's hybrid signature alone |
| Governance | owners, timelocks, pause, emergency removal | none |
| Recovery if the device is lost | owners remove the Guard after the emergency delay | **none — the funds are gone** |
| On-chain state | keys, approvals, queues, policy | one used-leaf bitmap |
| Ledger app | ships today | the four additions of [FWL-033](#requirements) are built |
| Who it is for | desks that already run a Safe | a single holder who wants quantum-safe storage and nothing else |

## What it does

1. You generate an XMSS key on the Fermion Ledger app (`GEN_XMSS_KEY`) and read out its public root, SEED, tree height and parameter set (`GET_XMSS_ROOT`), plus the device's ECDSA address (`GET_ADMIN_ADDRESS`). [FWL-001]
2. You deploy one `FermionWallet` contract with those values baked in as immutables. [FWL-002]
3. You send ERC-20 tokens to its address like any other address. Receiving needs no signature, no gas from you, and no cooperation from the wallet. [FWL-003]
4. To move tokens out, the device signs one EIP-712 `Transfer`. Anybody may relay the resulting transaction; the wallet verifies both signature halves, marks the one-time leaf as spent, and calls `transfer` on the token. [FWL-004]

There is no other way for tokens to leave. [FWL-005]

## Non-goals

Stated plainly, because each of these is what keeps the contract small:

- **No owners, admins, roles or upgrades.** The contract has no privileged caller and no upgrade path; the key is immutable from deployment. [FWL-006]
- **No recovery.** Lose the device (and its seed backup) and the balance is unreachable forever. Anyone who wants recovery should use FermionGuard with a Safe instead. This is the single biggest reason not to choose this product. [FWL-007]
- **No ETH.** The contract is not payable and has no `receive`; ETH sent by a self-destructing contract is simply stuck and ignored. A wallet that could receive ETH but not send it would be a trap. [FWL-008]
- **No `approve`, no arbitrary calls, no delegatecall, no batching.** `approve` would let an approved spender move tokens with no XMSS signature at all, which would void the entire point. [FWL-009]
- **No gas refunds to the relayer.** The wallet never pays anyone from its balance; a refund parameter is exactly how the Guard's escape hatch was once drainable. Relayers are paid out of band, or the holder relays their own transaction. [FWL-010]
- **No key rotation.** To change keys, transfer the balance to a new wallet — which only the current key can authorize. That is rotation, with no extra code. [FWL-011]

## The contract

```solidity
contract FermionWallet {
    bytes32 public immutable xmssRoot;
    bytes32 public immutable xmssSeed;
    uint256 public immutable treeHeight;   // 10, 16 or 20 (RFC 8391 parameter sets)
    address public immutable quantumAdmin; // the device's ECDSA address

    BitMaps.BitMap private _usedLeaves;    // the only mutable state
    function isLeafUsed(uint32 leafIndex) external view returns (bool);

    event Transferred(address indexed token, address indexed to, uint256 amount, uint32 leafIndex);

    function transfer(
        address token,
        address to,
        uint256 amount,
        uint64 validUntil,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature     // its embedded index is the leaf that is spent
    ) external;
}
```

That is the whole interface. [FWL-012] Note what is *absent*: there is no `leafIndex` argument. The
index that gets marked spent is the one inside the XMSS signature, never a number the caller supplies
alongside it — see below for why.

### The signed message

```
Transfer(address wallet,address token,address to,uint256 amount,uint32 leafIndex,uint64 validUntil)
```

under the EIP-712 domain `{ name: "FermionWallet", version: "1", chainId, verifyingContract: <the wallet> }`. The domain binds the chain and the wallet address, so a signature for one wallet can never be replayed on another wallet or another chain. [FWL-013] The device computes this digest itself from the fields it displays, exactly as it does for FermionGuard — it never signs a hash handed to it by the host. [FWL-014]

`leafIndex` appears in the signed struct but **not** in the calldata. The contract reads the index out
of the XMSS signature (`XMSS.Signature.leafIdx`) and uses that value both for the bitmap and when it
rebuilds the digest, so the two can never disagree: a signature whose struct field named a different
leaf than the one it actually used would simply fail the ECDSA check. This is the same discipline
`QuantumKeyRegistry` follows (`leafIndex = sig.leafIdx`), and it is not cosmetic — see
[One leaf, one digest](#one-leaf-one-digest). [FWL-034]

### What `transfer` checks, in order

1. `block.timestamp <= validUntil`, else revert. A signed transfer that was never relayed stops being valid. [FWL-015]
2. `leafIdx` is decoded from `xmssSignature` (the `leafIdx` field of `XMSS.Signature`, at a fixed offset once the signature is decoded — no cryptography involved) and `isLeafUsed(leafIdx)` must be false, else revert. This comes **before** the ~700k-gas verification, so a replay is refused for about 122k rather than 800k. It is not free, and saying so matters: nearly all of that 122k is what EIP-7623 charges for carrying a 2.4 KB signature in calldata at all, which no contract-side check can avoid. Checking early saves the verification, not the transaction. [FWL-016]
3. The ECDSA half recovers to `quantumAdmin` over the digest built with that `leafIdx` (via OpenZeppelin `SignatureChecker`, so an ERC-1271 signer also works). [FWL-017]
4. The XMSS half verifies against `(xmssRoot, xmssSeed)` at `treeHeight`, using [`xmss-solidity`](https://github.com/skalenetwork/xmss-solidity)'s four-argument `XMSS.verify`, the form that binds the tree height to the key. [FWL-018] No test can demonstrate this: swapping it for the three-argument form leaves the whole suite green, because the byte-length check does not bind the height — ABI decoding bounds offsets, not the decoded array's length, so a blob of exactly `2304 + 32·treeHeight` bytes can still decode to an authentication path of any length that fits, and only `verify`'s own comparison rejects it. It is enforced by a grep over `FermionWallet.sol` in `.github/workflows/contracts.yml`, exactly as [QKR-034a] is for the registry. [FWL-018a]
5. The leaf is marked spent **before** the token call. [FWL-019]
6. `SafeERC20.safeTransfer(token, to, amount)`. [FWL-020]

`msg.sender` is never consulted. Any address may relay a valid signature, and no address can do anything without one. [FWL-021]

**Both halves are required.** Breaking the wallet means forging ECDSA *and* XMSS over the same digest: a quantum adversary who breaks ECDSA still faces the hash-based half, and a flaw in our young XMSS code still leaves the battle-tested classical half. The device produces both in one confirmation (`SIGN_PREAPPROVAL`), so this costs the user nothing. [FWL-022]

## One leaf, one digest

Everything the XMSS half is worth rests on one rule: a WOTS+ one-time key signs **one** digest.
Sign two different digests with the same leaf and an attacker can combine the two chains into
signatures the holder never authorized. The bitmap is the on-chain backstop for that rule — the thing
that still holds when the device's own counter cannot be trusted.

A backstop that can be pointed at the wrong leaf is not a backstop. Had the index been a separate
calldata field, the holder's own device (compromised firmware, or a rollback) could sign leaf 5 twice
while labelling the two transfers leaf 0 and leaf 1: both would verify, both would execute, the bitmap
would record two untouched leaves, and the one condition the bitmap exists to prevent would have
happened with the chain's blessing. Taking the index from the signature closes that off structurally
rather than by adding a check that could be forgotten. [FWL-034]

## One key, one wallet

The bitmap lives in the wallet contract, so it can only see leaves spent by *that* wallet. If the same
XMSS key were bound to two FermionWallets — or to a FermionWallet **and** a Safe running FermionGuard —
each bitmap starts empty and, again, one leaf can be spent twice. This is the same mistake
[the key registry had](./quantum-key-registry.md) (QKR-009a), where it was fixable on-chain by keying the
bitmap on the root; here the contracts are separate and cannot see each other.

Therefore:

- **A key slot is used by exactly one contract.** The device records the verifying contract at first use for that slot and refuses to sign for any other — another wallet, or a Safe pre-approval. A key is either a FermionWallet key or a FermionGuard key, never both. [FWL-023]
- A holder who wants several wallets generates several keys — the app holds `MAX_KEYS = 4` (see [ledger-xmss-app.md](./ledger-xmss-app.md)). [FWL-024]

**Residual risk, stated plainly:** FWL-023 is enforced *only* on the device, and a device is exactly
what the backstop exists to distrust. A rolled-back or cloned device can bind one key to two contracts,
and no on-chain check in this design would catch it. So for the standalone wallet the "one leaf, once"
rule is device-enforced with no independent second opinion — weaker than FermionGuard, where the
registry keys leaf accounting by the root and holds across every Safe. Deployments that cannot accept
that should use the shared leaf registry below, or FermionGuard. [FWL-025]

### Optional: a shared leaf registry

A single immutable, permissionless `LeafRegistry` per chain, keyed by XMSS root, that every FermionWallet consults and marks. It restores the "one leaf, once, everywhere" invariant that the standalone design can only enforce on the device. It costs one external call and one cold `SSTORE` per transfer, and one more contract to deploy and trust. It is **not** part of the minimal product; a deployment chooses it at construction time by passing a registry address or the zero address. [FWL-026]

## Cost

| | Gas |
|---|---|
| **A transfer, whole transaction, h = 4** | **802k, measured** |
| **A transfer, whole transaction, h = 10** | **845k, measured** |
| A replay, refused before verification | 122k — almost all of it the calldata floor |
| of which XMSS verification, h = 10 (measured) | ~712k |
| of which XMSS verification, h = 16 (interpolated — no h = 16 vector or benchmark exists yet) | ~731k |
| of which XMSS verification, h = 20 (measured) | ~745k |
| of which ECDSA check, leaf bookkeeping, token transfer, base cost | ~90k |

Post-quantum verification on-chain is not cheap, and these are measured numbers rather than
a target: 802k and 845k come from the test suite, not from adding up the parts. The recommended tree heights are the RFC 8391 parameter sets 10, 16 and 20: h = 10 gives 1,024 transfers per key and is the sensible default for a personal wallet; h = 20 gives ~1.05M and costs ~33k more gas per transfer. The contract itself accepts any height from 1 to 20, exactly as `QuantumKeyRegistry` does, and deliberately does not whitelist the three standardized sets — the only Ledger build that exists uses h = 4, so a whitelist would satisfy this requirement by making the product unusable. Nothing about XMSS security distinguishes h = 4 from h = 10; what matters is that a leaf is used once, and that the height is bound to the key, which [FWL-018] requires. Choosing a height is a deployment decision, and choosing a small one costs you transfers, not safety. [FWL-027] Receiving tokens costs the sender nothing extra — it is an ordinary ERC-20 transfer to an address. [FWL-028]

When the leaves run out, the wallet still works for exactly as long as it takes to move the balance to a new wallet: the last leaf signs the last transfer. Plan the move before the counter reaches the end; the device shows leaves remaining (`GET_LEAF_INDEX`). [FWL-029]

## Deployment

The straightforward path is to deploy the contract, then send tokens to it. [FWL-030]

Optionally, a CREATE2 factory lets the address be computed before deployment, so tokens can be sent to it first and the contract deployed later, when a transfer is first needed. What pins the key to the address is that the constructor arguments are part of the init code, and CREATE2 hashes the init code: for a fixed factory, one address can only ever hold the wallet built with those exact `(xmssRoot, xmssSeed, treeHeight, quantumAdmin)` values. Nobody — including the holder — can deploy a *different* wallet there. The salt is then free; deriving it from the key as well is a convenience for rediscovering the address, not a security property. [FWL-031]

## What can go wrong

| Situation | Outcome |
|---|---|
| Quantum adversary forges ECDSA | Still needs the XMSS half; funds safe |
| Flaw in our XMSS verifier | Still needs the ECDSA half; funds safe |
| Compromised host, phishing frontend | The device shows token, recipient and amount and signs only what it displays |
| Relayer censors or front-runs | Anyone else can relay the same signature; the signature binds every field, so a front-runner can only submit the transfer the holder already authorized |
| Replayed transaction | The leaf is already spent on-chain; the transfer reverts before the expensive verification |
| Device lost or destroyed | **Funds are unrecoverable.** This is the accepted cost of the design (FWL-007) |
| Device rolled back or cloned | Leaf reuse becomes possible, and nothing on-chain stops it; see FWL-025 |
| Leaves exhausted | No further transfers; move the balance before that point (FWL-029) |
| Token with transfer fees or rebasing | Supported only as far as `safeTransfer` is: the signed `amount` is what is sent, not necessarily what is received |
| The token call reverts (paused, blocklisted, zero-value refused) | The whole transaction reverts, so the leaf is **not** marked spent on-chain — but the device already committed its counter before signing, so that leaf is gone from the device's side. Nothing is lost; the leaf is simply burned. [FWL-035] |
| …and then the token unpauses | The same signature is still valid and still relayable **by anyone** until `validUntil`, and there is no cancel path. The only control is signing short windows. [FWL-036] |

## Requirements

| ID | Requirement |
|---|---|
| FWL-001 | The key is generated on the Fermion Ledger app; only public values leave the device. |
| FWL-002 | Root, SEED, tree height and the device's ECDSA address are immutable constructor arguments. |
| FWL-003 | Receiving ERC-20 tokens requires no signature and no cooperation from the contract. |
| FWL-004 | Tokens leave only against an EIP-712 `Transfer` signed by the device, relayable by anyone. |
| FWL-005 | There is no other outbound path for tokens. |
| FWL-006 | No owner, admin, role, pause or upgrade mechanism exists. |
| FWL-007 | There is no recovery path; losing the device loses the balance. |
| FWL-008 | The contract is not payable and cannot send ETH. |
| FWL-009 | No `approve`, arbitrary call, delegatecall or batching. |
| FWL-010 | The contract never pays gas refunds from its balance. |
| FWL-011 | Rotation is a transfer to a new wallet, authorized by the current key. |
| FWL-012 | The external interface is exactly one state-changing function. |
| FWL-013 | The EIP-712 domain binds chain id and wallet address. |
| FWL-014 | The device derives the digest from displayed fields; it never signs a host-supplied hash. |
| FWL-015 | A transfer past `validUntil` reverts. |
| FWL-016 | The leaf-reuse check reads the index from the signature and precedes verification. |
| FWL-017 | The ECDSA half must recover to `quantumAdmin`. |
| FWL-018 | The XMSS half is verified with the height-bound `XMSS.verify`. |
| FWL-018a | That the four-argument form is the one called is not testable — the suite is green either way — and is enforced by a CI grep. |
| FWL-019 | The leaf is marked spent before the token call. |
| FWL-020 | Transfers use `SafeERC20.safeTransfer`. |
| FWL-021 | `msg.sender` carries no authority. |
| FWL-022 | Both signature halves are required over the same digest. |
| FWL-023 | A device key slot signs for exactly one verifying contract — one wallet, or Safes, never both. |
| FWL-024 | Multiple wallets require multiple keys. |
| FWL-025 | FWL-023 is device-enforced only; a rolled-back or cloned device defeats leaf accounting with no on-chain backstop. Documented residual risk. |
| FWL-026 | A shared leaf registry is an optional, non-default mitigation for FWL-025. |
| FWL-027 | The RFC 8391 sets 10, 16 and 20 are recommended; the contract accepts 1..20, as the registry does. |
| FWL-028 | Receiving costs the sender no more than an ordinary ERC-20 transfer. |
| FWL-029 | The device reports remaining leaves so the balance can be moved before exhaustion. |
| FWL-030 | Deployment binds the key at construction. |
| FWL-031 | An optional CREATE2 factory derives the address from the key, so the address pins the key. |
| FWL-032 | XMSS verification is the unmodified `xmss-solidity` library; the wallet adds no cryptography. |
| FWL-033 | The Ledger app needs four additions — `Transfer` type and `FermionWallet` domain, a wallet context screen, per-slot contract binding, and cross-product refusal — before any device can drive this product. No new APDU command is required. |
| FWL-034 | The spent leaf index is taken from the XMSS signature, never from a separate argument, and the digest is rebuilt with it. |
| FWL-035 | A reverting token call burns the leaf on the device while leaving it unspent on-chain; no funds are lost. |
| FWL-036 | A signed transfer stays relayable by anyone until `validUntil`, with no cancel path; short windows are the only control. |

## Relationship to the rest of this repository

- The XMSS verification is [`xmss-solidity`](https://github.com/skalenetwork/xmss-solidity) unchanged — the same library FermionGuard uses, with the same partial machine-checked proof (primitives and reject paths proven in Halmos; accept path by hand argument plus vectors at h = 4, 10 and 20 — see its `PROOF.md`), included as the submodule `contracts/lib/xmss-solidity`. FermionWallet adds no cryptography of its own. [FWL-032]
- The device is the same Fermion Ledger app ([ledger-xmss-app.md](./ledger-xmss-app.md)) — but **not** the same app build. Key generation and export (`GEN_XMSS_KEY`, `GET_XMSS_ROOT`, `GET_ADMIN_ADDRESS`, `GET_LEAF_INDEX`) are reused unchanged; signing is not. The app refuses payloads it does not recognize ("unknown or malformed payload fields abort the flow before screen 1"), and a `Transfer` is unrecognized: different EIP-712 type hash, domain name `FermionWallet`, `verifyingContract` = the wallet, and none of the fields Flow 2's screens are built around (no Safe address, no `txHash` pin, no `policyHash`, no payload class). Supporting FermionWallet therefore requires, in the app: [FWL-033]
  1. the `Transfer` type and the `FermionWallet` domain accepted by the payload parser, alongside `PreApproval`;
  2. a signing flow whose context screen shows **Wallet 0x…** and the chain instead of Safe / pin / policy — the existing token, amount, recipient, validity and decision screens carry over;
  3. per-slot binding to one verifying contract on one chain, recorded at first signature and enforced on every later one (FWL-023) — new NVM state the current app does not keep. The chain id belongs in the binding: FWL-031's CREATE2 factory gives the same wallet address on every chain, and those are two contracts with two bitmaps;
  4. a refusal path when a slot bound to a wallet is asked for a Safe pre-approval, and vice versa.

  All four are implemented in [`ledger-app/src/wallet.rs`](./ledger-app/src/wallet.rs) and checked against the app running in Speculos ([`ledger-app/test/test_wallet.py`](./ledger-app/test/test_wallet.py)): the digest the device reports matches the one `cast` computes for the fields sent, the XMSS half verifies under the published root by the RFC 8391 reference implementation, the ECDSA half recovers to `quantumAdmin`, and both directions of the binding are refused before a screen is drawn, consuming no leaf. They were additions, not redesigns: the counter-before-signature invariant, the hybrid output, the one-confirmation UX and the "display only signed fields" rule all hold as written. One gap remains — that build carries a single key slot, so FWL-024's several wallets wait on the key-generation flow. Also worth knowing: the `Transfer` payload is 132 bytes and fits one APDU, which the app now accepts as a single chunk.
- The two products share no on-chain code and no deployment. A holder may use both.
