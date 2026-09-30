# FermionWallet — the smallest possible post-quantum ERC-20 wallet

**Status: specification only. No contract is implemented yet.**

FermionWallet is a *second* product in this repository, separate from [FermionGuard](./fermionguard-module.md). Where FermionGuard adds a post-quantum second authorization to an existing Gnosis Safe — owners, threshold, policies, timelocks, recovery paths — FermionWallet throws all of that away and keeps one thing: **an address that holds ERC-20 tokens and releases them only against a signature from the Fermion Ledger app.**

It is deliberately the simplest contract that can be called a wallet: one immutable key, one operation, one piece of state.

| | FermionGuard | FermionWallet |
|---|---|---|
| What it protects | an existing Safe | its own balance |
| Authorization | Safe owners **and** the Ledger's hybrid approval | the Ledger's hybrid signature alone |
| Governance | owners, timelocks, pause, emergency removal | none |
| Recovery if the device is lost | owners remove the Guard after the emergency delay | **none — the funds are gone** |
| On-chain state | keys, approvals, queues, policy | one used-leaf bitmap |
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

    mapping(uint32 leafIndex => bool) public leafUsed;   // the only mutable state

    event Transferred(address indexed token, address indexed to, uint256 amount, uint32 leafIndex);

    function transfer(
        address token,
        address to,
        uint256 amount,
        uint32 leafIndex,
        uint64 validUntil,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature
    ) external;
}
```

That is the whole interface. [FWL-012]

### The signed message

```
Transfer(address wallet,address token,address to,uint256 amount,uint32 leafIndex,uint64 validUntil)
```

under the EIP-712 domain `{ name: "FermionWallet", version: "1", chainId, verifyingContract: <the wallet> }`. The domain binds the chain and the wallet address, so a signature for one wallet can never be replayed on another wallet or another chain. [FWL-013] The device computes this digest itself from the fields it displays, exactly as it does for FermionGuard — it never signs a hash handed to it by the host. [FWL-014]

### What `transfer` checks, in order

1. `block.timestamp <= validUntil`, else revert. A signed transfer that was never relayed stops being valid. [FWL-015]
2. `leafUsed[leafIndex]` is false, else revert. Checked **before** the ~700k-gas verification, so a replay costs the relayer almost nothing. [FWL-016]
3. The ECDSA half recovers to `quantumAdmin` (via OpenZeppelin `SignatureChecker`, so an ERC-1271 signer also works). [FWL-017]
4. The XMSS half verifies against `(xmssRoot, xmssSeed)` at `treeHeight`, using [`xmss-solidity`](https://github.com/skalenetwork/xmss-solidity)'s four-argument `XMSS.verify`, the form that binds the tree height to the key. [FWL-018]
5. `leafUsed[leafIndex] = true` is written **before** the token call. [FWL-019]
6. `SafeERC20.safeTransfer(token, to, amount)`. [FWL-020]

`msg.sender` is never consulted. Any address may relay a valid signature, and no address can do anything without one. [FWL-021]

**Both halves are required.** Breaking the wallet means forging ECDSA *and* XMSS over the same digest: a quantum adversary who breaks ECDSA still faces the hash-based half, and a flaw in our young XMSS code still leaves the battle-tested classical half. The device produces both in one confirmation (`SIGN_PREAPPROVAL`), so this costs the user nothing. [FWL-022]

## One key, one wallet

The used-leaf bitmap lives in the wallet contract, so it can only see leaves spent by *that* wallet. If the same XMSS key were bound to two FermionWallets, each would start with an empty bitmap and one one-time leaf could sign two different transfers — the condition that makes WOTS+ forgeable. This is the same mistake [the key registry had](./quantum-key-registry.md) (QKR-009a), where it was fixable on-chain by keying the bitmap on the root; here the wallets are separate contracts and cannot see each other.

Therefore:

- **A key slot may be bound to exactly one FermionWallet.** The device records the wallet address at first use for that slot and refuses to sign a `Transfer` for any other wallet. [FWL-023]
- A holder who wants several wallets generates several keys — the app holds `MAX_KEYS = 4` (see [ledger-xmss-app.md](./ledger-xmss-app.md)). [FWL-024]

**Residual risk, stated honestly:** a rolled-back or cloned device could still bind one key to two wallets, and no on-chain check in this design would catch it. Deployments that cannot accept that risk should use the optional shared leaf registry below, or FermionGuard, whose registry keys leaf accounting by the root across every Safe. [FWL-025]

### Optional: a shared leaf registry

A single immutable, permissionless `LeafRegistry` per chain, keyed by XMSS root, that every FermionWallet consults and marks. It restores the "one leaf, once, everywhere" invariant that the standalone design can only enforce on the device. It costs one external call and one cold `SSTORE` per transfer, and one more contract to deploy and trust. It is **not** part of the minimal product; a deployment chooses it at construction time by passing a registry address or the zero address. [FWL-026]

## Cost

| | Gas |
|---|---|
| XMSS verification, h = 10 | ~712k |
| XMSS verification, h = 20 | ~745k |
| ECDSA check, leaf bookkeeping, token transfer, base cost | ~90k |
| **Total per transfer** | **~0.8M** |

Post-quantum verification on-chain is not cheap, and this is the honest number. The supported tree heights are the RFC 8391 parameter sets 10, 16 and 20: h = 10 gives 1,024 transfers per key and is the sensible default for a personal wallet; h = 20 gives ~1.05M and costs ~33k more gas per transfer. [FWL-027] Receiving tokens costs the sender nothing extra — it is an ordinary ERC-20 transfer to an address. [FWL-028]

When the leaves run out, the wallet still works for exactly as long as it takes to move the balance to a new wallet: the last leaf signs the last transfer. Plan the move before the counter reaches the end; the device shows leaves remaining (`GET_LEAF_INDEX`). [FWL-029]

## Deployment

The straightforward path is to deploy the contract, then send tokens to it. [FWL-030]

Optionally, a CREATE2 factory lets the address be computed before deployment, so tokens can be sent to it first and the contract deployed later, when a transfer is first needed. The salt must commit to `(xmssRoot, xmssSeed, treeHeight, quantumAdmin)` so that the address itself pins the key, and no one else can deploy a different wallet at that address. [FWL-031]

## What can go wrong

| Situation | Outcome |
|---|---|
| Quantum adversary forges ECDSA | Still needs the XMSS half; funds safe |
| Flaw in our XMSS verifier | Still needs the ECDSA half; funds safe |
| Compromised host, phishing frontend | The device shows token, recipient and amount and signs only what it displays |
| Relayer censors or front-runs | Anyone else can relay the same signature; the signature binds every field, so a front-runner can only submit the transfer the holder already authorized |
| Replayed transaction | The leaf is already spent; the transfer reverts before the expensive verification |
| Device lost or destroyed | **Funds are unrecoverable.** This is the accepted cost of the design (FWL-007) |
| Device rolled back or cloned | Leaf reuse becomes possible; see FWL-025 |
| Leaves exhausted | No further transfers; move the balance before that point (FWL-029) |
| Token with transfer fees or rebasing | Supported only as far as `safeTransfer` is: the signed `amount` is what is sent, not necessarily what is received |
| Token that reverts on zero-value transfers | Reverts; nothing is lost, but the leaf is already spent |

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
| FWL-016 | The leaf-reuse check precedes signature verification. |
| FWL-017 | The ECDSA half must recover to `quantumAdmin`. |
| FWL-018 | The XMSS half is verified with the height-bound `XMSS.verify`. |
| FWL-019 | The leaf is marked spent before the token call. |
| FWL-020 | Transfers use `SafeERC20.safeTransfer`. |
| FWL-021 | `msg.sender` carries no authority. |
| FWL-022 | Both signature halves are required over the same digest. |
| FWL-023 | A device key slot signs for exactly one wallet address. |
| FWL-024 | Multiple wallets require multiple keys. |
| FWL-025 | A rolled-back or cloned device can defeat leaf accounting; documented residual risk. |
| FWL-026 | A shared leaf registry is an optional, non-default mitigation for FWL-025. |
| FWL-027 | Supported tree heights are the RFC 8391 sets 10, 16 and 20. |
| FWL-028 | Receiving costs the sender no more than an ordinary ERC-20 transfer. |
| FWL-029 | The device reports remaining leaves so the balance can be moved before exhaustion. |
| FWL-030 | Deployment binds the key at construction. |
| FWL-031 | An optional CREATE2 factory derives the address from the key, so the address pins the key. |
| FWL-032 | XMSS verification is the unmodified `xmss-solidity` library; the wallet adds no cryptography. |
| FWL-033 | The device is the unmodified Fermion Ledger app; no new APDU is required. |

## Relationship to the rest of this repository

- The XMSS verification is [`xmss-solidity`](https://github.com/skalenetwork/xmss-solidity) unchanged — the same formally verified library FermionGuard uses, included as the submodule `contracts/lib/xmss-solidity`. FermionWallet adds no cryptography of its own. [FWL-032]
- The device is the same Fermion Ledger app ([ledger-xmss-app.md](./ledger-xmss-app.md)), using `GEN_XMSS_KEY`, `GET_XMSS_ROOT`, `GET_ADMIN_ADDRESS`, `GET_LEAF_INDEX` and `SIGN_PREAPPROVAL`, with the transfer fields in place of a pre-approval's. A device that can drive FermionGuard can drive FermionWallet. [FWL-033]
- The two products share no on-chain code and no deployment. A holder may use both.
