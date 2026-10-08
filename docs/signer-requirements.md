# Signer requirements

**Status: specification, unaudited.** Normative for every signer that holds a Fermion key. Informational companion to the ERC draft [`erc-draft-hybrid-pq-signatures.md`](./erc-draft-hybrid-pq-signatures.md), which specifies the signature encoding; this document specifies what a signer must do before it produces one.

The contracts check two things: an ECDSA signature that recovers to the enrolled address, and an ML-DSA signature that verifies under the enrolled public key, both over the same 32-byte EIP-712 digest. They do not know what produced either half. So the Quantum Administrator of a Fermion Guard, and the key holder of a Fermion Wallet, may be any signer — a Ledger, an HSM, a custodian's vault — and the contracts cannot tell a careful signer from a careless one. This document is the contract between Fermion and the signer. A signer that does not meet it can lose the funds it protects while every on-chain check passes.

The Ledger app "Fermion" ([`ledger-app.md`](./ledger-app.md)) is the reference implementation. The Entrust nShield design ([`nshield-signer.md`](./nshield-signer.md)) is the second. Where this document and the Ledger app disagree, this document is the requirement and the app has a bug.

Terms: **MUST**, **MUST NOT**, **SHOULD** and **MAY** as in RFC 2119. **Signer**: the component that holds the private keys and releases signatures. **Host**: everything else — the computer, the browser, the SDK, the network. The host is assumed compromised throughout. **Reviewer**: the person who sees and approves the fields (the Ledger holder), or the k-of-n approvers of a signer without a screen.

## Scope

A conforming signer produces the signatures for the messages the two products define:

| Product | Messages | Defined in |
|---|---|---|
| Fermion Wallet | transfer batch (up to 8 legs), plain-text message, Safe transaction signed as a Safe owner | [`fermion-wallet.md`](./fermion-wallet.md#signed-messages), [`fermion-wallet.md`](./fermion-wallet.md#safe-owner-erc-1271) |
| Fermion Guard | quantum approval of a Safe transaction (inline or stored), module-transaction approval, enableModule, revoke of a stored approval, key rotation | [`fermion-guard.md`](./fermion-guard.md#quantum-approval), [`fermion-guard.md`](./fermion-guard.md#inline-and-stored-approvals), [`fermion-guard.md`](./fermion-guard.md#modules), [`fermion-guard.md`](./fermion-guard.md#key-rotation) |

A signer MUST NOT produce a Fermion signature over anything else: no arbitrary EIP-712 struct, no permit, no raw hash, no EIP-191 message outside the plain-text message type. [SR-001] A signer MAY support only a subset of the messages above (for example, Guard messages only), and MUST refuse the rest. [SR-002]

## Digest

Every signature, both halves, is over one 32-byte EIP-712 digest:

    digest = keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct(message))

The domains, type strings and field order are those of the contract the signature is for, and are defined only there: [`fermion-wallet.md`](./fermion-wallet.md#signed-messages) for the wallet's own messages, [`fermion-wallet.md`](./fermion-wallet.md#safe-owner-erc-1271) for the wrapping of a Safe transaction hash in the wallet's domain, and [`fermion-guard.md`](./fermion-guard.md#quantum-approval) for the Guard's. A signer MUST implement those definitions byte for byte and MUST NOT accept a domain or type it does not know. [SR-003]

- **Domain binding.** The domain's `chainId` and `verifyingContract` MUST come from the request and MUST be shown to the reviewer ([Display and refusal rules](#display-and-refusal-rules)). A signer MUST NOT default either. [SR-004]
- **Rebuilt, never received.** The signer MUST compute the digest itself, from the fields the reviewer approved. It MUST NOT sign a digest, a `safeTxHash`, a struct hash or any other hash supplied by the host, and MUST NOT accept a host hash even as a cross-check whose mismatch is only reported. [SR-005] Where a message contains a hash of other data — a Safe transaction's `data`, a module transaction's `dataHash` — the signer MUST receive the data itself and hash it, unless the data is shown to the reviewer only as that hash by design (a revoke names the approval it kills by its hash). [SR-006]
- **Safe owner path.** When a Fermion Wallet signs as a Safe owner, the signer receives the full SafeTx fields plus the Safe address and chain ID, computes the Safe's own `safeTxHash` for that Safe version, then wraps it in the wallet's domain as defined in [`fermion-wallet.md`](./fermion-wallet.md#safe-owner-erc-1271). Both steps happen inside the signer. [SR-007]
- **Inline and stored approvals are the same bytes.** A Guard approval is one struct whether the host appends it to the Safe's `signatures` or submits it to `preApprove`. The signer MUST NOT need to know which, and MUST NOT sign differently for either. [SR-008]

## Signature

- **Hybrid.** Every Fermion signature has two halves: ECDSA over secp256k1 and ML-DSA, both over the same digest. A signer MUST compute both inside its boundary and MUST NOT release either half unless both were computed. [SR-009] The wire encoding (ECDSA ‖ ML-DSA, and its ERC-1271 wrapping) is the ERC draft's.
- **ECDSA half.** 65 bytes `r ‖ s ‖ v` with `s` in the lower half of the curve order and `v ∈ {27, 28}`. The contracts check it by ECDSA recovery only (OpenZeppelin `tryRecover`, which rejects a high `s`). [SR-010] The ECDSA key's address MUST be an externally owned account: the contracts refuse an address with code at deployment and enrollment, and no contract-wallet admin is supported. [SR-011]
- **ML-DSA half: pure, empty context.** ML-DSA as in FIPS 204, the external (pure) interface — not HashML-DSA — with an empty context string. The message passed to ML-DSA is the 32-byte digest, so the internal message is `M' = 0x00 ‖ 0x00 ‖ digest`. [SR-012]
- **Parameter sets.** ML-DSA-44 (algorithm id `0x0101`) is the default; ML-DSA-65 (`0x0102`) is opt-in. The set is fixed per key at creation and the contract stores it. A signer MUST sign with the set its key was enrolled with. [SR-013] The contracts also accept ML-DSA-87 (`0x0103`); a signer MAY produce it. No v2 reference signer does: the Ledger app ships 44 and 65 only, and the nShield signer is a design. [SR-014]
- **Hedged signing.** Production signers MUST use FIPS 204 hedged signing, with `rnd` drawn fresh from an approved random source for every signature. Deterministic signing (`rnd = 0^32`) is allowed only in builds that cannot hold a production key and that say so to the reviewer and to the host. [SR-015]
- **Key material lifetime.** The expanded ML-DSA private key and the ECDSA private key MUST be wiped from working memory after each signing operation, including on rejection and on error. [SR-016]

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| public key / signature bytes | 1312 / 2420 | 1952 / 3309 | 2592 / 4627 |
| algorithm id | `0x0101` | `0x0102` | `0x0103` |

Sizes are from the [measured-facts table](./v2-decisions.md#measured-facts-cite-these-do-not-retype-from-memory) of the decision record.

## Display and refusal rules

A signature is an authorization. What the reviewer did not see, they did not authorize.

### What the reviewer must see

- **Every signed field.** Before the signer releases a signature, the reviewer MUST be shown every field of the message and of its domain, rendered from the bytes the signer will hash, and MUST approve explicitly. A field the reviewer was not shown MUST NOT be signed. [SR-017]
- **Only signed fields.** The signer MUST NOT show host-supplied context that is not part of the signed message (a label, a queue position, a balance) as if it constrained the signature. [SR-018] Two exceptions, each labelled as such: decoded names and token metadata from a verified descriptor ([below](#descriptors)), and a parameter decoded from signed calldata.
- **The product and the role.** Every review MUST name the product and role it signs for — Fermion Wallet transfer, Fermion Wallet as Safe owner, Fermion Guard quantum approval — so that a Guard approval and an owner signature over the same Safe transaction cannot be mistaken for each other. [SR-019]
- **Addresses in full**, as `0x` + EIP-55 checksummed hex, never truncated. **32-byte values in full.** [SR-020]
- **Amounts unambiguous.** An amount is shown either decimals-adjusted with the token symbol from a verified descriptor, or as the raw integer labelled as raw units together with the token contract address. A signer MUST NOT guess decimals. [SR-021]
- **Times as absolute UTC.** `validFrom` and `validUntil` are shown as absolute UTC date-times, never as durations. A time the signer cannot render exactly is refused, not rounded. [SR-022]
- **A Safe transaction** shows: the role, the Safe address, the chain, the Safe nonce, `to`, `value`, the decoded call (or the undecodable-call warning below), `operation`, `safeTxGas` and `baseGas`. [SR-023]
- **Safe self-administration** (`addOwnerWithThreshold`, `removeOwner`, `swapOwner`, `changeThreshold`, `setGuard`, `setFallbackHandler`, `enableModule`, `disableModule`, `setModuleGuard`) is shown on a dedicated screen that names the function and every argument, never as a generic decoded call. `enableModule` additionally opens with its own warning. [SR-024]

### Refusals

The signer MUST refuse each of the following **before showing anything to the reviewer**. There is no override, no setting, and no "show it and let the human decide". [SR-025]

| # | Refused | Why |
|---|---|---|
| 1 | A Safe transaction or module transaction with `operation = DelegateCall` | an owner or approval signature over a delegatecall hands the target the Safe's storage |
| 2 | A Safe transaction with non-zero `gasPrice`, non-zero `gasToken` or non-zero `refundReceiver` | the refund is paid from the Safe to whoever the host chose |
| 3 | An unlimited token approval | it outlives every later review |
| 4 | `validUntil − validFrom > 24 hours`, or `validFrom > validUntil` | the contracts reject it; a signature that can never be used must not be shown |
| 5 | A malformed request: unknown domain or type, a field out of range, trailing bytes, more than 8 legs in a wallet batch, a message kind the key's product does not sign | nothing well-defined to show |

"Unlimited approval" covers at least an ERC-20 `approve` (or `increaseAllowance`) whose amount is `2^256 − 1`, wherever it appears — the top-level call, a leg of a batch, or a call inside a decoded descriptor. [SR-026]

These refusals apply on both paths a Safe transaction reaches a signer — as a Fermion Guard approval and as a Fermion Wallet owner signature. On the owner path there may be no Guard on the Safe, so the signer is the only check. [SR-027]

### Validity window

Every signed message carries `validFrom` and `validUntil`; the contracts require `validFrom ≤ block.timestamp ≤ validUntil` and `validUntil − validFrom ≤ 24 h` ([`fermion-wallet.md`](./fermion-wallet.md#replay-and-validity-window)). A signer without a trusted clock cannot check `block.timestamp`; it checks the window's length and shape (refusal 4) and shows both times so the reviewer can judge them. A signer with a trusted clock SHOULD also refuse a `validUntil` already in the past. [SR-028]

### Undecodable calls

A call the signer cannot decode — no verified descriptor for its target and selector — is **not refused**. It MAY be signed only after a strong warning that the call cannot be verified, followed by: the target address, the 4-byte selector, the value, the complete calldata in hex (paged, never truncated), and `keccak256` of the calldata. [SR-029] Refusals 1–5 still apply first. Undecodable calldata cannot be checked for an unlimited approval; the warning is what the reviewer has.

### Descriptors

Contract calls are decoded with ERC-7730 descriptors signed by Ledger (Ledger's clear-signing registry). The signer MUST verify the descriptor's signature inside its boundary before using it. A descriptor whose signature does not verify, or that is missing, makes the call undecodable — it never makes it refused, and never makes it decoded. [SR-030] The host supplies descriptors; `fermion-sdk` caches them. The host is trusted for availability only.

### Signers without a screen

A signer with no screen of its own (an HSM) replaces "the reviewer sees and approves" with **k-of-n approver signatures over the same fields**: each approver sees the fields on a device of their own and signs a statement of them; the signer verifies k distinct approvals over exactly the fields it is about to hash, and only then signs. The approval statements MUST cover every field the screen rule above would show, and the refusals MUST be applied by the signer itself, not by the approvers' tools. [SR-031] The signer MUST NOT expose any interface that signs without that check — no host-callable raw sign with the Fermion keys. [SR-032]

## Key generation and backup

- **One key per contract.** Each Fermion Wallet and each Safe enrolled in Fermion Guard has its own ECDSA key and its own ML-DSA key. A signer MUST NOT reuse either half across two contracts, or across the two products. [SR-033]
- **Generated inside, never exported.** Private keys are generated or derived inside the signer and never leave it in plaintext. The signer exports public keys only: the ECDSA address and the ML-DSA public key. [SR-034]
- **The two halves are independent.** The ML-DSA key MUST NOT be computable from the ECDSA private key, or from anything a quantum attacker could obtain from the ECDSA public key. A quantum break of the ECDSA half must reveal nothing about the ML-DSA half. [SR-035]
- **Derivation, for phrase-based signers.** A signer that derives keys from a BIP-39 recovery phrase MUST use the Ledger app's derivation ([`ledger-app.md`](./ledger-app.md#key-derivation)), so a phrase restored on another conforming signer yields the same keys. [SR-036] A BIP-39 passphrase is recommended, not required.
- **Native generation, for HSMs.** An HSM MAY instead generate both keys natively from its own approved RNG and back them up under its own key-management scheme (for nShield, the Security World). Such keys are not restorable from a phrase. [SR-037]
- **Backup is mandatory and is the key control.** Fermion keys are stateless, so a restored copy is safe to use. Whoever holds the backup (the phrase, or the HSM's backup quorum) holds both halves of every key derived from it: compromise of the backup is compromise of every contract it controls. The signer's documentation MUST state who holds the backup and how it is split. [SR-038]
- **No recovery-phrase entry outside the device.** No host software may ask for a recovery phrase. Restore happens only on the signer. [SR-039]
- **Parameter set recorded with the key.** The signer MUST know, for each key, which ML-DSA set it belongs to, and MUST refuse to sign with it under another set. [SR-040]

## Distribution

A signer's firmware or application is part of the key: any code allowed to run the derivation can derive the key. A phrase-based signer's app MUST be installed only from a channel that verifies it (for the Ledger app, the Ledger Live catalog), and test builds MUST be distinguishable on the signer itself. [SR-041]

## Requirement index

| ID | Requirement |
|---|---|
| SR-001 | A signer produces Fermion signatures only over the message types the two products define: no arbitrary EIP-712, permit, raw hash or other EIP-191 message. |
| SR-002 | A signer may support a subset of the messages and must refuse the rest. |
| SR-003 | The digest is the EIP-712 digest of the contract's own domain and types, implemented byte for byte; unknown domains or types are refused. |
| SR-004 | The domain's chainId and verifyingContract come from the request, are shown, and are never defaulted. |
| SR-005 | The signer computes the digest from the approved fields and never signs, or cross-checks against, a host-supplied hash. |
| SR-006 | Hashed sub-data (Safe calldata, module dataHash) is received in full and hashed by the signer, except where a hash is itself the displayed field by design. |
| SR-007 | On the Safe owner path the signer computes safeTxHash and its wrapping in the wallet domain itself. |
| SR-008 | Inline and stored Guard approvals are the same signed bytes; the signer does not distinguish them. |
| SR-009 | Both halves are computed inside the signer over the same digest, and neither is released unless both were computed. |
| SR-010 | The ECDSA half is 65 bytes r‖s‖v with low s and v in {27, 28}. |
| SR-011 | The ECDSA key's address is an EOA. |
| SR-012 | ML-DSA is pure FIPS 204 with an empty context, over the 32-byte digest (M' = 0x00‖0x00‖digest). |
| SR-013 | ML-DSA-44 is the default and ML-DSA-65 opt-in; a key signs only under its enrolled set. |
| SR-014 | ML-DSA-87 is accepted by the contracts and may be produced; no v2 reference signer produces it. |
| SR-015 | Production signing is hedged with fresh rnd; deterministic signing only in builds that cannot hold a production key and say so. |
| SR-016 | Private key material is wiped from working memory after every signing operation, including rejection and error. |
| SR-017 | Every field of the message and its domain is shown and explicitly approved before signing. |
| SR-018 | Host-supplied context that is not signed is never shown as if it constrained the signature. |
| SR-019 | Every review names the product and role it signs for. |
| SR-020 | Addresses are shown in full EIP-55; 32-byte values in full. |
| SR-021 | Amounts are decimals-adjusted from a verified descriptor or shown as raw units with the token address; decimals are never guessed. |
| SR-022 | validFrom and validUntil are shown as absolute UTC; an unrenderable time is refused. |
| SR-023 | A Safe transaction review shows role, Safe, chain, Safe nonce, to, value, call, operation, safeTxGas and baseGas. |
| SR-024 | Safe self-administration calls get a dedicated screen naming the function and arguments; enableModule opens with its own warning. |
| SR-025 | The listed refusals happen before anything is shown, with no override. |
| SR-026 | An unlimited approval includes at least an ERC-20 approve or increaseAllowance of 2^256 − 1, anywhere in the request. |
| SR-027 | The refusals apply on both the Guard-approval and the Safe-owner paths. |
| SR-028 | A signer without a trusted clock checks the window's length and shape and shows both times; one with a trusted clock should also refuse an expired window. |
| SR-029 | An undecodable call may be signed only after a strong warning showing target, selector, value, full calldata hex and its keccak256. |
| SR-030 | Descriptors are Ledger-signed ERC-7730 and verified inside the signer; an unverifiable descriptor makes the call undecodable. |
| SR-031 | A signer without a screen requires k-of-n approver signatures over every field the screen rule would show, and applies the refusals itself. |
| SR-032 | A signer without a screen exposes no host-callable raw sign with the Fermion keys. |
| SR-033 | One ECDSA key and one ML-DSA key per contract; no reuse across contracts or products. |
| SR-034 | Private keys are generated or derived inside the signer and never exported in plaintext. |
| SR-035 | The ML-DSA key is not computable from the ECDSA private or public key. |
| SR-036 | Phrase-based signers use the Ledger app's derivation so a phrase restores the same keys. |
| SR-037 | An HSM may generate keys natively and back them up under its own scheme. |
| SR-038 | Backup is mandatory; the signer's documentation states who holds it and how it is split. |
| SR-039 | No host software asks for a recovery phrase; restore happens only on the signer. |
| SR-040 | Each key records its ML-DSA set and is refused under any other. |
| SR-041 | A phrase-based signer's app is installed only from a verifying channel, and test builds are distinguishable on the signer. |
