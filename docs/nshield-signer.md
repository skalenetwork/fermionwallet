# nShield signer (design)

**Status: design only. Nothing here is built, and nothing here is a requirement.** The requirements are [`signer-requirements.md`](./signer-requirements.md); this document describes how an Entrust nShield HSM could meet them. It is blocked on access to the paid CodeSafe SDK and to an nShield (or nShield as a Service). Unaudited.

## Why a second signer

The contracts check an ECDSA half and an ML-DSA half over an EIP-712 digest; they do not care what produced them ([`signer-requirements.md`](./signer-requirements.md)). The Ledger app ([`ledger-app.md`](./ledger-app.md)) suits a person holding a device. A custodian or treasury runs its keys in HSMs, with quorums instead of a single holder and audit trails instead of a screen. The nShield signer is the institutional reference signer: the same rules, enforced inside an HSM, with k-of-n approvers in place of the screen.

It is also the only planned signer that could produce ML-DSA-87, which the contracts accept and the Ledger app does not ship (decision record C4). Whether it does is decided when it is built.

## Shape

    approvers (Ledger / phone)          host (untrusted)              nShield 5 (CodeSafe 5)
    ────────────────────────────       ──────────────────            ─────────────────────────────────
    see the fields, sign an      ──►   collects request +     ──►    SEE app "fermion-signer"
    approval statement                 k approval statements           parse request   (signer-core)
                                                                       apply refusals  (signer-core)
                                                                       verify k-of-n approvals over the fields
                                                                       rebuild digest  (signer-core)
                                                                       sign ECDSA + ML-DSA with keys whose
                                                                         ACL allows only this SEE app
                                                         ◄──           return hybrid signature

### The SEE application

A CodeSafe 5 application runs inside the nShield 5's Secure Execution Engine. It is the only code that can use the Fermion keys. It:

1. receives a signing request in the same message format the Ledger app's `SIGN` command takes (kind byte and fields), plus the approval statements;
2. parses it and applies the refusal rules of [`signer-requirements.md`](./signer-requirements.md#display-and-refusal-rules) itself — delegatecall, gas-refund fields, unlimited approvals, a window over 24 hours — before looking at any approval;
3. checks that at least k distinct, currently enrolled approvers signed a statement of exactly the fields it parsed;
4. rebuilds the EIP-712 digest from those fields;
5. signs it with ECDSA secp256k1 and with ML-DSA, and returns both halves.

No host-callable operation signs with the Fermion keys directly. That is what the key ACLs below are for.

### Key ACLs bind the keys to the app

nShield keys carry an ACL fixed at generation. The Fermion keys are generated with ACLs that permit the sign operation only to the SEE application, identified by its signing key, so the host's ordinary nCore API cannot ask the HSM to sign an arbitrary hash with them. Without that binding the HSM would be a blind signer behind a well-written app, and [`signer-requirements.md`](./signer-requirements.md#signers-without-a-screen) would not be met.

To confirm against the CodeSafe 5 documentation: the exact ACL form that restricts a key to one SEE app, and how an app upgrade is authorized without re-generating keys.

### ML-DSA in firmware

nShield 5 firmware v13.8 and later provides ML-DSA natively. The SEE app calls it rather than carrying its own implementation. To confirm: that the firmware's ML-DSA offers the pure (external-interface) mode with an empty context and hedged signing, as [`signer-requirements.md`](./signer-requirements.md#signature) requires, rather than HashML-DSA only; which parameter sets it supports; and whether ML-DSA is inside the module's FIPS 140-3 Level 3 validation scope or only present in the firmware.

### ECDSA secp256k1

To confirm: secp256k1 support in the firmware (it is not a NIST curve), and low-`s` output or a way to normalize it inside the SEE app.

## Approvers replace the screen

An HSM has no screen, so "the reviewer sees every field and approves" becomes "k of n approvers each see every field on a device of their own and sign a statement of them" ([`signer-requirements.md`](./signer-requirements.md#signers-without-a-screen)).

- **Approver devices.** On Ledgers or phones (decision record); which app they run is not decided — the Ledger app specified in [`ledger-app.md`](./ledger-app.md) has no approver mode. Whatever it is, the approver's device renders the request with the same rules as the Ledger app's screens — addresses in full, times in UTC, the undecodable-call warning — because the approver's screen is now the honest surface.
- **Approval statement.** A signature by the approver's key over the request's fields (not over a hash the host computed). The format and the approvers' signature scheme are not decided.
- **Enrollment of approvers.** The set of approver keys and k are configuration of the SEE app, changed only under a quorum of the existing approvers or of the Security World's administrator cards. Not designed in detail.
- **Policy.** The SEE app is where a custodian's own policy could live (per-destination limits, time-of-day rules). Fermion Guard has no on-chain spending policy; limits, if any, live here.

## Backup: the Security World

An HSM signer does not derive keys from a recovery phrase. Keys are generated inside the nShield from its own RNG and protected by the Security World: key blobs encrypted under the world's key, which is recoverable only with k-of-n administrator cards (ACS). Losing an HSM is recovered by loading the Security World onto another nShield. Compromise of the ACS quorum is compromise of every key in the world, which is the HSM equivalent of a stolen recovery phrase ([`signer-requirements.md`](./signer-requirements.md#key-generation-and-backup)).

One key per contract holds here as on the Ledger: each wallet or enrolled Safe gets its own ECDSA key and its own ML-DSA key.

## signer-core: one parser, one rule set

The parsing of a signing request, the EIP-712 digest construction and the refusal rules are the same for every signer, and are the part most worth getting right once. They move into a shared Rust crate, `signer-core`, `no_std` and allocation-free:

| In signer-core | Not in signer-core |
|---|---|
| request parsing (kind byte and fields) | key derivation or generation |
| EIP-712 encoding and digest for every message kind | ML-DSA and ECDSA (the Ledger SDK, the nShield firmware) |
| the refusal rules | screens, approver verification |
| ERC-20 and Safe-admin call decoding; ERC-7730 descriptor application | transport |

The Ledger app uses it first; the SEE app reuses it. The order in the decision record: signer requirements, then the Ledger reference app, then `signer-core` extracted from it, then the nShield app. To confirm: that CodeSafe 5 can build and run a Rust `no_std` library inside a SEE application.

## Blocked on

- The CodeSafe 5 SDK, which is licensed and paid.
- An nShield 5 with CodeSafe enabled, or nShield as a Service.
- The confirmations listed above: pure ML-DSA with empty context, secp256k1, ML-DSA validation scope, SEE-only key ACLs, Rust in the SEE.

Until those exist this document is the whole of the nShield signer.

## Thales Luna as a port target

Thales Luna HSMs run custom code as Functionality Modules (FM). The same structure ports: an FM in place of the SEE app, Luna's key-usage restrictions in place of nShield ACLs, Luna's backup scheme in place of the Security World, and `signer-core` unchanged. Not investigated beyond that.

## Integration paths

- **Custodian HSM as the Quantum Administrator** of a Fermion Guard: this document.
- **Custodian vault as a Safe owner**, with Fermion Guard and a Ledger as the Quantum Administrator: no HSM work needed on the Fermion side; the vault signs SafeTx as an ordinary owner.
