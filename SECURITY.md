# Security policy

## Do not put real funds behind this

Nothing here has been audited, nothing is deployed on a public network, and the Ledger
app is a partial build. `release-spec.md` §11 makes an external security audit a
precondition of any mainnet deployment, and that audit has not happened.

The demo keys are public test keys, published in this repository and in every container
image. The Quantum Administrator key the demo signs with is anvil's, the Safe owners are
anvil's, and the XMSS key is generated deterministically from a fixed string. They exist
so that a stranger can run the demo in one command. They protect nothing.

## Reporting a vulnerability

Report privately through **GitHub's private vulnerability reporting** on this
repository (Security → Report a vulnerability). It reaches the maintainers without
becoming public, and it keeps the report, the fix and the advisory in one place.

Please do not open a public issue for anything that could be exploited, and please do
not disclose before a fix is available. If you would rather not use GitHub, say so in
any public channel without details and someone will arrange another route.

What helps, in rough order of usefulness: a failing test against this repository, the
exact commit you looked at, and what an attacker gains. A test that fails is worth more
than a paragraph, and this project's own findings have almost all arrived that way.

## What is in scope

- `contracts/src/` — the Guard, the key registry, the pre-approval engine, the
  standalone wallet, and the verifier wrapper.
- `contracts/lib/xmss-solidity/` — the XMSS verifier, which lives in
  [its own repository](https://github.com/skalenetwork/xmss-solidity) and has its own
  security note; report verifier issues there if you prefer.
- `ledger-app/` — the device app: the signing flow, the leaf counter, the NVM state,
  what is displayed versus what is signed.
- `demo/` — only where a defect would mislead someone about the product's behaviour.
  The demo's test keys and its permissive local chain are not vulnerabilities.
- The specifications, when a document claims a security property the code does not
  enforce. Several such claims have been found and corrected; more probably remain,
  and finding one is a real contribution.

## What is out of scope

- The JavaScript prototype in `src/`. It is an early model of the flows, it signs with
  an **HMAC-SHA256 demo MAC**, and it is not post-quantum and not the enforcement
  layer. Its own `package.json` says so.
- Anything requiring the collusion of every authorization role. `threat-model.md` §2.1
  is explicit that no on-chain system survives that, and the mitigation is
  organizational — keep the Administrator out of owner governance.
- Third-party code we depend on and have not modified: Safe, OpenZeppelin, Foundry,
  Ledger's SDK. Report those upstream; tell us too if it affects this system.
- Gas costs, unless a cost is high enough to deny service.

## Known weaknesses, stated up front

These are documented, not hidden, and a report that restates one is still welcome — but
it will be closed as known rather than fixed.

- **The proofs are narrower than the word suggests.** The XMSS verifier's primitives and
  its input-validation rejections are machine-checked against RFC 8391 for all inputs;
  the comparison of the recomputed root — which is what both accepts a genuine signature
  and rejects a forgery — rests on a hand argument, symbolic only at tree height 2, and
  concrete vectors. The registry and Guard proofs abstract authorization and both
  signature schemes, and `_checkBatchLegs`, the Guard's most intricate parsing, is not
  proven at all. Each proof's README says what it leaves out.
- **The standalone wallet has no on-chain backstop for leaf reuse.** One key bound to
  two wallets means two empty bitmaps, and only the device prevents it
  (`fermionwallet.md` [FWL-023], [FWL-025]).
- **The Ledger app is a subset of its specification**: one key slot, a demo tree height,
  no key-generation, rotation, attestation or retire commands. `ledger-app/README.md`
  lists every gap.
- **The owner threshold can activate a key alone**, because the registry checks the
  attestation against the address the owner signatures themselves name
  (`quantum-key-registry.md` [QKR-013], `threat-model.md` §2.1). Accepted, documented.
- **A Safe that attaches the Guard before registering a key can detach it with no
  timelock.** Deliberate, and it closes permanently the moment a key is registered.

## Fixes and disclosure

Security fixes are released before details are disclosed, and the advisory is published
with or after the fix (`release-spec.md` §9). If a fix needs a coordinated release with
a downstream user, we will say so rather than sit on it silently.
