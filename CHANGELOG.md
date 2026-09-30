# Changelog

Nothing has been released yet. `release-spec.md` §4 defines the stages; no stage has been
entered, and the first target is Testnet beta. Until then this file records what changed
and, where it matters, what turned out not to be true.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions will
follow [semantic versioning](https://semver.org/spec/v2.0.0.html) once there is a version.

## [Unreleased]

### Added

- **A second product.** `contracts/src/FermionWallet.sol` — a standalone ERC-20 wallet
  with one immutable XMSS key, one state-changing function and a used-leaf bitmap as its
  only mutable state. No owners, no recovery, no ETH, no `approve`, no arbitrary calls.
  It shares the XMSS library with the Guard and nothing else. Specified in
  `fermionwallet.md`; 32 of its 36 requirements are cited by tests.
- **A Ledger app that runs.** `ledger-app/` builds, generates its XMSS seed from the
  device's own entropy, signs pre-approvals and FermionWallet transfers with both hybrid
  halves over a digest it recomputes on-device, and is driven end to end in Speculos by
  the demo. It is a subset of `ledger-xmss-app.md` and must not hold real funds;
  `ledger-app/README.md` lists every gap.
- **Two more proofs.** The Guard and the pre-approval engine have twenty-eight properties
  proven against an executable specification with Halmos (`contracts/test/guard-proof/`),
  and the device's signing flow is model-checked exhaustively with the simulator proven
  to refine it (`demo/ledger-proof/`). Each names what it does not cover, and each
  records its planted-bug run: twenty mutations for the Guard, of which the two that
  survive name the single unit test that catches each instead.
- **The specifications as ERC drafts.** `eips/ERCS/` holds three Standards Track drafts —
  XMSS verification, the key registry, hybrid pre-approvals — with `eips/check_eips.py`
  requiring every error, event, type string and constant in them to exist in the Solidity
  byte for byte, and running the published test vector rather than only linking it.
- **A security policy.** `SECURITY.md`, with the known weaknesses stated up front rather
  than behind a reporting form.
- **The device's counter-before-signature ordering is a compile-time property.** A new
  `session.rs` makes `commit` the only source of a `Committed` token and `publish` take
  it by value, so releasing a signature before the leaf counter lands is not expressible;
  writing them in the wrong order is `error[E0425]`. It had been guarded by code review
  alone, and both device test suites claimed to check it while passing against a build
  with the ordering inverted.
- **Checks that keep the documentation honest.** `contracts/script/check_requirements.py`
  (every cited requirement ID exists, coverage reported),
  `contracts/script/check_doc_links.py` (every link, anchor and backticked path resolves),
  and `contracts/script/describe_spec.py` (the registry specification rendered back into
  English, regenerated or CI fails). Plus `demo/check_wire_protocol.py`: the APDU numbers
  and the signature blob's layout live in five places in three languages, and both times
  they drifted the failure was a burned one-time leaf.

### Fixed

- **Cross-Safe leaf reuse.** The registry's used-leaf bitmap was keyed per registration,
  so the same physical XMSS key registered by two Safes got two empty bitmaps — one leaf
  could sign two different digests, which is what makes WOTS+ forgeable. Now keyed by the
  XMSS root, globally per key.
- **The demo could never have relayed a hardware signature.** The device returns
  `r ‖ wotsSig ‖ authPath`; the relayer's decoder expected a `root ‖ seed` prefix, so
  every real-Ledger approval died on a length check *after* the device had spent a
  one-time leaf. The simulator hid it by sending two words the app does not.
- **A year that wrapped at 2³².** The device formatted a `uint64` timestamp's year as
  `u32`, so `validUntil = 135536078592187200` rendered byte-for-byte identically to a
  2026 date and was signed. Since a short validity window is the only control against a
  relay and there is no cancel path, the loss was a double spend.
- **The APDU numbers collided with the app they claim to follow.** `GET_SIGNATURE_CHUNK`
  sat on `0x18`, which is `PERFORM PRIVACY OPERATION` in Ledger's Ethereum app. The four
  commands with Ethereum analogues now take Ethereum's own numbers and everything
  FermionGuard-specific moved to `0x40`+.
- **A test that could pass for the wrong reason.** The Safe{Wallet} end-to-end test read
  the "this transaction will most likely fail" warning after a fixed sleep, and its
  *approved* branch asserted the warning was absent — so "the gas estimate has not
  arrived" was indistinguishable from "no warning".
- **The Safe App tells an operator what happened.** The Guard's reverts are decoded with
  a meaning and a remedy instead of "Flow failed — see log"; expiry, an exhausted key, a
  paused Safe and a hash mismatch are all distinct states with words; a permanently
  denied selector says so rather than reading as unsupported; and keyboard focus survives
  the four-second queue refresh, which it did not.

### Changed

- **What this project claims about its proofs.** "Formally verified" is gone from every
  document. The XMSS verifier's primitives and its input-validation rejections are
  machine-checked against RFC 8391 for all inputs; the comparison of the recomputed root —
  which is what both accepts a genuine signature and rejects a forgery — rests on a hand
  argument, symbolic only at tree height 2, and concrete vectors. The registry and Guard
  proofs abstract authorization and both signature schemes, and `_checkBatchLegs` is not
  proven at all. Each proof's README says what it leaves out, and the claim was narrowed
  three times in one day as each narrowing turned out to still be too strong.
- The Ledger app specification is now a dialect of Ledger's own Ethereum app — CLA, INS
  numbering, P1/P2 conventions, status words, screen idioms — with every borrowed claim
  cited to its primary source, and the deliberate deviations tabled with reasons.
- **Halmos runs under z3.** Every proof command in the READMEs and the XMSS library's CI
  now names `--solver z3`; a repository-wide `halmos.toml` is still to come. Its bundled
  default does not terminate on some queries here, which with assertion timeouts disabled
  is indistinguishable from a proof in progress: one lemma was abandoned as diverging
  after fifty-five minutes and passes in 0.43 seconds under z3. A run that hangs rather than fails is no result and no
  signal, and a solver that gives up reads exactly like "no counterexample found" — which
  reads as a mutation the proof missed.
- The threat model's mitigations were re-checked against the contracts rather than against
  other prose. Three named something that does not exist, including a recovery path that
  cannot exist: a wiped Administrator Ledger cannot rotate, because rotation needs the old
  key's possession proof.

### Known limitations

Carried deliberately, listed in `SECURITY.md` and in each document that owns one: the
proofs are narrower than the word suggests; the standalone wallet has no on-chain backstop
for leaf reuse; the Ledger app is a subset of its specification; the owner threshold can
activate a key alone; and a Safe that attaches the Guard before registering a key can
detach it with no timelock.
