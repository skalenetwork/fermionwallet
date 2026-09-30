# EIP drafts

The FermionGuard specifications, restated as standards: normative, implementation-independent,
and in the shape `ethereum/ERCs` expects. Three drafts, one per layer, each standing on its own:

| draft | layer | what it standardises |
| --- | --- | --- |
| [`ERCS/erc-draft-xmss-verification.md`](ERCS/erc-draft-xmss-verification.md) | cryptography | the ABI encoding of RFC 8391 XMSS keys and signatures, the exact hash instantiation, the domain checks, and the leaf-index accounting any authority-granting caller owes |
| [`ERCS/erc-draft-hash-based-key-registry.md`](ERCS/erc-draft-hash-based-key-registry.md) | key lifecycle | registration, rotation and time-locked revocation of a device-held one-time-signature key for a smart account, as a complete state machine |
| [`ERCS/erc-draft-hybrid-pre-approvals.md`](ERCS/erc-draft-hybrid-pre-approvals.md) | authorisation | authorisations carrying one classical and one post-quantum signature over one EIP-712 digest, matched and consumed atomically at execution |

They compose upwards — the registry requires the verification ERC's leaf rules, the pre-approval
ERC requires the registry's key states — and each is independently implementable. The drafts are
CC0 ([`LICENSE.md`](LICENSE.md)); the code they describe is not.

## What came from where

| repository specification | became |
| --- | --- |
| `quantum-key-registry.md`, `contracts/src/QuantumKeyRegistry.sol`, `contracts/test/registry-proof/RegistrySpec.sol` | the registry draft (the proved state machine is its §5 table) |
| `pre-approval-engine.md`, `contracts/src/PreApprovalEngine.sol` | the pre-approval draft |
| `xmss-solidity` (`src/XMSS.sol`, `test/proof/RFC8391.sol`), `contracts/src/XmssVerifier.sol` | the verification draft |
| `fermionguard-module.md`, `contracts/src/FermionGuard.sol` | the pre-approval draft's §10 (informative) and its Security Considerations |

### What is deliberately not in the drafts

An ERC's Specification has to be something a second implementer can satisfy. These parts of the
repository's specifications are product decisions, not candidates for a standard, and forcing
them into normative text would only bind implementers to one deployment's choices:

- the Safe guard mechanics — `checkTransaction`/`checkModuleTransaction` ordering, the
  `ITransactionGuard`/`IModuleGuard` pair at one address, Safe storage-slot reads,
  `getTransactionHash` recomputation, Safe version detection. Safe is a third-party account
  implementation; the *requirements* an enforcement hook must meet are stated (pre-approval
  draft §10 and Security Considerations), the mechanism is left to the implementation;
- the hardcoded selector deny-list, the per-account selector permit-list, the pinned
  `MultiSendCallOnly` address, the batch-leg limits, the per-account pause and its anti-veto
  cooldown, the emergency de-guard delay. Each is a policy this deployment chose; the standard
  states only the properties that make such policies sound (an immutable timelock, a
  key-independent detach path that is strictly slower than the co-signed one);
- the off-chain parts: the Ledger application's screens and APDU interface, the Safe App UI,
  the relayer and the indexer, the hardware-security policy, the release process;
- the threat model and the deployment guides, which argue *why* the rules are what they are. The
  drafts carry that argument in their Rationale and Security Considerations sections instead,
  which is where EIP readers look for it.

## Submitting

The drafts are complete except for what only the EIP process can assign. To submit:

1. **Open a discussion thread** for each draft on `ethereum-magicians.org` and put its URL in
   `discussions-to:`. A Draft without one fails the editors' lint.
2. **Fork `ethereum/ERCs`**, copy each file to `ERCS/erc-<PR number>.md` — the convention is to
   use the pull-request number as the ERC number — and replace `eip: <to be assigned>` with that
   number. Rename `assets/erc-draft-xmss-verification/` to `assets/erc-<number>/` and update the
   asset link in the Test Cases section.
3. **Resolve the cross-references.** Each draft refers to its siblings by name ("the companion
   ERC on …") because no numbers exist yet. Once the numbers are assigned, replace those phrases
   with `[ERC-N](./erc-N.md)` links and add the numbers to `requires:`. The `[XV-nn]`, `[KR-nn]`
   and `[PA-nn]` labels are stable and can be cited across drafts as they are.
4. **Lint.** The editors' linter is `eipw`:
   ```sh
   cargo install eipw          # needs a Rust toolchain
   eipw eips/ERCS/*.md
   ```
   It is not run in this repository's CI (no Rust toolchain in the contracts job);
   `check_eips.py` below covers the structural rules it enforces, plus fidelity checks `eipw`
   cannot make. Expect `eipw` to complain about `eip: <to be assigned>` and the placeholder
   `discussions-to:` until step 1 and step 2 are done — those two are the point of the
   placeholders.
5. **Expect the Specification to be questioned, not the Rationale.** The clauses most likely to
   draw review are `[XV-20]` (leaf records keyed by the public root), `[XV-24]` (the tree height
   comes from the registration, not the signature), `[KR-24]` (only the account may cancel a
   revocation) and `[PA-37]` (a single owner may not revoke an `ADMIN` approval). Each is
   load-bearing; each has its argument in the Rationale and a failure story in Security
   Considerations.

## Checks

```sh
python3 eips/check_eips.py
```

It enforces, for each draft:

- the EIP-1 preamble — required keys, their order, `title` ≤ 44 characters, `description` ≤ 140,
  the `author` form, `status`/`type`/`category`, an ISO `created` date, ascending `requires`;
- the required sections, in EIP-1's order, the RFC 2119/8174 boilerplate, and the exact
  `Copyright` line;
- that relative links resolve on disk and that external links are limited to the origins the
  EIP editors allow;
- **fidelity to the code**: every error and event declaration, every EIP-712 type string, the
  function signatures of the interfaces, and the named constants quoted in a draft must exist,
  byte for byte, in the Solidity the draft claims to describe.

The last group is the one that matters over time. A specification and its implementation drift
silently; a failing test says so. `check_eips.py` runs in CI next to the contract tests
(`.github/workflows/contracts.yml`).

## Mapping to the repository's requirement index

The repository's specifications carry requirement IDs (`[GRD-nnn]`, `[ENG-nnn]`, `[QKR-nnn]`)
that the contracts' tests cite. The drafts carry their own (`[XV-nn]`, `[KR-nn]`, `[PA-nn]`),
because a standard's clause numbering cannot depend on one repository's document structure.
Document-level correspondence is the table above. The clause-level map is worth writing once the
repository's requirement index settles; the single entry worth recording now, because it is the
security bug this work found rather than a restatement:

| draft clause | repository requirement | what it says |
| --- | --- | --- |
| `[XV-20]`, `[KR-12]` | `[QKR-009a]` | the consumed-leaf record is keyed by the XMSS root, never by a per-registration identifier — one physical key registered by two accounts must share one leaf record |
