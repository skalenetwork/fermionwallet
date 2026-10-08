# Fermion v2 build and release

How Fermion v2 is built, tested and released: the branch and its phases, signing, pinned
dependencies, deterministic deployment, local-chain testing, the Ledger catalog submission,
the web hosting, and what has to pass before v2.0.0 ships.

It does not restate the designs. Contracts: [Fermion Wallet](./fermion-wallet.md#deployment),
[Fermion Guard](./fermion-guard.md). Device: [Ledger app](./ledger-app.md). Risks:
[security](./security.md#residual-risks).

**Status: in development on branch `ml-dsa-v2`. Unaudited, and there is no audit gate** (see
[release gates](#release-gates)). Nothing is deployed on any public network.

## Contents

1. [Principles](#principles)
2. [What ships](#what-ships)
3. [Branch and phases](#branch-and-phases)
4. [Signed commits and tags](#signed-commits-and-tags)
5. [Pinned dependencies](#pinned-dependencies)
6. [Deterministic deployment](#deterministic-deployment)
7. [Local-chain testing](#local-chain-testing)
8. [Release gates](#release-gates)
9. [Ledger catalog submission](#ledger-catalog-submission)
10. [Web hosting and domain](#web-hosting-and-domain)
11. [Publishing v2.0.0](#publishing-v200)
12. [After v2.0.0](#after-v200)
13. [Not yet decided](#not-yet-decided)

---

## Principles

1. **One release, everything in it.** v2.0.0 is the first v2 release and contains all eleven
   phases: specs, both contracts, the Ledger app on Nano and Stax/Flex, fermion-sdk, the Safe
   App, the web UI, the Ledger Live app, demos, formal verification, and the docs and ERC
   draft. Nothing is released piecemeal.
2. **Contracts are immutable.** No proxies, no owners, no initialisation, no admin. A contract
   change is a new deployment at a new address. The verifier address is fixed in each
   contract at deployment.
3. **Same address everywhere.** Every shared contract is deployed through the same
   deterministic deployer with the same salt, so it has the same address on every chain.
4. **Signed history.** Every commit and every tag on the release path is signed.
5. **Users verify, not trust.** Each artifact can be checked against something published
   separately: contract addresses and code, the Ledger catalog signature, the web bundle hash.
6. **Clean major version.** Nothing from v1 (XMSS) is deployed, so there is nothing to
   migrate. The XMSS code, docs and tests are deleted in the v2 rewrite; history keeps them.

## What ships

| # | Artifact | Source | Distribution |
|---|---|---|---|
| R1 | ML-DSA verifier and key factory (`MLDSAVerifier`, `MLDSAKeyFactory`) | [`mldsa-solidity`](https://github.com/skalenetwork/mldsa-solidity) (MIT), git submodule under `contracts/lib/` | Deterministic deployment ([below](#deterministic-deployment)) |
| R2 | Verifier interface (`IPQVerifier`, algorithm ids) | [`pq-verifier-interface`](https://github.com/skalenetwork/pq-verifier-interface) (MIT) | Compiled in; not deployed |
| R3 | Fermion Wallet implementation and wallet factory | this repository (AGPL-3.0-or-later) | Deterministic deployment; wallets are clones, created up front |
| R4 | Fermion Guard | this repository | Deterministic deployment |
| R5 | Ledger app "Fermion" (Nano S Plus, Nano X, Stax, Flex) | `ledger-app/` | Ledger Live catalog only |
| R6 | fermion-sdk | this repository | npm, package name `fermion-sdk` |
| R7 | Safe App | this repository | Custom Safe App URL (moves with the domain, [below](#web-hosting-and-domain)) |
| R8 | Web UI (static, no backend) | this repository | GitHub Pages for previews; dedicated domain before mainnet |
| R9 | Ledger Live app | this repository | Ledger Live (needs Ledger listing) |
| R10 | Event watcher (self-hostable; email and webhook) | this repository | Source; no hosted service |
| R11 | Demos (real Ledger app in Speculos, Safe 1.5.0) | `demo/` | Container images |
| R12 | Formal verification artifacts | this repository | Source, run in CI where feasible |
| R13 | Docs and the ERC draft (CC0) | `docs/` | GitHub; the ERC goes to `ethereum/ERCs` |
| R14 | Release notes and `CHANGELOG.md` | GitHub Release | The changelog explains the XMSS to ML-DSA switch |

## Branch and phases

All v2 work happens on branch `ml-dsa-v2`. It merges to `main` only when **all eleven phases**
are done. Phases run in this order:

| # | Phase |
|---|---|
| 1 | Specs (these documents) |
| 2 | Contracts and tests (old docs, old contracts and old tests deleted together) |
| 3 | Ledger app, Nano |
| 4 | fermion-sdk |
| 5 | Safe App |
| 6 | Web UI |
| 7 | Ledger app, Stax/Flex |
| 8 | Ledger Live app |
| 9 | Demos |
| 10 | Formal verification |
| 11 | Docs and ERC |

One signed commit per phase (or a short series of signed commits), pushed to GitHub after the
phase, with every signature verified before the push.

Before the v2 rewrite deletes XMSS, the last XMSS commit gets the local tag `xmss-final`. It is
pushed only on the owner's go-ahead.

## Signed commits and tags

- Every commit on `ml-dsa-v2` and on `main` is signed (`git commit -S`).
- Before every push: `git log --show-signature` over the commits being pushed, and stop on
  any commit that does not show a good signature.
- The release tag `v2.0.0` is a signed annotated tag on the merge commit on `main`. Its message
  lists the shared contracts' addresses, the Ledger app version, the fermion-sdk version and
  the web bundle hash.
- Library releases are signed tags in their own repositories (`mldsa-solidity` v1.0.0,
  `xmss-solidity` v1.1.0); Fermion pins the commits.

## Pinned dependencies

Every dependency is pinned to an exact commit or version. Bumping one is a deliberate commit
with a reason.

| Dependency | Pin |
|---|---|
| `mldsa-solidity` | v1.0.0 (pending; until then a pinned commit) |
| `pq-verifier-interface` | `6efa8e3` |
| `xmss-solidity` | v1.1.0 (pending); removed from Fermion in phase 2 |
| OpenZeppelin contracts | `acd4ff74` |
| Safe smart-account | `dc437e8f` |
| forge-std | v1.16.2 |
| solc | 0.8.37, `via_ir` |
| Foundry | v1.8.3, pinned in `.github/workflows/contracts.yml`, `.github/workflows/release.yml` and `demo/Dockerfile` (bump all three together) |
| Ledger C SDK (ML-DSA) | v26.6.5, commit `87def514`. Pinned because the app uses private `MLDSA_internal_*` symbols for seeded keygen and signing |
| Ledger Rust SDK | 1.37.1, features `mldsa` and `mldsa_optimization` |
| Web UI, SDK | lockfile; no third-party scripts at run time |

Source: [measured facts](./v2-decisions.md#measured-facts-cite-these-do-not-retype-from-memory).

## Deterministic deployment

- Deployer: the Arachnid deterministic CREATE2 deployer at
  `0x4e59b44847b379578588920cA78FbF26c0B4956C`.
- Contracts deployed through it, each with a fixed salt: `MLDSAKeyFactory`, `MLDSAVerifier`,
  the Fermion Wallet implementation and its wallet factory, and Fermion Guard.
- Same addresses on every supported chain: Ethereum mainnet, Base, Arbitrum and Optimism.
- Deployment is **permissionless**: anyone can deploy the same bytecode with the same salt and
  get the same address. There are no owners and no initialisation calls.
- Fermion Wallets are clones of the one implementation (clone with immutable args), created
  **up front** in the wallet's one setup transaction, before any funds arrive. A wallet's
  address follows from its key, so it is the same on every chain
  ([deployment](./fermion-wallet.md#deployment)).
- Local tests deploy through the same deployer, etched into the local chain at its canonical
  address, so a test exercises the same addresses as production.

The salt values are fixed in phase 2 and published with the release.

## Local-chain testing

Before release, **all testing is on local chains**. No public testnet deployment happens before
v2.0.0.

- The local chain enforces the EIP-7825 per-transaction gas cap of 2^24 = 16,777,216 gas (live
  on mainnet since Fusaka, 2025-12-03), emulated where the node allows.
- The deterministic deployer is etched at its canonical address.
- Safe 1.3.0, 1.4.1 and 1.5.0 each get compatibility tests. Modules are tested on 1.5.0 only.
- The device in every end-to-end test and demo is the real Ledger app in Speculos.
- Every measured path must fit under the cap. Today's figures
  ([measured facts](./v2-decisions.md#measured-facts-cite-these-do-not-retype-from-memory)):

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| one-tx wallet setup | 5.55M | 9.53M | 14.99M |
| first transfer (stores A) | 5.90M | 9.56M | 16.30M (store A parts ahead) |
| later transfer | 2.82M | 3.83M | 5.60M |

The release notes **must** state that same-address deployment and the per-transaction cap on
the L2s have not been verified on live networks. Gas is re-measured after the Glamsterdam
repricing (planned Q4 2026).

## Release gates

There is **no audit gate**. The release says plainly that the verifier, the key factory and the
contracts are unaudited. What does gate v2.0.0:

### Contracts

- [ ] `forge test` passes, including fuzz and invariant suites, with no skipped tests.
- [ ] Every path in the table above fits under 2^24 on the local chain.
- [ ] Safe compatibility tests pass on 1.3.0, 1.4.1 and 1.5.0.
- [ ] Differential tests of the ML-DSA verifier against independent implementations (AWS-LC,
      ZKNox) pass.
- [ ] Emergency removal drill: request, freeze, rescue transfer, cancel, and final removal after
      the timelock, with no device present for the removal itself
      ([emergency removal](./fermion-guard.md#emergency-removal)).

### Formal verification

- [ ] Invariant fuzzing and symbolic proofs for Fermion Wallet and Fermion Guard, including the
      equivalence of inline and stored approvals
      ([inline and stored approvals](./fermion-guard.md#inline-and-stored-approvals)).
- [ ] A machine-checked proof that the ML-DSA verifier matches FIPS 204, with open-source tools
      only (for example K/Kontrol, hevm, Halmos). The plan, with effort estimates, is proposed
      before the work starts.
- [ ] The device model is checked against the **real** app in Speculos, on Nano and on Stax/Flex:
      generated button and touch sequences, screens and outputs compared with the model at
      every step.

### Ledger app

- [ ] Speculos tests pass on every supported model.
- [ ] Public keys and signatures match an independent ML-DSA implementation byte for byte
      (deterministic test build), and restore-from-phrase reproduces the public key.
- [ ] Real-device tests (signing time, stack, path enforcement) pass on Nano S Plus and on Flex
      or Stax. Nano X is emulator-only until a device is available.
- [ ] The release build signs hedged; deterministic signing is absent from it.

### End to end

- [ ] Wallet: create (one-tx setup), receive, first transfer, later transfer, batch, NFT send,
      Safe-owner signature, plain-text message; each with the real app in Speculos.
- [ ] Guard: enroll, inline approval, stored approval, revoke, rotate, module transaction on
      1.5.0, emergency removal; each through the Safe App.

## Ledger catalog submission

- The device app is named **Fermion** and is distributed through the Ledger Live catalog only.
  Sideloaded builds are for development with test keys.
- Before submission: a trademark and name search on "Fermion" (owner's task), and confirmation
  that the derivation purpose (placeholder `204'`) is unregistered in SLIP-44/BIP-43 usage.
- The submission documents the private SDK symbols the app depends on, and asks Ledger for a
  public seeded ML-DSA API.
- The Ledger Live app needs a Ledger listing and permission to exchange Fermion's custom APDUs
  with the device. It is built in this pass but untested against Ledger's review.
- ML-DSA-87 is not in the device app (no `HAVE_MLDSA_87`); the contracts accept it for other
  signers ([residual risks](./security.md#residual-risks)).

## Web hosting and domain

- Previews are served from GitHub Pages (`skalenetwork.github.io`). That origin is shared by
  every page of the organisation, including WebHID permission and storage; the risk is
  accepted for previews only.
- A **dedicated domain is required before mainnet use**. The repository rename
  (`fermionwallet` to `fermion`), the move to the domain, the Safe App URL change and the
  GitHub description update happen together, not before.
- The web UI is a static page with no backend: pinned dependencies, no third-party scripts, a
  strict Content Security Policy, and a bundle hash published with each release. It can also
  be run locally.
- No page ever has a recovery-phrase field ([key custody](./security.md#key-custody-and-hardware-policy)).

## Publishing v2.0.0

1. All gates above pass on the final commit of `ml-dsa-v2`.
2. Merge `ml-dsa-v2` into `main`; signed tag `v2.0.0` on the merge.
3. Deploy the shared contracts through the deterministic deployer on each chain, and check the
   addresses match the local-chain addresses.
4. Publish fermion-sdk to npm; publish the web bundle and its hash; publish the Safe App.
5. Submit the Ledger app; announce only once it is in the Ledger Live catalog.
6. GitHub Release with: addresses per chain, Ledger app version, fermion-sdk version, web bundle
   hash, gate evidence, the "unaudited" statement, the unverified-on-live-networks statement,
   and the [residual risks](./security.md#residual-risks).

## After v2.0.0

- **Contracts:** never patched. A defect is fixed by a new deployment. Wallet holders move funds
  with a signed transfer to a wallet on the new implementation; Safes re-enroll on the new Guard.
  The same applies to a new verifier: the verifier is fixed per contract, never switched.
- **Ledger app:** a defect is fixed by a new catalog version. Ledger Live installs only the latest
  version. Because keys derive from the phrase, an app update or reinstall does not change keys.
- **Security reports:** [`SECURITY.md`](../SECURITY.md). Fixes are released before details are
  disclosed.

## Not yet decided

These are open; this document does not decide them.

- The dedicated domain name.
- The key that signs release tags, and who controls the domain.
- Whether addresses are also published in a machine-readable manifest or ENS records.
- The salt values (phase 2).
- Whether Nano X ships, given it has no physical test device.
- The version numbering of fermion-sdk and the Ledger app relative to the product's v2.0.0.
