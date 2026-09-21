# FermionWallet Release Specification

This document defines what a FermionWallet release is, which components ship together, the gates each release must pass, the step-by-step release procedure, and how fixes, upgrades, and incidents are handled after release.

It does not restate component designs. Each requirement links to the document that owns it: the [MVP spec](./fermionwalletspec.md), [Guard](./fermionwallet-guard-module.md), [Key Registry](./quantum-key-registry.md), [Pre-approval Engine](./pre-approval-engine.md), [Ledger XMSS app](./ledger-xmss-app.md), [Add-on Service](./fermionwallet-add-on-service.md), [Service deployment](./fermionwallet-gnosis-service-deployment.md), [Hardware security policy](./hardware-security-policy.md), and [Threat model](./threat-model.md).

Items marked **Proposed** are defaults introduced by this document that have not yet been decided. They are collected in [Open decisions](#12-open-decisions).

## Contents

1. [Release principles](#1-release-principles)
2. [What ships in a release](#2-what-ships-in-a-release)
3. [Versioning and compatibility](#3-versioning-and-compatibility)
4. [Release stages](#4-release-stages)
5. [Release gates](#5-release-gates)
6. [Release procedure](#6-release-procedure)
7. [Supported environments](#7-supported-environments)
8. [Upgrades and migration](#8-upgrades-and-migration)
9. [Fixes, incidents, and rollback](#9-fixes-incidents-and-rollback)
10. [Roles and sign-off](#10-roles-and-sign-off)
11. [Current readiness](#11-current-readiness)
12. [Open decisions](#12-open-decisions)
13. [Release checklist](#13-release-checklist)

---

## 1. Release principles

1. **Contracts are immutable.** The Guard, Key Registry, and XMSS verifier are non-upgradeable. A contract "release" is a new deployment at new addresses, never an in-place change ([Guard: Immutability and deployment hygiene](./fermionwallet-guard-module.md#immutability-and-deployment-hygiene)).
2. **What was audited is what ships.** Every mainnet contract release deploys bytecode built from the exact commit the auditor signed off on, and the published `codehash` is the proof.
3. **Parameter lock.** The Ledger app, the on-chain verifier, and the Safe App are locked to one XMSS parameter set (`XMSS-SHA2_20_256` for 1.x). A release that changes the parameter set is a major release ([Ledger XMSS app: Security requirements](./ledger-xmss-app.md#security-requirements)).
4. **Fail closed.** No release may introduce a path that moves tokens outside `Safe.execTransaction` → Guard → ERC-20 `transfer` ([MVP spec §9](./fermionwalletspec.md#9-mvp-acceptance-criteria)).
5. **No-brick is a release invariant.** Every release must preserve both guaranteed exits: the quantum-approved removal after `ADMIN_TIMELOCK`, and the owners-only emergency de-guard after `EMERGENCY_TIMELOCK`. Both are exercised before every release (Gate G5).
6. **Users verify, not trust.** Every artifact a user installs can be checked against something published independently: contract codehashes, the Ledger catalog signature, the Safe App's IPFS CID, and the service image digest.

## 2. What ships in a release

A FermionWallet release is a set of versioned artifacts published together under one product version.

| # | Artifact | Source | Distribution | Owner doc |
|---|---|---|---|---|
| A1 | `XMSS` verifier library | `contracts/src/XMSS.sol` | CREATE2 deployment, verified source | [contracts/README](./contracts/README.md) |
| A2 | `QuantumKeyRegistry` | `contracts/src/QuantumKeyRegistry.sol` | CREATE2 deployment, verified source | [Key Registry](./quantum-key-registry.md) |
| A3 | `FermionWalletGuard` (transaction guard + module guard) | `contracts/src/FermionWalletGuard.sol` | CREATE2 deployment, verified source | [Guard](./fermionwallet-guard-module.md) |
| A4 | `deployments.json` | repository root | Git (signed tag), mirrored to `fermionwallet.eth` ENS text records | [Service deployment §2.3](./fermionwallet-gnosis-service-deployment.md#23-canonical-deployments--address-verification) |
| A5 | FermionWallet XMSS Ledger app | Ledger app repository | Ledger Live app catalog | [Ledger XMSS app](./ledger-xmss-app.md) |
| A6 | FermionWallet Safe App | Safe App bundle | `https://app.fermionwallet.io` + IPFS pin (ENS `contenthash`) | [Service deployment §2.4](./fermionwallet-gnosis-service-deployment.md#24-safe-app-distribution--verification) |
| A7 | Add-on service image | service source | `ghcr.io/skalenetwork/fermionwallet-service`, pinned by digest | [Service deployment §3](./fermionwallet-gnosis-service-deployment.md#3-add-on-service-infrastructure-specification) |
| A8 | Documentation and product site | `*.md`, `site/` | GitHub, GitHub Pages | this repository |
| A9 | Release notes | GitHub Release | GitHub Releases | §6.7 |

`XMSSStateful.sol` is a reference and test wrapper. It is not a deployed release artifact: leaf consumption in production is enforced by the Registry/Guard bitmap.

## 3. Versioning and compatibility

### 3.1 Product version

The product follows [Semantic Versioning](https://semver.org/) as `MAJOR.MINOR.PATCH`. The product version is what users see in release notes, the Safe App footer, and `deployments.json`.

| Change | Bump |
|---|---|
| New contract deployment (any bytecode change to A1–A3) | **MINOR** at least; **MAJOR** if enrolled Safes must re-run the key ceremony or the pre-approval EIP-712 types change |
| XMSS parameter set change | **MAJOR** |
| Ledger app, Safe App, or service change with no contract change | **MINOR** for features, **PATCH** for fixes |
| Documentation or site only | none (not a release) |

### 3.2 Component versions

Each artifact also carries its own version:

- **Contracts:** a `VERSION` constant returning the product version at deployment, plus the `codehash` in `deployments.json`.
- **Ledger app:** its own SemVer, reported by `GET_APP_CONFIG` together with the parameter set.
- **Safe App and service:** the product version they were released with.

### 3.3 Compatibility matrix

Every release publishes a compatibility matrix in its release notes. The Safe App and the service refuse to operate on combinations outside it.

| Product | Contracts (`deployments.json` version) | Ledger app (min) | Parameter set | Safe App | Service |
|---|---|---|---|---|---|
| 1.0.0 | 1.0.0 | 1.0.0 | `XMSS-SHA2_20_256` | 1.0.x | 1.0.x |

Enforcement:

- **Safe App:** on load, reads the connected Safe's guard address, looks it up in `deployments.json`, and checks `EXTCODEHASH` against the published `codehash`. On Ledger connect, it checks the app version and parameter set via `GET_APP_CONFIG`. It refuses to continue on any mismatch.
- **Service:** refuses to start if the configured Guard/Registry `codehash` doesn't match `deployments.json` for its version.
- **Ledger app:** refuses to sign payloads whose EIP-712 domain version it doesn't recognize.

## 4. Release stages

A version moves through four stages. Each stage has an entry gate; skipping a stage is not permitted for contract changes.

| Stage | Networks | Ledger app | Who may use it | Real funds |
|---|---|---|---|---|
| **Dev** | local, Sepolia | sideloaded dev build (`PENDING LEDGER REVIEW`) | engineers | never |
| **Testnet beta** | Sepolia and one L2 testnet | Ledger-signed developer-mode build | design partners | never |
| **Mainnet pilot** | Ethereum mainnet (single chain) | Ledger-signed developer-mode build | named pilot Safes under a written pilot agreement | yes, with a per-Safe value cap (**Proposed:** agreed per pilot) |
| **General availability** | all chains in §7.1 | Ledger Live catalog listing | anyone | yes |

Rules from the owner documents that apply at every stage:

- A device showing `PENDING LEDGER REVIEW` must never hold a production key ([Ledger XMSS app: Installation](./ledger-xmss-app.md#installation-supported-devices-and-updates)).
- Sideloaded builds are restricted to testnets ([Ledger XMSS app: Security requirements](./ledger-xmss-app.md#security-requirements)).
- No mainnet deployment before an external audit ([Guard: Production constraints](./fermionwallet-guard-module.md#production-constraints); [contracts/README](./contracts/README.md)).

## 5. Release gates

A release may not advance to the next stage until every gate for that stage passes. Each gate result is recorded in the release notes with a link to its evidence (CI run, report, or signed statement).

### G1 — Contracts correctness (all stages)

- [ ] `forge test` passes, including fuzz suites, with no skipped tests.
- [ ] XMSS verifier passes the reference vectors at h = 4, 10, and 20 and the tamper/negative tests ([contracts/README](./contracts/README.md)).
- [ ] Gas: `test_gas_verify_h20` passes (verification ≤ 1.1M gas; last measured 999,247).
- [ ] Integration test against a real Safe (v1.3.0 and v1.4.1): a pre-approval pinned to the `safeTxHash` of nonce N executes at nonce N, and the Guard's `getTransactionHash(..., nonce() - 1)` recomputation matches ([Guard: Production constraints](./fermionwallet-guard-module.md#production-constraints)).
- [ ] Malformed MultiSend fuzzing (truncated header, overrunning `dataLength`, trailing bytes, more than `maxBatchLegs`) reverts cheaply.
- [ ] A test proves `requestEmergencyDeGuard` succeeds while the Guard is paused (emergency allow runs before the pause check).
- [ ] Module guard coverage tested on Safe 1.5+: `execTransactionFromModule` cannot bypass policy.
- [ ] Every item in the Guard's "Virtual brain test against Safe semantics" has a named test.
- [ ] Slither and `solhint` clean, or every finding triaged in the release notes.

### G2 — Ledger app (testnet beta and later)

- [ ] `speculos`/`ragger` CI passes: signing flow, counter monotonicity across power cycles, exhaustion refusal, chunked payloads, and UI snapshots for every screen on NBGL and BAGL ([Ledger XMSS app: Deliverables](./ledger-xmss-app.md#deliverables-and-validation)).
- [ ] All device UI acceptance criteria pass ([Ledger XMSS app: Device UI acceptance criteria](./ledger-xmss-app.md#device-ui-acceptance-criteria)).
- [ ] Cross-verification: 10,000 device signatures verify in the Solidity verifier.
- [ ] Parameter set reported by `GET_APP_CONFIG` equals the parameter set of the verifier being released.

### G3 — Safe App and service (testnet beta and later)

- [ ] Every acceptance criterion in the Add-on Service's key-ceremony and pre-approval sections passes ([Add-on Service](./fermionwallet-add-on-service.md)).
- [ ] Codehash and compatibility checks (§3.3) are tested with a deliberately mismatched Guard address and fail visibly.
- [ ] Safe App CSP restricts iframe embedding to Safe{Wallet} ([Service deployment §5](./fermionwallet-gnosis-service-deployment.md#5-security--deployment-hardening-checklist)).
- [ ] Service starts with no signing keys configured and holds none.

### G4 — End-to-end (testnet beta and later)

- [ ] Full onboarding on a fresh Safe per [UI help: Adding the Guard](./ui-help.md#adding-the-guard-to-an-existing-safe): preflight, key ceremony, `setGuard`, verification transfer, **Protected ✓**.
- [ ] One single transfer, one batch (≥ 20 legs), one denial, one revocation, and one replaced-transaction case run end to end.
- [ ] Key rotation completes and the old key's pending approvals behave as specified in [Key Registry](./quantum-key-registry.md).

### G5 — No-brick drill (every stage, every release)

- [ ] Quantum-approved Guard removal succeeds after `ADMIN_TIMELOCK`, and any single owner can revoke it during the delay.
- [ ] Owners-only emergency de-guard succeeds after `EMERGENCY_TIMELOCK` with the add-on service **offline** and **no** Ledger present ([Service deployment §5](./fermionwallet-gnosis-service-deployment.md#5-security--deployment-hardening-checklist)).
- [ ] Emergency de-guard succeeds while the Guard is paused.

### G6 — External review (mainnet pilot and later)

- [ ] Independent audit of A1–A3 covering the exact release commit; all critical and high findings fixed and re-reviewed; report published with the release.
- [ ] Ledger security review submitted (pilot) and passed with catalog listing (GA).
- [ ] Threat model reviewed against the release and updated ([Threat model](./threat-model.md)).

### G7 — Publication (mainnet pilot and later)

- [ ] Deployed bytecode verified on Etherscan (or the chain's explorer) and Sourcify for every chain.
- [ ] `EXTCODEHASH` of each deployed contract equals the `codehash` in `deployments.json` on every chain.
- [ ] `deployments.json` and ENS records match.
- [ ] Safe App IPFS CID in the release notes matches the ENS `contenthash` and the bundle served at the primary URL.

## 6. Release procedure

### 6.1 Freeze

1. Create a release branch `release/X.Y` from `main`. Only fixes merge into it.
2. Open a tracking issue listing every gate in §5 for this version.

### 6.2 Build

1. Build every artifact from a clean checkout of the release commit, with pinned toolchains (Solidity compiler version, Foundry, Rust toolchain, Node.js, lockfiles).
2. Contracts must build reproducibly: two independent builds produce identical bytecode. Record the bytecode hash in the tracking issue.

### 6.3 Test and review

1. Run gates G1–G5 on the release commit.
2. For mainnet stages, deliver the release commit to the auditor (G6). Any fix produces a new commit, and G1–G5 re-run on it.

### 6.4 Tag

1. Create a signed annotated tag `vX.Y.Z` on the final commit.
2. Tag message lists: contract bytecode hashes, Ledger app version, parameter set, Safe App bundle hash, and service image digest.

### 6.5 Deploy contracts

1. Deploy A1–A3 with the CREATE2 deployment script against the canonical singleton factory, using the salts pinned for this version ([Service deployment §2.1](./fermionwallet-gnosis-service-deployment.md#21-deterministic-factory-deployment-create2)).
2. Deploy to one chain first, run G7 checks there, then deploy to the remaining chains.
3. Fill `deployments.json` with addresses and codehashes. Addresses for a version are written once and never edited.

### 6.6 Publish client artifacts

1. **Ledger app:** submit the tagged build to Ledger; for GA, wait for catalog listing before announcing.
2. **Safe App:** deploy the bundle to the primary URL, pin to IPFS, update the ENS `contenthash`.
3. **Service:** push the image to GHCR; publish its digest.
4. **ENS:** update the `fermionwallet.eth` text records for contract addresses.
5. Run G7.

### 6.7 Announce

Publish a GitHub Release for `vX.Y.Z` containing:

- summary of changes and the compatibility matrix (§3.3),
- every artifact identifier: contract addresses and codehashes per chain, Ledger app version, Safe App URL and IPFS CID, service image digest,
- gate evidence links, including the audit report,
- upgrade instructions for enrolled Safes (§8), if any,
- known issues.

Then update the README and the product site if the release changes status or availability.

## 7. Supported environments

### 7.1 Chains

**Proposed for 1.0 GA:** Ethereum mainnet, Arbitrum One, Optimism, Base, and Polygon — the chains named in [Service deployment §2.1](./fermionwallet-gnosis-service-deployment.md#21-deterministic-factory-deployment-create2). A chain is supported only if the canonical CREATE2 singleton factory and Safe's canonical `MultiSendCallOnly` exist there, and G7 passed on it.

Deploying to other chains is permissionless and yields identical addresses ([Service deployment §2.3](./fermionwallet-gnosis-service-deployment.md#23-canonical-deployments--address-verification)), but such chains are unsupported until listed in a release.

### 7.2 Safe versions

| Safe version | Supported | Condition |
|---|---|---|
| < 1.3.0 | No | Guards don't exist |
| 1.3.0, 1.4.1 | Yes | No enabled modules |
| 1.5.0+ | Yes | No enabled modules, or FermionWallet module guard installed via `setModuleGuard` |

Each release lists the exact Safe versions its integration tests covered. A Safe version not tested in G1 and G4 is not supported by that release.

### 7.3 Ledger devices

Nano S Plus, Nano X, Stax, and Flex, on the minimum firmware pinned by the Ledger app release. The original Nano S is not supported ([Ledger XMSS app: Installation](./ledger-xmss-app.md#installation-supported-devices-and-updates)).

## 8. Upgrades and migration

### 8.1 Client-only upgrades

Ledger app, Safe App, and service releases with no contract change need no action from enrolled Safes beyond installing the update.

- **Ledger app:** updates preserve the seed and leaf counter. Uninstalling destroys them and forces key rotation ([Ledger XMSS app: Installation](./ledger-xmss-app.md#installation-supported-devices-and-updates)). Release notes must repeat this warning.
- **Service:** stateless container swap with forward-only migrations ([Service deployment §3.3](./fermionwallet-gnosis-service-deployment.md#33-deployment-runbook)).

### 8.2 Contract upgrades

A new Guard is adopted by each Safe through Safe governance:

1. The new contracts are deployed at new addresses (§6.5).
2. The Safe creates an `ADMIN`-class pre-approval for `setGuard(<new Guard>)`. It executes after `ADMIN_TIMELOCK`, and any owner can revoke it during the delay.
3. If the release includes a new Registry, the Safe runs a new key ceremony against it before step 2. Enabling a Guard with no active key would block every transaction.
4. The Safe App walks owners through these steps and shows the old and new codehashes side by side.

### 8.3 Support window

**Proposed:** after a new contract version reaches GA, the previous contract version remains supported by the Safe App and service for 12 months, receiving security fixes to client components. Contracts themselves receive no fixes (§9.2); a contract-level vulnerability is handled as an incident.

## 9. Fixes, incidents, and rollback

### 9.1 Client fixes (Safe App, service)

Patch releases follow the full procedure but may run gates G1, G5, and G6 as no-ops when no contract or Ledger code changed. Rollback is by redeploying the previous bundle or image digest.

### 9.2 Contract vulnerabilities

Deployed contracts cannot be patched or rolled back.

1. **Contain:** pause affected Guards. Pausing is fast and low-privilege and fails closed; unpausing is slow and requires Safe governance plus a timelock ([Guard: Emergency pause](./fermionwallet-guard-module.md#emergency-pause-circuit-breaker)). The emergency de-guard stays available while paused.
2. **Notify:** alert every enrolled Safe through all configured channels, with instructions.
3. **Fix:** ship a new contract version through the full procedure, including audit review of the fix.
4. **Migrate:** Safes move to the new Guard per §8.2, or remove the Guard via the emergency path if they choose.

### 9.3 Ledger app defects

There is no rollback: Ledger Live installs the latest version only. A defect is fixed by publishing a new version ([Ledger XMSS app: Installation](./ledger-xmss-app.md#installation-supported-devices-and-updates)). If a defect could cause leaf reuse or blind signing, instruct users to stop signing immediately; the on-chain bitmap independently blocks leaf reuse.

### 9.4 Suspected key compromise

Follow the revocation and emergency procedure in [Key Registry](./quantum-key-registry.md). This is an operational incident, not a release.

### 9.5 Vulnerability disclosure

A `SECURITY.md` with a private reporting channel and a response-time commitment must exist before the mainnet pilot. Security fixes are released before details are disclosed; the advisory is published with or after the fix.

## 10. Roles and sign-off

| Role | Responsibility | Signs off |
|---|---|---|
| Release manager | Runs the procedure, owns the tracking issue, publishes the release | every stage |
| Contracts lead | G1, contract deployment, G7 | every stage |
| Ledger app lead | G2, Ledger submission | testnet beta and later |
| App/service lead | G3, Safe App and service publication | testnet beta and later |
| Security reviewer (independent of the authors) | G5, G6 triage, threat-model update | mainnet pilot and later |

A release advances only with sign-off from every role listed for its stage. One person may hold several roles, except that the security reviewer must not be the author of the code under review.

## 11. Current readiness

State of the repository at the time of writing, against the artifacts in §2:

| Artifact | State |
|---|---|
| A1 `XMSS` verifier | Implemented with tests and gas benchmarks; not audited |
| A2 `QuantumKeyRegistry` | In progress in `contracts/src/`; no tests yet |
| A3 `FermionWalletGuard` | In progress in `contracts/src/`; no tests yet |
| Pre-approval engine | `PreApprovalEngine.sol` in progress in `contracts/src/`; no tests yet |
| A4 `deployments.json` | Format specified; file not yet created |
| CREATE2 deployment script | Referenced by the deployment spec; `contracts/script/` is empty |
| A5 Ledger app | Specified; not yet built |
| A6 Safe App | Screens designed (`assets/ui/`); not yet built |
| A7 Service | Specified; not yet built |
| A8 Docs and site | Published |
| `SECURITY.md`, `CHANGELOG.md` | Not yet created |

No stage in §4 has been entered. The first release target is **Testnet beta**.

## 12. Open decisions

| # | Decision | Proposed default |
|---|---|---|
| D1 | GA chain list | Ethereum, Arbitrum One, Optimism, Base, Polygon (§7.1) |
| D2 | Mainnet pilot value cap | Agreed per pilot Safe in the pilot agreement |
| D3 | Previous-version support window | 12 months after the next version's GA (§8.3) |
| D4 | Key that signs release tags and `deployments.json` | A dedicated hardware-backed release key, published in the README |
| D5 | Ownership and control of `app.fermionwallet.io` and `fermionwallet.eth` | Held by the organization, not an individual; changes require two people |
| D6 | Auditor and audit scope | Contracts A1–A3 plus the Ledger app's signing and counter logic |
| D7 | Vulnerability disclosure channel and response time | Private email plus GitHub private advisories; acknowledge within 2 business days |
| D8 | Concrete `ADMIN_TIMELOCK` and `EMERGENCY_TIMELOCK` values for 1.0 | 48 hours and 14 days, as used in the user guide |

## 13. Release checklist

Copy into the release tracking issue.

```markdown
## Release vX.Y.Z — stage: <Dev | Testnet beta | Mainnet pilot | GA>

### Freeze and build
- [ ] release/X.Y branch created
- [ ] Toolchains pinned; reproducible contract build confirmed (bytecode hash: ...)

### Gates
- [ ] G1 Contracts correctness
- [ ] G2 Ledger app
- [ ] G3 Safe App and service
- [ ] G4 End-to-end
- [ ] G5 No-brick drill
- [ ] G6 External review (pilot/GA)
- [ ] G7 Publication (pilot/GA)

### Publish
- [ ] Signed tag vX.Y.Z
- [ ] Contracts deployed and verified on: ...
- [ ] deployments.json updated; ENS records updated
- [ ] Ledger app submitted / listed
- [ ] Safe App deployed; IPFS CID: ...
- [ ] Service image pushed; digest: ...
- [ ] GitHub Release published with compatibility matrix and gate evidence
- [ ] README and product site updated

### Sign-off
- [ ] Release manager
- [ ] Contracts lead
- [ ] Ledger app lead
- [ ] App/service lead
- [ ] Security reviewer
```
