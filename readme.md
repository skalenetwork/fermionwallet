# Fermion

<p align="center">
  <img src="./assets/fermionguard-logo.svg?v=2" alt="Fermion logo — a fermion holding a quantum" width="420"/>
</p>

**Post-quantum signatures for Ethereum accounts and Safes.** Every authority is a hybrid
signature: ECDSA (secp256k1) and ML-DSA (FIPS 204) over the same EIP-712 digest, both required,
both made on a Ledger after the user reads the details on its screen.

> **Status: in development on branch `ml-dsa-v2`. Unaudited. Not deployed on any public network.**
> Do not put real funds behind it. The v2 contracts, Ledger app, SDK and apps are being built in
> phases ([release](docs/release.md#branch-and-phases)); `main` still holds the earlier XMSS
> version until v2.0.0 is complete.

## Two products

| | Fermion Wallet | Fermion Guard |
|---|---|---|
| What it is | A post-quantum cold vault | A post-quantum gate for a Safe |
| What it protects | Its own balance | An existing Safe, with its owners and threshold |
| Authorization | A hybrid signature from the wallet's key | The owners' threshold **and** a hybrid quantum approval from the Safe's Quantum Administrator |
| Can do | Receive anything; send ETH, ERC-20, ERC-721, ERC-1155 (up to 8 per signature); sign as a Safe owner; sign plain-text messages | Gate every Safe transaction and module transaction; inline or stored approvals; key rotation; emergency removal by owners after 14 days |
| Cannot do | DeFi, approvals, arbitrary calls, modules | Act without the owners |
| Spec | [docs/fermion-wallet.md](docs/fermion-wallet.md) | [docs/fermion-guard.md](docs/fermion-guard.md) |

One Ledger app, **Fermion** (Nano S Plus, Nano X, Stax, Flex), signs for both, with ML-DSA-44 by
default and ML-DSA-65 as an option. Keys derive from the Ledger's recovery phrase, one key per
wallet or Safe. No Fermion interface ever asks for the recovery phrase.

## Documentation

| Document | What it covers |
|---|---|
| [Fermion Wallet](docs/fermion-wallet.md) | The vault contract |
| [Fermion Guard](docs/fermion-guard.md) | The Safe guard |
| [Ledger app](docs/ledger-app.md) | Key derivation, signing flows, screens |
| [Signer requirements](docs/signer-requirements.md) | What any conforming signer must do |
| [nShield signer](docs/nshield-signer.md) | Design for an HSM signer |
| [Security](docs/security.md) | Threat model, key custody, residual risks |
| [fermion-sdk](docs/sdk.md) | The client library |
| [Release](docs/release.md) | Build, test and release process |
| [User guide](docs/user-guide.md) | How to use it |
| [ERC draft](docs/erc-draft-hybrid-pq-signatures.md) | The hybrid signature format, as a standard |
| [Decision record](docs/v2-decisions.md) | Why v2 is the way it is |

## Libraries

- [`mldsa-solidity`](https://github.com/skalenetwork/mldsa-solidity): the on-chain ML-DSA verifier
  and key factory (MIT, unaudited).
- [`pq-verifier-interface`](https://github.com/skalenetwork/pq-verifier-interface): the shared
  `IPQVerifier` interface and algorithm identifiers (MIT).
- `fermion-sdk` on npm: the client library (built in a later phase).

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## About the author

**Stan (Konstantin) Kladko** — the rare builder who has worked on both sides of the quantum threat: the physics that creates it and the cryptography that must survive it.

- **Quantum physicist by training** — Ph.D. from the Max Planck Institute, M.S. from Kharkov University; Otto Hahn Research Fellow at Stanford University, where he worked with Nobel laureate Robert B. Laughlin on strongly correlated quantum systems; Director's Fellow in the Theoretical Division at Los Alamos National Laboratory, conducting national-security research in quantum materials.
- **Production cryptographer by trade** — Core Cryptography Lead at Ingrian Networks (enterprise data-privacy infrastructure later absorbed into SafeNet/Thales HSM lineage) and core computer-science team member at Sun Microsystems.
- **Ran the lab that certifies the world's crypto** — Director of Aspect Labs / BKP Security, a Silicon Valley cryptographic-module testing laboratory operating under NIST's Cryptographic Module Validation Program (CMVP), delivering FIPS 140-2 validations, Common Criteria evaluations, and FISMA assessments for government-grade cryptography. His lab work included side-channel security — presenting SPA/DPA (power-analysis) testing methodology to the NIST community. He hasn't just built secure cryptography; he has been the examiner that governments trust to certify it.
- **Proven at blockchain scale** — Co-founder and CTO of SKALE, an Ethereum-aligned blockchain network securing real value in production with BLS threshold cryptography his team took from paper to mainnet.
- **Serial infrastructure founder** — previously co-founded Galactic Exchange (big-data container clusters) and Cloudessa (cloud network-access security).

Few people on earth have run quantum-materials research at a national lab, directed a NIST-accredited cryptographic validation laboratory, shipped enterprise-grade cryptography, and operated a live blockchain network. That intersection is exactly what post-quantum custody requires — and it is why institutions evaluating their PQ migration path start the conversation with Stan.

Fermion is his answer to the question every custody board is now asking: *what protects the vault the day classical signatures stop being enough?*

## License

Fermion is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`). Libraries it uses keep their own licences: the ML-DSA verifier
([`mldsa-solidity`](https://github.com/skalenetwork/mldsa-solidity)) and the XMSS library
([`xmss-solidity`](https://github.com/skalenetwork/xmss-solidity)) are MIT, and the vendored
dependencies under `contracts/lib/` are under their own terms.
