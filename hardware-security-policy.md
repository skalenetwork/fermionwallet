# Hardware Security Policy — Ledger-Only Architecture

## FermionWallet Cryptographic Module (FCM)
### Hardware: Ledger device (Nano S Plus / Nano X / Stax / Flex), ST33-family Secure Element
### Firmware: Ledger OS (BOLOS) + FermionWallet XMSS app v1.x

**Document Version:** 2.0
**Date:** September 2026
**Author:** FermionWallet Security & Cryptography Team

> **Supersedes** the former FIPS 140-3 security policy for the backend HSM (`FW-HSM-v1.0`). That module has been **removed from the architecture**: FermionWallet is Ledger-only. The sole cryptographic module is the Administrator's Ledger secure element running the [FermionWallet XMSS app](./ledger-xmss-app.md). There is no server HSM, no cloud enclave, no host-side keystore — and therefore **no Root Master Key**: at-rest protection of key material is intrinsic to the secure element and needs no module-managed key-wrapping hierarchy.
>
> **Certification note.** Ledger secure elements are certified under **Common Criteria (EAL5+/EAL6+, AVA_VAN.5)** by ANSSI, not FIPS 140-3. This policy therefore does not claim FIPS validation; it maps the security objectives previously stated in FIPS terms onto the Ledger platform and states the invariants the FermionWallet XMSS app must enforce.

---

## 1. Module Overview & Cryptographic Boundary

The cryptographic module is the Ledger device's **ST33-family secure element (SE)** executing the FermionWallet XMSS app under Ledger OS. It generates, stores, and exercises:

- the stateful hash-based **XMSS key** (RFC 8391 / NIST SP 800-208, `XMSS-SHA2_20_256`: $n=32, w=16, h=20$) — the post-quantum half of every hybrid pre-approval, and
- the classical **ECDSA secp256k1 key** (`quantumAdmin` EOA) — the EIP-712 half,

both confined to the SE. The physical boundary is the SE package; the MCU, USB/BLE transport, host browser, and backend relayer are all **outside** the boundary and are treated as untrusted.

```text
+---------------------------- Ledger device -----------------------------+
|  +----------------- Secure Element (boundary) ---------------------+   |
|  |  FermionWallet XMSS app                                         |   |
|  |   - SK_SEED / SK_PRF (XMSS)      - SHA-256 engine               |   |
|  |   - secp256k1 admin key          - TRNG + DRBG                  |   |
|  |   - Monotonic leaf counter (SE NVRAM, increment-only)           |   |
|  |   - PIN verification, attestation key                           |   |
|  +--------------------------^--------------------------------------+  |
|                             | (screen + buttons: trusted display/input)|
+-----------------------------+------------------------------------------+
                              | USB / BLE (untrusted transport)
                     Host: Safe App / relayer daemon (holds no keys)
```

**Trusted I/O:** the device screen and buttons are the only trusted display and control path. Everything the Administrator confirms is rendered by the SE-controlled UI, never by the host.

---

## 2. Roles & Authentication

| Role | Authentication | Notes |
|---|---|---|
| **Administrator (User)** | Device PIN (4–8 digits, SE-enforced) + physical possession | 3 consecutive PIN failures wipe the device (zeroization). All signing services require PIN-unlocked session **and** per-operation physical confirmation. |
| **Relying party (host/backend)** | None (untrusted) | May submit requests and read public outputs only; cannot authorize anything. |
| **Safe owners / Crypto-Officer duties** | On-chain (owner co-signatures) | Governance actions (key registration, rotation, emergency de-guard) are authorized on-chain, not on the device — there is no privileged device role beyond the Administrator. |

---

## 3. Services

| Service (APDU) | Role | SSPs touched | Description |
|---|---|---|---|
| `GEN_XMSS_KEY` | Administrator | SK_SEED, SK_PRF (create); leaf counter (init = 0) | Generates the XMSS key from SE TRNG. **Not derived from the BIP-39 seed** — deliberately unrecoverable from the 24 words (a restore would reset leaf state and enable reuse-forgery). Runs a pairwise consistency test; zeroizes on failure. |
| `GET_XMSS_ROOT` | Any | none (public) | Returns `xmssRoot`, `treeHeight`, `parameterSet`. |
| `ATTEST_KEY` | Administrator | attestation key (read) | Clear-signs EIP-712 `QuantumKeyAttestation{safe, quantumAdmin, xmssRoot, treeHeight, parameterSet, registryNonce}` on-device for the registration ceremony. |
| `SIGN_PREAPPROVAL` | Administrator | SK_SEED, SK_PRF, admin key (read); leaf counter (increment) | Renders token/recipient/amount/window/Safe nonce/leaf index on the trusted screen; one physical confirmation releases **both hybrid halves** (ECDSA EIP-712 + XMSS) over the same digest. |
| `GET_STATUS` | Any | none (public) | App version, `xmssRoot`, current leaf index, leaves remaining ($2^h - idx$), key status. |
| Device wipe / app delete | Administrator (PIN) or automatic (3 PIN failures) | all CSPs | Zeroization — see §5. |

### 3.1 Leaf-counter invariants (enforced in SE firmware)

1. **Counter-before-signature.** `SIGN_PREAPPROVAL` reserves index $idx_{sig}$, commits $idx \leftarrow idx_{sig}+1$ to SE NVRAM, and only then computes and emits the signature. A power-pull mid-operation wastes leaf $idx_{sig}$; it can never reuse it.
2. **Exhaustion.** The app refuses to sign when $idx_{sig} \ge 2^h$ — all $2^h$ leaves (indices $0 \dots 2^h-1$) are usable; no off-by-one sacrifices the final leaf.
3. **No rollback path.** The counter is increment-only in SE NVRAM; no APDU, OS update, or restore can decrement or reset it while the key exists. Deleting the key destroys the seeds with the counter — a fresh key ceremony (new root, on-chain registration) is the only "reset."

---

## 4. Sensitive Security Parameters

**CSPs (secret, never leave the SE):**

1. **`SK_SEED`** — 256-bit XMSS WOTS+ derivation seed (SE TRNG).
2. **`SK_PRF`** — 256-bit XMSS message-randomizer key.
3. **secp256k1 Administrator private key** (`quantumAdmin`).
4. **Device PIN** verification data and SE-internal attestation private key.

**PSPs (public, integrity-protected):** `xmssRoot`, `treeHeight`, `parameterSet`, `quantumAdmin` address, app version.

**Protected state (not a key, CSP-grade tamper handling):** the **monotonic leaf counter** — rollback is a forgery enabler and is blocked by SE hardware.

**What no longer exists:** the former backend HSM's **Root Master Key (RMK)**, its KEK/KMAC derivation hierarchy, and NVRAM key-wrapping. At-rest confidentiality and integrity of CSPs are provided by the certified secure element itself (hardware memory encryption, tamper resistance, PIN gating). There is no module-managed storage-encryption key to generate, rotate, back up, or zeroize separately.

---

## 5. Zeroization, Loss & Recovery

- **Zeroization triggers:** authorized device wipe, FermionWallet app deletion, or 3 consecutive PIN failures. The SE destroys `SK_SEED`/`SK_PRF` and the counter irreversibly.
- **The XMSS key is intentionally unrecoverable** — from the 24-word phrase, from Ledger Recover, from backups. This is a security feature, not a gap: any restore path would resurrect a stale leaf counter.
- **Recovery is on-chain, not on-device.** A lost, wiped, or destroyed Ledger costs signing capability only, never funds: the organization runs the co-signed ceremony for a new XMSS root on a new device (`registerQuantumKey`, or emergency rotation via Safe governance — see [quantum-key-registry.md](./quantum-key-registry.md)), and the Safe's time-locked escape hatches never depend on the device.

---

## 6. Self-Tests & Assurance

- **Genuineness:** Ledger OS attestation (device ↔ Ledger HSM challenge) verifies the SE and OS are genuine before the app is installed; the host SDK re-checks app identity/version at session start.
- **Pairwise consistency test** after `GEN_XMSS_KEY` (sign/verify an internal block; zeroize on failure) and after any ECDSA key generation.
- **Counter sanity:** the app verifies $idx_{new} = idx_{old} + 1$ on every signature; any other observation locks the app pending key rotation.
- **Known-answer tests:** SHA-256 and XMSS verification KATs run at app launch.
- **Side channels / fault injection:** covered by the SE's CC EAL5+/EAL6+ (AVA_VAN.5) certification — hardware masking, constant-time primitives, and glitch detection are platform guarantees.

---

## 7. Host & Operational Requirements (outside the boundary)

- The backend relayer and Safe App hold **no key material**; they relay Ledger-produced signatures and maintain only an advisory mirror of the leaf index (resynced from the on-chain bitmap — see [pre-approval-engine.md](./pre-approval-engine.md)).
- The on-chain Guard independently verifies both hybrid halves and enforces leaf single-use in its bitmap, so even a fully compromised host cannot forge or replay an authorization.
- Administrators must keep device firmware and the FermionWallet app updated through Ledger Live's authenticated channel only.
