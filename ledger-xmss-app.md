# Ledger XMSS App

Custom Ledger embedded app giving the Quantum Administrator a hardware-held, stateful XMSS signing key. This is the sole cryptographic module of the FermionWallet architecture (see [`pre-approval-engine.md`](./pre-approval-engine.md)) — there is no host-side or HSM signing path.

## Programming language

- **Rust** (Ledger Rust SDK / `ledger-device-rust-sdk`) — preferred for memory safety in cryptographic state handling
- C (BOLOS C SDK) acceptable fallback if Rust SDK limitations block XMSS performance targets

## Open-source libraries / tooling used

- `ledger-device-rust-sdk` — app scaffolding, UI, APDU dispatch, NVM storage
- A vetted embedded XMSS implementation as reference (e.g., the RFC 8391 reference code / `xmss-reference`), ported to the secure-element constraints — no home-grown hash chains beyond the port
- Ledger `speculos` emulator + `ragger` test framework for CI
- `@ledgerhq/hw-transport-node-hid` / WebUSB on the host side (add-on service and Safe App)

## What the app does

1. **Key generation on device.** The XMSS private seed is generated inside the secure element and never leaves it. The app exports only the public root (registered on-chain as `xmssRoot`).
2. **Stateful signing.** Each signature consumes one leaf index. The index counter is a **monotonic counter in secure-element NVM**: incremented and committed *before* the signature is released. Rollback, restore, or host tampering cannot reuse an index.
3. **What-you-see-is-what-you-sign.** The device screen renders the pre-approval fields — token, recipient, amount, validity window, nonce, leaf index, Safe address, chain ID, policyHash — and requires physical confirmation per signature.
4. **Exhaustion handling.** The app warns at a configurable threshold (e.g., 90% of 2^h leaves) and refuses to sign past the final index; rotation to a new root is the only path forward.

## APDU interface (draft)

| INS | Command | Notes |
|---|---|---|
| `0x02` | `GET_XMSS_ROOT` | returns public root + tree height + parameter set |
| `0x04` | `GET_LEAF_INDEX` | returns next unused index (read-only) |
| `0x06` | `SIGN_PREAPPROVAL` | streams the EIP-712-style payload in chunks; device displays fields; on confirm, commits counter then returns XMSS signature |
| `0x08` | `GET_APP_CONFIG` | version, parameter set, remaining signatures |
| `0x0A` | `SIGN_ROTATION` | streams the `RotateQuantumKey` payload (new root, new admin, registryNonce); device shows the ROTATE QUANTUM KEY flow (old vs new ceremony words, abandoned-leaf count); on confirm, commits counter then returns the old key's XMSS possession proof |
| `0x0C` | `SIGN_DENIAL` | streams the denial record (payload hash + reason hash); device shows the red DENY flow; on confirm returns a plain ECDSA signature — **no counter commit, no leaf consumed** |

All commands are rejected while another signing session is in flight; no command exposes seed material.

## Installation, supported devices, and updates

**Supported devices.** Ledger **Nano S Plus, Nano X, Stax, and Flex** (all carry the ST33-family secure element with the monotonic-counter NVM primitives the app requires). The original Nano S is **not** supported: insufficient app flash for the XMSS working set. Minimum firmware: the latest stable Ledger OS for each device at release time, pinned in the app's `Cargo.toml`/manifest — the app refuses to install on older firmware.

**Installation path (production).** Through **Ledger Live → My Ledger → App catalog → "FermionWallet XMSS"**, after the app passes Ledger's third-party security review and is listed. This is the only path end users should use: catalog apps are signed by Ledger, and the device's genuine check + Ledger Live's signature verification together guarantee an unmodified binary on a genuine device. Until catalog listing is complete, institutional pilot users install a Ledger-signed release build via the same Ledger Live mechanism under the "developer mode" listing — **never** a self-built sideload for a key that will guard real funds.

**Installation path (development only).** Engineers use `cargo ledger build` + `ledgerctl install` sideloading onto a dev device, and `speculos` for CI. Sideloaded builds display a persistent "PENDING LEDGER REVIEW" warning on the device (standard BOLOS behavior for unsigned apps); any device showing that warning must never hold a production key.

**Verifying the app before the ceremony.** The Safe App's ceremony preflight (Stage A) queries `GET_APP_CONFIG` and checks: app name/version against the published release, parameter set `XMSS-SHA2_20_256`, and the device's genuine-check status via Ledger's attestation. The ceremony refuses to proceed on any mismatch — this is what the "device verified" line in the UI means, and it is machine-checked, not a user promise.

**Updates.** App updates ship through the same Ledger Live catalog channel. Updating the app **preserves NVM state** (seed and leaf counter live in app-owned NVM that survives app upgrades under BOLOS); uninstalling the app **destroys it** — Ledger Live warns, and so does this document: *uninstalling the XMSS app is equivalent to losing the device* and requires the on-chain key-rotation procedure ([`quantum-key-registry.md`](./quantum-key-registry.md)), never a restore. There is no rollback to older app versions (Ledger Live installs latest-only); a bad release is handled by publishing a fixed version, not by downgrade.

## Device UI specification

Illustrated screen-by-screen reference with mockups: [`ledger-ui.md`](./ledger-ui.md).

On-device screens for every flow, targeting both device families via the SDK's UI layers: **Stax/Flex** (touch, NBGL pages) and **Nano S+/X** (two buttons, paged steps). The device screen is the last honest surface in the system — everything here assumes the host is compromised.

### UI principles

1. **Reject is the default.** Every flow ends on a choice where the physically easiest action (right-most button page on Nano, bottom action on Stax) is *Reject*. Approving always requires deliberate navigation.
2. **No abbreviation of security-critical values.** Addresses and the XMSS root are shown in full, chunked `0x1234 5678 … ABCD` in 4-byte groups across pages. Amounts are decimals-adjusted with the token symbol *and* shown raw on a details page.
3. **One signature, one payload, one confirmation.** There is no "sign N pending transactions" mode in the firmware. A `MultiSendCallOnly` batch is a *single* payload: the device shows `BATCH — <n> legs`, per-token totals (host-supplied, informational), and the binding batch `dataHash` (first/last 8 hex, verified against the host UI) — leg-by-leg review happens in the add-on UI, and the on-chain Guard re-validates every leg independently.
4. **The leaf index is always visible.** It is the app's odometer; the Administrator learns to notice a jump (host attempting to burn leaves) the way a driver notices mileage.
5. **Every screen states the flow it belongs to.** Header shows `Register key`, `Sign approval #<leaf>`, or `Rotate key` — a host cannot present a rotation as a routine approval.

### Flow 1 — Key generation (`GET_XMSS_ROOT`, first run)

![Key generation screens](./assets/ui/ledger/ledger-keygen.svg)

| # | Screen | Content / action |
|---|---|---|
| 1 | Intent | "Generate quantum key for FermionWallet?" — shows parameter set (`XMSS-SHA2_20_256`) and lifetime ("~1,048,576 approvals") |
| 2 | Entropy notice | "Key is generated inside this device and cannot be exported or restored from your recovery phrase." Requires explicit acknowledgment — this is the #1 support surprise, surfaced before generation, not after |
| 3 | Progress | Tree construction progress bar with time estimate (minutes on Nano-class MCUs); cancellable until complete |
| 4 | Root review | Full root, chunked, multi-page; plus the derived **6-word ceremony code** rendered on-device — the words the owners will verify out-of-band come from the secure element itself, not from the host UI |
| 5 | Confirm export | "Share public root with host?" Approve/Reject. Only the root, height, and parameter set cross the wire |

Re-running `GET_XMSS_ROOT` after generation returns the existing root (screens 4–5 only); a second generation requires the explicit *Reset* flow in Settings with a typed-style double confirmation and a warning that the old key becomes unusable.

### Flow 2 — Sign pre-approval (`SIGN_PREAPPROVAL`)

![Signing screens 1–4](./assets/ui/ledger/ledger-sign-1.svg)
![Signing screens 5–8](./assets/ui/ledger/ledger-sign-2.svg)

| # | Screen | Content |
|---|---|---|
| 1 | Header | "Sign approval — leaf #184,203 of 1,048,576" (index + remaining budget in one glance) |
| 2 | Token | Symbol if the token contract address matches the app's built-in or CAL-provided list, otherwise "Unknown token" + full contract address |
| 3 | Amount | Decimals-adjusted (`500,000.00 USDC`); details page shows the raw uint256 |
| 4 | Recipient | Full address, chunked, multi-page — never truncated |
| 5 | Validity | Window as absolute UTC times ("Valid 21 Sep 15:40 → 21:40 UTC"), not durations — durations hide clock skew games |
| 6 | Context | Safe address (chunked) + chain name/ID + Safe nonce |
| 7 | Policy | `policyHash` first/last 8 hex chars (the one field verified by hash — the full policy is enforced on-chain, the hash only needs collision-level comparison) |
| 8 | Decision | "Approve transfer?" — Approve requires the long-press (Stax) / both-buttons (Nano) idiom; Reject is a single tap |

On approve: NVM counter commits, *then* the signature streams out (counter-before-signature invariant). On reject or timeout (60 s idle on the decision screen): APDU error, no state change, no leaf consumed. Unknown or malformed payload fields abort the flow before screen 1 — there is no "review anyway" path.

**Non-transfer classes (`PAYLOAD`/`ADMIN`):** the same flow with screens 2–4 replaced by target address (full, chunked), native ETH value, and the payload `dataHash` (first/last 8 hex). `ADMIN`-class payloads additionally show a warning header ("ADMIN ACTION — affects Safe governance") and, when the host supplies the decoded intent, a plain-language line such as "Removes the FermionWallet Guard". The class is part of the signed payload, so a host cannot present an admin action as a transfer.

### Flow 3 — Rotation (`SIGN_ROTATION`, old-key possession proof)

![Rotation screens](./assets/ui/ledger/ledger-rotate.svg)

Identical to Flow 1 with a red/emphasized header "ROTATE QUANTUM KEY", a screen showing old-root ceremony words vs new-root ceremony words, and the old key's remaining-leaf count ("You are abandoning 61,204 unused approvals") so an attacker cannot socially engineer a pointless rotation invisibly.

### Flow 4 — Deny (`SIGN_DENIAL`, ECDSA receipt, no leaf)

![Denial screens](./assets/ui/ledger/ledger-deny.svg)

Red-framed on every screen, header `DENY APPROVAL`. Shows the same decoded payload plus the app-supplied reason (its hash is part of the signed record) and states `No leaf will be consumed` explicitly. The signature is plain ECDSA over the denial record — the XMSS counter never moves, and the confirmation screen displays the unchanged leaf count. The red framing makes a denial visually impossible to mistake for the teal signing flow.

### Ambient screens

![Ambient and error screens](./assets/ui/ledger/ledger-ambient.svg)

- **Dashboard (app open, idle):** parameter set, leaf usage bar (`184,203 / 1,048,576 — 17%`), and exhaustion state. At ≥80% the bar turns amber; at ≥95% every signing flow begins with an extra "Rotation overdue" interstitial; at 100% the app refuses to sign and shows only the rotation instructions.
- **Settings:** exhaustion-warning threshold, key reset (double-confirmed, destructive-styled), firmware/app version and parameter set for audit photographs.

### Error screens

Every host-side failure has a distinct, plain-language device screen: `Payload rejected — field out of range`, `Session already active`, `Key exhausted — rotate`, `Clock window invalid`. No numeric-only error codes on the device; the APDU layer carries the codes, the human never sees them.

### Device UI acceptance criteria

- [ ] No signature can be produced without traversing every field screen of Flow 2 (enforced in firmware, verified by `ragger` snapshot tests on both NBGL and BAGL)
- [ ] Reject/timeout paths consume no leaf — power-cycle fuzzing across the decision screen shows counter monotonicity with zero unexplained increments
- [ ] Addresses and root never truncated anywhere in the firmware — snapshot-diffed against a forbidden-pattern list (`…` in an address context fails CI)
- [ ] Ceremony words rendered on-device match the host derivation for 10k random roots
- [ ] A rotation flow is visually impossible to mistake for a signing flow (distinct header, distinct color/emphasis on Stax)
- [ ] Screen 2 entropy notice shown before any key material is generated
- [ ] All screens localized-ready but shipping English-only (audit surface minimization)


## Security requirements

- **Counter-before-signature invariant**: the NVM counter commit must be atomic and precede signature release. A power loss between commit and release loses one leaf (acceptable); the reverse order is forbidden (catastrophic).
- NVM wear: counter updates must use the SDK's wear-leveled storage; budget ≥ 2^20 writes.
- Signing time: target < 3 s per signature on current devices (WOTS+ chains dominate; precompute where the SDK allows).
- Blind signing must be impossible: no raw-hash signing path; every signature goes through the field-rendering flow.
- The parameter set (e.g., `XMSS-SHA2_20_256` or keccak variant) is fixed at build time and attested via `GET_APP_CONFIG`; the on-chain verifier and the app must be parameter-locked to each other.
- App must pass Ledger's security review for distribution; until then, sideloaded builds are restricted to testnets.

## Defense-in-depth relationship to the chain

The on-chain used-leaf bitmap in the Guard/registry stays in place even after this app ships. Device counter and on-chain bitmap independently prevent leaf reuse; either alone is sufficient, both together tolerate a failure of the other.

## Deliverables and validation

- [ ] Rust app implementing the APDU interface above
- [ ] `speculos`/`ragger` CI suite: signing flow, counter monotonicity across power cycles, exhaustion refusal, chunked payload edge cases, and UI snapshot tests for every screen of every flow on both NBGL (Stax/Flex) and BAGL (Nano) targets
- [ ] Cross-verification test: 10k device signatures verified by the Solidity XMSS verifier in Foundry
- [ ] Host SDK in the add-on service (`ledger-xmss.ts`) replacing the Phase 1 software keystore path behind the same interface
- [ ] Ledger security review submission

## Design intent

Phase 1's split trust (Ledger ECDSA + software XMSS keystore) collapses into a single hardware trust anchor: the quantum signature itself comes from the secure element, with index state that a compromised host cannot corrupt.
