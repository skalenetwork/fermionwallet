# Ledger XMSS App

Custom Ledger embedded app giving the Quantum Administrator a hardware-held, stateful XMSS signing key. This is the sole cryptographic module of the FermionGuard architecture (see [`pre-approval-engine.md`](./pre-approval-engine.md)) — there is no host-side or HSM signing path.

## Programming language

- **Rust** (Ledger Rust SDK / `ledger-device-rust-sdk`) — preferred for memory safety in cryptographic state handling
- C (BOLOS C SDK) acceptable fallback if Rust SDK limitations block XMSS performance targets

## Open-source libraries / tooling used

- `ledger-device-rust-sdk` — app scaffolding, UI, APDU dispatch, NVM storage
- A vetted embedded XMSS implementation as reference (e.g., the RFC 8391 reference code / `xmss-reference`), ported to the secure-element constraints — no home-grown hash chains beyond the port
- Ledger `speculos` emulator + `ragger` test framework for CI
- `@ledgerhq/hw-transport-node-hid` / WebUSB on the host side (add-on service and Safe App)

## What the app does

1. **Key generation on device, multiple keys.** Each XMSS private seed is generated inside the secure element and never leaves it; the app exports only the public key (registered on-chain as `xmssRoot` + `xmssSeed`). The app holds up to four independent keys in separate slots (see [Multiple keys](#multiple-keys)), so a new key can be created — and a rotation proven with the old one — on the same device.
2. **Stateful signing.** Each signature consumes one leaf index of the key that signs. Every key has its own index counter, a **monotonic counter in secure-element NVM**: incremented and committed *before* the signature is released. Rollback, restore, or host tampering cannot reuse an index.
3. **What-you-see-is-what-you-sign.** The device screen renders the pre-approval fields — token, recipient, amount, validity window, nonce, leaf index, Safe address, chain ID, policyHash — and requires physical confirmation per signature.
4. **Hybrid classical half, from the same device.** The app also holds one secp256k1 key, derived at a fixed, app-specific BIP-32 path declared in the app manifest (never host-supplied). Its Ethereum address is the Administrator's `quantumAdmin`: the contracts verify every pre-approval's ECDSA half against it (`PreApprovalEngine`, `InvalidEcdsaSignature`) and require it to sign the key-registration attestation (`QuantumKeyRegistry`, `InvalidAttestation`). Without this half nothing the app produces can be registered or used on-chain. Unlike the XMSS seed, this key is stateless, so deriving it from the recovery phrase is safe.
5. **Exhaustion handling.** Per key: the app warns at a configurable threshold (e.g., 90% of 2^h leaves) and refuses to sign past the final index; rotation to a new root is the only path forward — which the same device can now perform by generating the successor key in another slot.

## Multiple keys

The app holds up to **`MAX_KEYS = 4`** XMSS keys, fixed at build time; the per-slot footprint (secret seeds, public key, counter, traversal cache) must fit the smallest supported device, verified in CI on Nano S Plus.

- **Isolated slots.** Each slot has its own `SK_SEED`, `SK_PRF`, public SEED, root, tree height, parameter set, and its own monotonic leaf counter. Signing with one key never reads or moves another key's counter.
- **One Administrator address.** The stateless `quantumAdmin` ECDSA key (item 4 above) is shared by all slots, so rotating to a key on the same device keeps the same Administrator address unless the owners co-sign a change.
- **Explicit key selection.** Every command that uses an XMSS key carries the slot index in APDU **`P2`** — not `P1`, which is already taken by the chunk flag of `SIGN_PREAPPROVAL` and the chunk index of `GET_SIGNATURE_CHUNK` — and the first 8 bytes of the root the host expects in that slot. The device refuses on mismatch (`Key mismatch — check host`), so a host can never make it sign with a key other than the one it named, and a slot that was retired and re-generated can't be confused with its predecessor.
- **The screen names the key.** Every signing, attestation, and rotation screen header shows the key as `Key <slot> · <first two ceremony words>`; the root-review screens show all six words.
- **Generating never destroys.** `GEN_XMSS_KEY` uses a free slot and leaves existing keys untouched; it is refused when all slots are in use.
- **Retiring is explicit.** `RETIRE_KEY` (Settings → *Retire key*) erases one slot's secrets after a double-confirmed, red-framed flow that shows the key's ceremony words and unused-leaf count and warns: *"Retire only after the rotation that replaces this key is confirmed on-chain. A retired key can never sign again."* The slot becomes free; a key generated there later is new random material with a new root, so no leaf can ever be reused. There is no device-wide *Reset*.

**Same-device rotation**, the normal case: (1) `GEN_XMSS_KEY` → new key in a free slot; (2) `SIGN_KEY_ATTESTATION` for the new slot; (3) `SIGN_ROTATION` with the **old** slot, whose payload names the new slot's root; (4) owners co-sign and the relayer submits `rotateQuantumKey`; (5) after one end-to-end test approval with the new key, `RETIRE_KEY` the old slot. The device recognizes a `newXmssRoot` that belongs to one of its own slots and says so on the rotation screens (`New key: Key 3 on this device`); any other root is shown as `New key: another device`.

## APDU interface (draft)

| INS | Command | Notes |
|---|---|---|
| `0x12` | `GEN_XMSS_KEY` | generates a new key in a free slot (Flow 1); returns the slot index and its public key. Refused when all `MAX_KEYS` slots are in use; never touches an existing key |
| `0x14` | `LIST_KEYS` | read-only: for each slot, whether it is free or in use, and for keys in use the root, tree height, parameter set, and leaves used / total |
| `0x02` | `GET_XMSS_ROOT` | for the selected slot: returns public root + public SEED + tree height + parameter set. The public SEED is a mandatory RFC 8391 verification input (registered on-chain as `xmssSeed`; registration rejects a zero seed); it is not secret |
| `0x04` | `GET_LEAF_INDEX` | returns the selected key's next unused index (read-only) |
| `0x06` | `SIGN_PREAPPROVAL` | with the selected key: streams the EIP-712 payload in chunks; device displays fields; on confirm, commits counter then returns **both hybrid halves over the same EIP-712 digest**: the ECDSA signature by the `quantumAdmin` key and the XMSS signature. One confirmation, released together — the host never obtains one half without the other |
| `0x08` | `GET_APP_CONFIG` | version, parameter set, `MAX_KEYS`, free slots |
| `0x18` | `GET_SIGNATURE_CHUNK` | reads back the signature the last confirmed signing command produced, 255 bytes at a time, with `P1` the chunk index. A signature is ~2.3 KB and an APDU response carries at most 255 bytes, so every signing command above answers with leaf index, digest and total length, and the host then pages the bytes out with this command. Read-only; consumes nothing |
| `0x0A` | `SIGN_ROTATION` | streams the full EIP-712 `RotateQuantumKey { safe, oldQuantumKeyId, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, registryNonce, validUntil }` and its domain (chain ID, verifying contract = the Guard). The selected slot is the **old** key. The device recomputes the digest from the fields it displays — it never signs a host-supplied hash — and refuses a `newXmssRoot` equal to the old key's root; a `newXmssRoot` held in another of its own slots is shown as such. Shows the ROTATE QUANTUM KEY flow (Flow 3); on confirm, commits counter then returns the old key's XMSS possession proof over that digest (the same digest the owners co-sign) |
| `0x0E` | `GET_ADMIN_ADDRESS` | returns the `quantumAdmin` address (the ECDSA key above); with the display flag set, shows the full address on-device for the ceremony preflight to compare |
| `0x10` | `SIGN_KEY_ATTESTATION` | for the selected slot: signs the EIP-712 `QuantumKeyAttestation { safe, xmssRoot, xmssSeed, treeHeight, parameterSet, registryNonce }` with the `quantumAdmin` key (the `ledgerAttestation` that `registerQuantumKey` and `rotateQuantumKey` verify). The host supplies only `safe`, the chain, and `registryNonce`; the device fills root, SEED, height, and parameter set **from its own key**, so a host cannot attest a substituted root. Device shows the Safe address (chunked), chain, ceremony words, and registryNonce. No counter commit, no leaf consumed |
| `0x16` | `RETIRE_KEY` | erases the selected slot's secrets and counter after the double-confirmed *Retire key* flow; the slot becomes free. No other slot is affected |
| `0x0C` | `SIGN_DENIAL` | streams the denial record (payload hash + reason hash); device shows the red DENY flow; on confirm returns a plain ECDSA signature by the `quantumAdmin` key — **no counter commit, no leaf consumed** |

All commands are rejected while another signing session is in flight; no command exposes seed material. Commands that use an XMSS key carry the slot index in **`P2`** and the expected root prefix; `P1` carries per-command parameters (the chunk flag of `SIGN_PREAPPROVAL`, the chunk index of `GET_SIGNATURE_CHUNK`, the display flag of `GET_ADMIN_ADDRESS`). See [Multiple keys](#multiple-keys).

## Installation, supported devices, and updates

**Supported devices.** Ledger **Nano S Plus, Nano X, Stax, and Flex** (all carry the ST33-family secure element with the monotonic-counter NVM primitives the app requires). The original Nano S is **not** supported: insufficient app flash for the XMSS working set. Minimum firmware: the latest stable Ledger OS for each device at release time, pinned in the app's `Cargo.toml`/manifest — the app refuses to install on older firmware.

**Installation path (production).** Through **Ledger Live → My Ledger → App catalog → "FermionGuard XMSS"**, after the app passes Ledger's third-party security review and is listed. This is the only path end users should use: catalog apps are signed by Ledger, and the device's genuine check + Ledger Live's signature verification together guarantee an unmodified binary on a genuine device. Until catalog listing is complete, institutional pilot users install a Ledger-signed release build via the same Ledger Live mechanism under the "developer mode" listing — **never** a self-built sideload for a key that will guard real funds.

**Installation path (development only).** Engineers use `cargo ledger build` + `ledgerctl install` sideloading onto a dev device, and `speculos` for CI. Sideloaded builds display a persistent "PENDING LEDGER REVIEW" warning on the device (standard BOLOS behavior for unsigned apps); any device showing that warning must never hold a production key.

**Verifying the app before the ceremony.** The Safe App's ceremony preflight (Stage A) queries `GET_APP_CONFIG` and checks: app name/version against the published release, parameter set `XMSS-SHA2_20_256`, and the device's genuine-check status via Ledger's attestation. The ceremony refuses to proceed on any mismatch — this is what the "device verified" line in the UI means, and it is machine-checked, not a user promise.

**Updates.** App updates ship through the same Ledger Live catalog channel. Updating the app **preserves NVM state** (seed and leaf counter live in app-owned NVM that survives app upgrades under BOLOS); uninstalling the app **destroys every key on it** — Ledger Live warns, and so does this document: *uninstalling the XMSS app is equivalent to losing the device* and requires the on-chain key-rotation procedure ([`quantum-key-registry.md`](./quantum-key-registry.md)), never a restore. There is no rollback to older app versions (Ledger Live installs latest-only); a bad release is handled by publishing a fixed version, not by downgrade.

## Device UI specification

Illustrated screen-by-screen reference with mockups: [`ledger-ui.md`](./ledger-ui.md).

On-device screens for every flow, targeting both device families via the SDK's UI layers: **Stax/Flex** (touch, NBGL pages) and **Nano S+/X** (two buttons, paged steps). The device screen is the last honest surface in the system — everything here assumes the host is compromised.

### UI principles

1. **Reject is the default.** Every flow ends on a choice where the physically easiest action (right-most button page on Nano, bottom action on Stax) is *Reject*. Approving always requires deliberate navigation.
2. **No abbreviation of security-critical values.** Addresses and the XMSS root are shown in full, chunked `0x1234 5678 … ABCD` in 4-byte groups across pages. Amounts are decimals-adjusted with the token symbol *and* shown raw on a details page.
3. **One signature, one payload, one confirmation.** There is no "sign N pending transactions" mode in the firmware. A `MultiSendCallOnly` batch is a *single* payload: the device shows `BATCH — <n> legs`, per-token totals (host-supplied, informational), and the binding batch `dataHash` (first/last 8 hex, verified against the host UI) — leg-by-leg review happens in the add-on UI, and the on-chain Guard re-validates every leg independently.
4. **The leaf index is always visible.** It is the app's odometer; the Administrator learns to notice a jump (host attempting to burn leaves) the way a driver notices mileage.
5. **Every screen states the flow and the key.** Header shows `Register key`, `Sign approval #<leaf>`, or `Rotate key`, plus `Key <slot> · <two ceremony words>` — a host can neither present a rotation as a routine approval nor switch keys unnoticed.

### Flow 1 — Key generation (`GEN_XMSS_KEY`, into a free slot)

![Key generation screens](./assets/ui/ledger/ledger-keygen.svg)

| # | Screen | Content / action |
|---|---|---|
| 1 | Intent | "Generate quantum key for FermionGuard?" — shows the target slot ("Key 3 of 4 — keys 1–2 are kept"), parameter set (`XMSS-SHA2_20_256`) and lifetime ("~1,048,576 approvals") |
| 2 | Entropy notice | "Key is generated inside this device and cannot be exported or restored from your recovery phrase." Requires explicit acknowledgment — this is the #1 support surprise, surfaced before generation, not after |
| 3 | Progress | Tree construction progress bar with time estimate (minutes on Nano-class MCUs); cancellable until complete |
| 4 | Root review | Full root, chunked, multi-page; plus the derived **6-word ceremony code** rendered on-device — the words the owners will verify out-of-band come from the secure element itself, not from the host UI |
| 5 | Confirm export | "Share public key with host?" Approve/Reject. Only the root, public SEED, height, and parameter set cross the wire |
| 6 | Attest (`SIGN_KEY_ATTESTATION`) | "Attest this key for Safe 0x…?" — Safe address (chunked), chain, ceremony words, registryNonce. Approve produces the `ledgerAttestation` the registry requires; the key fields come from the device, not the host |

`GET_XMSS_ROOT` for a slot in use returns that key's public key (screens 4–5 only); attestation (screen 6) is its own command and is repeated per Safe and per `registryNonce`. Generating another key uses the next free slot and leaves every existing key untouched; freeing a slot requires the explicit *Retire key* flow.

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
| 6 | Context | Safe address (chunked) + chain name/ID + **binding**, read from the signed `txHash`: `Pinned to Safe tx 0x5e1f…88ab` when it is set, or an amber `NOT PINNED — any matching transfer` when it is zero (a field-matched approval executes for *any* Safe transaction with this token, recipient and amount, at any Safe nonce, until used or expired). The Safe nonce is **not** shown: it is not in the signed payload, so displaying it would promise a binding the Guard does not enforce |
| 7 | Policy | `policyHash` first/last 8 hex chars (the one field verified by hash — the full policy is enforced on-chain, the hash only needs collision-level comparison) |
| 8 | Decision | "Approve transfer?" — Approve requires the long-press (Stax) / both-buttons (Nano) idiom; Reject is a single tap |

On approve: NVM counter commits, *then* both hybrid halves stream out — the ECDSA signature and the XMSS signature over the same digest (counter-before-signature invariant). On reject or timeout (60 s idle on the decision screen): APDU error, no state change, no leaf consumed. Unknown or malformed payload fields abort the flow before screen 1 — there is no "review anyway" path.

**Non-transfer classes (`PAYLOAD`/`ADMIN`):** the same flow with screens 2–4 replaced by target address (full, chunked), native ETH value, and the payload `dataHash` (first/last 8 hex). `ADMIN`-class payloads additionally show a warning header ("ADMIN ACTION — affects Safe governance") and, when the host supplies the decoded intent, a plain-language line such as "Removes the FermionGuard". The class is part of the signed payload, so a host cannot present an admin action as a transfer.

### Flow 3 — Rotation (`SIGN_ROTATION`, old-key possession proof)

![Rotation screens](./assets/ui/ledger/ledger-rotate.svg)

Signed with the **old** key's slot. Identical to Flow 1 with a red/emphasized header "ROTATE QUANTUM KEY", a screen showing old-root ceremony words vs new-root ceremony words (with `New key: Key <slot> on this device` or `New key: another device`), and the old key's remaining-leaf count ("You are abandoning 61,204 unused approvals") so an attacker cannot socially engineer a pointless rotation invisibly.

The possession proof is an XMSS signature over the **full** `RotateQuantumKey { safe, oldQuantumKeyId, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, registryNonce, validUntil }` digest, so every signed field is shown before the decision screen — no field is signed blind:

- Safe address (full, chunked) and chain;
- new Administrator address (full, chunked), flagged "CHANGES ADMINISTRATOR" when it differs from this device's own `quantumAdmin`;
- new key: ceremony words, first/last 4 bytes of root and SEED, tree height (as lifetime approvals) and parameter set;
- `registryNonce` and `validUntil` as an absolute UTC time.

`oldQuantumKeyId` is not human-meaningful and is shown only as a short fingerprint; it is bound by the owners' co-signatures over the same digest.

### Flow 4 — Deny (`SIGN_DENIAL`, ECDSA receipt, no leaf)

![Denial screens](./assets/ui/ledger/ledger-deny.svg)

Red-framed on every screen, header `DENY APPROVAL`. Shows the same decoded payload plus the app-supplied reason (its hash is part of the signed record) and states `No leaf will be consumed` explicitly. The signature is plain ECDSA over the denial record — the XMSS counter never moves, and the confirmation screen displays the unchanged leaf count. The red framing makes a denial visually impossible to mistake for the teal signing flow.

### Ambient screens

![Ambient and error screens](./assets/ui/ledger/ledger-ambient.svg)

- **Dashboard (app open, idle):** parameter set and one row per key in use — `Key <slot> · <two ceremony words>`, leaf usage bar (`184,203 / 1,048,576 — 17%`), and exhaustion state. At ≥80% the bar turns amber; at ≥95% every signing flow begins with an extra "Rotation overdue" interstitial; at 100% the app refuses to sign and shows only the rotation instructions.
- **Settings:** exhaustion-warning threshold, *Retire key* per slot (double-confirmed, destructive-styled, red-framed), firmware/app version and parameter set for audit photographs.

### Error screens

Every host-side failure has a distinct, plain-language device screen: `Payload rejected — field out of range`, `Session already active`, `Key exhausted — rotate`, `Clock window invalid`, `Key mismatch — check host`, `No free key slot — retire a key first`. No numeric-only error codes on the device; the APDU layer carries the codes, the human never sees them.

### Device UI acceptance criteria

- [ ] No signature can be produced without traversing every field screen of Flow 2 (enforced in firmware, verified by `ragger` snapshot tests on both NBGL and BAGL)
- [ ] Reject/timeout paths consume no leaf — power-cycle fuzzing across the decision screen shows counter monotonicity with zero unexplained increments
- [ ] Addresses and root never truncated anywhere in the firmware — snapshot-diffed against a forbidden-pattern list (`…` in an address context fails CI)
- [ ] Ceremony words rendered on-device match the host derivation for 10k random roots
- [ ] A rotation flow is visually impossible to mistake for a signing flow (distinct header, distinct color/emphasis on Stax)
- [ ] Screen 2 entropy notice shown before any key material is generated
- [ ] Key isolation: signing with one key never changes another key's counter, and `RETIRE_KEY` on one slot leaves every other slot byte-identical (NVM snapshot diff)
- [ ] A command whose root prefix does not match its slot is refused before any screen is shown; so is `GEN_XMSS_KEY` with no free slot
- [ ] All screens localized-ready but shipping English-only (audit surface minimization)


## Security requirements

- **Display only signed fields**: every value on a signing screen must come from the signed EIP-712 struct (or its domain). Host-supplied context that is not signed — a Safe nonce, a label, a queue position — must never be displayed as if it constrained the approval.
- **Key isolation**: every key has its own seeds and counter; no command can sign with, read, or reset a key other than the one it names (slot + root prefix). Retiring a key zeroizes that slot only; no command resets a counter while its key exists.
- **Counter-before-signature invariant**: the NVM counter commit must be atomic and precede signature release. A power loss between commit and release loses one leaf (acceptable); the reverse order is forbidden (catastrophic).
- NVM wear: counter updates must use the SDK's wear-leveled storage; budget ≥ 2^20 writes.
- Signing time: target < 3 s per signature on current devices (WOTS+ chains dominate; precompute where the SDK allows).
- **Hybrid binding**: the ECDSA and XMSS halves of a pre-approval are computed inside the device over the identical EIP-712 digest and released only together, after the counter commit. There is no command that returns an ECDSA signature over a pre-approval digest by itself.
- Blind signing must be impossible: no raw-hash signing path; every signature goes through the field-rendering flow.
- The parameter set (e.g., `XMSS-SHA2_20_256` or keccak variant) is fixed at build time and attested via `GET_APP_CONFIG`; the on-chain verifier and the app must be parameter-locked to each other.
- App must pass Ledger's security review for distribution; until then, sideloaded builds are restricted to testnets.

## Defense-in-depth relationship to the chain

The on-chain used-leaf bitmap in the Guard/registry stays in place even after this app ships. Device counter and on-chain bitmap independently prevent leaf reuse; either alone is sufficient, both together tolerate a failure of the other.

## Deliverables and validation

- [ ] Rust app implementing the APDU interface above
- [ ] `speculos`/`ragger` CI suite: signing flow, counter monotonicity across power cycles, exhaustion refusal, chunked payload edge cases, and UI snapshot tests for every screen of every flow on both NBGL (Stax/Flex) and BAGL (Nano) targets
- [ ] Cross-verification test: 10k device signatures verified by the Solidity XMSS verifier in Foundry, and device-produced hybrid pairs plus key attestations accepted end to end by `createPreApproval`, `registerQuantumKey`, and `rotateQuantumKey` (a real Safe in Foundry; the rotation test uses a device-produced possession proof, including a same-device rotation with the old and new key in two slots)
- [ ] Host SDK in the add-on service (`ledger-xmss.ts`) replacing the Phase 1 software keystore path behind the same interface
- [ ] Ledger security review submission

### Open items for FermionWallet

[fermionwallet.md](./fermionwallet.md) specifies a second product this app does not yet support. Its
`Transfer` payload is refused by the parser as written, so a shipped device cannot drive it. Adding it
needs no new APDU command, but does need (FWL-033):

- [ ] the `Transfer` type and the `FermionWallet` EIP-712 domain accepted alongside `PreApproval`, with `verifyingContract` = the wallet
- [ ] a signing flow for it: Flow 2's token, amount, recipient, validity and decision screens unchanged; the context screen shows **Wallet 0x…** and the chain in place of Safe address, `txHash` pin and `policyHash`
- [ ] per-slot binding to a single verifying contract, written at first signature and checked on every later one, held in NVM beside the leaf counter (FWL-023)
- [ ] refusal when a slot bound to a wallet is asked for a Safe pre-approval, or a slot used for Safes is asked for a wallet transfer — a key belongs to one product

The last two matter more than they look: the standalone wallet has no registry, so its on-chain bitmap
cannot see leaves spent elsewhere. For that product the device binding is the *only* thing keeping one
leaf to one digest, which is why FermionWallet records the weaker guarantee as a residual risk
(FWL-025) rather than claiming the defense in depth described above.

## Design intent

Phase 1's split trust (Ledger ECDSA + software XMSS keystore) collapses into a single hardware trust anchor: the quantum signature itself comes from the secure element, with index state that a compromised host cannot corrupt.
