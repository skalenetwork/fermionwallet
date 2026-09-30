# Ledger XMSS App

Custom Ledger embedded app giving the Quantum Administrator a hardware-held, stateful XMSS signing key. This is the sole cryptographic module of the FermionGuard architecture (see [`pre-approval-engine.md`](./pre-approval-engine.md)) — there is no host-side or HSM signing path.

## Relationship to Ledger's Ethereum app

This app is deliberately a *dialect* of Ledger's own Ethereum app (`LedgerHQ/app-ethereum`), not a fresh protocol. The class byte, the framing, the instruction numbers of the commands that have an Ethereum analogue, the derivation-path encoding, the chunking of long payloads, the status words, the app-configuration response, the token-descriptor mechanism, the review flow and its wording, and the home/settings layout are all taken from that app and from the Ledger secure SDK. Each such claim carries a bracketed source tag resolved in [Appendix A](#appendix-a--primary-sources); a claim we could not source is listed in [Appendix B](#appendix-b--assumptions) rather than asserted.

Five things have no Ethereum-app equivalent, and only these five. They are marked **[new]** wherever they appear:

| **[new]** | Why the Ethereum app has nothing like it |
|---|---|
| XMSS one-time leaf state and its NVM counter | Every ECDSA key is stateless; no Ethereum signature consumes anything |
| The hybrid double signature, released atomically | An Ethereum signature is one `v‖r‖s`; here the ECDSA and XMSS halves must both exist or neither may leave the device |
| Key generation on device | The Ethereum app derives all keys from the recovery phrase; a restorable XMSS seed would reset the counter and enable reuse forgery |
| Leaf-exhaustion states (warn, overdue, exhausted) | No Ethereum key can run out |
| Per-slot binding — slot index, expected root prefix, one verifying contract per slot | The Ethereum app has one key space and one chain vocabulary; here a slot is a distinct, spendable key whose identity the host must name and the device must confirm |

Everything else that differs is listed in [Deliberate deviations](#deliberate-deviations-from-the-ethereum-app) with the reason on one line. If it is not in that list and not marked **[new]**, it is the Ethereum app's behaviour.

## Programming language

- **Rust** (Ledger Rust SDK / `ledger-device-rust-sdk`) — preferred for memory safety in cryptographic state handling
- C (BOLOS C SDK) acceptable fallback if Rust SDK limitations block XMSS performance targets

## Open-source libraries / tooling used

- `ledger-device-rust-sdk` — app scaffolding, UI, APDU dispatch, NVM storage
- A vetted embedded XMSS implementation as reference (e.g., the RFC 8391 reference code / `xmss-reference`), ported to the secure-element constraints — no home-grown hash chains beyond the port
- Ledger `speculos` emulator + `ragger` test framework for CI
- `@ledgerhq/hw-transport-node-hid` / WebUSB on the host side (add-on service and Safe App)

## What the app does

1. **Key generation on device, multiple keys.** **[new]** Each XMSS private seed is generated inside the secure element and never leaves it; the app exports only the public key (registered on-chain as `xmssRoot` + `xmssSeed`). The app holds up to four independent keys in separate slots (see [Multiple keys](#multiple-keys)), so a new key can be created — and a rotation proven with the old one — on the same device.
2. **Stateful signing.** **[new]** Each signature consumes one leaf index of the key that signs. Every key has its own index counter, a **monotonic counter in secure-element NVM**: incremented and committed *before* the signature is released. Rollback, restore, or host tampering cannot reuse an index.
3. **What-you-see-is-what-you-sign.** The device renders every signed field and requires physical confirmation per signature, through the SDK's standard review flow — the same `Review …` intent page, tag/value field pages and `Hold to sign` confirmation an Ethereum-app user already knows [S6][S10].
4. **Hybrid classical half, from the same device.** The app also holds one secp256k1 key, at a BIP-32 path the host supplies in the Ethereum app's encoding and Ledger OS constrains to the app's declared subtree (see [Derivation path](#derivation-path)). Its Ethereum address is the Administrator's `quantumAdmin`: the contracts verify every pre-approval's ECDSA half against it (`PreApprovalEngine`, `InvalidEcdsaSignature`) and require it to sign the key-registration attestation (`QuantumKeyRegistry`, `InvalidAttestation`). Without this half nothing the app produces can be registered or used on-chain. Unlike the XMSS seed, this key is stateless, so deriving it from the recovery phrase is safe — it is derived exactly as the Ethereum app derives its own keys.
5. **Exhaustion handling.** **[new]** Per key: the app warns at a configurable threshold (e.g., 90% of 2^h leaves) and refuses to sign past the final index; rotation to a new root is the only path forward — which the same device can now perform by generating the successor key in another slot.

## Multiple keys

The app holds up to **`MAX_KEYS = 4`** XMSS keys, fixed at build time; the per-slot footprint (secret seeds, public key, counter, traversal cache) must fit the smallest supported device, verified in CI on Nano S Plus.

- **Isolated slots.** Each slot has its own `SK_SEED`, `SK_PRF`, public SEED, root, tree height, parameter set, and its own monotonic leaf counter. Signing with one key never reads or moves another key's counter.
- **One Administrator address.** The stateless `quantumAdmin` ECDSA key (item 4 above) is shared by all slots, so rotating to a key on the same device keeps the same Administrator address unless the owners co-sign a change.
- **Explicit key selection.** **[new]** Every command that uses an XMSS key carries the slot index in APDU **`P2`** — not `P1`, which is already taken by the chunk flag of `SIGN_PREAPPROVAL`, the chunk flag of `GET_SIGNATURE_CHUNK` and the display flag of `GET_ADMIN_ADDRESS`, exactly as `P1` is spoken for in the Ethereum app [S1][S2] — and the first 8 bytes of the root the host expects in that slot in its first data chunk. The device refuses on mismatch with `0x6A88` (screen: `Key mismatch — check host`), so a host can never make it sign with a key other than the one it named, and a slot that was retired and re-generated can't be confused with its predecessor.
- **The screen names the key.** Every signing, attestation and rotation review carries a `Key` field showing `Key <slot> · <first two ceremony words>`; the root-review pages show all six words.
- **Generating never destroys.** `GEN_XMSS_KEY` uses a free slot and leaves existing keys untouched; it is refused with `0x6A89` when all slots are in use.
- **Retiring is explicit.** `RETIRE_KEY` (Settings → *Retire key*) erases one slot's secrets after a double-confirmed flow, opened by an SDK warning page, that shows the key's ceremony words and unused-leaf count and warns: *"Retire only after the rotation that replaces this key is confirmed on-chain. A retired key can never sign again."* The slot becomes free; a key generated there later is new random material with a new root, so no leaf can ever be reused. There is no device-wide *Reset*.

**Same-device rotation**, the normal case: (1) `GEN_XMSS_KEY` → new key in a free slot; (2) `SIGN_KEY_ATTESTATION` for the new slot; (3) `SIGN_ROTATION` with the **old** slot, whose payload names the new slot's root; (4) owners co-sign and the relayer submits `rotateQuantumKey`; (5) after one end-to-end test approval with the new key, `RETIRE_KEY` the old slot. The device recognizes a `newXmssRoot` that belongs to one of its own slots and says so on the rotation pages (`New key: Key 3 on this device`); any other root is shown as `New key: another device`.

## APDU interface

### Framing

Framing is Ledger's, unchanged: a BOLOS APDU exchange "very close to ISO 7816-4" over USB HID / WebHID / BLE, where `Lc` is "always exactly 1 byte", there is "no `Le` field in APDU command", the command is at most "260 bytes: 5 bytes of header + 255 bytes of data" and the response at most "260 bytes: 258 bytes of response data + 2 bytes of status word" [S5].

- **CLA = `0xE0`** — the class byte the Ethereum app uses (`#define CLA 0xE0`) [S2].
- **INS values are even**: all 27 of the Ethereum app's are, from `0x02` to `0x3A` [S2]. The four commands with a direct Ethereum analogue keep *the Ethereum app's own number*, so a host developer's reflexes still work. The FermionGuard-specific commands start at `0x40`, above the Ethereum app's highest assignment, so no number means two different things in two apps.
- An unrecognised CLA returns `0x6E00` and an unrecognised INS `0x6D00` — the codes the Ethereum app's dispatcher returns for exactly those two cases (`cmd->cla != CLA → SWO_INVALID_CLA`; `default: sw = SWO_INVALID_INS`) [S2].

**Renumbering note for implementers.** This table supersedes an earlier draft in which `SIGN_PREAPPROVAL` was `0x06` and `GET_APP_CONFIG` was `0x08` — inverted from the Ethereum app, where `0x04` is SIGN and `0x06` is GET APP CONFIGURATION — and in which `GET_SIGNATURE_CHUNK` sat on `0x18`, the Ethereum app's PERFORM PRIVACY OPERATION. Old → new: `0x0E`→`0x02`, `0x06`→`0x04`, `0x08`→`0x06`, `0x12`→`0x40`, `0x14`→`0x42`, `0x02`→`0x44`, `0x04`→`0x46`, `0x10`→`0x48`, `0x0A`→`0x4A`, `0x0C`→`0x4C`, `0x16`→`0x4E`, `0x18`→`0x50`. Command *names*, `P1`/`P2` roles and payload layouts are unchanged by the renumbering.

### Commands with an Ethereum-app analogue

| INS | Command | Ethereum app | P1 | P2 |
|---|---|---|---|---|
| `0x02` | `GET_ADMIN_ADDRESS` | GET ETH PUBLIC ADDRESS `0x02` [S1] | `00` return, `01` display and confirm before returning [S1] | `00` (no chain code) |
| `0x04` | `SIGN_PREAPPROVAL` | SIGN ETH TRANSACTION `0x04` [S1] | `00` first payload block, `80` subsequent block [S1][S2] | slot index **[new]** |
| `0x06` | `GET_APP_CONFIG` | GET APP CONFIGURATION `0x06` [S1] | `00` | `00` |
| `0x0A` | `PROVIDE_ERC20_TOKEN_INFORMATION` | PROVIDE ERC 20 TOKEN INFORMATION `0x0A` [S1] | `00` legacy, `01` TLV [S1] | TLV chunking, `01` first / `00` following [S1] |

`GET_ADMIN_ADDRESS` returns the `quantumAdmin` public key and address in the Ethereum app's output layout — public-key length, uncompressed public key, address length, ASCII address [S1]. With `P1 = 01` it shows the address on-device first, through the SDK's address-review flow, which is what the ceremony preflight uses to let the Administrator compare it out-of-band. The Ethereum-app spelling of `GET_APP_CONFIG` is `GET_APP_CONFIGURATION`; both name the same command.

`SIGN_PREAPPROVAL` signs one EIP-712 pre-approval — or one FermionWallet `Transfer`, see [Open items for FermionWallet](#open-items-for-fermionwallet) — with the selected XMSS key **and** the `quantumAdmin` key. On confirm it commits the NVM counter, then answers with the leaf index, the digest and the signature length; the signature itself is paged out with `GET_SIGNATURE_CHUNK` (see [Signature readout](#signature-readout-new)). **[new]**

### FermionGuard-specific commands

All at `0x40` and above, all even, none colliding with an Ethereum-app instruction. Every command that names an XMSS key takes the slot index in `P2` and the expected root prefix in its data.

| INS | Command | P1 | P2 | Notes |
|---|---|---|---|---|
| `0x40` | `GEN_XMSS_KEY` | `00` | `00` | generates a new key in a free slot (Flow 1); returns the slot index and its public key. Refused with `0x6A89` when all `MAX_KEYS` slots are in use; never touches an existing key **[new]** |
| `0x42` | `LIST_KEYS` | `00` | `00` | read-only: for each slot, whether it is free or in use, and for keys in use the root, tree height, parameter set, and leaves used / total **[new]** |
| `0x44` | `GET_XMSS_ROOT` | `00` return, `01` display and confirm | slot | for the selected slot: returns public root + public SEED + tree height + parameter set. The public SEED is a mandatory RFC 8391 verification input (registered on-chain as `xmssSeed`; registration rejects a zero seed); it is not secret. `P1` follows the Ethereum app's public-key convention [S1] **[new]** |
| `0x46` | `GET_LEAF_INDEX` | `00` | slot | returns the selected key's next unused index (read-only) **[new]** |
| `0x48` | `SIGN_KEY_ATTESTATION` | `00` first, `80` more | slot | for the selected slot: signs the EIP-712 `QuantumKeyAttestation { safe, xmssRoot, xmssSeed, treeHeight, parameterSet, registryNonce }` with the `quantumAdmin` key (the `ledgerAttestation` that `registerQuantumKey` and `rotateQuantumKey` verify). The host supplies only `safe`, the chain and `registryNonce`; the device fills root, SEED, height and parameter set **from its own key**, so a host cannot attest a substituted root. Reviewed fields: `Safe`, `Network`, `Key`, `Registry nonce`. No counter commit, no leaf consumed. ECDSA only, so it returns `v ‖ r ‖ s` directly, in the Ethereum app's signature output layout [S1] |
| `0x4A` | `SIGN_ROTATION` | `00` first, `80` more | slot (the old key) | streams the full EIP-712 `RotateQuantumKey { safe, oldQuantumKeyId, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, registryNonce, validUntil }` and its domain (chain ID, verifying contract = the Guard). The slot in `P2` is the **old** key. The device recomputes the digest from the fields it displays — it never signs a host-supplied hash — and refuses a `newXmssRoot` equal to the old key's root; a `newXmssRoot` held in another of its own slots is shown as such. Shows the rotation flow (Flow 3); on confirm, commits the counter, then buffers the old key's XMSS possession proof over that digest (the same digest the owners co-sign) for `GET_SIGNATURE_CHUNK` **[new]** |
| `0x4C` | `SIGN_DENIAL` | `00` first, `80` more | slot | streams the denial record (payload hash + reason hash); device shows the denial flow; on confirm returns a plain ECDSA `v ‖ r ‖ s` by the `quantumAdmin` key — **no counter commit, no leaf consumed** |
| `0x4E` | `RETIRE_KEY` | `00` | slot | erases the selected slot's secrets and counter after the double-confirmed *Retire key* flow; the slot becomes free. No other slot is affected **[new]** |
| `0x50` | `GET_SIGNATURE_CHUNK` | `00` first chunk, `80` next | `00` | pages out the signature the last confirmed signing command produced, mirroring the Ethereum app's `P1_FIRST`/`P1_MORE` convention on the way out [S2]. Read-only; consumes nothing **[new]** |

A command that names a slot which is free is refused with `0x6A82`. No command exposes seed material.

**A session in flight.** A *signing* command that arrives while another signing session is open is refused with `0x6980` and the pending review is dismissed — which is exactly what the Ethereum app does: `handle_first_sign_chunk` returns `SWO_COMMAND_NOT_ALLOWED` when `appState != APP_STATE_IDLE`, and the main loop then calls `ui_idle()` to "dismiss any ongoing review" and `reset_app_context()` because the status word is not `SWO_SUCCESS` [S2]. Read-only commands (`GET_APP_CONFIG`, `LIST_KEYS`, `GET_LEAF_INDEX`, `GET_XMSS_ROOT` without the display flag, `GET_SIGNATURE_CHUNK`) are answered regardless, as the Ethereum app answers GET APP CONFIGURATION regardless [S2].

### Derivation path

The `quantumAdmin` secp256k1 key is addressed exactly as the Ethereum app addresses its keys. The host puts the path at the head of the first data chunk as `number of derivations (1 byte, max 10) ‖ index (4 bytes, big endian) × n` [S1]; the app's build declares `CURVE_APP_LOAD_PARAMS = secp256k1` and `PATH_APP_LOAD_PARAMS = "44'/60'"`, which the Ethereum app's own Makefile describes as an "isolation mechanism" enforced outside the app [S3]. Default and recommended path: `m/44'/60'/0'/0/0`.

This replaces an earlier rule in this document — "derived at a fixed, app-specific BIP-32 path declared in the app manifest (never host-supplied)". That was non-standard and bought nothing: what binds the Administrator is the `quantumAdmin` address recorded in `QuantumKeyRegistry`, and a host that names a different path gets a different address, which the registry rejects and which `GET_ADMIN_ADDRESS` with `P1 = 01` shows the Administrator before the ceremony.

### Chunked input

Long payloads stream in the Ethereum app's shape: `P1 = 0x00` for the first block, `P1 = 0x80` for each subsequent block, "255 bytes maximum data chunks" [S1][S2]. First-chunk layout for `SIGN_PREAPPROVAL`, `SIGN_ROTATION`, `SIGN_KEY_ATTESTATION` and `SIGN_DENIAL`:

| Field | Length |
|---|---|
| Number of BIP-32 derivations (max 10) | 1 |
| Derivation index, big endian | 4 × n |
| Total payload length, big endian | 4 |
| Expected root prefix, first 8 bytes of the slot's root **[new]** | 8 |
| Payload chunk | var |

Subsequent chunks carry the payload continuation and nothing else. The path-then-length-then-payload order and the 4-byte big-endian total length are SIGN ETH PERSONAL MESSAGE's layout [S1]. A payload that fits in one APDU is sent as a single `P1 = 0x00` block.

The total-length field counts the **payload only**: the path, the length field and the root prefix are header, not payload. So the payload lengths the parser discriminates on — 132 bytes for a FermionWallet `Transfer` against a pre-approval's 373, see [Open items for FermionWallet](#open-items-for-fermionwallet) — are unchanged by this header.

Mid-stream, a `P1` outside `{0x00, 0x80}`, a chunk that would overrun the declared total length, or a total length above the app's buffer aborts the session and discards everything received so far — `0x6B00`, `0x6A87`, `0x6A84` respectively. There is no resume.

### Signature readout **[new]**

An `XMSS-SHA2_20_256` signature is 2,820 bytes (`idx` 4 ‖ `r` 32 ‖ WOTS+ 67×32 ‖ auth path 20×32). A Ledger APDU response carries at most 258 data bytes [S5], and the SDK's I/O buffer is `OS_IO_SEPH_BUFFER_SIZE = 272` by default [S16]. The signature therefore cannot be returned the way the Ethereum app returns `v ‖ r ‖ s`, and this is the one place where FermionGuard needs a mechanism the Ethereum app has no equivalent for.

`SIGN_PREAPPROVAL` / `SIGN_ROTATION` respond, after the counter commit, with:

| Field | Length |
|---|---|
| Leaf index consumed, big endian | 4 |
| EIP-712 digest signed | 32 |
| Buffered signature length, big endian | 2 |

`GET_SIGNATURE_CHUNK` then pages the buffer: `P1 = 0x00` returns the first chunk, `P1 = 0x80` each following chunk, at most 255 bytes of data each, `0x9000` per chunk.

The buffer is laid out **XMSS signature first, ECDSA `v ‖ r ‖ s` last**, so a host cannot hold the classical half without having already received the complete quantum half — the hybrid-binding invariant survives the chunking literally, not just in spirit. The buffer is zeroized when its last byte has been delivered, and on the next signing command. Read-only commands do not disturb a readout in progress; `GET_SIGNATURE_CHUNK` with `P1 = 0x00` restarts it from the first chunk. `GET_SIGNATURE_CHUNK` with nothing buffered returns `0x6A88`.

The SDK does expose `CUSTOM_IO_APDU_BUFFER_SIZE` to enlarge the APDU buffer [S16], which would allow a single-response signature. We do not use it: a ~2.9 KB global I/O buffer on top of the XMSS working set is the wrong trade on Nano S Plus, and an oversized global I/O buffer reads as a finding in review.

### Status words

Drawn from the SDK's `include/status_words.h` [S4], restricted to codes the Ethereum app itself emits [S2] wherever one fits.

| SW | SDK name | Meaning here | In the Ethereum app |
|---|---|---|---|
| `0x9000` | `SWO_SUCCESS` | success | success |
| `0x6985` | `SWO_CONDITIONS_NOT_SATISFIED` | the Administrator rejected on the device, or the confirmation page timed out | user rejected a review [S2] |
| `0x6980` | `SWO_COMMAND_NOT_ALLOWED` | a signing command arrived while another signing session was open; the pending review is dismissed **[new for the dismissal only]** | `appState != APP_STATE_IDLE` [S2] |
| `0x6A80` | `SWO_INCORRECT_DATA` | payload malformed, unknown EIP-712 type or domain, field out of range, validity window inconsistent | its most-used error [S2] |
| `0x6A84` | `SWO_INSUFFICIENT_MEMORY` | declared payload larger than the app's buffer | same [S2] |
| `0x6A87` | `SWO_WRONG_DATA_LENGTH` | `Lc` inconsistent with the declared total length | used where `Lc` is wrong for the command [S2] |
| `0x6B00` | `SWO_WRONG_P1_P2` | `P1`/`P2` outside the values in the tables above, including a slot index ≥ `MAX_KEYS` | same [S2] |
| `0x6D00` | `SWO_INVALID_INS` | unknown instruction | same [S2] |
| `0x6E00` | `SWO_INVALID_CLA` | `CLA ≠ 0xE0` | same [S2] |
| `0x6501` | `SWO_MEMORY_WRITE_ERROR` | the leaf-counter commit did not land; no signature is released **[new]** | used, but for an unsupported transaction type, with a `TODO` in the source saying the code is wrong [S2]; our use is the SDK's ISO meaning, *"65 — Execution error, the state of persistent memory is changed"* [S4] |
| `0x6A81` | `SWO_FUNCTION_NOT_SUPPORTED` | the slot is bound to the other product — a wallet-bound key asked for a Safe pre-approval, or the reverse (FWL-023) **[new]** | not used |
| `0x6A82` | `SWO_FILE_NOT_FOUND` | the named slot is free **[new]** | used [S2] |
| `0x6A88` | `SWO_REFERENCED_DATA_NOT_FOUND` | root prefix does not match the named slot; or `GET_SIGNATURE_CHUNK` with nothing buffered **[new]** | used [S2] |
| `0x6A89` | `SWO_FILE_ALREADY_EXISTS` | `GEN_XMSS_KEY` with no free slot **[new]** | used [S2] |
| `0x6983` | `SWO_AUTH_METHOD_BLOCKED` | the key is exhausted: every leaf is spent, rotate **[new]** | not used — no Ethereum key can be exhausted |

No proprietary status word is minted. Every code above is an SDK-defined ISO 7816-4 code; the SDK reserves `67XX`, `6BXX`, `6DXX`, `6EXX`, `6FXX` with `XX ≠ 0`, and `9YYY` with `YYY ≠ 000`, for proprietary use [S4], and we stay out of those ranges so a host's generic Ledger error handling keeps working.

### `GET_APP_CONFIG` response

The first four bytes are the Ethereum app's response, byte for byte [S1], so a host that only knows the Ethereum app reads a valid answer:

| Field | Length | Value |
|---|---|---|
| Flags | 1 | `0x01` *arbitrary data signature enabled by user* — **always 0**, there is no blind-signing setting (see [Blind signing](#blind-signing)). `0x02` *ERC-20 token information needs to be provided externally* — **always 1**. `0x10`/`0x20` Transaction Check — 0 |
| Application major version | 1 | |
| Application minor version | 1 | |
| Application patch version | 1 | |
| Parameter-set identifier **[new]** | 1 | `0x01` = `XMSS-SHA2_20_256` |
| `MAX_KEYS` **[new]** | 1 | 4 |
| Slot-in-use bitmap **[new]** | 1 | bit *i* set ⇒ slot *i* holds a key |
| Tree height *h* **[new]** | 1 | 20 |

`Le = 8`; the Ethereum app's is 4 [S1].

### Token information

`PROVIDE_ERC20_TOKEN_INFORMATION` (`0x0A`) is adopted from the Ethereum app unmodified: same `P1` selection between the legacy raw payload and the TLV `DYNAMIC_TOKEN_DESCRIPTOR`, same `ticker ‖ address ‖ decimals ‖ chainId` signed body, same Ledger CAL signing key, same `P2` chunking for TLV, same one-byte "asset index" response [S1]. Flag `0x02` of `GET_APP_CONFIG` is therefore always set: the host must provide a descriptor for any token it wants named, exactly as with the Ethereum app. No token list is compiled into the app.

One behavioural difference, in our favour, stated so a reviewer does not read it as a gap: in the Ethereum app a token with no descriptor makes the call undecodable, the plugin falls back, and the transaction becomes blind-signable only [S21]. Here the payload's structure comes from a fixed EIP-712 type, not from calldata, so a missing descriptor costs only the ticker — `Amount` shows the raw integer and a `Token` field shows the full contract address. Nothing becomes blind.

## Installation, supported devices, and updates

**Supported devices.** Ledger **Nano S Plus, Nano X, Stax, and Flex** (all carry the ST33-family secure element with the monotonic-counter NVM primitives the app requires). The original Nano S is **not** supported: insufficient app flash for the XMSS working set. The Ethereum app's manifest also lists `apex_p` [S3]; FermionGuard adds a device only once the XMSS working set has been measured on it. Minimum firmware: the latest stable Ledger OS for each device at release time, pinned in the app's `Cargo.toml`/manifest — the app refuses to install on older firmware.

**Installation path (production).** Through **Ledger Live → My Ledger → App catalog → "FermionGuard XMSS"**, after the app passes Ledger's third-party security review and is listed. This is the only path end users should use: catalog apps are signed by Ledger, and the device's genuine check + Ledger Live's signature verification together guarantee an unmodified binary on a genuine device. Until catalog listing is complete, institutional pilot users install a Ledger-signed release build via the same Ledger Live mechanism under the "developer mode" listing — **never** a self-built sideload for a key that will guard real funds.

**Installation path (development only).** Engineers use `cargo ledger build` + `ledgerctl install` sideloading onto a dev device, and `speculos` for CI. Sideloaded builds display a persistent "PENDING LEDGER REVIEW" warning on the device (standard BOLOS behavior for unsigned apps); any device showing that warning must never hold a production key.

**Verifying the app before the ceremony.** The Safe App's ceremony preflight (Stage A) queries `GET_APP_CONFIG` and checks: app name/version against the published release, parameter-set identifier `0x01` (`XMSS-SHA2_20_256`), and the device's genuine-check status via Ledger's attestation. The ceremony refuses to proceed on any mismatch — this is what the "device verified" line in the UI means, and it is machine-checked, not a user promise.

**Updates.** App updates ship through the same Ledger Live catalog channel. Updating the app **preserves NVM state** (seed and leaf counter live in app-owned NVM that survives app upgrades under BOLOS); uninstalling the app **destroys every key on it** — Ledger Live warns, and so does this document: *uninstalling the XMSS app is equivalent to losing the device* and requires the on-chain key-rotation procedure ([`quantum-key-registry.md`](./quantum-key-registry.md)), never a restore. There is no rollback to older app versions (Ledger Live installs latest-only); a bad release is handled by publishing a fixed version, not by downgrade.

Ledger's own guidance records that "App settings are reset to their default values every time your app is updated or reinstalled after an OS update" [S11]. The exhaustion-warning threshold is a convenience and may reset; nothing security-relevant depends on a setting surviving an update, and the leaf counter is not a setting.

## Device UI specification

Illustrated screen-by-screen reference with mockups: [`ledger-ui.md`](./ledger-ui.md).

On-device screens for every flow. The device screen is the last honest surface in the system — everything here assumes the host is compromised.

### UI principles

1. **The SDK's review flow, not a custom one.** Every signing flow is an NBGL review: an intent page whose title begins with "Review" [S10], then the signed fields as tag/value pairs — one pair per step on the Nano screens, auto-paginated lists on Stax and Flex — then a confirmation page whose action is **Hold to sign** [S6], then a status page. The field numbering in the flows below is the order of the pairs, not a promise of one page each. The app uses the SDK's high-level use-case functions rather than low-level drawing: of those functions Ledger writes *"Prefer these over low-level rendering calls to stay in compliance with these guidelines with minimal effort"* [S22]. Navigation is bidirectional; the app does not use the streaming review APIs, which Ledger's own guidance tells apps to avoid — "Blocking users in a forward-only progression is not recommended UX" [S13] — even though the payload arrives over several APDUs. The payload is fully received and parsed before the first page is drawn.
2. **Rejection is always available, and is confirmed.** `Reject` is the footer of every review page, and choosing it raises the SDK's confirmation — `Reject operation?` / `Yes, reject` / `Go back to operation` [S6]. This replaces an earlier rule in this document that made Reject a single unconfirmed tap "so the physically easiest action is Reject": a mis-tapped reject throws away a pre-approval the owners are waiting on, and the asymmetry that matters is already supplied by `Hold to sign`, which no accidental touch produces.
3. **NBGL on every device; there is no BAGL build.** The Ethereum app builds with `ENABLE_NBGL_FOR_NANO_DEVICES = 1`, and the SDK sets `USE_NBGL = 1` for Nano X and Nano S Plus when that flag is set [S15]; the app ships no BAGL code path at all. This document previously specified separate "NBGL (Stax/Flex)" and "BAGL (Nano)" targets. It is one UI layer, rendered at four screen sizes.
4. **No colour carries meaning.** NBGL's entire palette is `BLACK`, `DARK_GRAY`, `LIGHT_GRAY`, `WHITE`, and under `BICOLOR_MODE` — the Nano screens — the first three are all `0` [S7]. The teal / amber / red framing convention this document used to specify was not implementable. Flows are distinguished by (a) the intent and confirmation titles, (b) the SDK's warning page and the warning icon it then places on the intent and confirmation pages (`nbgl_warning_t`, predefined warning set) [S6], and (c) explicit tag/value fields. The colours in the mock-ups are a reading aid for this document only, and say so.
5. **Addresses are EIP-55, in full.** Every address is rendered `0x` + EIP-55 mixed-case checksummed hex, as `getEthDisplayableAddress` / `getEthAddressStringFromBinary` do, with the EIP-1191 variant on chains 30 and 31 [S8], and is never truncated — Ledger's address guidance is that the address must be shown in full for comparison against its software counterpart [S9]. The `0x1234 5678 … ABCD` 4-byte grouping this document used to specify was ours alone and is gone: a reviewer comparing an address against a block explorer now sees the same string a Ledger user always sees, including its capitalisation, which is itself a checksum.
6. **32-byte hashes are shown in full too.** The Ethereum app's `Transaction hash` field shows the whole hash [S19]. `policyHash`, the Safe `txHash` pin, a batch `dataHash` and the XMSS root are therefore shown in full across pages, not as first/last 8 characters. Ledger permits hiding a long field behind progressive disclosure but restricts it to "fields that do not affect your user's privacy, security, or funds" [S13], which excludes every hash this app binds to.
7. **The leaf index is always visible.** **[new]** It is the app's odometer; the Administrator learns to notice a jump (a host burning leaves) the way a driver notices mileage. It is a `Leaf` field on every flow that consumes one, and a `Leaf` field stating that none is consumed on the flows that do not.
8. **One signature, one payload, one confirmation.** There is no "sign N pending transactions" mode in the firmware. A `MultiSendCallOnly` batch is a *single* payload: the review shows `Legs`, per-token totals (host-supplied, informational) and the binding batch `dataHash` in full — leg-by-leg review happens in the add-on UI, and the on-chain Guard re-validates every leg independently.
9. **Display only signed fields.** Every field on a review page comes from the signed EIP-712 struct or its domain. Host-supplied context that is not signed — a Safe nonce, a label, a queue position — is never displayed.

### Flow 1 — Key generation (`GEN_XMSS_KEY`, into a free slot) **[new]**

![Key generation screens](./assets/ui/ledger/ledger-keygen.svg)

| # | Page | Content / action |
|---|---|---|
| 1 | Intent | "Review new quantum key" — target slot ("Key 3 of 4 — keys 1–2 are kept"), parameter set (`XMSS-SHA2_20_256`), lifetime ("1,048,576 approvals") |
| 2 | No-backup warning | SDK warning page: "This key cannot be backed up" / "It is generated inside this device. It cannot be exported, and your recovery phrase will not restore it." Its action is `Generate key?`; declining returns to home. This is the #1 support surprise, surfaced before generation, not after |
| 3 | Progress | Tree-construction progress bar with a time estimate (minutes on Nano-class MCUs); cancellable until complete |
| 4 | Root review | Full 32-byte root across pages, plus the derived **6-word ceremony code** rendered on-device — the words the owners verify out-of-band come from the secure element itself, not from the host UI |
| 5 | Confirm export | "Share public key with host?" — Approve / Reject. Only the root, public SEED, height and parameter set cross the wire |
| 6 | Attest (`SIGN_KEY_ATTESTATION`) | Its own review: intent "Review key attestation", fields `Safe`, `Network`, `Key`, `Registry nonce`, confirmation "Sign attestation?" with Hold to sign. Approve produces the `ledgerAttestation` the registry requires; the key fields come from the device, not the host |

`GET_XMSS_ROOT` with `P1 = 01` for a slot in use replays pages 4–5 only; attestation (page 6) is its own command and is repeated per Safe and per `registryNonce`. Generating another key uses the next free slot and leaves every existing key untouched; freeing a slot requires the explicit *Retire key* flow.

### Flow 2 — Sign pre-approval (`SIGN_PREAPPROVAL`)

![Signing screens 1–4](./assets/ui/ledger/ledger-sign-1.svg)
![Signing screens 5–8](./assets/ui/ledger/ledger-sign-2.svg)

Intent page: **"Review approval"**. Then the signed fields, as tag/value pages. The first three reuse the Ethereum app's own labels and order — `Amount`, `To`, `Network` [S19] — so the rows a Ledger user reads first are the rows they already know; the FermionGuard fields follow.

| # | Field | Content |
|---|---|---|
| 1 | `Amount` | decimals-adjusted with the ticker, `500,000.00 USDC`, from the CAL descriptor the host provided. With no descriptor: the raw integer, no ticker |
| 2 | `Token` | shown only when there is no descriptor: full EIP-55 contract address, labelled `Unknown token` |
| 3 | `To` | recipient, full EIP-55 address |
| 4 | `Network` | chain name when the chain is known, otherwise the decimal chain ID — the Ethereum app's own fallback [S20] |
| 5 | `Safe` | Safe address, full EIP-55 **[new]** |
| 6 | `Valid from` / `Valid until` | absolute UTC times ("21 Sep 2026 15:40 UTC"), not durations — durations hide clock-skew games **[new]** |
| 7 | `Safe tx` | the binding read from the signed `txHash`: the full 32-byte hash when set. When it is zero, an SDK warning page precedes the review and the field reads `Not pinned — any matching transfer` (a field-matched approval executes for *any* Safe transaction with this token, recipient and amount, at any Safe nonce, until used or expired). The Safe nonce is **not** shown: it is not in the signed payload, so displaying it would promise a binding the Guard does not enforce **[new]** |
| 8 | `Policy hash` | full 32-byte `policyHash`; the full policy is enforced on-chain, the hash is what this signature binds **[new]** |
| 9 | `Key` | `Key 2 · orbit velvet` **[new]** |
| 10 | `Leaf` | `184,203 of 1,048,576` **[new]** |

Confirmation page: **"Sign approval?"** with **Hold to sign** [S6]. On approve the NVM counter commits, *then* the hybrid signature is buffered for `GET_SIGNATURE_CHUNK` — the ECDSA half and the XMSS half over the same digest (counter-before-signature invariant) **[new]**. Status page: `Operation signed` or `Operation rejected`, the SDK's own wording [S6]. On reject, or on a 60-second idle timeout on the confirmation page: `0x6985`, no state change, no leaf consumed. Unknown or malformed payload fields abort before the intent page with `0x6A80` — there is no "review anyway" path.

**Non-transfer classes (`PAYLOAD`/`ADMIN`):** the same flow with fields 1–3 replaced by `To` (the target, full EIP-55), `Value` (native ETH) and `Data hash` (full 32 bytes). An `ADMIN`-class payload additionally opens on an SDK warning page — "This operation affects Safe governance" — which puts the warning icon on the intent and confirmation pages [S6], and shows an `Effect` field with the decoded intent when the host supplies one ("Removes the FermionGuard"). The class is part of the signed payload, so a host cannot present an admin action as a transfer.

### Flow 3 — Rotation (`SIGN_ROTATION`, old-key possession proof) **[new]**

![Rotation screens](./assets/ui/ledger/ledger-rotate.svg)

Signed with the **old** key's slot. An SDK warning page — "You are replacing this Safe's quantum key" — precedes the intent page **"Review key rotation"**, so the warning icon sits on the intent and confirmation pages and the confirmation reads **"Sign key rotation?"**. A host can neither present a rotation as a routine approval nor hide which key signs it.

The possession proof is an XMSS signature over the **full** `RotateQuantumKey { safe, oldQuantumKeyId, newQuantumAdmin, newXmssRoot, newXmssSeed, treeHeight, parameterSet, registryNonce, validUntil }` digest, so every signed field is a page before the confirmation — no field is signed blind:

- `Safe` (full EIP-55) and `Network`;
- `New administrator` (full EIP-55), with its own SDK warning page when it differs from this device's own `quantumAdmin`;
- `New key` — ceremony words, full root and SEED, tree height as lifetime approvals, parameter set, and `Key 3 on this device` or `another device`;
- `Old key` — ceremony words and `Abandoning 61,204 unused approvals`, so an attacker cannot socially engineer a pointless rotation invisibly;
- `Registry nonce` and `Valid until` as an absolute UTC time;
- `Leaf` — the one old-key leaf this costs.

`oldQuantumKeyId` is not human-meaningful and is shown only as a short fingerprint; it is bound by the owners' co-signatures over the same digest.

### Flow 4 — Deny (`SIGN_DENIAL`, ECDSA receipt, no leaf)

![Denial screens](./assets/ui/ledger/ledger-deny.svg)

Intent page **"Review denial"**, confirmation **"Sign denial?"**, status `Operation signed`. Shows the same decoded payload plus the app-supplied reason (its hash is part of the signed record) and a `Leaf` field reading `None consumed`. The signature is plain ECDSA over the denial record — the XMSS counter never moves. A denial cannot be mistaken for an approval because its intent title, its confirmation title and its `Leaf` field all say what it is; it does not rely on a colour the device cannot draw.

### Home and settings

![Home, settings and error screens](./assets/ui/ledger/ledger-ambient.svg)

The home screen is the SDK's home-and-settings home page and nothing else: app icon, app name, and a one-line description [S12] — Ledger's guidance is that the home screen shows exactly those three things. The per-key leaf-usage dashboard this document used to put there has moved into settings. Where a key is bound to a single verifying contract on a single chain (FWL-023), the description line names that binding, because invisible state that decides whether a signature will be refused is state the Administrator should be able to read off the device. Settings come before the app's info [S11], mirroring the Ethereum app's own ordering [S17].

- **Settings → Keys** **[new]** — one row per slot: `Key <slot> · <two ceremony words>`, `184,203 / 1,048,576 (17%)`, the slot's exhaustion state, and its contract binding if it has one. A free slot reads `Free`. This is the audit-photograph page.
- **Settings → Exhaustion warning** — the threshold at which the warning page is prepended to signing flows.
- **Settings → Retire key** **[new]** — per slot, opening on an SDK warning page, then the review `Review key retirement` → ceremony words, unused-leaf count → `Retire key?`, held not tapped.
- **Info** — `Version` and `Developer` at minimum, which is what Ledger requires [S11]; the Ethereum app lists `Version`, `Developer`, `Copyright` [S17]. We add `Parameter set`, so the parameter lock is visible without a host.

There is no `Blind signing` switch, no `Debug contracts` switch and no `Raw messages` switch — three the Ethereum app has [S17] — because there is nothing this app can sign blind. See below.

Leaf-exhaustion states **[new]**, none of which the Ethereum app has an analogue for: at or above the warning threshold every signing flow opens with an SDK warning page ("Rotation overdue"); at 100% the app refuses to sign, returns `0x6983`, and shows a page whose only content is the rotation instruction.

### Blind signing

The Ethereum app treats blind signing as a user choice. When a transaction cannot be clear-signed it shows "This transaction cannot be clear-signed" / "Enable blind signing in the settings to sign this transaction." with the actions `Go to settings` and `Reject transaction` [S18], and the SDK's warning for the enabled case reads "Blind signing required" / "This transaction's details are not fully verifiable. If you sign, you could lose all your assets." [S6].

FermionGuard keeps the wording and drops the escape hatch: a payload this app cannot fully decode produces "This approval cannot be clear-signed" / "FermionGuard never signs a payload it cannot display." and one action, `Reject`. There is no setting to enable, which is why `GET_APP_CONFIG` flag `0x01` is always 0 and why the settings menu has no `Blind signing` switch. Ledger's guidance requires the blind-signing setting to default off and to warn on every blind transaction [S10]; refusing outright is strictly stronger, and is the one place where an experienced Ledger user should expect *less* freedom here than in the Ethereum app.

### Error reporting

The Ethereum app answers an APDU-level fault with a status word and leaves the screen where it was; it raises a screen only where the user has something to decide, the blind-signing choice being the example [S18]. FermionGuard follows that. It is a change from an earlier version of this document, which gave "every host-side failure a distinct, plain-language device screen":

- **Status word only, no screen**: malformed payload (`0x6A80`), session in flight (`0x6980`), slot free (`0x6A82`), root-prefix mismatch (`0x6A88`), no free slot (`0x6A89`), product mismatch (`0x6A81`), bad `P1`/`P2` (`0x6B00`), inconsistent length (`0x6A87`), oversized payload (`0x6A84`). The host has the code and is the right place to explain it.
- **Screen and status word**, because the Administrator must act on the device: `Key exhausted — rotate this key` (`0x6983`), the counter-commit failure `Could not record the leaf. No signature was produced.` (`0x6501`), and the blind-signing refusal above.
- **Screen, no status word**: the "Rotation overdue" warning page, which is part of a flow that then continues.

Where a device screen does exist it is plain language, never a numeric code — numeric codes live at the APDU layer, which is also where Ledger requires them to be documented: an `apdu.md` in the app repository listing every APDU and every error it can return, with error ranges following the SDK [S14].

### Device UI acceptance criteria

- [ ] No signature can be produced without traversing every field page of Flow 2 (enforced in firmware, verified by `ragger` snapshot tests on every supported device)
- [ ] Reject/timeout paths consume no leaf — power-cycle fuzzing across the confirmation page shows counter monotonicity with zero unexplained increments
- [ ] Addresses are EIP-55-checksummed and never truncated anywhere in the firmware — snapshot-diffed against a forbidden-pattern list (`…` in an address context fails CI), and the checksum capitalisation asserted against a reference implementation
- [ ] 32-byte values (`policyHash`, `txHash`, batch `dataHash`, XMSS root, digest) are shown in full, never abbreviated
- [ ] Ceremony words rendered on-device match the host derivation for 10k random roots
- [ ] A rotation flow cannot be mistaken for a signing flow: distinct intent title, distinct confirmation title, a warning page before the intent — and none of these distinctions relies on colour, which NBGL does not offer [S7]
- [ ] Page 2 no-backup warning shown before any key material is generated
- [ ] Key isolation: signing with one key never changes another key's counter, and `RETIRE_KEY` on one slot leaves every other slot byte-identical (NVM snapshot diff)
- [ ] A command whose root prefix does not match its slot is refused before any screen is shown; so is `GEN_XMSS_KEY` with no free slot
- [ ] The home screen shows only icon, name and description; settings precede info [S11][S12]
- [ ] Every status word in the table above is reachable in `ragger` and matches the app's `apdu.md`
- [ ] All screens localized-ready but shipping English-only (audit surface minimization)

## Deliberate deviations from the Ethereum app

Beyond the five **[new]** mechanisms, which have no counterpart to deviate from:

| Deviation | Reason, in one line |
|---|---|
| Blind signing cannot be enabled; no `Blind signing` setting; `GET_APP_CONFIG` flag `0x01` always 0 | A pre-approval this app cannot display is a pre-approval nobody can audit, and the Administrator signs for other people's funds. |
| `GET_APP_CONFIG` returns 8 bytes, not 4 | The parameter set, `MAX_KEYS`, slot bitmap and tree height must be machine-checkable in the ceremony preflight; the first 4 bytes are unchanged. |
| A signature is paged out with `GET_SIGNATURE_CHUNK` instead of returned by the signing command | 2,820 bytes does not fit a 258-byte APDU response [S5][S16]. |
| `P2` carries the key-slot index | `P1` is already the chunk flag; the Ethereum app has one key space and needs no slot selector. |
| A 60-second idle timeout on the confirmation page aborts the flow (`0x6985`, no leaf consumed) | `nbgl_use_case.c` has no idle timeout: the Ethereum app leaves a pending review up until the user answers or the host sends another signing command, which cancels it [S2]. Ours is operational, not a security control — an unattended device should not sit on an approval waiting for a host that may never come back. |
| No `Debug contracts` / `Raw messages` settings | Both exist to make undecodable data viewable; this app decodes a fixed EIP-712 type or refuses. |
| A missing token descriptor degrades one field instead of forcing blind signing | Our payload's structure comes from the EIP-712 type, not from calldata [S21]. |
| `Info` carries a `Parameter set` row beyond Ledger's required `Version` + `Developer` | The app and the on-chain verifier are parameter-locked; an auditor must be able to photograph the pairing. |

## Security requirements

- **Display only signed fields**: every value on a review page must come from the signed EIP-712 struct (or its domain). Host-supplied context that is not signed — a Safe nonce, a label, a queue position — must never be displayed as if it constrained the approval.
- **Key isolation**: every key has its own seeds and counter; no command can sign with, read, or reset a key other than the one it names (slot in `P2` + root prefix). Retiring a key zeroizes that slot only; no command resets a counter while its key exists.
- **Counter-before-signature invariant**: the NVM counter commit must be atomic and precede signature release. A power loss between commit and release loses one leaf (acceptable); the reverse order is forbidden (catastrophic).
- **Hybrid binding**: the ECDSA and XMSS halves of a pre-approval are computed inside the device over the identical EIP-712 digest and buffered only together, after the counter commit. The readout order puts the ECDSA half last, so no host can obtain it without the complete XMSS half. There is no command that returns an ECDSA signature over a pre-approval digest by itself.
- Blind signing must be impossible: no raw-hash signing path; every signature goes through the field-rendering flow; no setting can relax this.
- NVM wear: counter updates must use the SDK's wear-leveled storage; budget ≥ 2^20 writes.
- Signing time: target < 3 s per signature on current devices (WOTS+ chains dominate; precompute where the SDK allows).
- The parameter set (e.g., `XMSS-SHA2_20_256` or keccak variant) is fixed at build time and attested via `GET_APP_CONFIG`; the on-chain verifier and the app must be parameter-locked to each other.
- The build declares `CURVE_APP_LOAD_PARAMS = secp256k1` and `PATH_APP_LOAD_PARAMS = "44'/60'"`, so Ledger OS, not the app, refuses any derivation outside the declared subtree [S3].
- App must pass Ledger's security review for distribution; until then, sideloaded builds are restricted to testnets.

## Defense-in-depth relationship to the chain

The on-chain used-leaf bitmap in the Guard/registry stays in place even after this app ships. Device counter and on-chain bitmap independently prevent leaf reuse; either alone is sufficient, both together tolerate a failure of the other.

## Deliverables and validation

- [ ] Rust app implementing the APDU interface above
- [ ] an `apdu.md` in the app repository's docs folder — `doc/apdu.md`, where the Ethereum app keeps its own — in the layout Ledger's submission process requires, documenting every APDU and every status word it can return [S14]
- [ ] `speculos`/`ragger` CI suite: signing flow, counter monotonicity across power cycles, exhaustion refusal, chunked payload edge cases, `GET_SIGNATURE_CHUNK` readout including abort-mid-readout zeroization, and UI snapshot tests for every page of every flow on every supported device
- [ ] Cross-verification test: 10k device signatures verified by the Solidity XMSS verifier in Foundry, and device-produced hybrid pairs plus key attestations accepted end to end by `createPreApproval`, `registerQuantumKey`, and `rotateQuantumKey` (a real Safe in Foundry; the rotation test uses a device-produced possession proof, including a same-device rotation with the old and new key in two slots)
- [ ] Host SDK in the add-on service (`ledger-xmss.ts`) replacing the Phase 1 software keystore path behind the same interface
- [ ] Ledger security review submission

### Open items for FermionWallet

[fermionwallet.md](./fermionwallet.md) specifies a second product: one contract holding ERC-20 tokens,
no Safe and no registry. The four additions it needs (FWL-033) are implemented in
[`ledger-app/src/wallet.rs`](./ledger-app/src/wallet.rs), and checked against the app running in
Speculos by [`ledger-app/test/test_wallet.py`](./ledger-app/test/test_wallet.py):

- [x] the `Transfer` type and the `FermionWallet` EIP-712 domain accepted alongside `PreApproval`, with `verifyingContract` = the wallet. No new APDU command: `SIGN_PREAPPROVAL` streams either payload and the device tells them apart by length, 132 bytes against the pre-approval's 373
- [x] a signing flow for it: Flow 2's `Amount`, `Token`, `To`, `Network` and validity fields and its confirmation page unchanged; a `Wallet` field replaces `Safe`, `Safe tx` and `Policy hash` — a `Transfer` has no such fields, and showing one would break "display only signed fields"
- [x] per-slot binding to a single verifying contract **on a single chain**, written at first signature and checked on every later one, held in NVM beside the leaf counter (FWL-023). The chain id is part of it because FWL-031's CREATE2 factory puts one wallet address on every chain, and two wallets at that address on two chains have two separate used-leaf bitmaps. The home screen's description line shows it, because invisible state that decides whether a signature will be refused is state the Administrator should be able to read off the device
- [x] refusal when a slot bound to a wallet is asked for a Safe pre-approval, or a slot used for Safes is asked for a wallet transfer — a key belongs to one product. Both directions are refused before a single screen is drawn, with status word `0x6A81`, and consume no leaf

What is *not* done: this build has one key slot (`MAX_KEYS = 1`), so FWL-024 — several wallets needing
several keys — waits on the key-generation and retire flows.

The last two matter more than they look: the standalone wallet has no registry, so its on-chain bitmap
cannot see leaves spent elsewhere. For that product the device binding is the *only* thing keeping one
leaf to one digest, which is why FermionWallet records the weaker guarantee as a residual risk
(FWL-025) rather than claiming the defense in depth described above.

## Design intent

Phase 1's split trust (Ledger ECDSA + software XMSS keystore) collapses into a single hardware trust anchor: the quantum signature itself comes from the secure element, with index state that a compromised host cannot corrupt. The wire protocol and the screens are Ledger's; only the key is ours.

## Appendix A — primary sources

Revisions pinned so a reviewer can check each claim against the same bytes we read.

| Tag | Source |
|---|---|
| [S1] | `LedgerHQ/app-ethereum`, `doc/apdu.md` — the app's own APDU specification: the INS list, per-command `P1`/`P2`, the BIP-32 input layout ("Number of BIP 32 derivations to perform (max 10)" plus 4-byte big-endian indices), the 255-byte chunking of SIGN and SIGN PERSONAL MESSAGE, the GET APP CONFIGURATION output, the ERC-20 descriptor formats and signing key. https://github.com/LedgerHQ/app-ethereum/blob/develop/doc/apdu.md |
| [S2] | Same repo, `src/apdu_constants.h` (`#define CLA 0xE0`; `INS_*`; `P1_FIRST 0x00`, `P1_MORE 0x80`, `P1_CONFIRM 0x01`, `P1_NON_CONFIRM 0x00`; `APP_FLAG_*`) and `src/main.c` (`handleApdu`: `cmd->cla != CLA → SWO_INVALID_CLA`, `default: sw = SWO_INVALID_INS`); status-word usage counted across `src/`, where `handle_first_sign_chunk` returns `SWO_COMMAND_NOT_ALLOWED` on `appState != APP_STATE_IDLE`, a rejected review yields `SWO_CONDITIONS_NOT_SATISFIED`, and the main loop, on any status word other than success, runs `if (appState != APP_STATE_IDLE) { /* Dismiss any ongoing review before its UI buffers are freed */ ui_idle(); } reset_app_context();`. https://github.com/LedgerHQ/app-ethereum |
| [S3] | Same repo, `Makefile` — `CURVE_APP_LOAD_PARAMS += secp256k1`, and of `PATH_APP_LOAD_PARAMS`: *"Application allowed derivation paths. You should request a specific path for your app. This serve as an isolation mechanism."* — plus `makefile_conf/chain/ethereum.mk`, whose first line is *"Lock the application on its standard path for 1.5"* above `PATH_APP_LOAD_PARAMS += "44'/60'" "45'"` (and `"12381/3600"` for the ETH2 keys), and `ledger_app.toml` (`devices = ["apex_p", "nanox", "nanos+", "stax", "flex"]`) |
| [S4] | `LedgerHQ/ledger-secure-sdk`, `include/status_words.h` — every `SWO_*` code used above, and the closing note: *"Status words 67XX, 6BXX, 6DXX, 6EXX, and 6FXX, where XX is not 0, are proprietary status words, as well as 9YYY, where YYY is not 000."* https://github.com/LedgerHQ/ledger-secure-sdk/blob/master/include/status_words.h |
| [S5] | `LedgerHQ/app-boilerplate`, `doc/APDU.md` — framing: *"`Lc` length is always exactly 1 byte"*, *"No `Le` field in APDU command"*, *"Maximum size of APDU command is 260 bytes: 5 bytes of header + 255 bytes of data"*, *"Maximum size of APDU response is 260 bytes: 258 bytes of response data + 2 bytes of status word"*. https://github.com/LedgerHQ/app-boilerplate/blob/master/doc/APDU.md |
| [S6] | SDK `lib_nbgl/src/nbgl_use_case.c` — the exact strings: `"Hold to sign"`; `"Sign transaction"` / `"Sign message"` / `"Sign operation"`; `"Reject"`; `"Reject operation?"` / `"Yes, reject"` / `"Go back to operation"`; `"Operation signed"` / `"Operation rejected"`; and the blind-signing warning `"Blind signing required"` with *"This transaction's details are not fully verifiable. If you sign, you could lose all your assets."* Also `nbgl_useCaseReviewBlindSigning`, `nbgl_warning_t` and the predefined warning set |
| [S7] | SDK `lib_nbgl/include/nbgl_types.h` — `color_t` is `BLACK`, `DARK_GRAY`, `LIGHT_GRAY`, `WHITE`; under `BICOLOR_MODE`, `BLACK = DARK_GRAY = LIGHT_GRAY = 0` |
| [S8] | `LedgerHQ/ethereum-plugin-sdk`, `src/common_utils.c` — `getEthDisplayableAddress` writes `0x` then calls `getEthAddressStringFromBinary`, which keccak-hashes the 40 lowercase hex characters to set EIP-55 capitalisation — and, on chain IDs 30 and 31 only, hashes `<decimal chainId>0x<lowercase hex>` instead, the EIP-1191 variant. https://github.com/LedgerHQ/ethereum-plugin-sdk |
| [S9] | Ledger Developer Portal, *Address verification* design guideline — the address must be shown in full for comparison with its software counterpart; use `nbgl_useCaseAddressReview`. https://developers.ledger.com/docs/device-app/integration/design-guidelines/address |
| [S10] | Ledger Developer Portal, *Signing transactions and messages* — intent page → field review pages → signing page, with bidirectional navigation; the prompt must start with "Review"; key-value fields in the order From, Amount, To, Fees; rejection possible at any time and confirmed; the blind-signing setting defaults off and warns on every blind transaction. https://developers.ledger.com/docs/device-app/integration/design-guidelines/transactions |
| [S11] | Ledger Developer Portal, *Info and settings* — *"Your app must provide at least its version number and the developer name or organization"*; *"Settings must always appear before the app's info"*; *"App settings are reset to their default values every time your app is updated or reinstalled after an OS update."* https://developers.ledger.com/docs/device-app/integration/design-guidelines/info-settings |
| [S12] | Ledger Developer Portal, *App home screen* — *"Your app's home screen must show the app icon, name, and description."* https://developers.ledger.com/docs/device-app/integration/design-guidelines/home |
| [S13] | Ledger Developer Portal, *Advanced interactions* — the streaming review APIs, and *"Avoid transaction streaming in your app whenever possible. Blocking users in a forward-only progression is not recommended UX."*; progressive disclosure *"only for fields that do not affect your user's privacy, security, or funds."* https://developers.ledger.com/docs/device-app/integration/design-guidelines/advanced |
| [S14] | Ledger Developer Portal, *Submission deliverables — Documentation* — the repository must contain a docs folder documenting its APDUs and corresponding errors, in a file named `apdu.md`, with error ranges following the SDK. https://developers.ledger.com/docs/device-app/submission-process/deliverables/documentation |
| [S15] | `app-ethereum` `Makefile` (`ENABLE_NBGL_FOR_NANO_DEVICES = 1`) and SDK `Makefile.standard_app` (`USE_NBGL = 1` for `TARGET_NANOX`/`TARGET_NANOS2` when that flag is set); `app-ethereum/src/` contains an `nbgl/` directory and no BAGL directory |
| [S16] | SDK `Makefile.defines` (`DEFINES += OS_IO_SEPH_BUFFER_SIZE=272`, 448 with the address book) and `io/include/os_io.h` (`OS_IO_BUFFER_SIZE` = `CUSTOM_IO_APDU_BUFFER_SIZE` when an app defines it, otherwise `OS_IO_SEPH_BUFFER_SIZE`) |
| [S17] | `app-ethereum` `src/nbgl/ui_home.c` — the settings switches `Blind signing`, `Nonce`, `Raw messages`, `Smart account upgrade`, `Debug smart contracts`, `Transaction Check`, `Transaction hash`, all declared before the info list, and `infoTypes = {"Version", "Developer", "Copyright"}` |
| [S18] | `app-ethereum` `src/nbgl/ui_blind_signing.c` — `"This transaction cannot be clear-signed"` / `"Enable blind signing in the settings to sign this transaction."` / `"Go to settings"` / `"Reject transaction"`; on the Nano layout, `"Blind signing must\nbe enabled in\nsettings"` |
| [S19] | `app-ethereum` `src/nbgl/ui_approve_tx.c` — the field labels `From`, `Amount`, `To`, `Nonce`, `Max fees`, `Network` and `Transaction hash` (`Tx hash` on the Nano layout), the latter written from a `char tx_hash[2 + (INT256_LENGTH * 2) + 1]` buffer — the whole 32 bytes, never abbreviated — and `const char *title_prefix = "Review transaction";` |
| [S20] | `app-ethereum` `src/network.c` — `get_network_as_string_from_chain_id`: *"No network name found so simply copy the chain ID as the network name."* |
| [S21] | `app-ethereum` `src/plugins/erc20/erc20_plugin.c` (`ETH_PLUGIN_RESULT_FALLBACK` when `msg->item1 == NULL`, i.e. no token descriptor was provided) and `src/features/sign_tx/logic_sign_tx.c` (`"Plugin unavailable, using standard blind signing"`, then `ui_error_blind_signing()` when `!N_storage.dataAllowed`) |
| [S22] | Ledger Developer Portal, *Designing blockchain apps for Ledger devices* (design-guidelines intro) — of the NBGL high-level "use case" functions: *"Prefer these over low-level rendering calls to stay in compliance with these guidelines with minimal effort."* https://developers.ledger.com/docs/device-app/integration/design-guidelines/intro |

Revisions read: `app-ethereum` at `5a48940` (committed 2026-09-22); `ledger-secure-sdk` at `36e15cd` (2026-09-30); `ethereum-plugin-sdk` and `app-boilerplate` at their `develop`/`master` tips on 2026-09-30. Developer-portal pages fetched 2026-09-30. Where a portal page and the source disagree, the source wins and this document follows the source.

## Appendix B — assumptions

Claims this document relies on that we could not pin to a primary source. Each must be confirmed with Ledger before the review submission.

1. **A third-party app may use the Ledger PKI / CAL token-descriptor path.** The TLV format of `PROVIDE_ERC20_TOKEN_INFORMATION` is verified "via the Ledger PKI with key usage `COIN_META`" [S1], but nothing we found states whether a non-Ledger app can have descriptors signed for it, or whether the legacy secp256k1 CAL key is the only route open to us. If neither is, every token is an unnamed token and the `Token` field is always shown.
2. **The Rust SDK's NBGL bindings cover every use case named here** — review, warning page, address review, home-and-settings, progress bar. The C SDK demonstrably does; the Rust SDK is this app's first choice and its coverage was not verified command by command. The stated fallback to the C SDK covers this risk.
3. **App-owned NVM survives an app upgrade under BOLOS.** Asserted in *Updates* above and consistent with Ledger Live's uninstall warning, but we found no Ledger document stating it as a guarantee for a third-party app. If it is not guaranteed, an app update becomes a key rotation, which is a product-level change.
4. **A 60-second idle abort is acceptable to Ledger's reviewers.** `nbgl_use_case.c` contains no idle-timeout machinery, so ours is app-level, and the Ethereum app's answer to an abandoned review is to let the next signing command cancel it [S2]. It is listed as a deviation rather than dropped; if a reviewer objects, drop it and rely on that same host-driven cancel.
5. **`0x6983` for leaf exhaustion will not collide with a future SDK meaning.** It is the SDK's `SWO_AUTH_METHOD_BLOCKED` and the Ethereum app does not use it; choosing an existing ISO code over minting a proprietary one is the lesser risk, but it is not a sourced convention.
6. **Apex is not a target.** The Ethereum app's manifest lists `apex_p` [S3]; we have no figure for the XMSS working set on it, so the device list above omits it.
7. **A dedicated device icon is not yet assigned.** The home screen requires an icon, name and description [S12]; the name used here is "FermionGuard XMSS" and the icon is unspecified.
