# Ledger app "Fermion"

**Status: specification for the v2 app, unaudited.** No ML-DSA build of this app is committed yet: [`ledger-app/`](../ledger-app/README.md) is still the XMSS build and is replaced in phase 3 (Ledger Nano) and phase 7 (Stax/Flex). The measured figures below come from a Speculos prototype and are cited from the [measured-facts table](./v2-decisions.md#measured-facts-cite-these-do-not-retype-from-memory); anything not in that table is marked *not measured*.

One Ledger app, named **Fermion**, signs for both products: the Fermion Wallet cold vault ([`fermion-wallet.md`](./fermion-wallet.md)) and the Fermion Guard's Quantum Administrator ([`fermion-guard.md`](./fermion-guard.md)). Every signature it releases is hybrid — an ECDSA half and an ML-DSA half over the same 32-byte EIP-712 digest — and every digest is rebuilt on the device from fields the holder has just read. The app is the reference implementation of [`signer-requirements.md`](./signer-requirements.md); every SR rule applies to it, and this document says how the app meets each one.

The device screen is the last honest surface in the system. Everything here assumes the host — computer, browser, `fermion-sdk`, network — is compromised.

## Supported devices

| Device | UI | Status |
|---|---|---|
| Nano S Plus | NBGL, two buttons | phase 3 target; prototype measured in Speculos |
| Nano X | NBGL, two buttons | phase 3 target; prototype measured in Speculos; emulator-only until a device is available |
| Stax, Flex | NBGL, touch | phase 7 target; not built, memory not measured |

The app runs on these four devices only [LA-001]. The original Nano S is not supported. Apex is not a target (no measurement). Ledger's own Ethereum app builds its Nano screens with NBGL too (`ENABLE_NBGL_FOR_NANO_DEVICES = 1`), so there is one UI layer at four screen sizes and no BAGL code path [LA-002].

## Build and SDK

- **Rust**, on Ledger's device SDK, with the SDK's built-in ML-DSA (C code compiled into the app) enabled with the `mldsa` and `mldsa_optimization` features [LA-003]. `mldsa_optimization` is the low-RAM variant; without it the app does not fit the Nano X.
- **Pinned SDK: v26.6.5, commit `87def514`.** The pin is required, not cautious: seeded key generation and signing use the SDK's **private** symbols `MLDSA_internal_keygen` and `MLDSA_internal_sign`, which a later SDK may rename or remove. We ask Ledger for a public seeded API; until it exists every SDK upgrade is a re-validation [LA-004]. The Speculos gate used Rust SDK crate 1.37.1; the crate version is re-pinned in phase 3 against the SDK commit above.
- **Parameter sets in the build: ML-DSA-44 and ML-DSA-65 only.** One build serves both; the set is a runtime argument to the SDK per call [LA-005]. ML-DSA-87 is not compiled in (`HAVE_MLDSA_87` off): the contracts accept it, but no Ledger produces it in v2 (decision record C4). Enabling it would raise the signing stack for 44 and 65 too, because the SDK sizes its workspaces for the largest set, and the Nano X cannot hold it.
- **Manifest:** `CURVE_APP_LOAD_PARAMS = secp256k1` and `PATH_APP_LOAD_PARAMS = "204'/60'"`. Ledger OS, not the app, refuses any derivation outside that subtree [LA-006]. Speculos enforces the manifest path.

## Key derivation

Keys are derived from the device's recovery phrase. Nothing key-related is stored in the app's NVM: every command that needs a key derives it, uses it and wipes it [LA-007].

### Path

Each contract — each Fermion Wallet, each Safe enrolled in Fermion Guard — has its own key **slot**. A slot is the fully hardened BIP-32 node

    m / 204' / 60' / slot' / role' / paramSet'

| Level | Values |
|---|---|
| `204'` | purpose — a placeholder. Before release, confirm the number is unregistered in SLIP-44 / BIP-43 usage; changing it changes every key |
| `60'` | Ethereum |
| `slot'` | `0'`, `1'`, `2'`, … — one per contract, counted up by `fermion-sdk` |
| `role'` | `0'` = Fermion Wallet, `1'` = Fermion Guard |
| `paramSet'` | `0'` = ML-DSA-44, `1'` = ML-DSA-65 |

The host names the slot node; the device accepts only a path of exactly this shape, all five levels hardened, `paramSet' ∈ {0', 1'}` and `role' ∈ {0', 1'}`, and refuses any other path with `0x6A80` [LA-008]. The host cannot name the children below the slot node; the device derives them itself.

### The two halves come from two hardened siblings

    ECDSA key   = secp256k1 private key of   m/204'/60'/slot'/role'/paramSet'/0'
    xi          = SHA-256( label ‖ k1 )
                  where k1 = the 32-byte secp256k1 private key of m/204'/60'/slot'/role'/paramSet'/1'
    label       = "FermionWallet/ML-DSA-44/xi/v1"  or  "FermionWallet/ML-DSA-65/xi/v1"  (ASCII, no terminator)
    (pk, sk)    = ML-DSA.KeyGen_internal(xi)      FIPS 204, Algorithm 6, for the slot's parameter set

[LA-009] The ECDSA child `0'` is the only node whose public key ever appears on-chain. Its hardened sibling `1'` feeds the ML-DSA seed. A quantum attacker who recovers the `0'` private key from its public key learns nothing about `1'` or the slot node, because hardened children are computed from the parent's private key [LA-010]. xi is never derived from the ECDSA key's own node: that would let a quantum break of the classical half yield the post-quantum key, which is the hybrid defeated.

The label keeps the historical spelling `FermionWallet` for both roles; the role is separated by the path, not the label. The label is part of the key: changing a byte changes every ML-DSA key.

### One key per contract

A slot is used for exactly one contract on one product [LA-011]. `fermion-sdk` allocates the next unused slot for each new wallet or enrollment and finds existing ones on restore by scanning slots (see [`sdk.md`](./sdk.md)). The device enforces the role: a key derived under `role' = 0'` signs only Fermion Wallet messages, one under `1'` only Fermion Guard messages, and the wrong pairing is refused before any screen with `0x6A81` [LA-012]. The device does **not** record which contract a slot is used for (it keeps no state); the `verifyingContract` and the slot are shown on every review instead, and the contracts bind the key to one contract.

The parameter set of a key is part of its path, so the device always knows it and signs only under it [LA-013].

### Restore

The same recovery phrase on any Ledger running this app yields the same keys, byte for byte, for every slot. Restoring is safe: ML-DSA is stateless, so two devices holding one key cannot harm each other. It also means **the recovery phrase is the single secret behind both halves of every Fermion key**: whoever holds it holds everything [LA-014]. A BIP-39 passphrase is recommended, not required; the trade-off (protection of a stolen phrase backup against a second secret that can be lost) is set out in [`security.md`](./security.md). Restore happens only on the device; no Fermion UI has a recovery-phrase field.

The prototype's derivation was checked byte-identical against dilithium-py (public key, secret key, deterministic signature), and restoring the phrase reproduced the public key (decision record, device gate).

### Zeroization

After every command that derived a key, on success, rejection and error alike, the app wipes: both secp256k1 private keys (`0'` and `1'`), xi, the ML-DSA secret key and its expanded working state, and the signing randomness [LA-015]. The panic hook and the Quit path wipe them too. The readout buffer is wiped as described in [Response read-out](#response-read-out).

## Hedged signing

ML-DSA signing is hedged, as FIPS 204 defines it: a fresh 32-byte `rnd` from the device's hardware RNG for every signature [LA-016]. A test build signs deterministically (`rnd = 0^32`) so tests can compare against reference vectors. A test build is a different binary: it reports itself in `GET_APP_CONFIG`, it shows `Test build — not for real funds` on its home screen and in Info, and it must never hold a production phrase [LA-017].

ML-DSA is pure, external interface, empty context, over the 32-byte digest: `M' = 0x00 ‖ 0x00 ‖ digest` ([`signer-requirements.md`](./signer-requirements.md#signature)).

## APDU interface

The framing is Ledger's and the Ethereum app's, as documented for the XMSS build in [`ledger-xmss-app.md`](../ledger-xmss-app.md#framing): `CLA = 0xE0`; `Lc` one byte; at most 255 data bytes per command; long payloads in chunks with `P1 = 0x00` for the first and `P1 = 0x80` for each next one; even instruction numbers, keeping the Ethereum app's number where a command has an Ethereum analogue and using `0x40` and above for the rest [LA-018].

### Commands

| INS | Command | P1 | P2 | Data | Response |
|---|---|---|---|---|---|
| `0x02` | `GET_ADDRESS` | `00` return, `01` show and confirm first | `00` | slot path | ECDSA public key length ‖ uncompressed key ‖ address length ‖ ASCII address (the Ethereum app's layout) |
| `0x04` | `SIGN` | `00` first, `80` more | `00` | first chunk: slot path ‖ total length (4, big endian) ‖ payload; later chunks: payload | after the decision: digest (32) ‖ buffer length (2) |
| `0x06` | `GET_APP_CONFIG` | `00` | `00` | — | see below |
| `0x0A` | `PROVIDE_ERC20_TOKEN_INFORMATION` | as the Ethereum app | as the Ethereum app | Ledger-signed token descriptor | as the Ethereum app |
| `0x40` | `GET_MLDSA_PUBLIC_KEY` | `00` return, `01` show and confirm first | `00` | slot path | public-key length (2) ‖ keccak256(public key) (32); the key itself through `GET_RESPONSE_CHUNK` |
| `0x42` | `PROVIDE_DESCRIPTOR` | `00` first, `80` more | `00` | one Ledger-signed ERC-7730 descriptor | `00` |
| `0x50` | `GET_RESPONSE_CHUNK` | `00` first chunk, `80` next | `00` | — | up to 255 bytes of the buffered response |

A slot path is `number of derivations (1) ‖ index (4, big endian) × n`, the Ethereum app's encoding, with `n = 5` and the shape of [Path](#path).

`GET_ADDRESS` with `P1 = 01` and `GET_MLDSA_PUBLIC_KEY` with `P1 = 01` use the SDK's address-review flow: the page names the key (`Wallet key 3 · ML-DSA-44`) and shows the ECDSA address, or the keccak256 of the ML-DSA public key, in full. That hash is the `pkHash` the contracts store, so the holder can compare it with what the Safe App or web UI is about to enroll or deploy [LA-019].

`PROVIDE_ERC20_TOKEN_INFORMATION` is the Ethereum app's command, unmodified. `PROVIDE_DESCRIPTOR` carries one ERC-7730 descriptor in the form Ledger signs for its clear-signing registry; its exact framing is pinned against `LedgerHQ/app-ethereum` in phase 3. Both are verified against Ledger's signing key on receipt and held in RAM for the next `SIGN` session only [LA-020].

### The `SIGN` payload

The payload's first byte names the message kind; the rest is the message's fields in a fixed binary layout, defined per kind in the app's `apdu.md`. The device builds the EIP-712 encoding from those fields; the host never sends an EIP-712 encoding, a struct hash or a digest [LA-021].

| Kind | Message | Role | Defined in |
|---|---|---|---|
| `0x01` | transfer batch | Wallet | [`fermion-wallet.md`](./fermion-wallet.md#signed-messages) |
| `0x02` | plain-text message | Wallet | [`fermion-wallet.md`](./fermion-wallet.md#signed-messages) |
| `0x03` | Safe transaction, signed as a Safe owner | Wallet | [`fermion-wallet.md`](./fermion-wallet.md#safe-owner-erc-1271) |
| `0x10` | quantum approval of a Safe transaction | Guard | [`fermion-guard.md`](./fermion-guard.md#quantum-approval) |
| `0x11` | quantum approval of a module transaction | Guard | [`fermion-guard.md`](./fermion-guard.md#modules) |
| `0x12` | revoke of a stored approval | Guard | [`fermion-guard.md`](./fermion-guard.md#inline-and-stored-approvals) |
| `0x13` | key rotation | Guard | [`fermion-guard.md`](./fermion-guard.md#key-rotation) |
| `0x14` | approval of a Safe message (gated fallback handler) | Guard | [`fermion-guard.md`](./fermion-guard.md) |

A payload is fully received and parsed before the first page is drawn; nothing is streamed to the screen [LA-022]. The maximum payload size is set by the app's buffer, which is not yet fixed (not measured); a declared total length above it is refused with `0x6A84` before any data is kept.

### Response read-out

ML-DSA public keys and signatures exceed the 258-byte response limit, so they are paged out with `GET_RESPONSE_CHUNK`, 255 bytes per chunk [LA-023].

After the holder approves, `SIGN` answers with the digest it computed and the length of the buffered signature. The buffer is **ML-DSA signature first, ECDSA `r ‖ s ‖ v` last**, so a host cannot hold the classical half without having first received the whole post-quantum half [LA-024]. The host reorders the halves into the wire encoding (ECDSA ‖ ML-DSA) defined by the ERC draft.

| | ML-DSA-44 | ML-DSA-65 |
|---|---|---|
| public key read-out, chunks @255 B | 6 (measured) | 8 (measured) |
| ML-DSA signature alone, chunks @255 B | 10 (measured) | 13 (measured) |
| signature buffer with the 65-byte ECDSA half appended | 2,485 B → 10 chunks (computed, not measured) | 3,374 B → 14 chunks (computed, not measured) |

The buffer is wiped once its last byte has been delivered, at the start of every `SIGN` command (accepted or refused), on Quit, and in the panic hook [LA-025]. `GET_RESPONSE_CHUNK` with `P1 = 00` restarts the current read-out from the beginning; with nothing buffered it answers `0x6901`.

### Sessions

One signing session at a time. A `SIGN` first chunk that arrives while a session is open is refused with `0x6986` and the open review is dismissed, as the Ethereum app does [LA-026]. While a payload is half-streamed, every command other than its next `SIGN` chunk is answered `0x6986`. There is no idle timeout on the decision page: an abandoned review stays up until the holder decides or the host sends another `SIGN`, as in the Ethereum app (see [Open questions](#open-questions)).

### `GET_APP_CONFIG`

| Field | Length | Value |
|---|---|---|
| Flags | 1 | the Ethereum app's byte: `0x01` (blind signing enabled by setting) always 0; `0x02` (token information provided externally) always 1 |
| Version major, minor, patch | 3 | |
| Parameter sets | 1 | bit 0 = ML-DSA-44, bit 1 = ML-DSA-65; this build: `0x03` |
| Build | 1 | bit 0 = deterministic test build |

The first four bytes are the Ethereum app's response, so a host that only knows that app reads a valid answer.

### Status words

The values are the Rust SDK's `StatusWords`, as checked against the built XMSS app ([`ledger-app/README.md`](../ledger-app/README.md#apdu-surface)).

| SW | Meaning |
|---|---|
| `0x9000` | success |
| `0x6985` | the holder rejected on the device |
| `0x6986` | a signing session is in flight |
| `0x6A80` | refused before any screen; the one response byte gives the reason (below) |
| `0x6A81` | the key's role does not sign this message kind |
| `0x6A84` | declared payload larger than the app's buffer |
| `0x6901` | `GET_RESPONSE_CHUNK` with nothing buffered |
| `0x6E00` | wrong CLA |
| `0x6E01` | unknown INS |
| `0x6E02` | impossible `P1` / `P2` |
| `0x6E03` | length inconsistent with the command |
| `0x6D00` | the app reached a state it should not be able to reach; nothing was signed |

Refusal reasons with `0x6A80`: `01` delegatecall, `02` non-zero gas-refund field, `03` unlimited approval, `04` validity window, `05` malformed payload or path, `06` more than 8 legs, `07` Safe self-call that is not a named admin function, `08` Safe message given only as a hash [LA-027]. A refusal draws no screen: the host has the code and is the place to explain it.

## Acceptance rules

The device decides what it will put on the screen before it draws anything. These rules are the app's implementation of [`signer-requirements.md`](./signer-requirements.md#display-and-refusal-rules).

### Refused before any screen

| # | Refused | Applies to |
|---|---|---|
| 1 | `operation = DelegateCall`, except a Safe batch through `MultiSendCallOnly` ([Safe batches](#safe-batches)) | Safe transactions (kinds `0x03`, `0x10`); module transactions (`0x11`) with no exception |
| 2 | non-zero `gasPrice`, non-zero `gasToken` or non-zero `refundReceiver` | Safe transactions (`0x03`, `0x10`) |
| 3 | an unlimited approval: ERC-20 `approve` (`0x095ea7b3`) or `increaseAllowance` (`0x39509351`) with amount `2^256 − 1` | any call the device decodes, top level or inside a descriptor |
| 4 | `validUntil − validFrom > 86,400` seconds, or `validFrom > validUntil` | every kind |
| 5 | malformed: unknown kind, a field out of range, trailing bytes, a path of the wrong shape, an unrenderable time, more than 8 legs | every kind |
| 6 | a call by the Safe to itself (`to` = the Safe) that is not one of the nine admin functions of [Decoded calls](#decoded-calls), decodable or not, at top level or in a batch leg (decision record C9) | Safe transactions (`0x03`, `0x10`), module transactions (`0x11`) |
| 7 | a Safe message supplied only as a hash | Safe-message approvals (`0x14`) |

[LA-028] There is no setting, no override and no "review anyway" path for any of them. The device decodes the `approve` and `increaseAllowance` selectors and the EIP-2612 `Permit` typed-data type itself, without a descriptor, so rule 3 does not depend on the host supplying one [LA-029]. A self-call is the Safe-takeover vector, so rule 6 refuses it even though an undecodable *external* call only gets a warning [LA-059].

**No trusted clock.** A Ledger has no clock the app can trust, and a host-supplied "now" is the host's word. The device therefore checks the window's length and shape only (rule 4) and shows `Valid from` and `Valid until` as absolute UTC; the contracts enforce `validFrom ≤ block.timestamp ≤ validUntil` on-chain ([`fermion-wallet.md`](./fermion-wallet.md#replay-and-validity-window)) [LA-030].

### Safe batches

Decision record clarification C7, implementing [`signer-requirements.md`](./signer-requirements.md#safe-batches). A Safe transaction (kind `0x03` or `0x10`) with `operation = DelegateCall` is accepted only when `to` is the canonical `MultiSendCallOnly` deployment of Safe 1.3.0, 1.4.1 or 1.5.0. Those addresses are compiled into the app (the exact list is pinned against the Safe deployments in phase 3); the host cannot add one [LA-056]. The calldata must parse exactly as `multiSend(bytes)` with every leg `operation = Call`; any other leg operation, a truncated leg or trailing bytes is refused with reason `01` or `05` [LA-057]. Each leg is decoded as in [Decoded calls](#decoded-calls) and checked against rules 3, 5 and 6 as if it were a single transaction; an undecodable leg gets the warning page and its five fields. The review shows `Batch: N calls`, then every leg in order, headed `Call 2 of N`, with its `To`, `Value` and decoded call [LA-058]. `Operation` reads `Batch (MultiSendCallOnly)`. Module transactions (kind `0x11`) get no such exception. The number of legs is bounded only by the payload buffer (not measured).

### Decoded calls

A call in a Safe transaction or a module transaction is decoded, in this order:

1. empty `data` → a native ETH send (`Value` only);
2. a Safe self-administration function on the Safe itself (`to == safe`): `addOwnerWithThreshold`, `removeOwner`, `swapOwner`, `changeThreshold`, `setGuard`, `setFallbackHandler`, `enableModule`, `disableModule`, `setModuleGuard` → its dedicated screen naming the function and every argument [LA-031];
3. ERC-20 `transfer`, `transferFrom`, `approve`, `increaseAllowance` → built-in decoding, with the ticker and decimals when a Ledger-signed token descriptor was provided, raw units and the token address otherwise;
4. a call matched by a Ledger-signed ERC-7730 descriptor provided in this session → the descriptor's labels and formats;
5. any other call with `to == safe` → **refused** (rule 6);
6. anything else → **undecodable**.

The device verifies every descriptor's Ledger signature on receipt. A descriptor that fails verification is discarded; the call it would have described is undecodable, never refused for that reason and never decoded [LA-032]. `fermion-sdk` bundles and caches Ledger-signed descriptors for Fermion's own contracts and common protocols and fetches the rest; if a fetch fails it says so, and the device shows the call as undecodable.

### Undecodable calls: allowed after a strong warning

An undecodable call is **not refused** (decision record items 25 and 26). The review opens with the SDK's blind-signing warning page — *This transaction's details are not fully verifiable. If you sign, you could lose all your assets.* — and then shows, as fields: `Contract` (the target, full EIP-55), `Selector` (the 4 bytes), `Value`, `Calldata` (the complete calldata in hex, paged, never truncated) and `Calldata hash` (keccak256 of the calldata, in full). The warning icon then sits on the intent and decision pages [LA-033]. Rules 1–5 are applied first and still refuse.

> **C3 — the device model lags the spec.** The committed model [`demo/ledger-proof/device_spec.py`](../demo/ledger-proof/device_spec.py) (`aa55132`) still **refuses** an undecodable call (`displayable=False` → `Cannot display this call`), and [`demo/ledger-proof/README.md`](../demo/ledger-proof/README.md) lists that as claim R1. This spec follows the decision record and allows it after the warning. Updating the model — the undecodable flow as a warning page plus the five fields above, and R1 narrowed to rules 1–7 — is a phase-3 task, as are the self-call refusal (rule 6) and the Safe-message flow, as is the `MultiSendCallOnly` exception of [Safe batches](#safe-batches) (the model refuses every delegatecall). The model also has no revoke, key-rotation or module-transaction flow and no multi-leg batch; those are added in the same phase-3 update.

## Signing flows

Every flow is one NBGL review: an optional warning page, an intent page whose title starts with **Review**, the fields as tag/value pairs, a decision page, and a status page. Every flow shows a `Key` field (`Wallet key 3 · ML-DSA-44` / `Guard key 0 · ML-DSA-65`, from the slot path) and a `Network` field (chain name, or the decimal chain ID when unknown) [LA-034]. The fields of each message are those of the contract's struct; the anchors below are where the struct is defined, and the device shows every field of it and of its domain ([`signer-requirements.md`](./signer-requirements.md#what-the-reviewer-must-see)) [LA-035].

On approval, the device derives the slot's keys, computes the digest from the displayed fields, signs it with ML-DSA (hedged) and with ECDSA, buffers both, and wipes the keys. On rejection nothing is signed and `0x6985` is returned [LA-036].

### Fermion Wallet: transfer batch (kind `0x01`)

One signature authorizes 1 to 8 legs, executed atomically, with one nonce and one validity window ([`fermion-wallet.md`](./fermion-wallet.md#signed-messages)). Each leg is shown in full, in order, headed `Leg 2 of 3` [LA-037]:

| Leg | Fields |
|---|---|
| ETH | `Amount` (ETH, 18 decimals — the one asset whose decimals are known), `To` |
| ERC-20 | `Amount` (decimals and ticker from a Ledger-signed token descriptor, or raw units plus `Token` address), `To` |
| ERC-721 | `Collection`, `Token ID`, `To` |
| ERC-1155 | `Collection`, `Token ID`, `Amount`, `To` |

Then `Wallet` (the `verifyingContract`), `Network`, `Nonce`, `Valid from`, `Valid until`, `Key`. Intent `Review transfer`; decision `Sign transfer?`.

### Fermion Wallet: plain-text message (kind `0x02`)

For address-ownership proofs and Sign-In with Ethereum. The text is shown in full, paged, never truncated, followed by `Wallet`, `Network`, `Valid from`, `Valid until`, `Key` and the other fields of the message struct ([`fermion-wallet.md`](./fermion-wallet.md#signed-messages)). Intent `Review message`; decision `Sign message?` [LA-038]. The device never signs an arbitrary EIP-712 struct or a permit directly; third-party typed data appears only as the content of a Guard Safe-message approval (kind `0x14`), signed in the Guard's domain.

### Fermion Wallet: Safe transaction as owner (kind `0x03`)

The wallet is an owner of a Safe and answers the Safe's ERC-1271 check ([`fermion-wallet.md`](./fermion-wallet.md#safe-owner-erc-1271)). The host sends the SafeTx fields, the Safe address and the chain ID. The device applies the acceptance rules, shows the transaction, computes the Safe's `safeTxHash` itself, wraps it in the wallet's domain and signs the wrapped digest [LA-039].

The first field is `Role: Sign as Safe OWNER`; then `Safe`, `Network`, `Safe nonce`, the decoded call ([Decoded calls](#decoded-calls)) or the undecodable warning and fields, `Value`, `Operation: Call`, `safeTxGas`, `baseGas`, `Wallet`, `Valid from`, `Valid until`, `Key`. Intent `Review Safe transaction`; decision `Sign as Safe owner?`. A Safe self-administration call uses its dedicated screen, and `enableModule` its warning ([below](#fermion-guard-enablemodule)).

The owner path and the Guard path show the same Safe transaction differently on purpose — role field, intent and decision titles — because the two signatures authorize different things under different domains [LA-040].

### Fermion Guard: quantum approval, inline or stored (kind `0x10`)

Every Safe transaction on a guarded Safe needs one ([`fermion-guard.md`](./fermion-guard.md#quantum-approval)). The device signs **the same bytes** whether the host then appends the approval to the Safe's `signatures` or submits it to `preApprove` ([`fermion-guard.md`](./fermion-guard.md#inline-and-stored-approvals)); the screen does not ask and does not show which [LA-041].

Fields: `Role: Quantum APPROVAL`, `Safe`, `Network`, `Safe nonce`, the decoded call or the undecodable warning and fields, `Value`, `Operation: Call`, `safeTxGas`, `baseGas`, `Guard` (the `verifyingContract`), `Valid from`, `Valid until`, `Key`, and the remaining fields of the approval struct. Intent `Review quantum approval`; decision `Sign approval?`.

### Fermion Guard: module transaction (kind `0x11`)

On Safe 1.5.0 with the Guard as module guard, every module transaction needs an approval of its exact call ([`fermion-guard.md`](./fermion-guard.md#modules)). The host sends the full calldata; the device decodes it as above, computes `dataHash` itself and shows: `Role: Quantum APPROVAL`, `Module` (full EIP-55), `Safe`, `Network`, the call (`To`, decoded call or undecodable fields, `Value`), `Operation: Call`, the approval's own `Nonce`, `Valid from`, `Valid until`, `Guard`, `Key` [LA-042]. Intent `Review module transaction`; decision `Sign approval?`.

### Fermion Guard: enableModule

`enableModule(module)` on the Safe itself — in a Guard approval or an owner signature — opens with a warning page of its own, *Enabling a module gives it control of this Safe*, before the intent page; the dedicated admin screen then names `Function: enableModule` and the `Module` address in full [LA-043]. The device does not know the Safe's version; the Guard refuses `enableModule` on Safes before 1.5.0 on-chain ([`fermion-guard.md`](./fermion-guard.md#modules)).

### Fermion Guard: Safe message (kind `0x14`)

Decision record clarification C8: the Guard's gated fallback handler lets the Safe answer ERC-1271 for its own off-chain messages — Permit2 and CoW orders, SIWE — only when the Quantum Administrator approved that message on the device ([`fermion-guard.md`](./fermion-guard.md); [`signer-requirements.md`](./signer-requirements.md#safe-messages)).

The host sends the message itself, in one of two forms: EIP-712 typed data (domain, types, primary type, values) or EIP-191 plain text. The device computes the message's hash (EIP-712 or EIP-191), the Safe's message hash over it, and the approval digest; a message supplied only as a hash is refused (rule 7) [LA-060]. The message is shown as follows [LA-061]:

| Form | Shown |
|---|---|
| typed data with a verified Ledger-signed ERC-7730 descriptor | the descriptor's labels and formats (`Spender`, `Amount`, `Expires`, …), with the typed-data domain's `Contract` and `Network` |
| plain text (SIWE, ownership proofs) | the text in full, paged, never truncated |
| typed data without a verified descriptor | the blind-signing warning page, then the domain (every field present), `Primary type`, every field as name and raw value (paged, never truncated), and `Message hash` (its EIP-712 hash, in full) [LA-062] |

Rules 3–5 and 7 apply first: an EIP-2612 `Permit` of `2^256 − 1` is refused before any screen. Then `Role: Quantum APPROVAL`, `Safe`, `Network`, `Guard`, `Valid from`, `Valid until`, `Key`, and the remaining fields of the approval struct. Intent `Review message approval`; decision `Sign approval?`. The maximum message size is set by the payload buffer (not measured).

### Fermion Guard: revoke a stored approval (kind `0x12`)

The Quantum Administrator can revoke a stored approval with a hybrid-signed revoke ([`fermion-guard.md`](./fermion-guard.md#inline-and-stored-approvals)). The approval being revoked is named by its hash, shown in full; this is the one place a hash is the displayed field by design ([`signer-requirements.md`](./signer-requirements.md#digest)). Fields: `Safe`, `Network`, `Approval` (32 bytes), `Guard`, `Valid from`, `Valid until`, `Key`, and the remaining fields of the revoke struct. Intent `Review revocation`; decision `Sign revocation?` [LA-044].

### Fermion Guard: key rotation (kind `0x13`)

The current key approves the new key's hash ([`fermion-guard.md`](./fermion-guard.md#key-rotation)). Signed with the **old** slot. A warning page, *You are replacing this Safe's quantum key*, precedes the intent `Review key rotation`; the decision is `Sign key rotation?`. Fields: `Safe`, `Network`, `New key hash` (32 bytes, in full), `New parameter set`, `New administrator` (the new ECDSA address, full EIP-55), `Guard`, `Valid from`, `Valid until`, `Key` (the old one), and the remaining fields of the rotation struct [LA-045].

When the host also names the new key's slot path, the device derives that key itself; if it matches, the field reads `New key: Guard key 5 on this device`, otherwise `New key: another device`. A host cannot make a foreign key look local [LA-046].

### Enrollment and wallet creation

Creating a wallet or enrolling a Safe needs public keys, not a signature: `GET_ADDRESS` and `GET_MLDSA_PUBLIC_KEY` for the new slot, each with `P1 = 01` so the holder sees the key's address and `pkHash` on the device before anything is deployed.

## Screens

The SDK's high-level NBGL use cases throughout; nothing draws its own layout [LA-047]. Conventions carried over from the XMSS design, where their Ledger sources are cited ([`ledger-xmss-app.md`](../ledger-xmss-app.md#ui-principles)):

- `Reject` is available on every page and is confirmed: `Reject operation?` / `Yes, reject` / `Go back to operation`. Status pages are the SDK's `Operation signed` / `Operation rejected`.
- Navigation is bidirectional; no streaming review.
- No colour carries meaning (NBGL's Nano palette is monochrome). Flows are told apart by intent and decision titles, warning pages, and the `Role` field.
- Addresses are `0x` + EIP-55, in full; 32-byte values in full; times as absolute UTC (`21 Sep 2026 15:40 UTC`); amounts never decimals-guessed [LA-048].
- Only signed fields, plus labels from verified descriptors and values decoded from signed calldata.
- English only.

| Flow | Warning page before the intent | Intent | Decision |
|---|---|---|---|
| Transfer batch | — | `Review transfer` | `Sign transfer?` |
| Plain-text message | — | `Review message` | `Sign message?` |
| Safe tx as owner | if undecodable; if `enableModule` | `Review Safe transaction` | `Sign as Safe owner?` |
| Quantum approval | if undecodable; if `enableModule` | `Review quantum approval` | `Sign approval?` |
| Module transaction | if undecodable | `Review module transaction` | `Sign approval?` |
| Revoke | — | `Review revocation` | `Sign revocation?` |
| Key rotation | always | `Review key rotation` | `Sign key rotation?` |
| Safe message | if typed data has no verified descriptor | `Review message approval` | `Sign approval?` |
| Show address / key | — | address review | `Confirm` |

### Nano S Plus and Nano X

One tag/value pair per page; long values (calldata, message text, a 32-byte hash) continue over as many pages as they need, each page numbered. Left and right buttons navigate; the decision page is accepted by pressing both buttons, as the SDK's Nano review does (to pin against the SDK's Nano use case in phase 3; the XMSS documents said Hold to sign on all four devices), and `Reject` is a page of its own [LA-049]. Full calldata on a Nano can run to many pages; that is the cost of signing a call the device cannot decode, and the warning says so.

### Stax and Flex

The same pages in the same order, laid out by the SDK as auto-paginated tag/value lists. The decision is **Hold to sign**; a tap does not sign [LA-050]. Long values open in the SDK's full-value view, never truncated in the list. Stax/Flex are built in phase 7; their screens are pinned by Speculos snapshots then.

### Home, settings, info

Home: app icon, name `Fermion`, one-line description — nothing else. No settings: there is no blind-signing switch, because undecodable calls are allowed by the warning flow above, not by a setting (see [Open questions](#open-questions)). Info: `Version`, `Developer`, `ML-DSA sets: 44, 65`, and `Build: test` on a test build [LA-051].

### Checks

The device model in [`demo/ledger-proof/`](../demo/ledger-proof/README.md) is checked against the **real app** in Speculos, Nano and Stax/Flex: generated button and touch sequences, screens and outputs compared with the model at every step [LA-052]. Speculos snapshot tests pin every page of every flow on every supported device. Device signatures are verified by the on-chain verifier in Foundry and by an independent ML-DSA implementation.

## Memory and performance

| | Figure | Source |
|---|---|---|
| Peak stack, key generation + signing, with `mldsa_optimization` | 10,092 B, same for 44 and 65 | measured (Speculos) |
| Nano S Plus | 6.6 KB spare | measured (Speculos) |
| Nano X | fits only without the XMSS buffers and with `HEAP_SIZE` 2048 | measured (Speculos) |
| Stax, Flex | — | not measured |
| ML-DSA-87 on Nano X | does not fit | measured (Speculos), decision record item 43 |
| Signing time on real hardware | — | not measured |
| Maximum payload / calldata the buffer accepts | — | not measured |

The Nano X configuration has the thinnest margin; the v2 app carries no XMSS code at all, which is the condition under which it fits [LA-053].

## Security notes

- **Side channels.** Ledger's SDK documents no side-channel hardening for its ML-DSA. Treat the ML-DSA implementation as unhardened against power and EM analysis by an attacker with physical access [LA-054]. See [`security.md`](./security.md).
- **The phrase is the key.** One recovery phrase controls both halves of every slot. Its custody is the key control.
- **Distribution.** Any app allowed the `204'/60'` path can derive these keys. Production installs come only from the Ledger Live catalog; a sideloaded build shows Ledger's "Pending Ledger review" warning and must never hold a production phrase [LA-055].
- **Unaudited.** The app, the SDK's ML-DSA, the verifier and the contracts are unaudited.

## What this build is not

- **Not built yet.** The spec precedes the code; `ledger-app/` is the XMSS build until phase 3.
- **No ML-DSA-87.** Contract-level only in v2.
- **No Stax/Flex build** until phase 7; no Stax/Flex measurement.
- **No trusted clock.** Expiry is enforced on-chain only.
- **No per-contract binding on the device.** The device is stateless; the slot and the `verifyingContract` are shown, and `fermion-sdk` allocates slots.
- **No public seeded ML-DSA API.** The app depends on private SDK symbols at a pinned commit.
- **No side-channel hardening** documented.
- **Not in the Ledger Live catalog**, not reviewed by Ledger, and the `204'` purpose is a placeholder.
- **Not audited.**

## Open questions

Product questions the decision record does not answer. They are recorded, not decided.

1. **Blind-signing setting.** Ledger's guidelines require blind signing to be enabled by a setting that defaults off. The record allows undecodable calls after a warning, with no setting. Does Ledger's review require the switch?
2. **Safe batch size.** Whether Safe batches through `MultiSendCallOnly` get a maximum number of legs (the wallet's own batches stop at 8), beyond what the payload buffer allows.
3. **Unlimited approval, wider.** Does rule 3 also cover `setApprovalForAll(…, true)`, Permit2 approvals, or amounts just below `2^256 − 1`?
4. **Plain-text message.** For both the wallet message and Safe-message SIWE text: maximum length, and whether non-printable or non-ASCII text is shown escaped, shown as hex, or refused.
5. **Idle timeout.** None, as in the Ethereum app (assumed here), or an app-level timeout on the decision page?
6. **Third-party descriptors.** Whether Ledger will sign ERC-20 and ERC-7730 descriptors that a third-party app may verify (open since the XMSS design).
7. **Slot discovery.** The gap limit `fermion-sdk` uses when scanning slots on restore.

## Requirement index

| ID | Requirement |
|---|---|
| LA-001 | The app runs on Nano S Plus, Nano X, Stax and Flex only. |
| LA-002 | All devices use NBGL; there is no BAGL code path. |
| LA-003 | ML-DSA comes from the Ledger SDK with the mldsa and mldsa_optimization features. |
| LA-004 | The SDK is pinned at v26.6.5 87def514 because seeded keygen and signing use private MLDSA_internal symbols. |
| LA-005 | One build supports ML-DSA-44 and ML-DSA-65; ML-DSA-87 is not compiled in. |
| LA-006 | The manifest declares secp256k1 and the path 204'/60', so Ledger OS refuses other derivations. |
| LA-007 | No key material is stored in NVM; keys are derived per command. |
| LA-008 | The device accepts only a five-level fully hardened slot path m/204'/60'/slot'/role'/paramSet' with valid role and set. |
| LA-009 | The ECDSA key is child 0' of the slot node; xi is SHA-256 of the label and child 1''s private key; the ML-DSA key is KeyGen_internal(xi). |
| LA-010 | The ML-DSA seed comes from a hardened sibling of the ECDSA key, never from the ECDSA key's own node. |
| LA-011 | A slot is used for exactly one contract on one product. |
| LA-012 | A key signs only the message kinds of its role; the wrong pairing is refused with 0x6A81 before any screen. |
| LA-013 | A key signs only under the parameter set in its path. |
| LA-014 | The same phrase restores the same keys; the phrase is the single secret behind both halves. |
| LA-015 | Private keys, xi, the ML-DSA secret and working state and the signing randomness are wiped after every command, including on rejection, error, Quit and panic. |
| LA-016 | ML-DSA signing is hedged with fresh rnd from the device RNG. |
| LA-017 | Deterministic signing exists only in a test build that reports itself in GET_APP_CONFIG and on screen. |
| LA-018 | APDU framing, chunking and numbering follow Ledger's and the Ethereum app's conventions. |
| LA-019 | GET_ADDRESS and GET_MLDSA_PUBLIC_KEY with P1 = 01 show the address or the full pkHash before returning. |
| LA-020 | Token and ERC-7730 descriptors are verified against Ledger's key on receipt and held for the next session only. |
| LA-021 | The host sends message fields, never an EIP-712 encoding, struct hash or digest. |
| LA-022 | A payload is fully received and parsed before the first page is drawn. |
| LA-023 | Public keys and signatures are read out in 255-byte chunks with GET_RESPONSE_CHUNK. |
| LA-024 | The signature buffer holds the ML-DSA half first and the ECDSA half last. |
| LA-025 | The response buffer is wiped after its last byte, at every SIGN, on Quit and on panic. |
| LA-026 | One signing session at a time; a second SIGN is refused with 0x6986 and the open review dismissed. |
| LA-027 | Refusals return 0x6A80 with a one-byte reason and draw no screen. |
| LA-028 | Delegatecall (except a MultiSendCallOnly Safe batch), non-zero gas-refund fields, unlimited approvals, windows over 24 h or inverted, malformed payloads, non-admin Safe self-calls and hash-only Safe messages are refused before any screen, with no override. |
| LA-029 | The device decodes approve, increaseAllowance and EIP-2612 Permit natively so the unlimited-approval refusal needs no descriptor. |
| LA-030 | Without a trusted clock the device checks only the window's length and shape and shows both times in UTC. |
| LA-031 | Safe self-administration calls are shown on a dedicated screen naming the function and every argument. |
| LA-032 | A descriptor that fails Ledger-signature verification is discarded and the call is treated as undecodable. |
| LA-033 | An undecodable call is shown after the blind-signing warning with target, selector, value, full calldata and its hash. |
| LA-034 | Every review shows a Key field naming role, slot and set, and a Network field. |
| LA-035 | Every field of the message and of its domain is shown. |
| LA-036 | On approval the digest is computed from the displayed fields and both halves are signed and buffered; on rejection nothing is signed. |
| LA-037 | Each leg of a transfer batch is shown in full and in order. |
| LA-038 | A plain-text message is shown in full, never truncated. |
| LA-039 | On the owner path the device computes the safeTxHash and its wallet-domain wrapping itself. |
| LA-040 | Owner signatures and Guard approvals over the same Safe transaction are visibly distinct by role field and titles. |
| LA-041 | Inline and stored approvals are one flow over identical bytes. |
| LA-042 | A module-transaction approval shows the module and the full decoded call, and the device computes dataHash itself. |
| LA-043 | enableModule opens with its own warning page and a dedicated screen naming the module. |
| LA-044 | A revoke shows the revoked approval's hash in full. |
| LA-045 | A key rotation is signed by the old key, opens with a warning, and shows the new key hash, set and administrator. |
| LA-046 | A new key is labelled as on this device only when the device derived it and it matches. |
| LA-047 | All screens use the SDK's high-level NBGL use cases. |
| LA-048 | Addresses EIP-55 in full, 32-byte values in full, times absolute UTC, amounts never decimals-guessed. |
| LA-049 | On Nano devices long values are paged, never truncated, and the decision page needs both buttons. |
| LA-050 | On Stax and Flex the decision is Hold to sign. |
| LA-051 | Home shows only icon, name and description; Info shows version, developer, ML-DSA sets and test-build status. |
| LA-052 | The device model is checked against the real app in Speculos on Nano and Stax/Flex. |
| LA-053 | The v2 app carries no XMSS code. |
| LA-054 | The SDK's ML-DSA is treated as unhardened against side channels. |
| LA-055 | Production installs come only from the Ledger Live catalog; sideloaded builds never hold a production phrase. |
| LA-056 | A delegatecall Safe transaction is accepted only to a canonical MultiSendCallOnly address compiled into the app. |
| LA-057 | A MultiSendCallOnly batch must parse exactly with every leg a Call, or it is refused. |
| LA-058 | Every leg of a Safe batch is decoded, checked as a single transaction and shown in full, in order. |
| LA-059 | A Safe self-call other than the nine admin functions is refused before any screen, decodable or not. |
| LA-060 | For a Safe-message approval the device receives the message itself and computes its hash, the Safe message hash and the digest; a hash alone is refused. |
| LA-061 | Safe-message typed data is shown through a verified ERC-7730 descriptor; plain text is shown in full. |
| LA-062 | Undecodable typed data is shown after the blind-signing warning with its domain, primary type, every raw field and its hash. |
