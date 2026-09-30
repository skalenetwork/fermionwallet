# Ledger XMSS App — Device UI Reference

Screen-by-screen visual reference for the FermionGuard Ledger app. The normative behavior lives in [`ledger-xmss-app.md`](./ledger-xmss-app.md) ("Device UI specification"); this document is the illustrated companion — what the Administrator actually sees, in order, for every flow.

Every flow is one of the Ledger SDK's standard NBGL reviews: an intent page whose title starts with **Review**, the signed fields as tag/value pages, a confirmation page with **Hold to sign**, and a status page (`Operation signed` / `Operation rejected`). `Reject` is the footer of every page and, when chosen, raises the SDK's own confirmation — `Reject operation?` / `Yes, reject` / `Go back to operation`. Nothing in this app draws its own layout; the sources for each of those strings are in [`ledger-xmss-app.md`](./ledger-xmss-app.md) Appendix A.

**One UI layer, four screen sizes.** Stax, Flex, Nano X and Nano S Plus all run NBGL — Ledger's own Ethereum app builds with `ENABLE_NBGL_FOR_NANO_DEVICES = 1` and ships no BAGL code path. The mockups below show the Nano-class rendering; the touch devices lay the same pages out as larger pages with identical content and ordering.

**The mockups use colour; the device cannot.** NBGL's whole palette is `BLACK`, `DARK_GRAY`, `LIGHT_GRAY`, `WHITE`, and on the Nano screens the first three collapse to one. Colour in the images below is a reading aid for this document and carries no device meaning. On the device, flows are told apart by three things, all of which survive a monochrome screen:

| Flow | Intent title | Confirmation | Warning page before the intent? |
|---|---|---|---|
| Sign approval | `Review approval` | `Sign approval?` | only when the approval is not pinned to a Safe tx, the class is `ADMIN`, or the key is past its warning threshold |
| Deny | `Review denial` | `Sign denial?` | no — the `Leaf: None consumed` field is the tell |
| Rotate key | `Review key rotation` | `Sign key rotation?` | yes, always |
| Key generation | `Review new quantum key` | `Generate key?` on the warning page | yes — the no-backup warning |
| Retire key | `Review key retirement` | `Retire key?` | yes, always |

## Signing flow (`SIGN_PREAPPROVAL`)

No signature exists until every field page has been traversed and the confirmation page held. There is no skip, no summary-only mode, no raw-hash path.

![Signing screens 1–4](./assets/ui/ledger/ledger-sign-1.svg)

The intent page names the flow; then the first three fields are the Ethereum app's own labels, in its own order, so the rows a Ledger user reads first are rows they already know:

1. **`Amount`** — decimals-adjusted with the ticker from the CAL descriptor the host provided (`500,000.00 USDC`). With no descriptor: the raw integer, no ticker.
2. **`Token`** — shown only when there is no descriptor: the full EIP-55 contract address, labelled `Unknown token`. A missing descriptor costs the ticker and nothing else; unlike the Ethereum app, nothing here becomes blind-signable.
3. **`To`** — the recipient, full EIP-55 checksummed address, never truncated. Compare it against the value you verified out-of-band, not against the host screen alone. The mixed-case capitalisation is itself a checksum.
4. **`Network`** — the chain name when the chain is known, otherwise its decimal chain ID.

![Signing screens 5–8](./assets/ui/ledger/ledger-sign-2.svg)

5. **`Safe`** — the Safe address, full EIP-55.
6. **`Guard`** — the `verifyingContract` from the signed EIP-712 domain, full EIP-55, beside the chain it belongs to. This page exists because approving a payload is what **marries this key slot to that contract on that chain, permanently**: the binding is written to NVM with the leaf counter, the app holds one key, and there is no retire or key-generation command to undo it. A stale or wrong Guard address here costs the key and every unused leaf on it, and a buggy host does that as easily as an attacker — so the one field that decides it must not be the one field the review never draws.
7. **`Valid from` / `Valid until`** — absolute UTC times, never durations. A timestamp the device cannot render honestly is refused before the review opens rather than drawn: the year is carried as 64 bits and a value past the last representable second answers `0x6A80` with no page and no human involved, because a wrapped year would render as a plausible near date and the validity window is the only control over how long a signed transfer stays relayable.
8. **`Safe tx`** — the binding read from the signed `txHash`, as the full 32-byte hash. When it is zero the review is preceded by a warning page and the field reads `Not pinned — any matching transfer`. No Safe nonce: it is not in the signed payload.
9. **`Policy hash`** — the full 32-byte `policyHash`, not an abbreviation: it is one of the values this signature binds, and Ledger's guidance reserves shortened or hidden fields for data that does not affect the user's funds.
10. **`Key`** — `Key 2 · orbit velvet`, so a host cannot switch keys unnoticed.
11. **`Leaf`** — `184,203 of 1,048,576`. The odometer: a number that jumped since last time is the host trying to burn leaves.

Then **`Sign approval?`** with **Hold to sign**. On approve, the counter commits in secure-element NVRAM *before* the hybrid signature — the ECDSA half and the XMSS half over the same digest — is buffered for the host to page out with `GET_SIGNATURE_CHUNK`, XMSS bytes first and the ECDSA half last, so the host can never hold the classical half alone. Rejecting, or 60 s idle on the confirmation page, consumes no leaf.

**PAYLOAD/ADMIN classes** reuse this flow with fields 1–3 replaced by `To`, `Value` and `Data hash` (full 32 bytes). The three fields a class does not use must be zero, and the device refuses the payload before any screen if they are not: the engine's commitment hashes only the fields its own class uses, so a non-zero value in the others would be signed, undrawn and unenforced at once; an `ADMIN` payload opens on a warning page, which then puts the warning icon on the intent and confirmation pages. A **batch** shows `Legs`, per-token totals (informational) and the binding batch `dataHash` in full — legs are reviewed in the app, the hash is verified on the device:

![Batch signing screens](./assets/ui/ledger/ledger-batch.svg)

## Denial flow — a receipt that costs no leaf

![Denial flow](./assets/ui/ledger/ledger-deny.svg)

Denying produces a Ledger-signed refusal as auditable as an approval but touching no XMSS state: the signature is plain ECDSA over the denial record (payload hash + reason hash), the leaf counter never moves, and a `Leaf: None consumed` field says so on the review itself. The reason is entered in the app (required, free text + quick-picks) before the device flow starts; the device displays it so you sign what the audit log will say. A denial is distinguishable from an approval by its intent title, its confirmation title and that `Leaf` field — never by a frame colour the device cannot draw.

## Key generation (`GEN_XMSS_KEY`) — ceremony Stage B

![Key generation](./assets/ui/ledger/ledger-keygen.svg)

Six pages: the intent (`Review new quantum key`, with parameter set and lifetime), the **no-backup warning page** (the key is intentionally not derivable from the recovery phrase — restoring a seed would reset the leaf counter and enable reuse forgery), tree-construction progress (not shown; cancellable until complete), the root review with the **6-word ceremony code rendered by the secure element** and the full 32-byte root, the export confirmation (only the root, public SEED, height and parameter set leave the device — the public SEED is required on-chain to verify signatures), and the key attestation (`SIGN_KEY_ATTESTATION`), its own review whose fields are `Safe`, `Network`, `Key` and `Registry nonce`: the device signs the registry's `QuantumKeyAttestation` with its `quantumAdmin` key, filling the key fields itself so the host can't substitute a root. The app holds up to four keys: generation always fills a free slot and never touches an existing key, and every review carries a `Key` field (`Key 2 · orbit velvet`). Reading a key back (`GET_XMSS_ROOT` with `P1 = 01`) replays the root-review and export pages only; attestation is repeated per Safe.

## Rotation (`SIGN_ROTATION`)

![Rotation flow](./assets/ui/ledger/ledger-rotate.svg)

Signed with the **old** key — on the same device, where the new key sits in another slot, or on the old device — as the possession proof of the [rotation procedure](./quantum-key-registry.md). A warning page opens the flow, so the warning icon sits on the intent (`Review key rotation`) and confirmation (`Sign key rotation?`) pages; the fields say which device holds the successor (`New key: Key 3 on this device` or `another device`). The device shows every field of the signed `RotateQuantumKey` payload: `Safe` and `Network`, the `New administrator` address (with its own warning page when it changes), the new key's ceremony words, full root, height and parameter set, `Registry nonce` and `Valid until` in UTC. It also shows old vs. new ceremony words (verify both out-of-band), the number of approvals being abandoned (so a pointless rotation can't be socially engineered invisibly), and a `Leaf` field naming the cost: one old-key leaf. The device hashes the displayed fields itself; it never signs a digest supplied by the host.

## Home, settings and errors

![Home, settings and errors](./assets/ui/ledger/ledger-ambient.svg)

- **Home (idle):** the SDK's home page and nothing more — app icon, app name, one-line description. Ledger's guidance is that the home screen shows exactly those three, so the per-key usage dashboard lives in settings; where a key is bound to one verifying contract on one chain, the description line names that binding.
- **Settings → Keys:** one row per slot — `Key 1 · orbit velvet`, `184,203 / 1,048,576 (17%)`, exhaustion state, contract binding if any. A free slot reads `Free`. This is the page to photograph for an audit. Settings come before the app's info, which carries `Version`, `Developer` and `Parameter set`.
- **Settings → Retire key:** double-confirmed and destructive, opening on a warning page that shows the key's ceremony words and unused leaves and warns to retire only after the replacing rotation is confirmed on-chain. Erases that one slot.
- **Rotation-overdue warning page:** prepended to every signing flow once the key passes the warning threshold.
- **Key exhausted:** at 100% the app refuses to sign and answers `0x6983`; the only content on screen is the rotation instruction.
- **Errors:** an APDU-level fault gets a status word and no screen, as in the Ethereum app — the host has the code and is the place to explain it. A screen appears only where the Administrator must act on the device: key exhausted, a failed counter commit (`Could not record the leaf. No signature was produced.`), and the clear-signing refusal (`This approval cannot be clear-signed` / `FermionGuard never signs a payload it cannot display.`, with `Reject` as the only action — there is no blind-signing setting to go and enable).

## Acceptance criteria

The `ragger` snapshot suite pins every page above on all four supported devices; the full checklist is in [`ledger-xmss-app.md`](./ledger-xmss-app.md) ("Device UI acceptance criteria"). Headline invariants: no signature without full-field traversal, reject/timeout never consumes a leaf, addresses EIP-55 and never truncated, 32-byte hashes never abbreviated, rotation impossible to mistake for signing without relying on colour.
