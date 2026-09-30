# FermionGuard Ledger app

The Quantum Administrator's device app: the hybrid signer of
[`ledger-xmss-app.md`](../ledger-xmss-app.md). It holds one stateful XMSS key whose
one-time-leaf counter lives in secure-element NVM, and the stateless secp256k1 key
whose Ethereum address the contracts pin as `quantumAdmin`. A pre-approval is signed
with both halves over the same EIP-712 digest, and the digest is recomputed on the
device from the fields it rendered — the host never supplies a hash.

Rust, on Ledger's [device SDK](https://github.com/LedgerHQ/ledger-device-rust-sdk),
targeting Nano S Plus and Nano X (BAGL screens, the two-button idiom of the Ledger
Ethereum app).

## Build

Only docker is needed; the toolchain, the BOLOS SDKs and `cargo-ledger` all live in
Ledger's official image.

```sh
./build.sh              # Nano S Plus -> build/nanos2/bin/app.elf
./build.sh nanox        # Nano X      -> build/nanox/bin/app.elf
```

## Run it in Speculos

```sh
docker run --rm -p 5000:5000 -p 9999:9999 \
  -v "$PWD/build/nanos2/bin":/app ghcr.io/ledgerhq/speculos:latest \
  --model nanosp --display headless --api-port 5000 --apdu-port 9999 \
  --seed "test test test test test test test test test test test junk" /app/app.elf
```

Screens at http://localhost:5000, APDUs on TCP 9999. The demo drives exactly this —
see [`demo/LEDGER.md`](../demo/LEDGER.md) — with `LEDGER_TRANSPORT=speculos`. The
seed above is anvil's, so the device's `quantumAdmin` address is
`0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65`, anvil account 4, which is the address
the demo registers on-chain.

## Install on a device (development only)

```sh
cargo ledger build nanosplus --load     # inside the builder image, device unlocked
```

A sideloaded build shows the standard "PENDING LEDGER REVIEW" warning. Per
`ledger-xmss-app.md`, a device showing that warning must never hold a production
key.

## APDU surface

CLA `0xE0`. Every command names the key slot in **P2**; this build has one slot,
`0x01`. The framing is the one `demo/ledger_device.py` speaks.

| INS | Command | P1 | Response |
|---|---|---|---|
| `0x02` | `GET_XMSS_ROOT` | `0x00` | root(32) ‖ seed(32) ‖ treeHeight(1) ‖ parameterSet(32) |
| `0x04` | `GET_LEAF_INDEX` | `0x00` | next unused leaf, 4 bytes big-endian |
| `0x06` | `SIGN_PREAPPROVAL` | `0x00` first chunk, `0x80` more follow, `0x81` last | on the last chunk, once the human has decided: leaf(4) ‖ digest(32) ‖ totalLen(2) |
| `0x08` | `GET_APP_CONFIG` | `0x00` | flags(1) ‖ version(3) ‖ MAX_KEYS(1) ‖ freeSlots(1) ‖ treeHeight(1) ‖ parameterSet(32) |
| `0x0E` | `GET_ADMIN_ADDRESS` | `0x00`, or `0x01` to show it on-device | address(20) |
| `0x18` | `GET_SIGNATURE_CHUNK` | chunk index | up to 255 bytes of `ecdsa(65) ‖ r(32) ‖ wotsSig(67×32) ‖ auth(h×32)` |

The signature blob carries no public key: the root and SEED are already on-chain from
registration, and `contracts/script/Demo.s.sol` decodes exactly this layout.

Status words: `0x9000` ok, `0x6985` rejected on the device, `0x6986` a signing
session is already in flight, `0x6A84` no one-time leaves left, `0x6E00` wrong CLA,
`0x6E01` unknown command, `0x6E02` impossible P1/P2 (including a slot this build
does not have), `0x6E03` bad length, `0x6D00` a command this build does not
implement.

## What is checked

`test/test_app.py` runs the built app in Speculos and drives it through the demo's
own transport, checking the three things that decide whether an approval the device
signs is one the Guard accepts:

1. the digest the device reports is the EIP-712 digest of the fields the host sent —
   computed independently with `cast`, so the device's keccak and the contracts'
   encoding are compared, not assumed;
2. the XMSS half verifies under the root and SEED the device published, checked by
   the RFC 8391 reference implementation in `contracts/lib/xmss-solidity/py` (the
   same reference the Solidity verifier is proven against, and which agrees with the
   RFC authors' C code);
3. the ECDSA half recovers to the device's own `quantumAdmin` address, with `s` in
   the lower half of the curve order — OpenZeppelin's `ECDSA` rejects a high `s`, so
   a device that emitted one would produce approvals the Guard always refuses.

Plus the firmware behaviour that is easy to get wrong: the leaf counter advances by
exactly one per signature, a rejection consumes nothing, the review really shows
every field, and an exhausted key refuses to sign.

```sh
./build.sh && python3 test/test_app.py    # needs docker and Foundry's cast
```

The full path — register the device's key on chain, sign on the device, relay to the
Guard — is the demo's `LEDGER_TRANSPORT=speculos` profile; see
[`demo/LEDGER.md`](../demo/LEDGER.md).

## What this build is not

`ledger-xmss-app.md` specifies more than this build contains. What is missing is
listed here rather than stubbed, so nothing reads as done when it is not:

- **One key slot, not four.** `GEN_XMSS_KEY`, `LIST_KEYS` and `RETIRE_KEY` are
  absent, and so is the key-generation flow (Flow 1) with its entropy notice.
- **The XMSS seeds are derived from the device's recovery phrase**, not generated
  from the secure element's TRNG and sealed in NVM. This contradicts item 2 of the
  spec and the Flow 1 entropy notice: a key on this build *is* restorable from the
  recovery phrase, so two devices with the same phrase would hold the same XMSS key
  and could spend the same leaf twice. It is acceptable for the demo — where the
  on-chain used-leaf bitmap is the backstop — and must not hold real funds.
- **No `SIGN_ROTATION`, `SIGN_KEY_ATTESTATION` or `SIGN_DENIAL`** (Flows 3 and 4).
  The registration attestation the demo needs is produced off-device.
- **Nano only.** Stax and Flex need the NBGL screen layer.
- **Amounts are shown in raw units**, not decimals-adjusted with a symbol: that needs
  a token list (Ledger's CAL) the app does not carry, and guessing 18 decimals would
  be a display that lies. The recipient, Safe and target addresses *are* shown in
  full, EIP-55 checksummed, as the spec requires.
- **No 60-second idle timeout on the decision screen.** A review stays open until the
  human decides; the host's own timeout is what ends an abandoned session.

None of these is a shortcut in the signing path: the counter-before-signature
commit, the recomputed digest, and the field-by-field review are implemented as
specified, because those are what the Guard's security rests on.

## Layout

| Path | |
|---|---|
| `src/main.rs` | APDU dispatch, home screen, command handlers |
| `src/fmt.rs` | screen formatting with no allocator: amounts, addresses, UTC times |
| `build.sh` | build in Ledger's container, ELF where Speculos and the demo expect it |
| `ledger_app.toml` | manifest for Ledger's tooling and CI |
