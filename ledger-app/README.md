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

The numbering is the Ethereum app's. The three commands with an Ethereum analogue
keep that app's own number — `0x02` GET ETH PUBLIC ADDRESS, `0x04` SIGN, `0x06` GET
APP CONFIGURATION — and the FermionGuard-specific ones sit at `0x40` and above, clear
of the Ethereum app's highest assignment, so no number means two different things in
two apps.

| INS | Command | P1 | Response |
|---|---|---|---|
| `0x02` | `GET_ADMIN_ADDRESS` | `0x00`, or `0x01` to show it on-device | address(20) |
| `0x04` | `SIGN_PREAPPROVAL` | `0x00` first chunk, `0x80` more follow, `0x81` last | on the last chunk, once the human has decided: leaf(4) ‖ digest(32) ‖ totalLen(2) |
| `0x06` | `GET_APP_CONFIG` | `0x00` | flags(1) ‖ version(3) ‖ MAX_KEYS(1) ‖ freeSlots(1) ‖ treeHeight(1) ‖ parameterSet(32) |
| `0x44` | `GET_XMSS_ROOT` | `0x00` | root(32) ‖ seed(32) ‖ treeHeight(1) ‖ parameterSet(32) |
| `0x46` | `GET_LEAF_INDEX` | `0x00` | next unused leaf, 4 bytes big-endian |
| `0x50` | `GET_SIGNATURE_CHUNK` | `0x00` first chunk, `0x80` each next one | up to 255 bytes of `r(32) ‖ wotsSig(67×32) ‖ auth(h×32) ‖ ecdsa(65)` |

The ECDSA half is deliberately last: a host that reads only the first chunk holds
neither half whole, so the classical signature cannot leave the device ahead of the
quantum one. The blob carries no public key: the root and SEED are already on-chain
from registration, and `contracts/script/Demo.s.sol` decodes exactly the XMSS half
the host takes off the front.

Status words: `0x9000` ok, `0x6985` rejected on the device, `0x6986` a signing
session is already in flight, `0x6A80` a field the device will not sign or cannot show
honestly, `0x6A81` the key slot belongs to a different contract, `0x6A84` no one-time
leaves left, `0x6901` nothing buffered to read out, `0x6E00` wrong CLA, `0x6E01` an
instruction number the dispatcher does not know — including the commands
`ledger-xmss-app.md` defines that this build does not implement, and including a host
that still speaks the old numbering — `0x6E02` impossible P1/P2 (including a slot this
build does not have), `0x6E03` bad length, including a chunk of `SIGN_PREAPPROVAL`
with no data, `0x6D00` the firmware declining to go on because it reached a state it
should not be able to reach — a step of the signing path that cannot fail, failing.
These are the Rust SDK's `StatusWords` values, checked against the built app rather
than assumed.

Four of them differ from `ledger-xmss-app.md`; see [Where this build differs from the
spec](#where-this-build-differs-from-the-spec).

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
exactly one per signature, a rejection consumes nothing, the review really shows every
field — including the `verifyingContract` the slot marries itself to — a spent
signature cannot be read out a second time nor survive a signing command that is
refused, a chunk with no data is refused instead of opening a session, a validity
window the Guard could never accept is refused before any screen, and an exhausted key
refuses to sign.

`test/test_wallet.py` does the same for the FermionWallet `Transfer` path and the
one-key-one-contract binding, and `test/test_fmt_utc.py` checks that no screen says
less than the payload: the calendar arithmetic against Python's own, on the host, and
on the device the two places a value is refused rather than drawn short.

`test/test_payload_class.py` covers the other half of the zero-field rule. Everything
above sends `approvalClass: 0`, and so does every host in the tree, so the `PAYLOAD`
and `ADMIN` arm of `unused_fields_are_zero` — the one that requires `token`,
`recipient` and `amount` to be zero — had no check of any kind: deleting it left
`test_app.py` entirely green. It checks that arm in both directions, that a class-1 review
draws `Target`, `Value` and `Data hash` rather than the transfer triple, and that an
`ADMIN` approval says so on its heading, which is the only place the class appears on
the screen.

```sh
./build.sh && python3 test/test_app.py      # needs docker and Foundry's cast
python3 test/test_wallet.py                 # its own ports and container
python3 test/test_fmt_utc.py                # --host for the parts needing no device
python3 test/test_payload_class.py          # the PAYLOAD and ADMIN classes
```

Each suite owns its Speculos ports so they can run together; `APP_TEST_PORTS`,
`WALLET_TEST_PORTS`, `FMT_UTC_PORTS` and `PAYLOAD_TEST_PORTS` move them.

### The one invariant, and which half of it a test can reach

`ledger-xmss-app.md` calls one thing catastrophic to invert, and it has two halves:
the leaf counter must commit to NVM **before** a signature is released, and the leaf
the counter consumed must be the leaf the signature is computed under. Two WOTS+
signatures under one one-time leaf over two different digests is what makes the scheme
forgeable, and either half getting it wrong produces exactly that pair.

This section used to claim both halves as compile-time properties and say no test here
could reach either. One of those claims was right, one was false, and the sentence
about tests was false as well. What follows is what was measured.

**The ordering** is the half no host-side test can observe. Speculos keeps NVM in RAM,
so there is no power cut to stage and nothing to look at afterwards — move the commit
to after the signature is published and all four suites stay green. It is a property of
the build instead: `src/session.rs` owns the counter and the signature buffer privately
and hands out a `Committed` token that only `commit` can produce, and `publish` — the
only writer of the flag `GET_SIGNATURE_CHUNK` reads — takes that token **by value**. A
build that released the signature first has no token to pass. Two probes, each built in
Ledger's container, and a third that has nothing to build:

| probe | what the build says |
|---|---|
| put the `session::publish(...)` call above the `session::commit(...)` that produces its argument | `error[E0425]: cannot find value committed in this scope` |
| call `session::publish` twice with the one token | `error[E0382]: use of moved value: committed` |
| set `BLOB_READY` any other way | there is no other way to try: it, `BLOB` and `BLOB_CURSOR` are private to `session.rs`, and `publish` is the only writer |

**The binding** — commit leaf N, sign leaf N — was claimed in the same breath, and it
was not true. `publish` handed its closure the committed leaf as a `u32`, and a closure
is free to ignore its parameter: `xmss::sign(&key, 0, …)` compiled clean, and in
Speculos it produced two WOTS+ signatures that both verify under leaf 0, over two
different digests, while the counter marched 0 → 1 → 2 and the device reported leaves 0
and 1. Three further one-line edits compiled too: a closure reading the outer `leaf`
instead of its own parameter, `session::commit(0, …)` regardless of the real leaf
(which regresses the counter), and two `commit` calls in a row yielding two tokens for
one leaf.

The leaf now travels as three types rather than a number, because it has three
consumers (`src/session.rs` has the full argument):

- `session::Leaf` — private field, and `session::reserve` is its only factory. The
  digest, the review's `Leaf` page and the four bytes the host is answered with all
  take a `Leaf`, so none of them can be handed a literal.
- `session::Reserved` — the leaf this session intends to spend, consumed **by value**
  by `commit`.
- `session::Signing` — what `xmss::sign` takes. Minted only inside `publish`, out of
  the `Committed` token, and neither `Copy` nor `Clone`.

| probe | what the build says |
|---|---|
| `xmss::sign(&key, 0, …)` | `error[E0308]: expected Signing, found integer` |
| the closure reads the outer `leaf` instead of its parameter | `error[E0308]: expected Signing, found Leaf` — and the two values are equal now anyway |
| `session::commit(0, …)` | `error[E0308]: expected Reserved, found integer` |
| reserve a fresh leaf inside the closure and sign under that | `error[E0308]: expected Signing, found Leaf` |
| two `reserve`/`commit` pairs in a row | compiles — the one thing a type cannot say is that a reservation still matches the counter, so `session::commit` checks it at run time. Against that build the device answers `0x6D00` on the second commit, having spent one leaf and released no signature at all: `?` propagates before `publish` is reached. Measured in Speculos, not argued |

And it is **not** true that no test here can reach the binding. `test_app.py` spends
every remaining leaf of the tree and verifies each signature under the leaf the device
reported; against the `xmss::sign(&key, 0, …)` build it fails with

```
FAIL  every leaf's XMSS half verifies, not just the first: failed at leaves
      [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] — suspect the auth path or ADRS
```

and nothing else. The checks above the loop pass under that mutant, and the loop starts
at leaf 2, so be exact about why: the suite's one verified signature is leaf 0's, which
is the leaf the mutant hardcodes, and leaf 1 is signed by the hand-streamed block,
which reads the status word and pages the blob out but never puts it through
`xmss_ref.verify`. The exhaustive loop is the only thing here that verifies a signature
under a leaf other than 0, and it is what catches this. That loop was already there.
The claim that nothing here could reach this was wrong about the suite as well as about
the compiler, and it is why nobody looked.

The full path — register the device's key on chain, sign on the device, relay to the
Guard — is the demo's `LEDGER_TRANSPORT=speculos` profile; see
[`demo/LEDGER.md`](../demo/LEDGER.md).

## What this build is not

`ledger-xmss-app.md` specifies more than this build contains. What is missing is
listed here rather than stubbed, so nothing reads as done when it is not:

- **One key slot, not four.** `GEN_XMSS_KEY`, `LIST_KEYS` and `RETIRE_KEY` are
  absent, and so is the key-generation flow (Flow 1) with its entropy notice.
- **The XMSS key is generated on first use, not by an explicit ceremony.** The seed
  itself is right: 32 bytes from the secure element's hardware RNG, written to NVM,
  never derived from the recovery phrase and never exported, because a stateful key
  restored onto a second device would sign one one-time leaf twice
  (`hardware-security-policy.md`). What is missing is the ceremony around it —
  Flow 1's entropy notice, the root review, the six ceremony words — so the first
  `GET_XMSS_ROOT` silently creates a key instead of asking. There is no way to
  retire or replace it either, since `RETIRE_KEY` is absent.
- **A fresh emulator is a fresh key.** Speculos keeps NVM in memory, so restarting
  it generates a new key and resets the counter; the demo therefore reads
  `GET_XMSS_ROOT` at setup and registers whatever the device holds. On a real device
  the key survives app updates, as BOLOS specifies.
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

### Checks that are defence in depth, not live paths

`fmt.rs` records overflow instead of truncating and every review asks about it once,
after its last field. On this build **no payload can make that flag true**, and saying
so plainly is the point of this list: a comment that claims a live check nobody can
reach is why the truncation channels below went unexamined for so long.

- **`Buf::overflowed` and the text arena's flag.** The widest value any review draws is
  a `2^256 - 1` amount — 78 digits, 25 separators and `" raw units"`, 113 characters —
  into a `Buf<128>`, and the pre-approval review's fourteen fields are at most 804
  bytes of a 1024-byte arena, five more address fields of headroom. `push_utc`'s own
  taint cannot fire either, because `review_and_digest` asks `fmt::utc_renderable`
  about every timestamp *before* a screen is drawn and answers `0x6A80` instead. So
  deleting the readers changes nothing any host can observe, and every suite stays
  green; `test_fmt_utc.py` therefore checks that they are *present*, and its D1-D3
  device checks pin them from the other side — remove the `utc_renderable` pre-checks
  as well and seven of those go red.
- **`intern`.** It used to copy what fitted the arena and drop the rest with nothing
  recorded anywhere, which is the one thing `fmt.rs` exists to prevent, one layer out.
  Text that does not fit now reads `FIELD TOO LONG - REJECT` and raises the arena's own
  sticky flag, which all four screens that build text read beside `Buf::overflowed`.
- **`push_address`'s inner buffer.** Twenty bytes is forty hex characters exactly, so
  the `Buf<40>` it checksums through is written to capacity with no margin at all. An
  overflow there would checksum `FIELD TOO LONG - REJECT` and produce a
  plausible-looking address with the wrong capitalisation; the overflow is now read and
  the caller's buffer tainted with it.
- **What no `Buf` can see: the widget.** The SDK's `Page` draws `MAX_CHAR_PER_LINE`
  characters and drops the rest with no mark, so a value well inside its buffer can
  still be cut in half on the screen. That is why the binding lives in a
  `MultiFieldReview` of its own and the home screen carries only fixed strings and the
  leaf count — and the leaf count is the remaining exposure: `"1,048,576 of 1,048,576"`
  is 22 characters, so a tree of height 20 or more would be cut there. `HEIGHT` is 4.
  `test_fmt_utc.py`'s D4 checks the shape that fixes it for the binding; nothing can
  check it for a tree height this build does not have.

## Where this build differs from the spec

The list above is about commands and flows that are absent. These are places where a
command that *is* here behaves differently from `ledger-xmss-app.md`. They are recorded
rather than fixed because each one would break `demo/ledger_device.py`, the host half
of this protocol, and the two have to ship together; none of them is a difference the
Guard's security rests on.

| `ledger-xmss-app.md` | This build | Why it is left |
|---|---|---|
| `GET_SIGNATURE_CHUNK` takes `P2 = 00` (it names no key) | `P2 = slot`, like every other command | The dispatcher checks the slot once for the whole APDU surface, which is what makes "no command can act on a key other than the one it names" a single line rather than a per-command argument. The readout names no key, so the check is redundant there — but `demo/ledger_device.py::_send` puts the slot in `P2` of every command it sends, so accepting only `00` would reject the host in the tree. |
| Read-only commands are answered while a signing session is in flight, as the Ethereum app answers GET APP CONFIGURATION regardless | All commands but `SIGN_PREAPPROVAL` answer `0x6986` while a payload is half-streamed | Two of the read-only commands are not read-only in this build: `GET_XMSS_ROOT` has no display flag and always draws "Reading key…", and on a fresh device it *generates* the key. Drawing a screen over a half-streamed session is worse than refusing it. Answering the two that really are inert (`GET_APP_CONFIG`, `GET_LEAF_INDEX`) while refusing the others would be the spec's behaviour for a build that has the display flag. |
| A signing command arriving mid-session is refused with `0x6980` | `0x6986` | `0x6986` is the Rust SDK's own `StatusWords::Busy`, and `demo/ledger_device.py` has a sentence for it. `0x6980` has no SDK constant here. |
| `GET_SIGNATURE_CHUNK` with nothing buffered returns `0x6A88` | `0x6901` | `0x6901` is the SDK's `StatusWords::CmdNotAccepted`. `0x6A88` is also the spec's code for a root-prefix mismatch, which this build does not implement (it has one slot and takes no root prefix), so the two meanings cannot be told apart here. |

One place this build is deliberately **stricter** than the spec. `ledger-xmss-app.md`
answers `0x6A80` for a "validity window inconsistent" and leaves *inconsistent* to the
app, and the app's rule was `validFrom > validTo`. `PreApprovalEngine.sol`'s is
`validTo <= validFrom || validTo - validFrom < MIN_WINDOW`, with `MIN_WINDOW` at 15
minutes — so an equal window, and every window up to 899 seconds, passed every
pre-check here, reached the holder as a page that looks like any other, spent a
one-time leaf on approval, and reverted `InvalidWindow` on every relay attempt for
ever. The device now refuses those before any screen, for the reason the wallet path
already refused `validUntil == 0` unseen: a signature that could never be used should
be refused rather than shown. The contract's third clause, `validTo <=
block.timestamp`, has no analogue here — the device has no clock — and no host in this
tree sends a window shorter than a day, so nothing on the host side changes.
`demo/app_api.py` already had the rule (`MIN_VALIDITY = 15 * 60  # PreApprovalEngine.MIN_WINDOW`)
and the device did not, which is the shape of gap the device is supposed to be the
last line against: the host that enforces it is not the one holding the key.

One further difference has been closed rather than recorded, and the account of it here
was itself wrong until now — it said the whole thing was done, in the past tense, and
half of it was not.

The spec requires the signature buffer to be zeroized once its last byte has been
delivered and again on the next signing command. The first half was true: a complete
readout wipes the buffer, and `test/test_app.py` checks the consequence — there is
nothing left to read, by either `P1` — because Speculos cannot show a test the device's
RAM. The second half was true only of a signing command the app went on to *accept*.
`session::discard` sat inside the branch that accepts a first chunk, so all three
refused shapes — a chunk with no data, a continuation with no session open, and a
stream that overruns `eip712::PAYLOAD_LEN` — were refused without touching the buffer,
and `P1 = 0x00` went on re-serving all 2,369 bytes of the last one-time signature for
as long as the host never finished the readout.

The rule is now stated on the command rather than on its outcome: **`discard` is the
first line of `sign_pre_approval`, so every signing command the dispatcher accepts as
one wipes the buffer, whether that command is then accepted or refused.** (A `0x04`
with an impossible `P1` never reaches `sign_pre_approval` — `TryFrom<ApduHeader>`
answers `0x6E02` first — so it is not a signing command for this purpose.)
`test/test_app.py` drives the two shapes that can arrive while a readout is live and
checks both directions: refused, no session opened, and nothing left to read
afterwards. The third cannot arrive while a readout is live at all — a half-open stream
and a buffered signature never coexist, because `handle` answers `0x6986` to
`GET_SIGNATURE_CHUNK` while a payload is half-streamed — so it is checked for the
refusal and the session it must not leave behind.

Two other ways out of the app used to leave the buffer populated: `home()`'s `Quit`
page, on the way to `exit_app`, and a panic. Both now go through `discard` first —
`set_panic!` takes `main.rs::wiping_panic`, which discards and then hands over to the
SDK's `exiting_panic`. Belongs in the list above rather than in this one: the `Quit`
path is code a test could drive, the panic hook is not. There is no way to stage a
panic from the host, so what is checked is that the hook is installed and that `discard`
touches nothing that can itself panic — not that it has been seen to fire.

What is left, deliberately, is a host that simply stops talking: it keeps its half-read
spent signature until another signing command arrives or the app closes. The wider rule
— wipe the readout on any command that is not a chunk request — was considered and
rejected, because it would have `GET_LEAF_INDEX` destroy a readout a well-behaved host
is in the middle of. `test/test_app.py` checks that residual as a behaviour rather than
leaving it undescribed.

Nothing here argues the spec is wrong. The `P2` and status-word rows are the spec
being right and this build being one host-side release behind it; the read-only row is
the spec assuming `GET_XMSS_ROOT`'s display flag, which this build does not have.

## Layout

| Path | |
|---|---|
| `src/main.rs` | APDU dispatch, home screen, command handlers, the pre-approval review |
| `src/session.rs` | the leaf counter and the signature buffer, and the type that orders them |
| `src/eip712.rs` | the `PreApproval` field layout and the digest, recomputed on the device |
| `src/wallet.rs` | FermionWallet's `Transfer`: fields, digest, review, and the key's contract binding |
| `src/xmss.rs` | the stateful half: key derivation, one-time signing, authentication path |
| `src/fmt.rs` | screen formatting with no allocator: amounts, addresses, UTC times |
| `test/test_app.py` | the Safe pre-approval path end to end, in Speculos |
| `test/test_wallet.py` | the FermionWallet path and the one-key-one-contract binding |
| `test/test_fmt_utc.py` | that no screen says less than the payload: host and device |
| `test/test_payload_class.py` | the `PAYLOAD` and `ADMIN` classes, and their half of the zero-field rule |
| `build.sh` | build in Ledger's container, ELF where Speculos and the demo expect it |
| `ledger_app.toml` | manifest for Ledger's tooling and CI |
