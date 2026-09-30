//! FermionGuard — the Quantum Administrator's Ledger app.
//!
//! The device holds the hybrid signing key of `ledger-xmss-app.md`: one stateful
//! XMSS key whose leaf counter lives in secure-element NVM, and the stateless
//! secp256k1 key whose address the contracts know as `quantumAdmin`. Every
//! pre-approval is signed with both halves over the same EIP-712 digest, and the
//! digest is recomputed on the device from the fields it rendered — the host never
//! supplies a hash.
//!
//! Wire protocol: CLA 0xE0, key slot in P2, the framing documented in
//! `demo/ledger_device.py`. Screens follow the Ledger Ethereum app's Nano idiom:
//! a paged home screen, one field per page, and a final Approve/Reject where
//! Reject is the single tap.

#![no_std]
#![no_main]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod eip712;
mod fmt;
mod session;
mod wallet;
mod xmss;

use ledger_device_sdk::ecc::{make_bip32_path, ECPrivateKey, ECPublicKey, Secp256k1, SeedDerive};
use ledger_device_sdk::random;
use ledger_device_sdk::io::{ApduHeader, Comm, Event, Reply, StatusWords};
use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};
use ledger_device_sdk::ui::bitmaps::{Glyph, CHECKMARK, CROSSMARK, EYE};
use ledger_device_sdk::ui::gadgets::{
    EventOrPageIndex, Field, MultiFieldReview, MultiPageMenu, Page, PageStyle, SingleMessage,
};
use ledger_device_sdk::{include_gif, NVMData};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

// ── The keys this build holds ────────────────────────────────────────────────

/// The Administrator's classical half. Fixed in the app, never host-supplied:
/// `QuantumKeyRegistry` pins this address as `quantumAdmin`, so the path is part of
/// the app's identity and is declared in `[package.metadata.ledger] path`.
const ADMIN_PATH: [u32; 5] = make_bip32_path(b"m/44'/60'/0'/0/4");

/// The parameter-set string the registry records for this key.
const PARAMETER_SET_PREIMAGE: &[u8] = b"XMSS-SHA2_4_256-DEMO";

/// One key slot in this build; the spec's `MAX_KEYS = 4` needs the key-generation
/// and retire flows, which this build does not have (see README.md).
const MAX_KEYS: u8 = 1;
const SLOT: u8 = 1;

// ── APDU surface ─────────────────────────────────────────────────────────────

const CLA: u8 = 0xE0;

/// Rejections the host understands (`demo/ledger_device.py::_sw_message`), on top
/// of the SDK's `StatusWords`.
const SW_BUSY: u16 = 0x6986;
const SW_EXHAUSTED: u16 = 0x6A84;
const SW_BAD_FIELDS: u16 = 0x6A80;

/// P1 of `SIGN_PREAPPROVAL`: the chunk's place in the stream.
const P1_FIRST: u8 = 0x00;
const P1_MORE: u8 = 0x80;
const P1_LAST: u8 = 0x81;

enum Ins {
    /// 0x44 — root ‖ seed ‖ treeHeight ‖ parameterSet of the slot's key.
    GetXmssRoot,
    /// 0x46 — the next unused leaf, 4 bytes big-endian.
    GetLeafIndex,
    /// 0x04 — stream the pre-approval fields; the last chunk waits for the human.
    SignPreApproval { chunk: u8 },
    /// 0x06 — what the ceremony preflight checks the device against.
    GetAppConfig,
    /// 0x02 — the `quantumAdmin` address, 20 bytes.
    GetAdminAddress { display: bool },
    /// 0x50 — the next 255 bytes of the blob the last signature produced:
    /// `P1 = 0x00` restarts from the first chunk, `P1 = 0x80` continues.
    GetSignatureChunk { first: bool },
}

impl TryFrom<ApduHeader> for Ins {
    type Error = StatusWords;

    fn try_from(h: ApduHeader) -> Result<Self, Self::Error> {
        // Every command names the key slot in P2; this build has exactly one.
        let slot_ok = h.p2 == SLOT;
        // The numbering is the Ethereum app's: the commands with an Ethereum analogue
        // keep its own number (0x02 GET ETH PUBLIC ADDRESS, 0x04 SIGN, 0x06 GET APP
        // CONFIGURATION), and everything FermionGuard-specific sits at 0x40 and above,
        // clear of the Ethereum app's highest assignment (ledger-xmss-app.md).
        match (h.ins, h.p1, slot_ok) {
            (0x44, 0, true) => Ok(Ins::GetXmssRoot),
            (0x46, 0, true) => Ok(Ins::GetLeafIndex),
            (0x04, p1 @ (P1_FIRST | P1_MORE | P1_LAST), true) => {
                Ok(Ins::SignPreApproval { chunk: p1 })
            }
            (0x06, 0, _) => Ok(Ins::GetAppConfig),
            (0x02, p1 @ (0 | 1), true) => Ok(Ins::GetAdminAddress { display: p1 == 1 }),
            (0x50, p1 @ (P1_FIRST | P1_MORE), true) => {
                Ok(Ins::GetSignatureChunk { first: p1 == P1_FIRST })
            }
            // A known command with impossible parameters is a host bug, not an
            // unknown command: say which of the two it is.
            (0x02 | 0x04 | 0x06 | 0x44 | 0x46 | 0x50, _, _) => Err(StatusWords::BadP1P2),
            _ => Err(StatusWords::BadIns),
        }
    }
}

// ── Device state ─────────────────────────────────────────────────────────────
//
// The leaf counter and the signature buffer live in `session.rs`, which owns them
// privately so that "counter first, signature second" is something the compiler
// checks rather than something this file remembers to do.

/// The streamed payload of the signing session in flight. Static because 373 bytes of
/// locals under the whole review would not fit the Nano's stack.
static mut PAYLOAD: [u8; eip712::PAYLOAD_LEN] = [0; eip712::PAYLOAD_LEN];
static mut PAYLOAD_LEN: usize = 0;
static mut STREAMING: bool = false;
static mut CHUNK_BUF: [u8; 255] = [0; 255];

fn total_leaves() -> u32 {
    1u32 << xmss::HEIGHT
}

// ── Key material ─────────────────────────────────────────────────────────────

fn admin_key() -> ECPrivateKey<32, 'W'> {
    Secp256k1::derive_from_path(&ADMIN_PATH)
}

/// keccak256(uncompressed public key without its 0x04 tag)[12..32].
fn admin_address() -> [u8; 20] {
    let pk: ECPublicKey<65, 'W'> = admin_key().public_key().unwrap();
    let digest = eip712::keccak(&[&pk.pubkey[1..65]]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..32]);
    address
}

/// The XMSS secret material, in secure-element NVM: a flag byte and 32 bytes drawn
/// from the device's hardware RNG the first time a key is needed.
///
/// It is deliberately **not** derived from the recovery phrase, and the difference
/// from `admin_key()` two functions up is the whole point. The classical half is
/// stateless, so deriving it from the phrase is safe and `ledger-xmss-app.md` item 4
/// says to. A stateful key is the opposite: restore it onto a second device and that
/// device's leaf counter starts from zero, so one one-time leaf signs two different
/// digests — the condition that makes WOTS+ forgeable. `hardware-security-policy.md`
/// therefore requires this seed to be generated inside the secure element and to be
/// unrecoverable, and it never leaves here: nothing in the APDU surface reads it, and
/// only the public root and SEED derived from it go on the wire.
#[link_section = ".nvm_data"]
static mut XMSS_SEED: NVMData<AtomicStorage<[u8; 33]>> = NVMData::new(AtomicStorage::new(&[0u8; 33]));

/// Marks the stored seed as real material rather than the blank initial value.
const SEED_PRESENT: u8 = 0xA5;

/// The key of this slot, generating its seed on first use.
///
/// Generation is the one moment the device is irreplaceable, so it happens here and
/// nowhere else: there is no command that imports, exports or resets it. A power loss
/// during the commit leaves the previous value (atomic storage), so the app either has
/// the old key or the new one, never half of either.
#[allow(static_mut_refs)]
fn xmss_key() -> xmss::Key {
    let mut stored = unsafe { *XMSS_SEED.get_mut().get_ref() };
    if stored[0] != SEED_PRESENT {
        SingleMessage::new("Creating key...").show();
        stored[0] = SEED_PRESENT;
        random::rand_bytes(&mut stored[1..33]);
        unsafe { XMSS_SEED.get_mut().update(&stored) };
    }
    let mut material = [0u8; 32];
    material.copy_from_slice(&stored[1..33]);
    stored.fill(0);
    let key = xmss::derive(&material);
    material.fill(0);
    key
}

fn parameter_set() -> [u8; 32] {
    eip712::keccak(&[PARAMETER_SET_PREIMAGE])
}

// ── The classical half of a hybrid signature ─────────────────────────────────

/// `r ‖ s ‖ v` as `ECDSA.recover` wants it: 64 bytes of scalars and a recovery id
/// of 27 or 28, with `s` in the lower half of the curve order (OpenZeppelin's
/// `ECDSA` rejects a high `s`, so a device that emitted one would produce approvals
/// the Guard always refuses).
fn sign_ecdsa(digest: &[u8; 32]) -> Option<[u8; 65]> {
    // secp256k1's group order, and its halfway point.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    let (der, der_len, parity) = admin_key().deterministic_sign(digest).ok()?;
    let (r, s) = parse_der(&der[..der_len as usize])?;

    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&r);
    let mut parity = parity != 0;
    if s > HALF_ORDER {
        // s := n - s, and the recovered point flips to the other root.
        let neg = sub(&ORDER, &s);
        out[32..64].copy_from_slice(&neg);
        parity = !parity;
    } else {
        out[32..64].copy_from_slice(&s);
    }
    out[64] = 27 + parity as u8;
    Some(out)
}

/// `30 L 02 Lr r 02 Ls s`, with each scalar left-padded to 32 bytes.
fn parse_der(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    let mut at = 2;
    let mut scalar = |at: &mut usize| -> Option<[u8; 32]> {
        if der.get(*at) != Some(&0x02) {
            return None;
        }
        let len = *der.get(*at + 1)? as usize;
        let bytes = der.get(*at + 2..*at + 2 + len)?;
        // DER may carry a leading zero for sign, or drop leading zero bytes.
        let bytes = if bytes.len() > 32 { &bytes[bytes.len() - 32..] } else { bytes };
        let mut w = [0u8; 32];
        w[32 - bytes.len()..].copy_from_slice(bytes);
        *at += 2 + len;
        Some(w)
    };
    let r = scalar(&mut at)?;
    let s = scalar(&mut at)?;
    Some((r, s))
}

fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let v = a[i] as i16 - b[i] as i16 - borrow;
        out[i] = (v & 0xff) as u8;
        borrow = if v < 0 { 1 } else { 0 };
    }
    out
}

// ── Screens ──────────────────────────────────────────────────────────────────

const APP_ICON: Glyph = Glyph::from_include(include_gif!("icons/app_fermionguard_14x14.gif"));

/// Every string a review displays is cut from this one static arena, so the review's
/// peak stack stays flat however many fields it grows to.
///
/// This was introduced as a fix for a SIGSEGV part-way through a signing session, on
/// the theory that a dozen field strings as stack locals had overflowed the stack.
/// That theory is wrong and the comment that asserted it has been removed:
/// `arm-none-eabi-nm`/`objdump` on the crashing build put the whole inlined signing
/// frame at 2,744 bytes against 27,304 bytes of stack, and overflowing the stack here
/// would corrupt bss and trip `app_stack_canary` rather than fault. Bounded stack is
/// still the better shape, but it fixed nothing: the crash is a wild write somewhere
/// else and is still open.
static mut TEXT: [u8; 1024] = [0; 1024];
static mut TEXT_USED: usize = 0;

/// Start a new screen's worth of strings. Every `intern` after this overwrites the
/// previous review's text, so no `&'static str` from an earlier review may be held.
#[allow(static_mut_refs)]
pub(crate) fn text_reset() {
    unsafe { TEXT_USED = 0 }
}

/// Copy `s` into the arena and return a view that outlives the buffer it was built
/// in. Text beyond the arena is dropped rather than overwriting a neighbour — and
/// the arena is sized for every field of every flow, so that does not happen.
#[allow(static_mut_refs)]
pub(crate) fn intern(s: &str) -> &'static str {
    unsafe {
        let start = TEXT_USED;
        let end = core::cmp::min(start + s.len(), TEXT.len());
        TEXT[start..end].copy_from_slice(&s.as_bytes()[..end - start]);
        TEXT_USED = end;
        core::str::from_utf8(&TEXT[start..end]).unwrap_or("")
    }
}

/// An address as EIP-55 checksummed hex, full length, never truncated.
fn push_address<const M: usize>(buf: &mut fmt::Buf<M>, address: &[u8; 20]) {
    let mut lower = fmt::Buf::<40>::new();
    lower.push_hex(address);
    let checksum = eip712::keccak(&[lower.as_str().as_bytes()]);
    buf.push_address(address, &checksum);
}

fn push_hash<const M: usize>(buf: &mut fmt::Buf<M>, bytes: &[u8; 32]) {
    buf.push_str("0x");
    buf.push_hex(bytes);
}

/// Show the Administrator's address on the device, so a ceremony can compare the
/// address on the screen with the one the host claims (`GET_ADMIN_ADDRESS` with the
/// display flag set).
fn review_address(address: &[u8; 20]) {
    text_reset();
    let mut buf = fmt::Buf::<44>::new();
    push_address(&mut buf, address);
    let fields = [Field { name: "Administrator", value: intern(buf.as_str()) }];
    MultiFieldReview::new(
        &fields,
        &["Verify", "Administrator"],
        Some(&EYE),
        "Done",
        Some(&CHECKMARK),
        "Done",
        Some(&CHECKMARK),
    )
    .show();
}

/// What a review does instead of showing a page it cannot draw honestly: say so on the
/// device, and take the decision away.
///
/// The status word is `0x6A80`, not the `0x6985` of a human pressing Reject. That
/// distinction is the whole point of having this function: nobody refused anything
/// here — the firmware could not render a field — and a device whose one promise is
/// that its screen does not lie must not report a decision the holder never made.
/// `0x6A80` already covers it on the host side ("a field the device refuses to sign,
/// or cannot show honestly", `demo/ledger_device.py`).
///
/// It draws a screen rather than answering silently because `ledger-ui.md`, "Errors",
/// makes the clear-signing refusal one of the three cases the Administrator has to be
/// told about on the device: there is no blind-signing setting to go and enable, so the
/// screen is the whole explanation.
fn refuse_to_display() -> Result<(), Reply> {
    SingleMessage::new("Cannot display - rejected").show_and_wait();
    Err(Reply(SW_BAD_FIELDS))
}

/// The pre-approval review: every signed field on its own page, in the order the
/// Ethereum app uses, ending on Approve/Reject. `Ok(())` if the human approved; the
/// status word to answer with if not.
///
/// Nothing on these pages comes from anywhere but the signed struct — a Safe nonce
/// or a host label would promise a binding the Guard does not enforce.
fn review_pre_approval(f: &eip712::Fields, leaf: u32) -> Result<(), Reply> {
    // One buffer, written and interned once per field, so the stack holds 128 bytes
    // of text at a time instead of every field of the flow at once.
    text_reset();
    let mut buf = fmt::Buf::<128>::new();

    buf.push_str("#");
    buf.push_u32_grouped(leaf);
    buf.push_str(" of ");
    buf.push_u32_grouped(total_leaves());
    let leaf_text = intern(buf.as_str());

    buf.clear().push_amount(f.amount(), 0).push_str(" raw units");
    let amount = intern(buf.as_str());
    buf.clear().push_amount(f.value(), 0).push_str(" wei");
    let value = intern(buf.as_str());

    push_address(buf.clear(), f.token());
    let token = intern(buf.as_str());
    push_address(buf.clear(), f.recipient());
    let recipient = intern(buf.as_str());
    push_address(buf.clear(), f.target());
    let target = intern(buf.as_str());
    push_address(buf.clear(), f.safe());
    let safe = intern(buf.as_str());
    push_address(buf.clear(), f.verifying_contract());
    let guard = intern(buf.as_str());

    buf.clear().push_utc(f.valid_from());
    let valid_from = intern(buf.as_str());
    buf.clear().push_utc(f.valid_to());
    let valid_to = intern(buf.as_str());

    buf.clear().push_amount(f.chain_id(), 0);
    let network = intern(buf.as_str());

    push_hash(buf.clear(), f.policy_hash());
    let policy = intern(buf.as_str());
    push_hash(buf.clear(), f.data_hash());
    let data_hash = intern(buf.as_str());

    // The binding, read from the signed txHash: pinned to one Safe transaction, or
    // field-matched against any transaction that fits.
    buf.clear();
    if f.tx_hash() == &[0u8; 32] {
        buf.push_str("NOT PINNED - any matching transfer");
    } else {
        push_hash(&mut buf, f.tx_hash());
    }
    let pinned = intern(buf.as_str());

    // Every field of this review went through one `Buf`, and `overflowed` is sticky
    // across `clear`, so this one question covers all of them: did any page end up
    // saying less than the payload it is about to ask the holder to sign? If so there
    // is nothing to ask — `ledger-ui.md`, "Errors": the clear-signing refusal has
    // `Reject` as its only action, and there is no blind-signing setting to go and
    // enable. Unreachable with the buffers as sized here, which is the point: it is
    // the check that keeps it unreachable when a field is added or a buffer shrinks.
    if buf.overflowed() {
        return refuse_to_display();
    }
    // The tail every class shows; only the three value pages differ.
    //
    // `Guard` is the EIP-712 `verifyingContract`, and it sits next to `Network`
    // because the two are one fact: the binding this key slot takes on at its first
    // approval is `chainId ‖ verifyingContract` together (`wallet.rs::commit_binding`),
    // and with `MAX_KEYS = 1` and no retire command that binding is for the life of
    // the key. It was the one signed field the review never drew, which made the
    // permanent consequence of an approval the only thing the holder could not see.
    let tail = [
        Field { name: "Valid from", value: valid_from },
        Field { name: "Valid to", value: valid_to },
        Field { name: "Safe", value: safe },
        Field { name: "Guard", value: guard },
        Field { name: "Network", value: network },
        Field { name: "Policy", value: policy },
        Field { name: "Binding", value: pinned },
    ];
    let transfer = [
        Field { name: "Leaf", value: leaf_text },
        Field { name: "Token", value: token },
        Field { name: "Amount", value: amount },
        Field { name: "Recipient", value: recipient },
    ];
    let payload = [
        Field { name: "Leaf", value: leaf_text },
        Field { name: "Target", value: target },
        Field { name: "Value", value: value },
        Field { name: "Data hash", value: data_hash },
    ];
    // As many pages as the flow has: the four head fields, then the seven of the tail.
    let mut fields: [Field; 11] = [
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
        Field { name: "", value: "" },
    ];
    let head = if f.approval_class() == 0 { &transfer } else { &payload };
    for (slot, field) in fields.iter_mut().zip(head.iter().chain(tail.iter())) {
        *slot = Field { name: field.name, value: field.value };
    }

    let heading = match f.approval_class() {
        0 => "Sign approval",
        1 => "Sign payload",
        _ => "ADMIN ACTION",
    };
    let approved = MultiFieldReview::new(
        &fields,
        &[heading, leaf_text],
        Some(&APP_ICON),
        "Approve",
        Some(&CHECKMARK),
        "Reject",
        Some(&CROSSMARK),
    )
    .show();
    if approved {
        Ok(())
    } else {
        Err(StatusWords::UserCancelled.into())
    }
}

// ── Command handlers ─────────────────────────────────────────────────────────

#[allow(static_mut_refs)]
fn handle(comm: &mut Comm, ins: Ins) -> Result<(), Reply> {
    // "All commands are rejected while another signing session is in flight"
    // (ledger-xmss-app.md): a half-streamed payload is such a session.
    if unsafe { STREAMING } {
        if !matches!(ins, Ins::SignPreApproval { .. }) {
            return Err(Reply(SW_BUSY));
        }
    }

    match ins {
        Ins::GetAppConfig => {
            // flags ‖ version ‖ MAX_KEYS ‖ free slots ‖ treeHeight ‖ parameterSet
            comm.append(&[
                0x00,
                VERSION[0],
                VERSION[1],
                VERSION[2],
                MAX_KEYS,
                0,
                xmss::HEIGHT as u8,
            ]);
            comm.append(&parameter_set());
            Ok(())
        }
        Ins::GetAdminAddress { display } => {
            let address = admin_address();
            if display {
                review_address(&address);
            }
            comm.append(&address);
            Ok(())
        }
        Ins::GetLeafIndex => {
            comm.append(&session::next_leaf().to_be_bytes());
            Ok(())
        }
        Ins::GetXmssRoot => {
            SingleMessage::new("Reading key...").show();
            let key = xmss_key();
            let root = xmss::public_root(&key);
            comm.append(&root);
            comm.append(&key.seed);
            comm.append(&[xmss::HEIGHT as u8]);
            comm.append(&parameter_set());
            Ok(())
        }
        Ins::SignPreApproval { chunk } => sign_pre_approval(comm, chunk),
        Ins::GetSignatureChunk { first } => session::read_chunk(comm, first),
    }
}

/// Every signed field the review does not draw for this approval class must be zero.
///
/// A `PreApproval` carries both the transfer triple (`token`, `recipient`, `amount`)
/// and the payload triple (`target`, `value`, `dataHash`), and the class decides which
/// of the two the Guard reads: `PreApprovalEngine::_commitment` and `_fieldsMatch`
/// hash `(safe, class, token, recipient, amount)` for `TRANSFER` and
/// `(safe, class, target, value, dataHash)` for `PAYLOAD`/`ADMIN`, and never look at
/// the other three. The review follows the same split, drawing one triple and not the
/// other.
///
/// So three fields of every pre-approval are signed, never shown, and never read
/// on-chain. That is a small hole rather than a large one — the Guard would ignore
/// whatever they said — but it is a hole of exactly the shape this app exists to close:
/// a value covered by the digest that the holder was never asked about. Requiring them
/// to be zero closes it without a page nobody can act on: an undrawn field can then
/// carry nothing.
///
/// Every host in this repository already sends zeros there (`demo/app_api.py`,
/// `demo/server.py`, `demo/ledger_device.py`'s own test vectors), and
/// `demo/ledger_sim.py` refuses a class other than `TRANSFER` outright.
fn unused_fields_are_zero(f: &eip712::Fields) -> bool {
    if f.approval_class() == 0 {
        f.target() == &[0u8; 20] && f.value() == &[0u8; 32] && f.data_hash() == &[0u8; 32]
    } else {
        f.token() == &[0u8; 20] && f.recipient() == &[0u8; 20] && f.amount() == &[0u8; 32]
    }
}

/// Parse the streamed payload, refuse anything malformed *before* a single screen,
/// check what this key slot is already committed to, and show every signed field.
/// Returns the digest to sign and the binding to commit, or the reason not to.
///
/// The payload's length says which product it belongs to: a `PreApproval` for a Safe
/// running FermionGuard, or a FermionWallet `Transfer`. Both lengths are fixed and
/// unequal, so no new APDU command is needed and the pre-approval wire format is
/// untouched [FWL-033].
#[allow(static_mut_refs)]
fn review_and_digest(leaf: u32) -> Result<([u8; 32], u8, [u8; 32], [u8; 20]), Reply> {
    let payload = unsafe { &PAYLOAD };
    match unsafe { PAYLOAD_LEN } {
        eip712::PAYLOAD_LEN => {
            let fields = eip712::Fields::new(payload);
            if fields.approval_class() > 2
                || fields.valid_from() > fields.valid_to()
                || !fmt::utc_renderable(fields.valid_to())
                || !unused_fields_are_zero(&fields)
            {
                // "Payload rejected — field out of range", "Clock window invalid":
                // there is no "review anyway" path.
                //
                // A `validTo` the formatter cannot draw as a date is refused here,
                // before any screen, rather than shown as `NOT A DATE - REJECT`: the
                // field is unreviewable either way and refusing costs no one a
                // decision. `validFrom` needs no clause of its own — it is already
                // required not to exceed `validTo`, so a renderable `validTo` makes
                // it renderable too.
                return Err(Reply(SW_BAD_FIELDS));
            }
            let contract = *fields.verifying_contract();
            wallet::check_binding(wallet::KIND_GUARD, fields.chain_id(), &contract)?;
            let digest = eip712::digest(&fields, leaf);
            review_pre_approval(&fields, leaf)?;
            Ok((digest, wallet::KIND_GUARD, *fields.chain_id(), contract))
        }
        wallet::PAYLOAD_LEN => {
            let head: &[u8; wallet::PAYLOAD_LEN] =
                payload[..wallet::PAYLOAD_LEN].try_into().unwrap();
            let fields = wallet::Fields::new(head);
            // A wallet with no address, or a window that has already closed, is a
            // signature that could never be used: refuse it unseen rather than ask.
            // So is a `validUntil` the formatter cannot draw as a date — and for a
            // Transfer the window is the only control there is [FWL-036], so a field
            // the holder cannot read is a control that is off while looking on.
            if fields.wallet() == &[0u8; 20]
                || fields.valid_until() == 0
                || !fmt::utc_renderable(fields.valid_until())
            {
                return Err(Reply(SW_BAD_FIELDS));
            }
            let contract = *fields.wallet();
            wallet::check_binding(wallet::KIND_WALLET, fields.chain_id(), &contract)?;
            let digest = wallet::digest(&fields, leaf);
            wallet::review(&fields, leaf, total_leaves(), &APP_ICON)?;
            Ok((digest, wallet::KIND_WALLET, *fields.chain_id(), contract))
        }
        _ => Err(StatusWords::BadLen.into()),
    }
}

/// Accumulate the streamed fields; on the last chunk, run the whole ceremony:
/// parse, refuse anything malformed before a single screen, show every field, and
/// only then commit the counter and release both halves.
#[allow(static_mut_refs)]
fn sign_pre_approval(comm: &mut Comm, chunk: u8) -> Result<(), Reply> {
    // Copied out of the APDU buffer, because the reply is written into the same
    // buffer. Static, not a local: this frame is the deepest one in the app (it goes
    // on to run the whole review), and the Nano's stack has no 255 bytes to spare.
    let len = {
        let received = comm.get_data()?;
        if received.len() > unsafe { CHUNK_BUF.len() } {
            return Err(StatusWords::BadLen.into());
        }
        unsafe { CHUNK_BUF[..received.len()].copy_from_slice(received) };
        received.len()
    };
    let data = unsafe { &CHUNK_BUF[..len] };

    // A chunk with no data is refused before any state is touched, and in particular
    // before a session is opened.
    //
    // This is the sharp edge an old host finds first. Before the renumbering, `0x04`
    // was `GET_LEAF_INDEX`: no data, `P1 = 0x00`, and it now lands here as
    // `SIGN_PREAPPROVAL` with `P1_FIRST` and `Lc = 0`. That used to answer `0x9000`
    // with zero bytes — which a host reads as "leaf 0" — and leave a streaming session
    // open, after which every read-only command came back `0x6986` and nothing said
    // why. Failing here instead makes the first call the one that reports the problem.
    //
    // It is also why the refusal has to sit *above* the reset below: `P1_FIRST` throws
    // away a buffered signature, so an empty first chunk would otherwise destroy a
    // readout the host had not finished.
    if data.is_empty() {
        return Err(StatusWords::BadLen.into());
    }

    unsafe {
        // `P1_LAST` with no session open is a payload that arrived whole: the wallet's
        // 132-byte `Transfer` fits in one APDU, and a host that sends it as a single
        // chunk is doing nothing wrong. `P1_MORE` with no session is still a bug.
        if chunk == P1_FIRST || (chunk == P1_LAST && !STREAMING) {
            PAYLOAD_LEN = 0;
            // "The buffer is zeroized ... and on the next signing command"
            // (ledger-xmss-app.md).
            session::discard();
        } else if !STREAMING {
            // A continuation with nothing to continue.
            return Err(StatusWords::CmdNotAccepted.into());
        }
        if PAYLOAD_LEN + data.len() > eip712::PAYLOAD_LEN {
            STREAMING = false;
            return Err(StatusWords::BadLen.into());
        }
        PAYLOAD[PAYLOAD_LEN..PAYLOAD_LEN + data.len()].copy_from_slice(data);
        PAYLOAD_LEN += data.len();
        STREAMING = chunk != P1_LAST;
    }
    if chunk != P1_LAST {
        return Ok(());
    }

    // ── The last chunk: everything below happens before any screen ──
    let leaf = session::next_leaf();
    if leaf >= total_leaves() {
        return Err(Reply(SW_EXHAUSTED));
    }
    let (digest, kind, chain_id, contract) = review_and_digest(leaf)?;

    // Counter and binding first, durably, then the signatures — never the other way
    // round. `session::commit` is the only source of the `Committed` token and
    // `session::publish` demands one by value, so this is the order the build enforces
    // and not the order this line happens to be written in.
    let committed = session::commit(leaf, kind, &chain_id, &contract);
    SingleMessage::new("Signing...").show();

    let ecdsa = sign_ecdsa(&digest).ok_or::<Reply>(StatusWords::Unknown.into())?;
    let key = xmss_key();
    session::publish(committed, |leaf, blob: &mut [u8; session::BLOB_LEN]| {
        // XMSS first, ECDSA last: the host cannot hold the classical half without
        // having already taken delivery of the whole quantum one. `leaf` comes out of
        // the commit token, so the leaf signed here is the leaf the counter consumed.
        xmss::sign(&key, leaf, &digest, &mut blob[..xmss::SIG_LEN]);
        blob[xmss::SIG_LEN..].copy_from_slice(&ecdsa);
    });

    comm.append(&leaf.to_be_bytes());
    comm.append(&digest);
    comm.append(&(session::BLOB_LEN as u16).to_be_bytes());
    Ok(())
}

// ── Home screen ──────────────────────────────────────────────────────────────

const VERSION: [u8; 3] = [
    parse_u8(env!("CARGO_PKG_VERSION_MAJOR")),
    parse_u8(env!("CARGO_PKG_VERSION_MINOR")),
    parse_u8(env!("CARGO_PKG_VERSION_PATCH")),
];

const fn parse_u8(s: &str) -> u8 {
    let b = s.as_bytes();
    let (mut i, mut v) = (0, 0u8);
    while i < b.len() {
        v = v * 10 + (b[i] - b'0');
        i += 1;
    }
    v
}

/// What this key slot is married to, in full: the contract, the chain, and which
/// product they belong to.
///
/// Its own review rather than a home page, because a home page cannot hold it. The
/// SDK's `Page` draws at most three lines of `MAX_CHAR_PER_LINE` — 51 characters — and
/// drops the rest without a mark: `Safe guard ‹42-character address› on chain 31337`
/// is 64 characters, so the chain id fell off the end of every binding this app has
/// ever displayed, and a 78-digit chain id would have taken the address with it.
/// `MultiFieldReview` paginates its values instead, so the address is drawn EIP-55 and
/// whole, and the chain id is drawn whole however many digits it has — which is what
/// `ledger-xmss-app.md` asks for ("no abbreviation of security-critical values") and
/// what `ledger-ui.md` puts on `Settings → Keys`.
fn review_binding() {
    text_reset();
    let mut buf = fmt::Buf::<128>::new();

    push_address(&mut buf, &wallet::bound_contract());
    let contract = intern(buf.as_str());
    buf.clear().push_amount(&wallet::bound_chain(), 0);
    let chain = intern(buf.as_str());

    let name = if wallet::bound_kind() == wallet::KIND_GUARD { "Safe guard" } else { "Wallet" };
    let fields =
        [Field { name, value: contract }, Field { name: "Network", value: chain }];
    MultiFieldReview::new(
        &fields,
        &["Key is for", name],
        Some(&EYE),
        "Done",
        Some(&CHECKMARK),
        "Done",
        Some(&CHECKMARK),
    )
    .show();
}

/// The Ethereum app's home idiom: "<app> is ready", the version, and Quit, plus a
/// FermionGuard page for the odometer — the leaf count the Administrator is meant
/// to recognize (`ledger-xmss-app.md`: "the leaf index is always visible").
fn home(comm: &mut Comm) -> Ins {
    let mut leaves = fmt::Buf::<24>::new();
    leaves.push_u32_grouped(session::next_leaf());
    leaves.push_str(" of ");
    leaves.push_u32_grouped(total_leaves());

    // Which product this key is committed to, if any: invisible state that decides
    // whether a signature will be refused belongs where the holder can find it
    // [FWL-023]. Only the short answer goes on the page — press both buttons for the
    // contract and the chain, which need a widget that paginates. Everything a `Page`
    // shows here is a fixed string or the leaf count, so nothing on the home screen
    // can be cut off mid-value again.
    let bound = match wallet::bound_kind() {
        wallet::KIND_GUARD => "a Safe guard",
        wallet::KIND_WALLET => "a FermionWallet",
        _ => "not used yet",
    };

    let pages = [
        &Page::new(PageStyle::PictureNormal, ["FermionGuard", "is ready"], Some(&APP_ICON)),
        &Page::new(PageStyle::BoldNormal, ["Leaves used", leaves.as_str()], None),
        &Page::new(PageStyle::BoldNormal, ["Key is for", bound], None),
        &Page::new(PageStyle::BoldNormal, ["Version", env!("CARGO_PKG_VERSION")], None),
        &Page::new(PageStyle::BoldNormal, ["Quit", ""], None),
    ];
    let binding = 2;
    let quit = pages.len() - 1;

    loop {
        match MultiPageMenu::new(comm, &pages).show() {
            EventOrPageIndex::Event(Event::Command(ins)) => return ins,
            EventOrPageIndex::Event(_) => (),
            EventOrPageIndex::Index(i) if i == quit => ledger_device_sdk::exit_app(0),
            EventOrPageIndex::Index(i) if i == binding && wallet::bound_kind() != wallet::KIND_UNBOUND => {
                review_binding()
            }
            EventOrPageIndex::Index(_) => (),
        }
    }
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = Comm::new().set_expected_cla(CLA);
    loop {
        // The home screen is also the event loop: it returns when a host command
        // arrives, and the SDK has already refused a wrong CLA or unknown INS.
        let ins = home(&mut comm);
        match handle(&mut comm, ins) {
            Ok(()) => comm.reply_ok(),
            Err(sw) => comm.reply(sw),
        }
    }
}
