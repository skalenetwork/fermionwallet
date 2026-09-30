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

mod fmt;

use ledger_device_sdk::ecc::{make_bip32_path, ECPublicKey, ECPrivateKey, SeedDerive, Secp256k1};
use ledger_device_sdk::hash::sha3::Keccak256;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::io::{ApduHeader, Comm, Event, Reply, StatusWords};
use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};
use ledger_device_sdk::ui::bitmaps::Glyph;
use ledger_device_sdk::ui::gadgets::{EventOrPageIndex, MultiPageMenu, Page, PageStyle};
use ledger_device_sdk::{include_gif, NVMData};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

// ── The key this build holds ─────────────────────────────────────────────────

/// The Administrator's classical half. Fixed in the app, never host-supplied:
/// `QuantumKeyRegistry` pins this address as `quantumAdmin`, so the path is part
/// of the app's identity and is declared in `[package.metadata.ledger] path`.
const ADMIN_PATH: [u32; 5] = make_bip32_path(b"m/44'/60'/0'/0/4");

/// Tree height of the XMSS key: 2^4 = 16 one-time signatures. Small on purpose —
/// this is the demo/pilot parameter set, and it is what the on-chain verifier is
/// registered for. The parameter set below is the string the registry records.
const TREE_HEIGHT: u8 = 4;
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
const SW_NOT_IMPLEMENTED: u16 = 0x6D00;

/// P1 of `SIGN_PREAPPROVAL`: the chunk's place in the stream.
const P1_FIRST: u8 = 0x00;
const P1_MORE: u8 = 0x80;
const P1_LAST: u8 = 0x81;

enum Ins {
    /// 0x02 — root ‖ seed ‖ treeHeight ‖ parameterSet of the slot's key.
    GetXmssRoot,
    /// 0x04 — the next unused leaf, 4 bytes big-endian.
    GetLeafIndex,
    /// 0x06 — stream the pre-approval fields; the last chunk waits for the human.
    SignPreApproval { chunk: u8 },
    /// 0x08 — what the ceremony preflight checks the device against.
    GetAppConfig,
    /// 0x0E — the `quantumAdmin` address, 20 bytes.
    GetAdminAddress,
    /// 0x18 — 255-byte slice `index` of the signature blob the last sign produced.
    GetSignatureChunk { index: u8 },
}

impl TryFrom<ApduHeader> for Ins {
    type Error = StatusWords;

    fn try_from(h: ApduHeader) -> Result<Self, Self::Error> {
        // Every command names the key slot in P2; this build has exactly one.
        let slot_ok = h.p2 == SLOT;
        match (h.ins, h.p1, slot_ok) {
            (0x02, 0, true) => Ok(Ins::GetXmssRoot),
            (0x04, 0, true) => Ok(Ins::GetLeafIndex),
            (0x06, p1 @ (P1_FIRST | P1_MORE | P1_LAST), true) => {
                Ok(Ins::SignPreApproval { chunk: p1 })
            }
            (0x08, 0, _) => Ok(Ins::GetAppConfig),
            (0x0E, 0 | 1, true) => Ok(Ins::GetAdminAddress),
            (0x18, index, true) => Ok(Ins::GetSignatureChunk { index }),
            // A known command with impossible parameters is a host bug, not an
            // unknown command: say which of the two it is.
            (0x02 | 0x04 | 0x06 | 0x0E | 0x18, _, _) => Err(StatusWords::BadP1P2),
            _ => Err(StatusWords::BadIns),
        }
    }
}

// ── Device state ─────────────────────────────────────────────────────────────

/// The one-time-leaf counter, the app's odometer. Atomic storage: a power loss
/// during the commit leaves either the old or the new value, never a torn one.
/// `ledger-xmss-app.md`: committed *before* a signature is released.
#[link_section = ".nvm_data"]
static mut LEAF_COUNTER: NVMData<AtomicStorage<u32>> = NVMData::new(AtomicStorage::new(&0u32));

#[allow(static_mut_refs)]
fn next_leaf() -> u32 {
    unsafe { *LEAF_COUNTER.get_mut().get_ref() }
}

/// Commit `leaf + 1` durably. Returns once the NVM write has landed.
#[allow(static_mut_refs)]
fn consume_leaf(leaf: u32) {
    unsafe { LEAF_COUNTER.get_mut().update(&(leaf + 1)) }
}

fn total_leaves() -> u32 {
    1u32 << TREE_HEIGHT
}

// ── The classical half ───────────────────────────────────────────────────────

fn admin_key() -> ECPrivateKey<32, 'W'> {
    Secp256k1::derive_from_path(&ADMIN_PATH)
}

/// keccak256(uncompressed public key without its 0x04 tag)[12..32].
fn admin_address() -> [u8; 20] {
    let pk: ECPublicKey<65, 'W'> = admin_key().public_key().unwrap();
    let mut digest = [0u8; 32];
    let mut k = Keccak256::new();
    k.hash(&pk.pubkey[1..65], &mut digest).unwrap();
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..32]);
    address
}

fn parameter_set() -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak256::new();
    k.hash(PARAMETER_SET_PREIMAGE, &mut out).unwrap();
    out
}

// ── Command handlers ─────────────────────────────────────────────────────────

fn handle(comm: &mut Comm, ins: Ins) -> Result<(), Reply> {
    match ins {
        Ins::GetAppConfig => {
            // flags ‖ version ‖ MAX_KEYS ‖ free slots ‖ treeHeight ‖ parameterSet
            comm.append(&[0x00, VERSION[0], VERSION[1], VERSION[2], MAX_KEYS, 0, TREE_HEIGHT]);
            comm.append(&parameter_set());
            Ok(())
        }
        Ins::GetAdminAddress => {
            comm.append(&admin_address());
            Ok(())
        }
        Ins::GetLeafIndex => {
            comm.append(&next_leaf().to_be_bytes());
            Ok(())
        }
        // Both need the XMSS key material; not in this build yet (README.md).
        Ins::GetXmssRoot | Ins::SignPreApproval { .. } | Ins::GetSignatureChunk { .. } => {
            Err(Reply(SW_NOT_IMPLEMENTED))
        }
    }
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

/// The Ethereum app's home idiom: "<app> is ready", the version, and Quit, with a
/// FermionGuard-specific page for the odometer — the leaf count the Administrator
/// is meant to recognize (`ledger-xmss-app.md`: "the leaf index is always visible").
fn home(comm: &mut Comm) -> Ins {
    const APP_ICON: Glyph = Glyph::from_include(include_gif!("icons/app_fermionguard_14x14.gif"));
    let mut leaves = fmt::Buf::<24>::new();
    leaves.push_u32_grouped(next_leaf());
    leaves.push_str(" of ");
    leaves.push_u32_grouped(total_leaves());

    let pages = [
        &Page::new(PageStyle::PictureNormal, ["FermionGuard", "is ready"], Some(&APP_ICON)),
        &Page::new(PageStyle::BoldNormal, ["Leaves used", leaves.as_str()], None),
        &Page::new(PageStyle::BoldNormal, ["Version", env!("CARGO_PKG_VERSION")], None),
        &Page::new(PageStyle::BoldNormal, ["Quit", ""], None),
    ];
    let quit = pages.len() - 1;

    loop {
        match MultiPageMenu::new(comm, &pages).show() {
            EventOrPageIndex::Event(Event::Command(ins)) => return ins,
            EventOrPageIndex::Event(_) => (),
            EventOrPageIndex::Index(i) if i == quit => ledger_device_sdk::exit_app(0),
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
