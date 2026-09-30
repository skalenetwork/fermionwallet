//! The one-time-leaf counter and the buffer a signature is paged out of.
//!
//! This module exists for a single invariant, the one `ledger-xmss-app.md` calls
//! catastrophic to invert: **the leaf counter commits to NVM before a signature is
//! released**. A signature that escapes before the counter lands is a one-time leaf
//! that can sign two different digests, and two WOTS+ signatures under one leaf are
//! what make the scheme forgeable.
//!
//! Nothing host-side can check that ordering — Speculos keeps NVM in RAM, so a test
//! that power-cuts between the two steps has nothing to observe, and moving the commit
//! after the release leaves `test_app.py` and `test_wallet.py` entirely green. So the
//! ordering is enforced here instead, by the type system:
//!
//! * [`Committed`] has no public field and no public constructor. The only function
//!   that returns one is [`commit`], which does the NVM write and returns after it has
//!   landed.
//! * [`publish`] takes a `Committed` **by value**, and is the only code anywhere that
//!   sets the flag `GET_SIGNATURE_CHUNK` reads. `BLOB`, `BLOB_READY` and `BLOB_CURSOR`
//!   are private to this module, so there is no second way in.
//!
//! A build that released the signature first would have no token to hand `publish`
//! and would not compile. That is the mechanism; `README.md` records it, and the
//! falsification is to swap the two statements and watch `cargo ledger build` fail.
//!
//! # And which leaf it is
//!
//! The ordering is only half of the invariant. The other half is that the leaf the
//! counter consumed is the leaf the WOTS+ signature is computed under: *commit N,
//! sign N*. Getting that wrong is the same catastrophe by another route — a counter
//! that marches while the signing index stands still hands out two signatures under
//! one one-time leaf, which is exactly what makes the scheme forgeable.
//!
//! This used to be a comment claiming the leaf "travels inside the token", and it did
//! not hold: `publish` handed the closure a `u32` the closure was free to ignore, and
//! `xmss::sign(&key, 0, …)` compiled clean and produced precisely that forgeable pair
//! on a real emulator. The leaf now travels as a *type*, and there are three of them
//! because the leaf has three consumers:
//!
//! * [`Leaf`] — the value. Private field, so only this module builds one; [`reserve`]
//!   is the only factory. `eip712::digest`, `wallet::digest` and the two reviews take
//!   a `Leaf`, so `digest(&fields, 0)` does not compile: the digest's `xmssLeafIndex`
//!   and the number on the review's `Leaf` page cannot come from anywhere else.
//! * [`Reserved`] — the leaf this signing session intends to spend, read once from the
//!   counter. Consumed by value by [`commit`], which is what stops a second commit
//!   being written against the same reservation.
//! * [`Signing`] — the leaf `xmss::sign` must use. Built **only** inside [`publish`],
//!   out of the `Committed` token, and neither `Copy` nor `Clone`, so it cannot be
//!   conjured, duplicated or replaced. `xmss::sign` takes it by value, so
//!   `xmss::sign(&key, 0, …)`, `xmss::sign(&key, some_other_leaf, …)` and
//!   `xmss::sign(&key, session::reserve(16).unwrap().leaf(), …)` are all type errors.
//!
//! What remains is one thing a type cannot say — that the reservation still matches
//! the counter — and [`commit`] checks it at run time and refuses. `README.md` lists
//! the probes for all of this.

use ledger_device_sdk::io::{Comm, Reply, StatusWords};
use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};
use ledger_device_sdk::NVMData;

use crate::xmss;

/// `r(32) ‖ wotsSig(67×32) ‖ auth(h×32) ‖ ecdsa(65)` — the blob
/// `GET_SIGNATURE_CHUNK` hands back. No public key: the root and SEED are already
/// on-chain from registration, and `contracts/script/Demo.s.sol::_decodeXmss` parses
/// exactly this once the host has taken the ECDSA half off the end.
///
/// The ECDSA half is **last** so that a host which reads only the first chunk holds
/// neither half whole: the classical signature cannot leave the device until the
/// quantum one has been paged out in full.
pub const BLOB_LEN: usize = xmss::SIG_LEN + 65;

/// Data bytes per `GET_SIGNATURE_CHUNK` reply.
const CHUNK: usize = 255;

/// The one-time-leaf counter, the app's odometer. Atomic storage: a power loss during
/// the commit leaves either the old or the new value, never a torn one.
#[link_section = ".nvm_data"]
static mut LEAF_COUNTER: NVMData<AtomicStorage<u32>> = NVMData::new(AtomicStorage::new(&0u32));

/// The signature the last approval produced, and how far it has been paged out.
/// Private: `publish` is the only writer of `BLOB_READY`, which is what makes the
/// counter-before-signature ordering a property of the build rather than of a comment.
static mut BLOB: [u8; BLOB_LEN] = [0; BLOB_LEN];
static mut BLOB_READY: bool = false;
static mut BLOB_CURSOR: usize = 0;

/// One one-time leaf of the tree, as a value nothing outside this module can build.
///
/// The field is private and [`reserve`] is the only factory, so every consumer of "the
/// leaf this approval spends" — the digest, the review's `Leaf` page, the four bytes
/// the host is answered with — is holding a number that came from the counter. A
/// literal will not type-check in any of those places.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Leaf(u32);

impl Leaf {
    /// The index itself, for the one place it has to become a number again: the
    /// big-endian bytes of `xmssLeafIndex` and the digits on the screen.
    pub fn index(self) -> u32 {
        self.0
    }
}

/// The leaf a signing session intends to spend, read once from the counter.
///
/// [`commit`] takes it **by value**, so a second commit needs a second reservation —
/// and a second reservation no longer matches the counter, which `commit` notices.
pub struct Reserved {
    leaf: Leaf,
}

impl Reserved {
    /// The leaf this session will spend, for the digest and the review. `Leaf` is
    /// `Copy` because those two read it before the commit consumes the reservation;
    /// what `xmss::sign` takes is [`Signing`], which is not.
    pub fn leaf(&self) -> Leaf {
        self.leaf
    }
}

/// The leaf the WOTS+ signature **must** be computed under.
///
/// Built only inside [`publish`], from the `Committed` token, and deliberately neither
/// `Copy` nor `Clone` nor publicly constructible: the only `Signing` in existence is
/// the one the fill closure is handed, so `xmss::sign` cannot be reached with any
/// other index. That is what makes "commit N, sign N" a property of the build rather
/// than of the line it is written on — see the module documentation.
pub struct Signing(Leaf);

impl Signing {
    /// Spend the token: the index `xmss::sign` walks its tree at. By value, so it
    /// cannot be read twice.
    pub fn index(self) -> u32 {
        self.0.index()
    }
}

/// Proof that the one-time leaf it names has been committed to NVM.
///
/// Unconstructible outside this module — every field is private and `commit` is the
/// only function that returns one. See the module documentation: this is the whole
/// mechanism behind the counter-before-signature invariant.
pub struct Committed {
    leaf: Leaf,
}

/// The next unused leaf.
#[allow(static_mut_refs)]
pub fn next_leaf() -> u32 {
    unsafe { *LEAF_COUNTER.get_mut().get_ref() }
}

/// Claim the next unused leaf for the approval being reviewed, or `None` when the tree
/// is spent.
///
/// The exhaustion test lives here rather than in the caller so that "which leaf is
/// this" and "is there one left" are one read of one counter.
pub fn reserve(total_leaves: u32) -> Option<Reserved> {
    let leaf = next_leaf();
    if leaf >= total_leaves {
        None
    } else {
        Some(Reserved { leaf: Leaf(leaf) })
    }
}

/// Commit `leaf + 1` and the key slot's contract binding, durably, and hand back the
/// proof [`publish`] demands.
///
/// Returns once the NVM writes have landed. The binding is state a released signature
/// depends on just as the counter is, so it is written here, under the same rule and
/// at the same moment.
///
/// The one check the types cannot make is made here: the reservation must still be the
/// counter's current value. In the pristine flow it always is — `sign_pre_approval`
/// reserves once and commits once, and nothing between the two writes the counter — so
/// this branch is **unreachable as the app is written today**, and it is here for the
/// edit that changes that. It is what a second `commit` against a second reservation
/// runs into, and what stops the counter being written backwards to a leaf that has
/// already been signed under. `Reply` rather than a panic: refusing the command leaves
/// a device that still answers.
#[allow(static_mut_refs)]
pub fn commit(
    reserved: Reserved,
    kind: u8,
    chain_id: &[u8; 32],
    contract: &[u8; 20],
) -> Result<Committed, Reply> {
    let leaf = reserved.leaf;
    if leaf.index() != next_leaf() {
        return Err(StatusWords::Unknown.into());
    }
    unsafe { LEAF_COUNTER.get_mut().update(&(leaf.index() + 1)) };
    crate::wallet::commit_binding(kind, chain_id, contract);
    Ok(Committed { leaf })
}

/// Fill the readout buffer and open it to the host — the moment the signature is
/// released.
///
/// `fill` is handed the [`Signing`] token for the leaf the counter has just consumed,
/// and the whole buffer to write. Taking `Committed` by value is what stops this being
/// called before [`commit`]; minting the `Signing` token here, and nowhere else, is
/// what stops the signature being computed under a different leaf.
#[allow(static_mut_refs)]
pub fn publish(committed: Committed, fill: impl FnOnce(Signing, &mut [u8; BLOB_LEN])) {
    unsafe {
        fill(Signing(committed.leaf), &mut BLOB);
        BLOB_CURSOR = 0;
        BLOB_READY = true;
    }
}

/// Forget the buffered signature and wipe it.
///
/// `ledger-xmss-app.md`, "Signature readout": *"The buffer is zeroized when its last
/// byte has been delivered, and on the next signing command."* A spent signature is
/// not secret in the way a key is — it is on its way to a public chain — but it is the
/// output of a one-time leaf, and leaving 2.8 KB of it in RAM for the next app to find
/// is state this device has no reason to keep.
///
/// Four callers, which between them are every way out of a buffered signature:
///
/// * the last byte of a readout, in [`read_chunk`] below;
/// * the *first line* of `main.rs::sign_pre_approval` — every signing command the
///   dispatcher accepts as one, whether that command goes on to be accepted or
///   refused. It used to be inside the branch that accepts a first chunk, so the three
///   refused shapes (an empty chunk, a continuation with no session, a chunk over the
///   length limit) all left the spent blob re-servable by `P1 = 0x00`;
/// * `main.rs::home`, on the way to `exit_app`;
/// * `main.rs::wiping_panic`, the panic hook, for the same reason.
///
/// What is left is a host that simply stops talking: it holds a half-read spent
/// signature until the app is closed or another signing command arrives. That is
/// recorded in `README.md` rather than closed, because the alternative — wiping the
/// readout on any command that is not a chunk request — would have `GET_LEAF_INDEX`
/// destroy a readout a well-behaved host is in the middle of.
#[allow(static_mut_refs)]
pub fn discard() {
    unsafe {
        BLOB_READY = false;
        BLOB_CURSOR = 0;
        BLOB.fill(0);
    }
}

/// Page out the next `CHUNK` bytes: `first` restarts from byte zero, otherwise the
/// readout continues where it left off.
///
/// Delivering the last byte zeroizes the buffer, so the chunk after a complete readout
/// — and a `P1 = 0x00` restart after one — is answered as "nothing buffered" rather
/// than served again. That refusal is also the only host-visible evidence that the
/// wipe happened: Speculos does not expose the device's RAM.
#[allow(static_mut_refs)]
pub fn read_chunk(comm: &mut Comm, first: bool) -> Result<(), Reply> {
    // Nothing to fetch until an approval has produced a blob, or after one has been
    // paged out in full.
    if !unsafe { BLOB_READY } {
        return Err(StatusWords::CmdNotAccepted.into());
    }
    let start = if first { 0 } else { unsafe { BLOB_CURSOR } };
    if start >= BLOB_LEN {
        // Unreachable while the buffer is wiped at the end of a readout, and kept as
        // the backstop for a cursor that ever ends up past the end some other way.
        return Err(StatusWords::BadP1P2.into());
    }
    let end = core::cmp::min(start + CHUNK, BLOB_LEN);
    comm.append(unsafe { &BLOB[start..end] });
    unsafe { BLOB_CURSOR = end };
    if end == BLOB_LEN {
        discard();
    }
    Ok(())
}
