//! FermionWallet support: the `Transfer` payload, its digest, its review screens, and
//! the one-key-one-contract binding that the standalone wallet depends on.
//!
//! FermionWallet ([`fermionwallet.md`](../../fermionwallet.md)) is the other product
//! this key can sign for: a single contract holding ERC-20 tokens that releases them
//! only against a hybrid signature, with no Safe, no owners and no registry. The
//! device work it needs is [FWL-033]:
//!
//! 1. the `Transfer` type and the `FermionWallet` domain accepted by the parser —
//!    here, told apart from a `PreApproval` by the streamed payload's length, so no
//!    new APDU command and no change to the pre-approval wire format;
//! 2. a review whose context page is the **wallet**, not a Safe: the struct has no
//!    Safe address, no `txHash` pin and no `policyHash`, and showing a field that is
//!    not in the signed struct is exactly what `ledger-xmss-app.md` forbids;
//! 3. per-slot binding to one verifying contract, recorded at first signature and
//!    enforced on every later one [FWL-023];
//! 4. refusal when a slot bound to a wallet is asked for a Safe pre-approval, or the
//!    other way round — a key belongs to one product.
//!
//! Points 3 and 4 are not tidiness. The standalone wallet has no registry, so its
//! used-leaf bitmap can only see the leaves *it* spent: bind one key to two
//! contracts and one one-time leaf can sign two different digests, which is the
//! condition that makes WOTS+ forgeable. On the Safe side the registry keys leaf
//! accounting by the XMSS root and catches that on-chain; for a wallet this device
//! is the only thing standing in the way, which `fermionwallet.md` records as a
//! residual risk [FWL-025].

use ledger_device_sdk::io::Reply;
use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};
use ledger_device_sdk::ui::bitmaps::{CHECKMARK, CROSSMARK};
use ledger_device_sdk::ui::gadgets::{Field, MultiFieldReview};
use ledger_device_sdk::NVMData;

use crate::eip712::{keccak, DOMAIN_TYPE, DOMAIN_VERSION};
use crate::fmt;

/// `chainId(32) ‖ wallet(20) ‖ token(20) ‖ to(20) ‖ amount(32) ‖ validUntil(8)`.
///
/// The wallet address is both the EIP-712 `verifyingContract` and the struct's
/// `wallet` field, so it is streamed once. Nothing else is: `leafIndex` is the
/// device's own counter, never host-supplied.
pub const PAYLOAD_LEN: usize = 132;

/// Distinct from `eip712::PAYLOAD_LEN`, which is how the two are told apart.
const _: () = assert!(PAYLOAD_LEN != crate::eip712::PAYLOAD_LEN);

const DOMAIN_NAME: &[u8] = b"FermionWallet";
const TRANSFER_TYPE: &[u8] = b"Transfer(address wallet,address token,address to,\
uint256 amount,uint32 leafIndex,uint64 validUntil)";

const PAD12: [u8; 12] = [0u8; 12];
const PAD24: [u8; 24] = [0u8; 24];
const PAD28: [u8; 28] = [0u8; 28];

/// Which product a payload belongs to. Stored in NVM beside the bound address, so a
/// refusal can say *which* product the key already belongs to instead of just "no".
pub const KIND_UNBOUND: u8 = 0;
pub const KIND_GUARD: u8 = 1;
pub const KIND_WALLET: u8 = 2;

/// "This key is bound to a different contract" — a host bug or an attack, not a
/// malformed field, so it gets its own status word
/// (`demo/ledger_device.py::_sw_message` prints it).
pub const SW_WRONG_BINDING: u16 = 0x6A81;

// ── The binding: one key slot, one verifying contract ────────────────────────

/// `kind ‖ verifyingContract(20)`. Atomic storage for the same reason the leaf
/// counter uses it: a power loss during the write leaves the old value or the new
/// one, never half of each.
#[link_section = ".nvm_data"]
static mut BINDING: NVMData<AtomicStorage<[u8; 21]>> = NVMData::new(AtomicStorage::new(&[0u8; 21]));

#[allow(static_mut_refs)]
fn binding() -> [u8; 21] {
    unsafe { *BINDING.get_mut().get_ref() }
}

/// What this slot is already committed to, if anything.
pub fn bound_kind() -> u8 {
    binding()[0]
}

pub fn bound_contract() -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&binding()[1..]);
    out
}

/// May this slot sign for `(kind, contract)`? Called before a single screen is drawn:
/// a refusal the human never sees is a refusal they cannot be talked past.
pub fn check_binding(kind: u8, contract: &[u8; 20]) -> Result<(), Reply> {
    match bound_kind() {
        KIND_UNBOUND => Ok(()),
        k if k == kind && bound_contract() == *contract => Ok(()),
        _ => Err(Reply(SW_WRONG_BINDING)),
    }
}

/// Record the binding durably. Called with the leaf commit, *before* the signatures
/// are released, for the same reason: a signature that escaped before the state it
/// depends on was written is a signature the state cannot account for.
#[allow(static_mut_refs)]
pub fn commit_binding(kind: u8, contract: &[u8; 20]) {
    if bound_kind() != KIND_UNBOUND {
        return;
    }
    let mut value = [0u8; 21];
    value[0] = kind;
    value[1..].copy_from_slice(contract);
    unsafe { BINDING.get_mut().update(&value) }
}

// ── The streamed fields ─────────────────────────────────────────────────────

/// Byte ranges of a `Transfer` payload, in one place so a screen and the digest can
/// never read different bytes for the same field.
pub struct Fields<'a>(&'a [u8; PAYLOAD_LEN]);

impl<'a> Fields<'a> {
    pub fn new(payload: &'a [u8; PAYLOAD_LEN]) -> Self {
        Fields(payload)
    }

    pub fn chain_id(&self) -> &'a [u8; 32] {
        self.0[0..32].try_into().unwrap()
    }
    /// The `verifyingContract` of the domain and the `wallet` field of the struct.
    pub fn wallet(&self) -> &'a [u8; 20] {
        self.0[32..52].try_into().unwrap()
    }
    pub fn token(&self) -> &'a [u8; 20] {
        self.0[52..72].try_into().unwrap()
    }
    pub fn to(&self) -> &'a [u8; 20] {
        self.0[72..92].try_into().unwrap()
    }
    pub fn amount(&self) -> &'a [u8; 32] {
        self.0[92..124].try_into().unwrap()
    }
    pub fn valid_until(&self) -> u64 {
        u64::from_be_bytes(self.0[124..132].try_into().unwrap())
    }
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`, the digest both halves of the
/// hybrid signature cover — computed here, from the fields the device rendered.
///
/// The domain is `{ name: "FermionWallet", version: "1", chainId, verifyingContract:
/// the wallet }`, so a signature for one wallet is meaningless to any other wallet or
/// chain [FWL-013]. `leaf` is the device's counter; the contract reads the same index
/// out of the XMSS signature and rebuilds this digest with it, so a mislabelled leaf
/// fails the ECDSA half [FWL-034].
pub fn digest(f: &Fields, leaf: u32) -> [u8; 32] {
    let domain = keccak(&[
        &keccak(&[DOMAIN_TYPE]),
        &keccak(&[DOMAIN_NAME]),
        &keccak(&[DOMAIN_VERSION]),
        f.chain_id(),
        &PAD12,
        f.wallet(),
    ]);
    let struct_hash = keccak(&[
        &keccak(&[TRANSFER_TYPE]),
        &PAD12,
        f.wallet(),
        &PAD12,
        f.token(),
        &PAD12,
        f.to(),
        f.amount(),
        &PAD28,
        &leaf.to_be_bytes(),
        &PAD24,
        &f.valid_until().to_be_bytes(),
    ]);
    keccak(&[&[0x19, 0x01], &domain, &struct_hash])
}

// ── The review ───────────────────────────────────────────────────────────────

/// Every signed field on its own page, ending on Approve/Reject — the pre-approval
/// flow's screens for token, amount, recipient and validity, with the Safe/pin/policy
/// pages replaced by the one thing that takes their place: the wallet being spent
/// from. Returns whether the human approved.
pub fn review(f: &Fields, leaf: u32, total_leaves: u32, icon: &ledger_device_sdk::ui::bitmaps::Glyph) -> bool {
    let mut leaf_text = fmt::Buf::<28>::new();
    leaf_text.push_str("#");
    leaf_text.push_u32_grouped(leaf);
    leaf_text.push_str(" of ");
    leaf_text.push_u32_grouped(total_leaves);

    let mut amount = fmt::Buf::<128>::new();
    amount.push_amount(f.amount(), 0);
    amount.push_str(" raw units");

    let mut token = fmt::Buf::<44>::new();
    crate::push_address(&mut token, f.token());
    let mut to = fmt::Buf::<44>::new();
    crate::push_address(&mut to, f.to());
    let mut wallet = fmt::Buf::<44>::new();
    crate::push_address(&mut wallet, f.wallet());

    let mut valid_until = fmt::Buf::<32>::new();
    valid_until.push_utc(f.valid_until());

    let mut network = fmt::Buf::<112>::new();
    network.push_amount(f.chain_id(), 0);

    let fields = [
        Field { name: "Leaf", value: leaf_text.as_str() },
        Field { name: "Token", value: token.as_str() },
        Field { name: "Amount", value: amount.as_str() },
        Field { name: "Recipient", value: to.as_str() },
        Field { name: "Valid until", value: valid_until.as_str() },
        Field { name: "Wallet", value: wallet.as_str() },
        Field { name: "Network", value: network.as_str() },
    ];
    MultiFieldReview::new(
        &fields,
        // Short enough not to scroll on a Nano's 16-character line, and it cannot be
        // mistaken for the Safe flow's "Sign approval".
        &["Send tokens", leaf_text.as_str()],
        Some(icon),
        "Approve",
        Some(&CHECKMARK),
        "Reject",
        Some(&CROSSMARK),
    )
    .show()
}
