//! The EIP-712 digest of a pre-approval, recomputed on the device.
//!
//! The host streams the *fields*; the device hashes them itself and signs only what
//! it hashed. A host that displays one transfer and asks for another gets a
//! signature over the fields on the screen, which the Guard then refuses — which is
//! the whole point of the device (`ledger-xmss-app.md`: "Display only signed
//! fields", "no raw-hash signing path").
//!
//! The type strings below are the ones `PreApprovalEngine` and its EIP-712 domain
//! use verbatim; they are hashed at run time so the pre-images stay readable here
//! rather than becoming opaque 32-byte constants nobody can check.

use ledger_device_sdk::hash::sha3::Keccak256;
use ledger_device_sdk::hash::HashInit;

/// The payload the host streams, exactly (`demo/ledger_device.py::encode_payload`).
pub const PAYLOAD_LEN: usize = 373;

pub const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const DOMAIN_NAME: &[u8] = b"FermionGuard";
pub const DOMAIN_VERSION: &[u8] = b"1";
const PRE_APPROVAL_TYPE: &[u8] = b"PreApproval(address safe,uint8 approvalClass,address token,\
address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,\
uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,\
bytes32 txHash)";

const PAD12: [u8; 12] = [0u8; 12];
const PAD24: [u8; 24] = [0u8; 24];
const PAD28: [u8; 28] = [0u8; 28];
const PAD31: [u8; 31] = [0u8; 31];

/// Byte ranges of the streamed payload. One place, so a screen and the digest can
/// never read different bytes for the same field.
pub struct Fields<'a>(&'a [u8; PAYLOAD_LEN]);

impl<'a> Fields<'a> {
    pub fn new(payload: &'a [u8; PAYLOAD_LEN]) -> Self {
        Fields(payload)
    }

    pub fn chain_id(&self) -> &'a [u8; 32] {
        self.word(0)
    }
    pub fn verifying_contract(&self) -> &'a [u8; 20] {
        self.address(32)
    }
    pub fn safe(&self) -> &'a [u8; 20] {
        self.address(52)
    }
    pub fn approval_class(&self) -> u8 {
        self.0[72]
    }
    pub fn token(&self) -> &'a [u8; 20] {
        self.address(73)
    }
    pub fn recipient(&self) -> &'a [u8; 20] {
        self.address(93)
    }
    pub fn amount(&self) -> &'a [u8; 32] {
        self.word(113)
    }
    pub fn target(&self) -> &'a [u8; 20] {
        self.address(145)
    }
    pub fn value(&self) -> &'a [u8; 32] {
        self.word(165)
    }
    pub fn data_hash(&self) -> &'a [u8; 32] {
        self.word(197)
    }
    pub fn valid_from(&self) -> u64 {
        u64::from_be_bytes(self.0[229..237].try_into().unwrap())
    }
    pub fn valid_to(&self) -> u64 {
        u64::from_be_bytes(self.0[237..245].try_into().unwrap())
    }
    pub fn nonce(&self) -> &'a [u8; 32] {
        self.word(245)
    }
    pub fn quantum_key_id(&self) -> &'a [u8; 32] {
        self.word(277)
    }
    pub fn policy_hash(&self) -> &'a [u8; 32] {
        self.word(309)
    }
    pub fn tx_hash(&self) -> &'a [u8; 32] {
        self.word(341)
    }

    fn word(&self, at: usize) -> &'a [u8; 32] {
        self.0[at..at + 32].try_into().unwrap()
    }
    fn address(&self, at: usize) -> &'a [u8; 20] {
        self.0[at..at + 20].try_into().unwrap()
    }
}

pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = Keccak256::new();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; 32];
    ctx.finalize(&mut out).unwrap();
    out
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)` — the digest both halves of
/// the hybrid signature cover. The leaf index is part of the signed struct, and it is
/// the device's own counter value rather than anything the host sent — which is why it
/// arrives as a [`session::Leaf`](crate::session::Leaf) and not a `u32`: nothing
/// outside `session` can build one, so `digest(&fields, 0)` does not compile and the
/// `xmssLeafIndex` this digest covers cannot drift away from the leaf
/// `session::commit` consumed.
pub fn digest(f: &Fields, leaf: crate::session::Leaf) -> [u8; 32] {
    let leaf = leaf.index();
    let domain = keccak(&[
        &keccak(&[DOMAIN_TYPE]),
        &keccak(&[DOMAIN_NAME]),
        &keccak(&[DOMAIN_VERSION]),
        f.chain_id(),
        &PAD12,
        f.verifying_contract(),
    ]);
    let struct_hash = keccak(&[
        &keccak(&[PRE_APPROVAL_TYPE]),
        &PAD12,
        f.safe(),
        &PAD31,
        &[f.approval_class()],
        &PAD12,
        f.token(),
        &PAD12,
        f.recipient(),
        f.amount(),
        &PAD12,
        f.target(),
        f.value(),
        f.data_hash(),
        &PAD24,
        &f.valid_from().to_be_bytes(),
        &PAD24,
        &f.valid_to().to_be_bytes(),
        f.nonce(),
        f.quantum_key_id(),
        &PAD28,
        &leaf.to_be_bytes(),
        f.policy_hash(),
        f.tx_hash(),
    ]);
    keccak(&[&[0x19, 0x01], &domain, &struct_hash])
}
