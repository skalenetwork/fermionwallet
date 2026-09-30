//! Formatting for the device screen: no allocator, no `core::fmt`, every result a
//! `&str` backed by a caller-owned buffer.
//!
//! A screen that silently truncated an address or an amount would be a security
//! bug (`ledger-xmss-app.md`: "no abbreviation of security-critical values"), so
//! every writer here records overflow instead of trimming and callers size their
//! buffers for the longest value the field can hold.
//!
//! Two rules make that a guarantee rather than an intention:
//!
//! * nothing here ever returns part of a value. A field that did not fit its buffer
//!   reads `TOO_LONG`, and a timestamp past `MAX_UTC_SECS` reads `NOT_A_DATE` — both
//!   digit-free, so neither can be misread as the value it replaced;
//! * `Buf::overflowed` is sticky across `clear`, so a review that writes every field
//!   through one buffer can ask, once, whether any page it is about to show says less
//!   than the payload it is asking the holder to sign — and not show it.

/// What a field reads as when it did not fit its buffer. `as_str` returns this in
/// place of the prefix that *did* fit: a truncated amount or a truncated chain id is
/// a screen that says less than the payload, which is the bug this module exists to
/// prevent. Deliberately digit-free, so no part of it can be read as a value.
pub const TOO_LONG: &str = "FIELD TOO LONG - REJECT";

/// What a timestamp reads as when `push_utc` will not draw it. See `MAX_UTC_SECS`.
/// Digit-free for the same reason: there is no year in it to misread as a date.
pub const NOT_A_DATE: &str = "NOT A DATE - REJECT";

/// The last second `push_utc` will draw: 23:59:59 on 31 Dec 9999 UTC. One second
/// later the year needs five digits, and a five-digit year is not a date any holder
/// of this device is being asked to consent to — it is a `uint64` that no honest
/// signer produced. `push_utc` writes `NOT_A_DATE` for it instead.
pub const MAX_UTC_SECS: u64 = 253_402_300_799;

/// Whether `push_utc` will draw this timestamp as a date. A caller that has a way to
/// refuse — a status word, a rejected payload — should ask this *before* the review
/// and refuse, rather than put `NOT_A_DATE` in front of the holder: the field is
/// unreviewable either way, and refusing costs no one a decision.
pub fn utc_renderable(secs: u64) -> bool {
    secs <= MAX_UTC_SECS
}

/// A fixed-capacity ASCII buffer. `overflowed` records that something written into it
/// could not be shown honestly, so a caller can refuse a payload rather than display
/// half a value.
pub struct Buf<const N: usize> {
    bytes: [u8; N],
    len: usize,
    /// The value currently in the buffer did not fit. `clear` resets it.
    full: bool,
    /// Some value written since `new` could not be shown honestly — it did not fit,
    /// or `push_utc` refused to draw it. `clear` does *not* reset this: one `Buf` is
    /// written once per field for a whole review, so this is the flag that answers
    /// "was any page of that review a lie?" after the last field is built.
    tainted: bool,
}

impl<const N: usize> Buf<N> {
    pub fn new() -> Self {
        Buf { bytes: [0u8; N], len: 0, full: false, tainted: false }
    }

    /// The value, or `TOO_LONG` if it did not fit. Never a prefix of a value: a
    /// caller that forgets to check `overflowed` still cannot put half an address or
    /// a truncated number on the screen.
    pub fn as_str(&self) -> &str {
        if self.full {
            return TOO_LONG;
        }
        // Only ASCII is ever written, so this is always valid UTF-8.
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }

    /// Sticky across `clear`: true once any value written into this buffer overflowed
    /// it or was a timestamp `push_utc` would not draw. A review that builds its
    /// fields in one `Buf` can therefore check this once, after the last field, and
    /// not proceed — every such field is a page that shows less than the payload it
    /// asks the holder to sign.
    pub fn overflowed(&self) -> bool {
        self.tainted
    }

    /// Reuse the buffer for the next value. One `Buf` written many times keeps the
    /// Nano's small stack from holding a dozen field strings at once.
    pub fn clear(&mut self) -> &mut Self {
        self.len = 0;
        self.full = false;
        self
    }

    fn push(&mut self, b: u8) {
        if self.len < N {
            self.bytes[self.len] = b;
            self.len += 1;
        } else {
            self.full = true;
            self.tainted = true;
        }
    }

    pub fn push_str(&mut self, s: &str) -> &mut Self {
        for &b in s.as_bytes() {
            self.push(b);
        }
        self
    }

    /// Plain decimal.
    pub fn push_u32(&mut self, v: u32) -> &mut Self {
        self.decimal(v, false)
    }

    /// Decimal with thousands separators — `1,048,576` reads at a glance, which is
    /// the point of showing a leaf budget.
    pub fn push_u32_grouped(&mut self, v: u32) -> &mut Self {
        self.decimal(v, true)
    }

    fn decimal(&mut self, mut v: u32, grouped: bool) -> &mut Self {
        let mut digits = [0u8; 10];
        let mut n = 0;
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
            if v == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            self.push(digits[i]);
            if grouped && i > 0 && i % 3 == 0 {
                self.push(b',');
            }
        }
        self
    }

    /// Lowercase hex, no `0x` prefix.
    pub fn push_hex(&mut self, bytes: &[u8]) -> &mut Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in bytes {
            self.push(HEX[(b >> 4) as usize]);
            self.push(HEX[(b & 0x0f) as usize]);
        }
        self
    }

    /// An address, `0x`-prefixed, EIP-55 checksummed and never truncated. `keccak`
    /// is keccak256 of the 40-character lowercase hex form, supplied by the caller
    /// so this module needs no crypto dependency.
    pub fn push_address(&mut self, address: &[u8; 20], keccak: &[u8; 32]) -> &mut Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.push_str("0x");
        for (i, &b) in address.iter().enumerate() {
            for (j, nibble) in [b >> 4, b & 0x0f].into_iter().enumerate() {
                let c = HEX[nibble as usize];
                let pos = 2 * i + j;
                let shift = if pos % 2 == 0 { 4 } else { 0 };
                let upper = ((keccak[pos / 2] >> shift) & 0x0f) >= 8;
                self.push(if upper { c.to_ascii_uppercase() } else { c });
            }
        }
        self
    }

    /// A 256-bit big-endian amount as a decimal with `decimals` fractional digits,
    /// trailing zeros dropped: `500,000.5`, never `5e23`.
    pub fn push_amount(&mut self, amount: &[u8; 32], decimals: u8) -> &mut Self {
        // Repeated long division of the big-endian word by 10 collects the decimal
        // digits least-significant first. 78 digits covers 2^256 - 1.
        let mut work = *amount;
        let mut digits = [0u8; 80];
        let mut n = 0;
        loop {
            let mut rem = 0u16;
            let mut zero = true;
            for byte in work.iter_mut() {
                let cur = (rem << 8) | *byte as u16;
                *byte = (cur / 10) as u8;
                rem = cur % 10;
                if *byte != 0 {
                    zero = false;
                }
            }
            digits[n] = b'0' + rem as u8;
            n += 1;
            if zero {
                break;
            }
        }
        let d = decimals as usize;
        // At least one integer digit: "0.5", not ".5".
        while n <= d {
            digits[n] = b'0';
            n += 1;
        }
        for i in (0..n - d).rev() {
            self.push(digits[d + i]);
            if i > 0 && i % 3 == 0 {
                self.push(b',');
            }
        }
        // Fractional digits run from digits[d-1] down to digits[0]; drop the zeros
        // at the tail, which are digits[0], digits[1], …
        let mut lowest = d;
        for i in 0..d {
            if digits[i] != b'0' {
                lowest = i;
                break;
            }
        }
        if lowest < d {
            self.push(b'.');
            for i in (lowest..d).rev() {
                self.push(digits[i]);
            }
        }
        self
    }

    /// A Unix second as `21 Sep 2025 15:40 UTC`: the absolute time the payload
    /// signed, not a duration — durations hide clock-skew games.
    ///
    /// A timestamp past `MAX_UTC_SECS` is not drawn at all: it reads `NOT_A_DATE` and
    /// taints the buffer. This ended with `push_u32(year as u32)` on a `uint64`
    /// timestamp, so the year wrapped at 2^32 and every plausible date had an
    /// enormous twin that rendered character for character the same —
    /// `validUntil = 1790769600` and `validUntil = 135536078592187200` both drew
    /// `30 Sep 2026 12:00 UTC`, while the digest covered the value that was sent.
    /// `fermionwallet.md` [FWL-036] makes a signed transfer relayable by anyone until
    /// `validUntil`, with no cancel path, and says short windows are the only control
    /// there is. A holder who reads a date that has passed signs a replacement and
    /// the relayer spends both: the amount leaves the wallet twice. So the year is
    /// carried as `i64` and bounded to four digits *before* anything is drawn, and a
    /// year outside that is not drawn at all — the holder is not asked to consent to
    /// a field the screen is lying about.
    pub fn push_utc(&mut self, secs: u64) -> &mut Self {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        if !utc_renderable(secs) {
            self.tainted = true;
            return self.push_str(NOT_A_DATE);
        }
        let tod = (secs % 86_400) as u32;
        // Civil date from days since the epoch (Howard Hinnant's civil_from_days).
        let z = (secs / 86_400) as i64 + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = if month <= 2 { y + 1 } else { y };

        // The `secs` guard above already bounds the year at 9999. This bounds the
        // *year itself*, before a single character is drawn, so that no arithmetic
        // slip anywhere above this line can put a wrapped or five-digit year on the
        // screen: the check and the thing it protects are one line apart.
        if year < 1970 || year > 9999 {
            self.tainted = true;
            return self.push_str(NOT_A_DATE);
        }

        self.push_u32(day as u32);
        self.push_str(" ");
        self.push_str(MONTHS[(month - 1) as usize]);
        self.push_str(" ");
        // Lossless: `year` is in 1970..=9999 by the check above. It is the cast that
        // used to be here without one that turned an unbounded window into a date.
        self.push_u32(year as u32);
        self.push_str(" ");
        self.push_two(tod / 3600);
        self.push_str(":");
        self.push_two((tod % 3600) / 60);
        self.push_str(" UTC")
    }

    fn push_two(&mut self, v: u32) {
        self.push(b'0' + ((v / 10) % 10) as u8);
        self.push(b'0' + (v % 10) as u8);
    }
}
