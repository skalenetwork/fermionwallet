//! Formatting for the device screen: no allocator, no `core::fmt`, every result a
//! `&str` backed by a caller-owned buffer.
//!
//! A screen that silently truncated an address or an amount would be a security
//! bug (`ledger-xmss-app.md`: "no abbreviation of security-critical values"), so
//! every writer here records overflow instead of trimming and callers size their
//! buffers for the longest value the field can hold.

/// A fixed-capacity ASCII buffer. `overflowed` records that something did not fit,
/// so a caller can refuse a payload rather than display half a value.
pub struct Buf<const N: usize> {
    bytes: [u8; N],
    len: usize,
    full: bool,
}

impl<const N: usize> Buf<N> {
    pub fn new() -> Self {
        Buf { bytes: [0u8; N], len: 0, full: false }
    }

    pub fn as_str(&self) -> &str {
        // Only ASCII is ever written, so this is always valid UTF-8.
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }

    pub fn overflowed(&self) -> bool {
        self.full
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
    pub fn push_utc(&mut self, secs: u64) -> &mut Self {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
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

        self.push_u32(day as u32);
        self.push_str(" ");
        self.push_str(MONTHS[(month - 1) as usize]);
        self.push_str(" ");
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
