//! Small cryptographic primitives shared by the auth and CSRF layers.
//!
//! These are the irreducible byte-level operations underneath the password,
//! session-token, and CSRF-token types.  They are expressed as **traits** so
//! the behavior hangs off the value being operated on (a byte sequence, a
//! string) rather than living as free-standing functions.

// ── ToHex ─────────────────────────────────────────────────────────────────────

/// Lowercase-hex encoding for any byte sequence.
pub(crate) trait ToHex {
    /// Encode `self` as a lowercase hex string.
    fn to_hex(&self) -> String;
}

impl<T: AsRef<[u8]>> ToHex for T {
    fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bytes = self.as_ref();
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}

// ── ConstantTimeEq ──────────────────────────────────────────────────────────────

/// Constant-time equality, for comparing secrets (token hashes, CSRF tokens)
/// without leaking how many leading characters matched via a timing oracle.
pub(crate) trait ConstantTimeEq {
    /// Compare `self` to `other` in time independent of the contents.
    ///
    /// Differing lengths short-circuit, which is acceptable for the
    /// fixed-width hex digests this is used on.
    fn ct_eq(&self, other: &Self) -> bool;
}

impl ConstantTimeEq for str {
    fn ct_eq(&self, other: &Self) -> bool {
        let (a, b) = (self.as_bytes(), other.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_round_trips_known_value() {
        assert_eq!([0x00, 0xff, 0x10].to_hex(), "00ff10");
        assert_eq!(Vec::<u8>::new().to_hex(), "");
    }

    #[test]
    fn ct_eq_matches_str_eq() {
        assert!("abcdef".ct_eq("abcdef"));
        assert!(!"abcdef".ct_eq("abcdeg"));
        assert!(!"abc".ct_eq("abcd"));
    }
}
