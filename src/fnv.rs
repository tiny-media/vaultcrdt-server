/// FNV-1a 64-bit over UTF-16 code units (JS `charCodeAt` / `str.encode_utf16()`).
///
/// Output is 16-char lowercase hex, zero-padded. The plugin hashes JS string
/// units, not UTF-8 bytes — non-ASCII diverges if this hashes bytes instead.
pub fn fnv1a_64_hex(s: &str) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for unit in s.encode_utf16() {
        hash ^= u64::from(unit);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::fnv1a_64_hex;

    #[test]
    fn golden_ascii() {
        assert_eq!(fnv1a_64_hex("vaultcrdt fnv golden"), "a6a9b25f2a464e61");
    }

    #[test]
    fn golden_non_ascii() {
        // 17 chars including spaces; plugin `charCodeAt` vector.
        let s = "äöü€ deleter täst";
        assert_eq!(s.chars().count(), 17);
        assert_eq!(fnv1a_64_hex(s), "708d67b2a1da6d2f");
    }

    #[test]
    fn golden_empty() {
        assert_eq!(fnv1a_64_hex(""), "cbf29ce484222325");
    }
}
