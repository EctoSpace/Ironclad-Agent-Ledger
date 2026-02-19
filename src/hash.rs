use sha2::{Digest, Sha256};

pub const GENESIS_PREVIOUS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[inline]
pub fn sha256_hex(input: &[u8]) -> String {
    let hash = Sha256::digest(input);
    hex::encode(hash)
}

pub fn content_hash_input(previous_hash: &str, sequence: i64, payload_json: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(previous_hash.len() + 32 + payload_json.len());
    out.extend_from_slice(previous_hash.as_bytes());
    out.extend_from_slice(sequence.to_string().as_bytes());
    out.extend_from_slice(payload_json.as_bytes());
    out
}

pub fn compute_content_hash(previous_hash: &str, sequence: i64, payload_json: &str) -> String {
    let input = content_hash_input(previous_hash, sequence, payload_json);
    sha256_hex(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_is_64_hex_chars() {
        let h = compute_content_hash(GENESIS_PREVIOUS_HASH, 0, r#"{"type":"genesis","message":"test"}"#);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn same_input_same_hash() {
        let a = compute_content_hash(GENESIS_PREVIOUS_HASH, 1, "{}");
        let b = compute_content_hash(GENESIS_PREVIOUS_HASH, 1, "{}");
        assert_eq!(a, b);
    }
}
