//! Text encoding for startup secret entropy.

use zeroize::Zeroize;

pub fn lowercase_hex_secret(mut entropy: [u8; 32]) -> [u8; 64] {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 64];
    for (index, byte) in entropy.iter().copied().enumerate() {
        encoded[index * 2] = LOWER_HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = LOWER_HEX[usize::from(byte & 0x0f)];
    }
    entropy.zeroize();
    encoded
}

#[cfg(test)]
mod tests {
    use super::lowercase_hex_secret;

    #[test]
    fn lowercase_hex_secret_encodes_high_nibble_first() {
        let mut entropy = [0_u8; 32];
        entropy[1] = 0xff;
        entropy[31] = 0x80;
        let mut expected = [b'0'; 64];
        expected[2..4].copy_from_slice(b"ff");
        expected[62..].copy_from_slice(b"80");
        assert_eq!(lowercase_hex_secret(entropy), expected);
    }

    #[test]
    fn lowercase_hex_secret_has_no_nul_or_uppercase() {
        for entropy in [[0_u8; 32], [0xff_u8; 32]] {
            let encoded = lowercase_hex_secret(entropy);
            assert!(!encoded.contains(&0));
            assert!(encoded
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
        }
    }
}
