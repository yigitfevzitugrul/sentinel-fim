//! Lowercase hexadecimal encoding used in baselines, reports and key files.

use std::fmt::Write as _;

/// Error for malformed hex input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid hex string: {0}")]
pub struct HexError(&'static str);

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decodes lowercase hex. Uppercase is rejected so every value has exactly
/// one textual form.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    if !text.len().is_multiple_of(2) {
        return Err(HexError("odd length"));
    }
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| Ok((nibble(hi)? << 4) | nibble(lo)?))
        .collect()
}

/// Decodes exactly `N` bytes.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    decode(text)?
        .try_into()
        .map_err(|_| HexError("wrong length"))
}

/// UTF-16 code units as big-endian hex (4 digits per unit).
pub fn encode_u16(units: &[u16]) -> String {
    let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_be_bytes()).collect();
    encode(&bytes)
}

pub fn decode_u16(text: &str) -> Result<Vec<u16>, HexError> {
    let bytes = decode(text)?;
    if !bytes.len().is_multiple_of(2) {
        return Err(HexError("incomplete UTF-16 code unit"));
    }
    let (pairs, _) = bytes.as_chunks::<2>();
    Ok(pairs.iter().map(|&pair| u16::from_be_bytes(pair)).collect())
}

fn nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(HexError("expected lowercase 0-9a-f")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
        assert!(decode("AB").is_err());
        assert!(decode_array::<2>("aabbcc").is_err());
    }

    #[test]
    fn u16_round_trip() {
        let units = [0x0062, 0xD800, 0xFFFF];
        assert_eq!(encode_u16(&units), "0062d800ffff");
        assert_eq!(decode_u16("0062d800ffff").unwrap(), units);
        assert!(decode_u16("00").is_err());
    }
}
