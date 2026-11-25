//! Hex and unpadded base64url, written out here so the setuid binary needs
//! no extra dependencies to read its pairing file.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for DecodeError {}

/// The lowercase hex digit for a value below 16.
fn hex_digit(nibble: u8) -> char {
    char::from(match nibble {
        0..=9 => b'0'.wrapping_add(nibble),
        _ => b'a'.wrapping_add(nibble.wrapping_sub(10)),
    })
}

#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

const fn hex_value(digit: u8) -> Result<u8, DecodeError> {
    match digit {
        b'0'..=b'9' => Ok(digit.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(digit.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(digit.wrapping_sub(b'A').wrapping_add(10)),
        _ => Err(DecodeError("invalid hex digit")),
    }
}

/// # Errors
/// Fails on an odd number of digits or a character that is not a hex digit.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(DecodeError("hex string has odd length"));
    }
    pairs.iter().map(|&[high, low]| Ok(hex_value(high)? << 4 | hex_value(low)?)).collect()
}

/// # Errors
/// Fails if the text is not hex or does not decode to exactly `N` bytes.
pub fn hex_decode_array<const N: usize>(text: &str) -> Result<[u8; N], DecodeError> {
    hex_decode(text)?.try_into().map_err(|_e| DecodeError("hex value has the wrong length"))
}

/// The base64url character for a value below 64.
fn b64_char(sextet: u8) -> char {
    char::from(match sextet {
        0..=25 => b'A'.wrapping_add(sextet),
        26..=51 => b'a'.wrapping_add(sextet.wrapping_sub(26)),
        52..=61 => b'0'.wrapping_add(sextet.wrapping_sub(52)),
        62 => b'-',
        _ => b'_',
    })
}

const fn b64_value(c: u8) -> Result<u8, DecodeError> {
    match c {
        b'A'..=b'Z' => Ok(c.wrapping_sub(b'A')),
        b'a'..=b'z' => Ok(c.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0').wrapping_add(52)),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(DecodeError("invalid base64url character")),
    }
}

/// Unpadded base64url (RFC 4648 section 5).
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        // Sextets of the 24-bit group, with missing input bytes as zero.
        let (b0, b1, b2, sextets) = match *chunk {
            [b0] => (b0, 0, 0, 2),
            [b0, b1] => (b0, b1, 0, 3),
            [b0, b1, b2] => (b0, b1, b2, 4),
            _ => continue,
        };
        let group = [b0 >> 2, (b0 & 0x03) << 4 | b1 >> 4, (b1 & 0x0f) << 2 | b2 >> 6, b2 & 0x3f];
        out.extend(group.into_iter().take(sextets).map(b64_char));
    }
    out
}

/// Strict unpadded base64url: rejects padding, other alphabets, and
/// non-canonical trailing bits.
///
/// # Errors
/// Fails on any input that [`b64_encode`] could not have produced.
pub fn b64_decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    const NON_CANONICAL: DecodeError = DecodeError("non-canonical base64url");
    let mut out = Vec::with_capacity(text.len().saturating_mul(3).div_ceil(4));
    for chunk in text.as_bytes().chunks(4) {
        match *chunk {
            [c0, c1, c2, c3] => {
                let (v0, v1, v2, v3) = (b64_value(c0)?, b64_value(c1)?, b64_value(c2)?, b64_value(c3)?);
                out.extend([v0 << 2 | v1 >> 4, (v1 & 0x0f) << 4 | v2 >> 2, (v2 & 0x03) << 6 | v3]);
            }
            [c0, c1, c2] => {
                let (v0, v1, v2) = (b64_value(c0)?, b64_value(c1)?, b64_value(c2)?);
                if v2 & 0x03 != 0 {
                    return Err(NON_CANONICAL);
                }
                out.extend([v0 << 2 | v1 >> 4, (v1 & 0x0f) << 4 | v2 >> 2]);
            }
            [c0, c1] => {
                let (v0, v1) = (b64_value(c0)?, b64_value(c1)?);
                if v1 & 0x0f != 0 {
                    return Err(NON_CANONICAL);
                }
                out.push(v0 << 2 | v1 >> 4);
            }
            _ => return Err(DecodeError("invalid base64url length")),
        }
    }
    Ok(out)
}

/// # Errors
/// Fails if the text is not base64url or does not decode to exactly `N` bytes.
pub fn b64_decode_array<const N: usize>(text: &str) -> Result<[u8; N], DecodeError> {
    b64_decode(text)?.try_into().map_err(|_e| DecodeError("base64url value has the wrong length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&data)).unwrap(), data);
        assert_eq!(hex_encode(&[0x00, 0x9a, 0xff]), "009aff");
        assert_eq!(hex_decode("009AfF").unwrap(), [0x00, 0x9a, 0xff]);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode_array::<2>("abcdef").is_err());
    }

    #[test]
    fn b64_known_vectors() {
        // RFC 4648 section 10, without padding.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_encode(plain.as_bytes()), encoded);
            assert_eq!(b64_decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(b64_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64_decode("-_8").unwrap(), [0xfb, 0xff]);
    }

    #[test]
    fn b64_is_strict() {
        assert!(b64_decode("Zg==").is_err(), "padding");
        assert!(b64_decode("Zh").is_err(), "non-canonical trailing bits");
        assert!(b64_decode("Zm9").is_err(), "non-canonical trailing bits");
        assert!(b64_decode("Z").is_err(), "impossible length");
        assert!(b64_decode("+/8").is_err(), "standard alphabet");
    }

    #[test]
    fn b64_round_trip_all_lengths() {
        let data: Vec<u8> = (0..200_u8).map(|i| i.wrapping_mul(37)).collect();
        for len in 0..data.len() {
            assert_eq!(b64_decode(&b64_encode(&data[..len])).unwrap(), &data[..len]);
        }
    }
}
