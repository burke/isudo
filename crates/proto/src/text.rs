//! Rendering untrusted bytes so that nothing is hidden from the reader.
//!
//! Used wherever text chosen by someone else is shown: a denial reason on the
//! caller's terminal, a command on the test phone. The iOS app applies the
//! same rules to the approval card.

/// True for characters that change how surrounding text is displayed without
/// being visible themselves: bidirectional controls, zero-width characters,
/// and other invisible format characters.
#[must_use]
pub const fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'                  // soft hyphen
        | '\u{034F}'                // combining grapheme joiner
        | '\u{061C}'                // Arabic letter mark
        | '\u{115F}' | '\u{1160}'   // Hangul fillers
        | '\u{17B4}' | '\u{17B5}'   // Khmer inherent vowels
        | '\u{180B}'..='\u{180F}'   // Mongolian variation selectors
        | '\u{200B}'..='\u{200F}'   // zero-width space and joiners, LRM, RLM
        | '\u{2028}' | '\u{2029}'   // line and paragraph separators
        | '\u{202A}'..='\u{202E}'   // bidi embeddings and overrides
        | '\u{2060}'..='\u{206F}'   // word joiner, invisible operators, bidi isolates
        | '\u{3164}'                // Hangul filler
        | '\u{FE00}'..='\u{FE0F}'   // variation selectors
        | '\u{FEFF}'                // byte-order mark
        | '\u{FFA0}'                // halfwidth Hangul filler
        | '\u{FFF9}'..='\u{FFFB}'   // interlinear annotation
        | '\u{1D173}'..='\u{1D17A}' // musical format controls
        | '\u{E0000}'..='\u{E0FFF}' // tags and variation selectors supplement
    )
}

fn push_hex(out: &mut String, value: u32) {
    let digits = (0..8_u32).rev().map(|i| value >> i.saturating_mul(4) & 0xf);
    for digit in digits.skip_while(|d| *d == 0) {
        out.push(char::from_digit(digit, 16).unwrap_or('?'));
    }
    if value == 0 {
        out.push('0');
    }
}

/// Escapes control characters, invisible characters, and bytes that are not
/// valid UTF-8, leaving everything else as it was. The result is always safe
/// to print to a terminal on one line.
#[must_use]
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() || is_invisible(c) => {
                    out.push_str("\\u{");
                    push_hex(&mut out, u32::from(c));
                    out.push('}');
                }
                c => out.push(c),
            }
        }
        for byte in chunk.invalid() {
            out.push_str("\\x");
            if *byte < 0x10 {
                out.push('0');
            }
            push_hex(&mut out, u32::from(*byte));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_untouched() {
        assert_eq!(escape("rm -rf /tmp/build é 日本".as_bytes()), "rm -rf /tmp/build é 日本");
    }

    #[test]
    fn controls_and_escapes() {
        assert_eq!(escape(b"a\x1b[2Kb\nc\\"), "a\\u{1b}[2Kb\\nc\\\\");
        assert_eq!(escape(b"\0"), "\\u{0}");
    }

    #[test]
    fn bidi_override_is_visible() {
        // "Trojan Source" style reordering.
        assert_eq!(escape("ls \u{202e}gnp.exe".as_bytes()), "ls \\u{202e}gnp.exe");
        assert_eq!(escape("a\u{200b}b".as_bytes()), "a\\u{200b}b");
        assert_eq!(escape("x\u{e0041}".as_bytes()), "x\\u{e0041}");
    }

    #[test]
    fn invalid_utf8_is_shown_as_bytes() {
        assert_eq!(escape(b"ok\xff\xfeok"), "ok\\xff\\xfeok");
        assert_eq!(escape(b"\x80"), "\\x80");
        assert_eq!(escape(b"a\xc0\x0a"), "a\\xc0\\n");
    }
}
