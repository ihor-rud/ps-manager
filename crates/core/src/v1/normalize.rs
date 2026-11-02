//! Input normalization (spec section 4).

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The `WS` set of spec section 4.1: Unicode `White_Space` as of 16.0, frozen.
///
/// Deliberately not `char::is_whitespace`, which follows whatever Unicode
/// version the Rust toolchain ships.
#[must_use]
pub const fn is_ws(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// `NormalizeText` (spec section 4.2), used for identity and account.
pub fn text(input: &str) -> String {
    let nfkc: String = input.nfkc().collect();
    // `char::to_lowercase` is the full, context-free, locale-independent mapping.
    let lowered: String = nfkc.chars().flat_map(char::to_lowercase).collect();
    let mut out = String::with_capacity(lowered.len());
    let mut pending_space = false;
    for c in lowered.nfkc() {
        if is_ws(c) {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    out
}

/// `NormalizeSite` (spec section 4.3).
pub fn site(input: &str) -> String {
    let full = text(input);
    let mut s = full.as_str();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s = &s[..i];
    }
    if let Some(i) = s.rfind('@') {
        s = &s[i + 1..];
    }
    if let Some(i) = s.rfind(':')
        && s[i + 1..].bytes().all(|b| b.is_ascii_digit())
    {
        s = &s[..i];
    }
    s = s.trim_matches(is_ws);
    s = s.trim_end_matches('.');
    if let Some(rest) = s.strip_prefix("www.")
        && !rest.is_empty()
    {
        s = rest;
    }
    s.to_owned()
}

/// `NormalizeSecret` (spec section 4.4): NFC only.
#[must_use]
pub fn secret(input: &str) -> Zeroizing<String> {
    // NFC output is at most 3x the input; reserving up front keeps the secret
    // from being copied into buffers that are freed without being wiped.
    let mut out = Zeroizing::new(String::with_capacity(input.len() * 3));
    out.extend(input.nfc());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_folds_case_width_and_space() {
        assert_eq!(text("  Jane \u{00A0}\t DOE \n"), "jane doe");
        // Fullwidth "ABC", the "fi" ligature, modifier capital A, Kelvin sign.
        assert_eq!(text("\u{FF21}\u{FF22}\u{FF23}"), "abc");
        assert_eq!(text("\u{FB01}le"), "file");
        assert_eq!(text("\u{1D2C}"), "a");
        assert_eq!(text("\u{212A}"), "k");
        // Lowercasing is not case folding: sharp s stays.
        assert_eq!(text("\u{00DF}"), "\u{00DF}");
    }

    #[test]
    fn text_lowercase_is_context_free() {
        // Capital sigma at the end of a word does not become final sigma.
        assert_eq!(text("X\u{03A3}"), "x\u{03C3}");
        // Capital I with dot above lowercases to "i" plus a combining dot.
        assert_eq!(text("\u{0130}"), "i\u{0307}");
    }

    #[test]
    fn site_strips_url_parts() {
        for input in [
            "github.com",
            "GitHub.com",
            "https://github.com",
            "https://www.github.com/login?next=/x#top",
            "user:pass@www.GITHUB.com:8443",
            "github.com.",
            "  www.github.com  ",
            // Fullwidth "github.com".
            "\u{FF47}\u{FF49}\u{FF54}\u{FF48}\u{FF55}\u{FF42}\u{FF0E}\u{FF43}\u{FF4F}\u{FF4D}",
        ] {
            assert_eq!(site(input), "github.com", "{input:?}");
        }
    }

    #[test]
    fn site_keeps_meaningful_parts() {
        assert_eq!(site("accounts.example.com"), "accounts.example.com");
        assert_eq!(site("www."), "www");
        assert_eq!(site("localhost:3000"), "localhost");
        assert_eq!(site("[::1]:8080"), "[::1]");
        assert_eq!(site("\u{00C4}\u{00D6}.example"), "\u{00E4}\u{00F6}.example");
        assert_eq!(site("My Bank"), "my bank");
        assert_eq!(site("https://"), "");
    }

    #[test]
    fn normalization_is_idempotent() {
        for input in [
            "\u{0130}X",
            "X\u{03A3}",
            "\u{FF21}\u{FF22} \u{FF43}",
            "\u{01C5}X",
            "\u{216B}",
            "x\u{0301}y",
        ] {
            let once = text(input);
            assert_eq!(text(&once), once, "{input:?}");
        }
    }

    #[test]
    fn secret_only_composes() {
        assert_eq!(secret("e\u{0301}").as_str(), "\u{00E9}");
        assert_eq!(
            secret(" Mixed Case \u{FB01} ").as_str(),
            " Mixed Case \u{FB01} "
        );
    }
}
