//! Capability-free text checks shared by stanza and payload validation.

/// Validate the RFC 5646/BCP 47 well-formed syntax used by `xml:lang`.
/// Registry membership is intentionally not required: private-use and future
/// registered subtags remain valid, while malformed/duplicate extensions and
/// variants are rejected.
pub fn valid_language_tag(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 || !value.is_ascii() {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    const GRANDFATHERED: &[&str] = &[
        "art-lojban",
        "cel-gaulish",
        "en-gb-oed",
        "i-ami",
        "i-bnn",
        "i-default",
        "i-enochian",
        "i-hak",
        "i-klingon",
        "i-lux",
        "i-mingo",
        "i-navajo",
        "i-pwn",
        "i-tao",
        "i-tay",
        "i-tsu",
        "no-bok",
        "no-nyn",
        "sgn-be-fr",
        "sgn-be-nl",
        "sgn-ch-de",
        "zh-guoyu",
        "zh-hakka",
        "zh-min",
        "zh-min-nan",
        "zh-xiang",
    ];
    if GRANDFATHERED.contains(&lower.as_str()) {
        return true;
    }
    let parts = lower.split('-').collect::<Vec<_>>();
    if parts.iter().any(|part| {
        part.is_empty() || part.len() > 8 || !part.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }) {
        return false;
    }
    if parts[0] == "x" {
        return parts.len() > 1;
    }
    let primary = parts[0];
    if !primary.bytes().all(|byte| byte.is_ascii_alphabetic()) || !matches!(primary.len(), 2..=8) {
        return false;
    }
    let mut index = 1;
    if primary.len() <= 3 {
        let mut extlangs = 0;
        while index < parts.len()
            && parts[index].len() == 3
            && parts[index].bytes().all(|byte| byte.is_ascii_alphabetic())
            && extlangs < 3
        {
            extlangs += 1;
            index += 1;
        }
    }
    if index < parts.len()
        && parts[index].len() == 4
        && parts[index].bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        index += 1;
    }
    if index < parts.len()
        && ((parts[index].len() == 2
            && parts[index].bytes().all(|byte| byte.is_ascii_alphabetic()))
            || (parts[index].len() == 3 && parts[index].bytes().all(|byte| byte.is_ascii_digit())))
    {
        index += 1;
    }
    let mut variants = std::collections::HashSet::new();
    while index < parts.len()
        && ((parts[index].len() >= 5)
            || (parts[index].len() == 4
                && parts[index]
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_digit)))
    {
        if !variants.insert(parts[index]) {
            return false;
        }
        index += 1;
    }
    let mut extensions = std::collections::HashSet::new();
    while index < parts.len() && parts[index].len() == 1 && parts[index] != "x" {
        if !extensions.insert(parts[index]) {
            return false;
        }
        index += 1;
        let start = index;
        while index < parts.len() && (2..=8).contains(&parts[index].len()) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    if index < parts.len() && parts[index] == "x" {
        index += 1;
        if index == parts.len() {
            return false;
        }
        index = parts.len();
    }
    index == parts.len()
}

/// Unicode bidi embeddings, overrides, isolates and their terminators can
/// reorder neighbouring UI text without being visible themselves. They are
/// not needed to store ordinary RTL scripts (Arabic/Hebrew characters remain
/// valid), so profile fields reject these formatting controls at ingress.
pub fn contains_unsafe_bidi_controls(value: &str) -> bool {
    value
        .chars()
        .any(|character| matches!(character as u32, 0x202a..=0x202e | 0x2066..=0x2069))
}
