//! Input policy of operator-written text.

pub fn valid_administrative_text(
    value: &str,
    max_chars: usize,
    max_bytes: usize,
    multiline: bool,
) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.chars().count() <= max_chars
        && value.chars().all(|character| {
            let code = character as u32;
            let allowed_space = multiline && matches!(character, '\t' | '\n' | '\r');
            (allowed_space || !(code <= 0x1f || (0x7f..=0x9f).contains(&code)))
                && !(0x202a..=0x202e).contains(&code)
        })
}
