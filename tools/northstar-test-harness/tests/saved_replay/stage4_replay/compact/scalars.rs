use super::super::Rejection;
use super::parser::Budget;

pub(super) fn text_bound<const N: usize>(text: &str, budget: &mut Budget) -> Result<(), Rejection> {
    if budget.scalar(text)? > N {
        return Err(Rejection::Bound);
    }
    budget.bytes(text.len())?;
    if text.contains('\0') {
        Err(Rejection::Bound)
    } else {
        Ok(())
    }
}
pub(super) fn hex_bound(
    text: &str,
    max: usize,
    exact: bool,
    budget: &mut Budget,
) -> Result<(), Rejection> {
    budget.scalar(text)?;
    let cap = max.checked_mul(2).ok_or(Rejection::Bound)?;
    if text.len() > cap {
        return Err(Rejection::Bound);
    }
    if (exact && text.len() != cap) || !text.len().is_multiple_of(2) {
        return Err(Rejection::Encoding);
    }
    budget.bytes(text.len())?;
    if !text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Rejection::Encoding);
    }
    Ok(())
}

pub(super) fn unhex(text: &str, budget: &mut Budget) -> Result<Vec<u8>, Rejection> {
    let n = text.len() / 2;
    budget.bytes(text.len().checked_add(n).ok_or(Rejection::Bound)?)?;
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut result = Vec::with_capacity(n);
    for pair in text.as_bytes().chunks_exact(2) {
        result.push((digit(pair[0]) << 4) | digit(pair[1]));
    }
    Ok(result)
}
pub(super) fn lower_hex(raw: &[u8], budget: &mut Budget) -> Result<String, Rejection> {
    let len = raw.len().checked_mul(2).ok_or(Rejection::Bound)?;
    budget.bytes(raw.len().checked_add(len).ok_or(Rejection::Bound)?)?;
    let mut result = String::with_capacity(len);
    let h = b"0123456789abcdef";
    for &b in raw {
        result.push(h[usize::from(b >> 4)] as char);
        result.push(h[usize::from(b & 15)] as char);
    }
    Ok(result)
}
pub(super) fn utf8<'a>(raw: &'a [u8], budget: &mut Budget) -> Result<Option<&'a str>, Rejection> {
    budget.bytes(raw.len().checked_mul(2).ok_or(Rejection::Bound)?)?;
    Ok(std::str::from_utf8(raw).ok())
}
