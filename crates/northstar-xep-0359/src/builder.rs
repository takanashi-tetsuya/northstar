//! Safe XML fragment builders for XEP-0359 elements.

use crate::error::SidError;
use crate::wire::validate_id;
use northstar_xmpp_types::jid::CanonicalJid;
use std::fmt::Write;

pub fn build_origin_id(id: &str) -> Result<String, SidError> {
    validate_id(id)?;
    Ok(format!(
        "<origin-id xmlns='urn:xmpp:sid:0' id='{}'/>",
        escaped(id)
    ))
}

pub fn build_stanza_id(id: &str, by: &CanonicalJid) -> Result<String, SidError> {
    validate_id(id)?;
    Ok(format!(
        "<stanza-id xmlns='urn:xmpp:sid:0' id='{}' by='{}'/>",
        escaped(id),
        escaped(&by.to_string())
    ))
}

pub fn build_referenced_stanza(id: &str, by: Option<&CanonicalJid>) -> Result<String, SidError> {
    validate_id(id)?;
    let by = by
        .map(|value| format!(" by='{}'", escaped(&value.to_string())))
        .unwrap_or_default();
    Ok(format!(
        "<referenced-stanza xmlns='urn:xmpp:sid:0' id='{}'{by}/>",
        escaped(id)
    ))
}

fn escaped(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            other => {
                let _ = output.write_char(other);
            }
        }
    }
    output
}
