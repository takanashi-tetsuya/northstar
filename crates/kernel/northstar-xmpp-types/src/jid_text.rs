//! Splitting of JID text that is already canonical: no preparation or validation.

pub fn bare_jid(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

pub fn localpart(jid: &str) -> &str {
    bare_jid(jid).split('@').next().unwrap_or(jid)
}

pub fn jid_domain(jid: &str) -> Option<&str> {
    bare_jid(jid).split_once('@').map(|(_, domain)| domain)
}
