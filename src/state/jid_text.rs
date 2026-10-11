//! JID text helpers and XML escaping.

pub fn bare_jid(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

pub fn localpart(jid: &str) -> &str {
    bare_jid(jid).split('@').next().unwrap_or(jid)
}

pub fn jid_domain(jid: &str) -> Option<&str> {
    bare_jid(jid).split_once('@').map(|(_, domain)| domain)
}

pub fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn attr_escape(value: &str) -> String {
    xml_escape(value)
}
