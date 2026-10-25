//! Escaping of text for XML that is assembled outside `XmlElement`.

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
