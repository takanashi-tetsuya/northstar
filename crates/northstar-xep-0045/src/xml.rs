//! Capability-free XML escaping and formatting utilities for XEP-0045 payloads.

#![forbid(unsafe_code)]

use std::fmt::Write;

/// Escape XML text content (`&`, `<`, `>`).
pub fn escape_xml_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(c),
        }
    }
    output
}

/// Escape XML attribute content (`&`, `<`, `>`, `"`, `'`).
pub fn escape_xml_attr(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(c),
        }
    }
    output
}

/// Minimal, deterministic XML element builder for safe string construction.
#[derive(Clone, Debug, Default)]
pub struct XmlElement {
    name: &'static str,
    prefix: Option<&'static str>,
    namespace: Option<&'static str>,
    attributes: Vec<(&'static str, String)>,
    children: Vec<String>,
    text: Option<String>,
}

impl XmlElement {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            prefix: None,
            namespace: None,
            attributes: Vec::new(),
            children: Vec::new(),
            text: None,
        }
    }

    pub const fn namespaced(name: &'static str, namespace: &'static str) -> Self {
        Self {
            name,
            prefix: None,
            namespace: Some(namespace),
            attributes: Vec::new(),
            children: Vec::new(),
            text: None,
        }
    }

    pub const fn prefixed(
        prefix: &'static str,
        name: &'static str,
        namespace: &'static str,
    ) -> Self {
        Self {
            name,
            prefix: Some(prefix),
            namespace: Some(namespace),
            attributes: Vec::new(),
            children: Vec::new(),
            text: None,
        }
    }

    pub fn attr(mut self, name: &'static str, value: impl std::fmt::Display) -> Self {
        self.attributes.push((name, value.to_string()));
        self
    }

    pub fn optional_attr(
        mut self,
        name: &'static str,
        value: Option<impl std::fmt::Display>,
    ) -> Self {
        if let Some(val) = value {
            self.attributes.push((name, val.to_string()));
        }
        self
    }

    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    pub fn child(mut self, child_xml: impl Into<String>) -> Self {
        self.children.push(child_xml.into());
        self
    }

    pub fn push_child(&mut self, child_xml: impl Into<String>) {
        self.children.push(child_xml.into());
    }

    pub fn finish(self) -> String {
        let mut buf = String::new();
        self.render_into(&mut buf);
        buf
    }

    fn render_into(self, buf: &mut String) {
        buf.push('<');
        if let Some(p) = self.prefix {
            buf.push_str(p);
            buf.push(':');
        }
        buf.push_str(self.name);

        if let Some(ns) = self.namespace {
            if let Some(p) = self.prefix {
                let _ = write!(buf, " xmlns:{}=\"{}\"", p, escape_xml_attr(ns));
            } else {
                let _ = write!(buf, " xmlns=\"{}\"", escape_xml_attr(ns));
            }
        }

        for (name, val) in self.attributes {
            let _ = write!(buf, " {}=\"{}\"", name, escape_xml_attr(&val));
        }

        let has_text = self.text.as_ref().is_some_and(|t| !t.is_empty());
        let has_children = !self.children.is_empty();

        if !has_text && !has_children {
            buf.push_str("/>");
            return;
        }

        buf.push('>');
        if let Some(t) = self.text {
            buf.push_str(&escape_xml_text(&t));
        }
        for child in self.children {
            buf.push_str(&child);
        }

        buf.push_str("</");
        if let Some(p) = self.prefix {
            buf.push_str(p);
            buf.push(':');
        }
        buf.push_str(self.name);
        buf.push('>');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_xml_text() {
        assert_eq!(
            escape_xml_text("Hello & <World>"),
            "Hello &amp; &lt;World&gt;"
        );
        assert_eq!(escape_xml_text("normal text"), "normal text");
    }

    #[test]
    fn test_escape_xml_attr() {
        assert_eq!(
            escape_xml_attr(r#"a & b < c > d "e" 'f'"#),
            "a &amp; b &lt; c &gt; d &quot;e&quot; &apos;f&apos;"
        );
    }

    #[test]
    fn test_xml_element_builder() {
        let el = XmlElement::new("item")
            .attr("affiliation", "owner")
            .attr("role", "moderator")
            .optional_attr("nick", Some("alice"))
            .optional_attr("reason", None::<&str>)
            .finish();
        assert_eq!(
            el,
            r#"<item affiliation="owner" role="moderator" nick="alice"/>"#
        );

        let parent = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
            .child(XmlElement::new("status").attr("code", "110").finish())
            .finish();
        assert_eq!(
            parent,
            r#"<x xmlns="http://jabber.org/protocol/muc#user"><status code="110"/></x>"#
        );
    }
}
