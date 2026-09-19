//! Lightweight XML primitives for safe XML element building and escaping.

use std::fmt::Write as _;

/// Escape characters for XML text content (&, <, >).
pub fn escape_xml_text(output: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            other => {
                let _ = output.write_char(other);
            }
        }
    }
}

/// Escape characters for XML attribute values (&, <, >, ', ").
pub fn escape_xml_attr(output: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
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
}

/// A lightweight XML element representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlElement {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<XmlElementContent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum XmlElementContent {
    Element(XmlElement),
    Text(String),
    Raw(String),
}

impl XmlElement {
    /// Create a new XML element with given tag name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Create a new XML element with given tag name and xmlns attribute.
    pub fn namespaced(name: impl Into<String>, namespace: &str) -> Self {
        let mut element = Self::new(name);
        element
            .attributes
            .push(("xmlns".to_owned(), namespace.to_owned()));
        element
    }

    /// Add an attribute key-value pair.
    pub fn attr(mut self, name: impl Into<String>, value: impl ToString) -> Self {
        self.attributes.push((name.into(), value.to_string()));
        self
    }

    /// Add an optional attribute if value is Some.
    pub fn optional_attr(mut self, name: impl Into<String>, value: Option<impl ToString>) -> Self {
        if let Some(value) = value {
            self.attributes.push((name.into(), value.to_string()));
        }
        self
    }

    /// Add a child element.
    pub fn child(mut self, child: XmlElement) -> Self {
        self.children.push(XmlElementContent::Element(child));
        self
    }

    /// Push a child element.
    pub fn push_child(&mut self, child: XmlElement) {
        self.children.push(XmlElementContent::Element(child));
    }

    /// Add escaped text content.
    pub fn text(mut self, text: impl ToString) -> Self {
        self.children
            .push(XmlElementContent::Text(text.to_string()));
        self
    }

    /// Add pre-formatted/raw XML fragment.
    pub fn raw_fragment(mut self, fragment: impl ToString) -> Self {
        self.children
            .push(XmlElementContent::Raw(fragment.to_string()));
        self
    }

    /// Render this element into a String.
    pub fn finish(self) -> String {
        let mut out = String::new();
        self.write_to(&mut out);
        out
    }

    /// Write XML representation to a buffer.
    pub fn write_to(&self, out: &mut String) {
        out.push('<');
        out.push_str(&self.name);
        for (k, v) in &self.attributes {
            out.push(' ');
            out.push_str(k);
            out.push_str("='");
            escape_xml_attr(out, v);
            out.push('\'');
        }

        if self.children.is_empty() {
            out.push_str("/>");
        } else {
            out.push('>');
            for child in &self.children {
                match child {
                    XmlElementContent::Element(el) => el.write_to(out),
                    XmlElementContent::Text(t) => escape_xml_text(out, t),
                    XmlElementContent::Raw(r) => out.push_str(r),
                }
            }
            out.push_str("</");
            out.push_str(&self.name);
            out.push('>');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_special_characters_correctly() {
        let mut text = String::new();
        escape_xml_text(&mut text, "hello <world> & friends");
        assert_eq!(text, "hello &lt;world&gt; &amp; friends");

        let mut attr = String::new();
        escape_xml_attr(&mut attr, "quote 'single' and \"double\" & <tags>");
        assert_eq!(
            attr,
            "quote &apos;single&apos; and &quot;double&quot; &amp; &lt;tags&gt;"
        );
    }

    #[test]
    fn builds_nested_elements() {
        let el = XmlElement::namespaced("set", "http://jabber.org/protocol/rsm")
            .optional_attr("opt", Some("val"))
            .optional_attr("none", None::<&str>)
            .child(XmlElement::new("first").attr("index", 0).text("item-1"))
            .child(XmlElement::new("last").text("item-2"));

        assert_eq!(
            el.finish(),
            "<set xmlns='http://jabber.org/protocol/rsm' opt='val'><first index='0'>item-1</first><last>item-2</last></set>"
        );
    }
}
