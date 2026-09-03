//! Safe XML building, fragment validation, and text escaping primitives.

use std::fmt::Write as _;

/// Escape characters for XML text content (`&`, `<`, `>`).
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

/// Escape characters for XML attribute values (`&`, `<`, `>`, `'`, `"`).
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

/// Helper returning an owned escaped XML text string.
pub fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    escape_xml_text(&mut out, value);
    out
}

/// Helper returning an owned escaped XML attribute string.
pub fn attr_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    escape_xml_attr(&mut out, value);
    out
}

/// Validate that an XML element QName matches NCName or Prefix:NCName production.
pub fn validate_qname(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 256 {
        return Err("invalid-qname-length");
    }
    let is_valid_start_char = |c: char| {
        matches!(
            c,
            'a'..='z'
                | 'A'..='Z'
                | '_'
                | '\u{C0}'..='\u{D6}'
                | '\u{D8}'..='\u{F6}'
                | '\u{F8}'..='\u{2FF}'
                | '\u{370}'..='\u{37D}'
                | '\u{37F}'..='\u{1FFF}'
                | '\u{200C}'..='\u{200D}'
                | '\u{2070}'..='\u{218F}'
                | '\u{2C00}'..='\u{2FEF}'
                | '\u{3001}'..='\u{D7FF}'
                | '\u{F900}'..='\u{FDCF}'
                | '\u{FDF0}'..='\u{FFFD}'
        )
    };
    let is_valid_char =
        |c: char| is_valid_start_char(c) || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}');

    let mut parts = name.split(':');
    let first = parts.next().ok_or("empty-qname")?;
    let mut chars = first.chars();
    let first_char = chars.next().ok_or("empty-prefix")?;
    if !is_valid_start_char(first_char) || !chars.all(is_valid_char) {
        return Err("invalid-qname-char");
    }

    if let Some(second) = parts.next() {
        if parts.next().is_some() {
            return Err("multiple-colons-in-qname");
        }
        let mut chars = second.chars();
        let first_char = chars.next().ok_or("empty-local-name")?;
        if !is_valid_start_char(first_char) || !chars.all(is_valid_char) {
            return Err("invalid-qname-char");
        }
    }

    Ok(())
}

/// A lightweight, allocation-conscious XML element builder.
#[derive(Clone, Debug)]
pub struct XmlElement {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<XmlElementContent>,
}

#[derive(Clone, Debug)]
enum XmlElementContent {
    Element(XmlElement),
    Text(String),
    Raw(String),
}

impl XmlElement {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn namespaced(name: impl Into<String>, namespace: &str) -> Self {
        let mut element = Self::new(name);
        element
            .attributes
            .push(("xmlns".to_owned(), namespace.to_owned()));
        element
    }

    pub fn dynamic(name: &str) -> Result<Self, &'static str> {
        validate_qname(name)?;
        Ok(Self::new(name.to_owned()))
    }

    pub fn attr(mut self, name: impl Into<String>, value: impl ToString) -> Self {
        self.attributes.push((name.into(), value.to_string()));
        self
    }

    pub fn optional_attr(mut self, name: impl Into<String>, value: Option<impl ToString>) -> Self {
        if let Some(value) = value {
            self.attributes.push((name.into(), value.to_string()));
        }
        self
    }

    pub fn child(mut self, child: XmlElement) -> Self {
        self.children.push(XmlElementContent::Element(child));
        self
    }

    pub fn push_child(&mut self, child: XmlElement) {
        self.children.push(XmlElementContent::Element(child));
    }

    pub fn text(mut self, text: impl ToString) -> Self {
        self.children
            .push(XmlElementContent::Text(text.to_string()));
        self
    }

    pub fn raw_fragment(mut self, fragment: impl ToString) -> Self {
        self.children
            .push(XmlElementContent::Raw(fragment.to_string()));
        self
    }

    pub fn push_raw_fragment(&mut self, fragment: impl ToString) {
        self.children
            .push(XmlElementContent::Raw(fragment.to_string()));
    }

    /// Append an XML fragment string after validating its well-formedness with roxmltree.
    pub fn validated_fragment(mut self, fragment: &str) -> Result<Self, &'static str> {
        self.push_validated_fragment(fragment)?;
        Ok(self)
    }

    /// Append an XML fragment string after validating its well-formedness with roxmltree.
    pub fn push_validated_fragment(&mut self, fragment: &str) -> Result<(), &'static str> {
        if fragment.trim().is_empty() {
            return Ok(());
        }
        let wrapped = format!("<_root_>{fragment}</_root_>");
        roxmltree::Document::parse(&wrapped).map_err(|_| "malformed-fragment")?;
        self.push_raw_fragment(fragment);
        Ok(())
    }

    /// Render element to an XML string.
    pub fn finish(self) -> String {
        let mut out = String::new();
        self.write_to(&mut out);
        out
    }

    /// Render only the element's children (inner XML).
    pub fn finish_children(self) -> String {
        let mut out = String::new();
        for child in self.children {
            match child {
                XmlElementContent::Element(el) => el.write_to(&mut out),
                XmlElementContent::Text(t) => escape_xml_text(&mut out, &t),
                XmlElementContent::Raw(r) => out.push_str(&r),
            }
        }
        out
    }

    fn write_to(self, out: &mut String) {
        out.push('<');
        out.push_str(&self.name);
        for (k, v) in self.attributes {
            out.push(' ');
            out.push_str(&k);
            out.push_str("='");
            escape_xml_attr(out, &v);
            out.push('\'');
        }

        if self.children.is_empty() {
            out.push_str("/>");
        } else {
            out.push('>');
            for child in self.children {
                match child {
                    XmlElementContent::Element(el) => el.write_to(out),
                    XmlElementContent::Text(t) => escape_xml_text(out, &t),
                    XmlElementContent::Raw(r) => out.push_str(&r),
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
    fn escapes_text_and_attributes() {
        assert_eq!(
            xml_escape("a & b < c > d ' e \" f"),
            "a &amp; b &lt; c &gt; d ' e \" f"
        );
        assert_eq!(
            attr_escape("a & b < c > d ' e \" f"),
            "a &amp; b &lt; c &gt; d &apos; e &quot; f"
        );
    }

    #[test]
    fn validates_element_names() {
        assert!(validate_qname("item").is_ok());
        assert!(validate_qname("pubsub:publish").is_ok());
        assert!(validate_qname("ns_1:my-name.v2").is_ok());
        assert!(validate_qname("").is_err());
        assert!(validate_qname("123bad").is_err());
        assert!(validate_qname("a:b:c").is_err());
        assert!(validate_qname("<bad>").is_err());
    }

    #[test]
    fn builds_xml_elements() {
        let el = XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub").child(
            XmlElement::new("items").attr("node", "test&node").child(
                XmlElement::new("item")
                    .attr("id", "1")
                    .text("hello <world>"),
            ),
        );
        let s = el.finish();
        assert_eq!(s, "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='test&amp;node'><item id='1'>hello &lt;world&gt;</item></items></pubsub>");
    }

    #[test]
    fn validates_fragments() {
        let mut el = XmlElement::new("test");
        assert!(el.push_validated_fragment("<valid a='1'/>").is_ok());
        assert!(el.push_validated_fragment("<unclosed>").is_err());
    }
}
