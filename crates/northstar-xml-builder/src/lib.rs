//! Typed XML output builder for protocol-generated stanzas.

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use std::borrow::Cow;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlElement {
    name: Cow<'static, str>,
    attributes: Vec<(&'static str, String)>,
    children: Vec<XmlNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedXmlFragment(String);

#[derive(Clone, Debug, Eq, PartialEq)]
enum XmlNode {
    Element(XmlElement),
    Text(String),
    ValidatedFragment(ValidatedXmlFragment),
}

impl ValidatedXmlFragment {
    pub fn parse(fragment: &str) -> Result<Self> {
        const MAX_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
        const MAX_FRAGMENT_DEPTH: usize = 128;
        const MAX_FRAGMENT_NODES: usize = 65_536;
        const MAX_ATTRIBUTES_PER_ELEMENT: usize = 128;
        if fragment.len() > MAX_FRAGMENT_BYTES {
            bail!("outbound XML fragment exceeds the validated size limit");
        }
        let wrapped = format!("<northstar-fragment>{fragment}</northstar-fragment>");
        let document =
            roxmltree::Document::parse(&wrapped).context("outbound XML fragment is malformed")?;
        let mut node_count = 0_usize;
        for node in document.descendants() {
            node_count += 1;
            if node_count > MAX_FRAGMENT_NODES {
                bail!("outbound XML fragment exceeds the validated node limit");
            }
            if node.is_element() {
                if node
                    .ancestors()
                    .filter(|ancestor| ancestor.is_element())
                    .count()
                    > MAX_FRAGMENT_DEPTH
                {
                    bail!("outbound XML fragment exceeds the validated depth limit");
                }
                if node.attributes().len() > MAX_ATTRIBUTES_PER_ELEMENT {
                    bail!("outbound XML fragment exceeds the validated attribute limit");
                }
            } else if node.is_comment() || node.is_pi() {
                bail!("outbound XML fragment contains a restricted XML node");
            }
        }
        Ok(Self(fragment.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl XmlElement {
    pub fn new(name: &'static str) -> Self {
        assert!(valid_xml_name(name), "invalid static XML element name");
        Self {
            name: Cow::Borrowed(name),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn dynamic(name: &str) -> Result<Self> {
        if !valid_xml_name(name) {
            bail!("invalid dynamic XML element name");
        }
        Ok(Self {
            name: Cow::Owned(name.to_owned()),
            attributes: Vec::new(),
            children: Vec::new(),
        })
    }

    pub fn namespaced(name: &'static str, namespace: &'static str) -> Self {
        Self::new(name).attr("xmlns", namespace)
    }

    pub fn attr(mut self, name: &'static str, value: impl ToString) -> Self {
        assert!(valid_xml_name(name), "invalid static XML attribute name");
        assert!(
            self.attributes
                .iter()
                .all(|(existing, _)| *existing != name),
            "duplicate static XML attribute"
        );
        self.attributes.push((name, value.to_string()));
        self
    }

    pub fn optional_attr(self, name: &'static str, value: Option<impl ToString>) -> Self {
        match value {
            Some(value) => self.attr(name, value),
            None => self,
        }
    }

    pub fn text(mut self, value: impl Into<String>) -> Self {
        self.children.push(XmlNode::Text(value.into()));
        self
    }

    pub fn child(mut self, child: XmlElement) -> Self {
        self.push_child(child);
        self
    }

    pub fn push_child(&mut self, child: XmlElement) {
        self.children.push(XmlNode::Element(child));
    }

    pub fn validated_fragment(mut self, fragment: &str) -> Result<Self> {
        self.push_validated_fragment(fragment)?;
        Ok(self)
    }

    pub fn push_validated_fragment(&mut self, fragment: &str) -> Result<()> {
        self.children
            .push(XmlNode::ValidatedFragment(ValidatedXmlFragment::parse(
                fragment,
            )?));
        Ok(())
    }

    pub fn finish(&self) -> String {
        let mut output = self.open();
        if self.children.is_empty() {
            output.truncate(output.len() - 1);
            output.push_str("/>");
            return output;
        }
        self.write_children_into(&mut output);
        output.push_str("</");
        output.push_str(self.name.as_ref());
        output.push('>');
        output
    }

    pub fn finish_children(&self) -> String {
        let mut output = String::new();
        self.write_children_into(&mut output);
        output
    }

    fn write_children_into(&self, output: &mut String) {
        for child in &self.children {
            match child {
                XmlNode::Element(element) => output.push_str(&element.finish()),
                XmlNode::Text(text) => escape_text_into(text, output),
                XmlNode::ValidatedFragment(fragment) => output.push_str(fragment.as_str()),
            }
        }
    }

    pub fn open(&self) -> String {
        let mut output = String::from("<");
        output.push_str(self.name.as_ref());
        for (name, value) in &self.attributes {
            output.push(' ');
            output.push_str(name);
            output.push_str("='");
            escape_attribute_into(value, &mut output);
            output.push('\'');
        }
        output.push('>');
        output
    }

    pub fn close(&self) -> String {
        let mut output = String::from("</");
        output.push_str(self.name.as_ref());
        output.push('>');
        output
    }
}

fn valid_xml_name(name: &str) -> bool {
    let mut parts = name.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    valid_xml_ncname(first)
        && parts
            .next()
            .is_none_or(|second| valid_xml_ncname(second) && parts.next().is_none())
}

fn valid_xml_ncname(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn escape_attribute_into(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            '\t' => output.push_str("&#x9;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            _ if xml_10_character(character) => output.push(character),
            _ => output.push('\u{FFFD}'),
        }
    }
}

fn escape_text_into(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\r' => output.push_str("&#xD;"),
            _ if xml_10_character(character) => output.push(character),
            _ => output.push('\u{FFFD}'),
        }
    }
}

fn xml_10_character(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{D7FF}').contains(&character)
        || ('\u{E000}'..='\u{FFFD}').contains(&character)
        || ('\u{10000}'..='\u{10FFFF}').contains(&character)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn runtime_values_are_escaped_once() {
        let xml = XmlElement::new("message")
            .attr("to", "a'b&c@example.test")
            .child(XmlElement::new("body").text("<hello & goodbye>"))
            .finish();
        assert_eq!(xml, "<message to='a&apos;b&amp;c@example.test'><body>&lt;hello &amp; goodbye&gt;</body></message>");
        Document::parse(&xml).unwrap();
    }

    #[test]
    fn whitespace_and_forbidden_controls_round_trip_safely() {
        let xml = XmlElement::new("probe")
            .attr("value", "tab\tline\nreturn\rcontrol\u{0007}")
            .text("line\rcontrol\u{0001}")
            .finish();
        let document = Document::parse(&xml).unwrap();
        let root = document.root_element();
        assert_eq!(
            root.attribute("value"),
            Some("tab\tline\nreturn\rcontrol\u{FFFD}")
        );
        assert_eq!(root.text(), Some("line\rcontrol\u{FFFD}"));
    }

    #[test]
    fn validated_nested_stanza_preserves_namespaces() {
        let nested = "<message xmlns='jabber:client'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'/></forwarded></message>";
        let xml = XmlElement::namespaced("sent", "urn:xmpp:carbons:2")
            .validated_fragment(nested)
            .unwrap()
            .finish();
        let document = Document::parse(&xml).unwrap();
        let namespaces = document
            .descendants()
            .filter(|node| node.is_element())
            .map(|node| node.tag_name().namespace().unwrap_or_default())
            .collect::<Vec<_>>();
        assert_eq!(
            namespaces,
            [
                "urn:xmpp:carbons:2",
                "jabber:client",
                "urn:xmpp:forward:0",
                "jabber:client"
            ]
        );
    }

    #[test]
    fn malformed_and_restricted_fragments_are_rejected() {
        for fragment in [
            "<message><body></message>",
            "<message><!-- hidden --></message>",
            "<message><?client instruction?></message>",
            "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///secret'>]><x/>",
        ] {
            assert!(ValidatedXmlFragment::parse(fragment).is_err(), "{fragment}");
        }
    }

    #[test]
    fn fragment_resource_limits_fail_before_serialization() {
        let attributes = (0..129)
            .map(|index| format!(" a{index}='value'"))
            .collect::<String>();
        assert!(ValidatedXmlFragment::parse(&format!("<item{attributes}/>")).is_err());
        assert!(ValidatedXmlFragment::parse(&"<item/>".repeat(65_535)).is_err());
        assert!(ValidatedXmlFragment::parse(&"x".repeat(4 * 1024 * 1024 + 1)).is_err());
    }

    #[test]
    fn dynamic_names_cross_a_fallible_boundary() {
        assert!(XmlElement::dynamic("client-preferences").is_ok());
        for name in ["", "9bad", "bad name", "a:b:c"] {
            assert!(XmlElement::dynamic(name).is_err());
        }
    }
}
