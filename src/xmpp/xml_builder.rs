//! Typed XML output builder for protocol-generated stanzas. Element and
//! attribute names are compile-time strings; every runtime value is escaped
//! exactly once. Raw XML requires an explicit parse-validation boundary.

use anyhow::{bail, Context, Result};
use std::borrow::Cow;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XmlElement {
    name: Cow<'static, str>,
    attributes: Vec<(&'static str, String)>,
    children: Vec<XmlNode>,
}

/// An opaque XML fragment that crossed the one permitted raw-fragment
/// boundary.  Keeping validation in a type makes it impossible for callers
/// that splice a parsed/stored stanza into a typed wrapper to accidentally
/// skip the same resource and restricted-XML checks used by `XmlElement`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedXmlFragment(String);

#[derive(Clone, Debug, Eq, PartialEq)]
enum XmlNode {
    Element(XmlElement),
    Text(String),
    ValidatedFragment(ValidatedXmlFragment),
}

impl ValidatedXmlFragment {
    pub(crate) fn parse(fragment: &str) -> Result<Self> {
        // A fragment may originate in durable storage or from a previously
        // parsed stanza. Parsing proves well-formedness (including duplicate
        // attribute and namespace-binding rules); the explicit structural
        // limits prevent a syntactically valid but excessively deep fragment
        // from turning serialization into an unbounded resource sink.
        const MAX_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
        const MAX_FRAGMENT_DEPTH: usize = 128;
        const MAX_FRAGMENT_NODES: usize = 65_536;
        const MAX_ATTRIBUTES_PER_ELEMENT: usize = 128;
        if fragment.len() > MAX_FRAGMENT_BYTES {
            bail!("outbound XML fragment exceeds the validated size limit");
        }
        // This wrapper is parser input only. It permits the protocol payload
        // to contain multiple sibling elements while still requiring one
        // well-formed XML document at the validation boundary.
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
                // RFC 6120 restricted XML applies to data restored from
                // durable storage just as it does to live input. Preserve
                // only protocol nodes and text at this explicit raw-fragment
                // boundary; comments and processing instructions must never
                // be smuggled into a server-generated stream.
                bail!("outbound XML fragment contains a restricted XML node");
            }
        }
        Ok(Self(fragment.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl XmlElement {
    pub(crate) fn new(name: &'static str) -> Self {
        assert!(valid_xml_name(name), "invalid static XML element name");
        Self {
            name: Cow::Borrowed(name),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Construct an element whose QName came from a parsed protocol payload.
    /// Most output should use [`Self::new`] so names remain compile-time
    /// constants. Extensible protocols such as XEP-0049 Private XML must echo
    /// application-defined element names; those names cross this explicit,
    /// fallible validation boundary before they can reach the serializer.
    pub(crate) fn dynamic(name: &str) -> Result<Self> {
        if !valid_xml_name(name) {
            bail!("invalid dynamic XML element name");
        }
        Ok(Self {
            name: Cow::Owned(name.to_owned()),
            attributes: Vec::new(),
            children: Vec::new(),
        })
    }

    /// Construct an element in an explicit default namespace. Namespace URIs
    /// are compile-time protocol constants; runtime data belongs in escaped
    /// attributes or text nodes instead.
    pub(crate) fn namespaced(name: &'static str, namespace: &'static str) -> Self {
        Self::new(name).attr("xmlns", namespace)
    }

    pub(crate) fn attr(mut self, name: &'static str, value: impl ToString) -> Self {
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

    pub(crate) fn optional_attr(self, name: &'static str, value: Option<impl ToString>) -> Self {
        match value {
            Some(value) => self.attr(name, value),
            None => self,
        }
    }

    pub(crate) fn text(mut self, value: impl Into<String>) -> Self {
        self.children.push(XmlNode::Text(value.into()));
        self
    }

    pub(crate) fn child(mut self, child: XmlElement) -> Self {
        self.push_child(child);
        self
    }

    pub(crate) fn push_child(&mut self, child: XmlElement) {
        self.children.push(XmlNode::Element(child));
    }

    pub(crate) fn validated_fragment(mut self, fragment: &str) -> Result<Self> {
        self.push_validated_fragment(fragment)?;
        Ok(self)
    }

    pub(crate) fn push_validated_fragment(&mut self, fragment: &str) -> Result<()> {
        self.children
            .push(XmlNode::ValidatedFragment(ValidatedXmlFragment::parse(
                fragment,
            )?));
        Ok(())
    }

    pub(crate) fn finish(&self) -> String {
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

    /// Serialize only the validated children. This is used by extension APIs
    /// whose caller supplies the protocol wrapper (for example a PubSub
    /// `<items/>` event) but must still prohibit arbitrary string joining.
    pub(crate) fn finish_children(&self) -> String {
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

    /// Opening tag for a streaming XML entity whose closing tag is emitted at
    /// a later transport boundary.
    pub(crate) fn open(&self) -> String {
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

    /// Closing tag for a streaming XML entity whose opening tag was emitted
    /// earlier. The QName is still validated by the ordinary constructor, so
    /// stream-control paths never need a raw `</...>` literal.
    pub(crate) fn close(&self) -> String {
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
            // XML normalizes literal attribute whitespace. Character
            // references preserve the exact protocol value on parse.
            '\t' => output.push_str("&#x9;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            _ if xml_10_character(character) => output.push(character),
            // Rust strings can contain XML 1.0-forbidden C0 controls. Never
            // let one turn an otherwise safe builder call into malformed
            // wire XML or a connection-wide parser failure.
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
            // XML parsers normalize a literal carriage return to LF.
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
    use super::{ValidatedXmlFragment, XmlElement};
    use roxmltree::Document;

    #[test]
    fn runtime_values_are_escaped_once() {
        let xml = XmlElement::new("message")
            .attr("to", "a'b&c@example.test")
            .child(XmlElement::new("body").text("<hello & goodbye>"))
            .finish();
        assert_eq!(
            xml,
            "<message to='a&apos;b&amp;c@example.test'><body>&lt;hello &amp; goodbye&gt;</body></message>"
        );
        Document::parse(&xml).unwrap();
    }

    #[test]
    fn valid_xml_unicode_attributes_and_text_round_trip_exactly() {
        // A deterministic property-style corpus exercises every escaping
        // delimiter together with non-ASCII scripts and supplementary-plane
        // scalar values. Parsing must recover the exact runtime input: this
        // catches both missing escaping and accidental double escaping.
        let corpus = [
            "",
            "plain ASCII",
            "'\"<&>",
            "already looks escaped: &amp; &apos; &lt;",
            "日本語／繁體中文／한국어",
            "Español, français, Deutsch, Esperanto, Latine",
            "emoji 🙂🚀 and combining e\u{301}",
            "xmlns='urn:evil' /><injected/>",
        ];
        for value in corpus {
            let xml = XmlElement::namespaced("probe", "urn:northstar:test")
                .attr("value", value)
                .text(value.to_owned())
                .finish();
            let document = Document::parse(&xml).unwrap_or_else(|error| {
                panic!("builder emitted malformed XML for {value:?}: {error}")
            });
            let root = document.root_element();
            assert_eq!(root.tag_name().namespace(), Some("urn:northstar:test"));
            assert_eq!(root.attribute("value"), Some(value));
            assert_eq!(root.text().unwrap_or_default(), value);
            assert_eq!(root.children().filter(|node| node.is_element()).count(), 0);
        }
    }

    #[test]
    fn attribute_whitespace_round_trips_and_forbidden_controls_are_replaced() {
        let xml = XmlElement::new("probe")
            .attr("value", "tab\tline\nreturn\rcontrol\u{0007}")
            .text("line\rcontrol\u{0001}".to_owned())
            .finish();
        let document = Document::parse(&xml).unwrap();
        let root = document.root_element();
        assert_eq!(
            root.attribute("value"),
            Some("tab\tline\nreturn\rcontrol\u{FFFD}")
        );
        assert_eq!(root.text(), Some("line\rcontrol\u{FFFD}"));
        assert!(!xml.contains('\u{0007}'));
        assert!(!xml.contains('\u{0001}'));
    }

    #[test]
    fn explicit_namespace_reset_survives_validated_fragment_boundary() {
        let xml = XmlElement::namespaced("outer", "urn:northstar:outer")
            .validated_fragment("<inner xmlns=''><value>safe</value></inner>")
            .unwrap()
            .finish();
        let document = Document::parse(&xml).unwrap();
        let outer = document.root_element();
        let inner = outer.children().find(|node| node.is_element()).unwrap();
        let value = inner.children().find(|node| node.is_element()).unwrap();
        assert_eq!(outer.tag_name().namespace(), Some("urn:northstar:outer"));
        // roxmltree represents an explicit default-namespace reset as the
        // empty namespace URI rather than `None`; both descendants must stay
        // outside the inherited outer namespace.
        assert_eq!(inner.tag_name().namespace(), Some(""));
        assert_eq!(value.tag_name().namespace(), Some(""));
        assert_eq!(value.text(), Some("safe"));
    }

    #[test]
    fn stream_open_and_empty_element_are_structural() {
        let stream = XmlElement::new("stream:stream")
            .attr("xmlns:stream", "http://etherx.jabber.org/streams")
            .attr("from", "example.test");
        let complete_stream = format!("{}{}", stream.open(), stream.close());
        let document = Document::parse(&complete_stream).unwrap();
        assert_eq!(document.root_element().tag_name().name(), "stream");
        assert_eq!(
            document.root_element().tag_name().namespace(),
            Some("http://etherx.jabber.org/streams")
        );
        assert!(XmlElement::new("success").finish().ends_with("/>"));
    }

    #[test]
    fn validated_nested_stanza_preserves_each_namespace_boundary() {
        let nested = "<message xmlns='jabber:client'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'><body>nested</body></message></forwarded></message>";
        let xml = XmlElement::namespaced("sent", "urn:xmpp:carbons:2")
            .validated_fragment(nested)
            .unwrap()
            .finish();
        let document = Document::parse(&xml).unwrap();
        let elements = document
            .descendants()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        assert_eq!(
            elements[0].tag_name().namespace(),
            Some("urn:xmpp:carbons:2")
        );
        assert_eq!(elements[1].tag_name().namespace(), Some("jabber:client"));
        assert_eq!(
            elements[2].tag_name().namespace(),
            Some("urn:xmpp:forward:0")
        );
        assert_eq!(elements[3].tag_name().namespace(), Some("jabber:client"));
        assert_eq!(elements[4].tag_name().namespace(), Some("jabber:client"));
        assert_eq!(elements[4].text(), Some("nested"));
    }

    #[test]
    fn malformed_raw_fragments_are_rejected_before_serialization() {
        for fragment in [
            "<message><body></message>",
            "</northstar-fragment><evil/></northstar-fragment>",
            "<unbound:element/>",
            "&external_entity;",
            "<!DOCTYPE x [<!ENTITY external_entity SYSTEM 'file:///secret'>]><x/>",
        ] {
            let error = XmlElement::new("body")
                .validated_fragment(fragment)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("outbound XML fragment is malformed"),
                "unexpected validation error for {fragment:?}: {error:#}"
            );
        }
    }

    #[test]
    fn restricted_xml_nodes_are_rejected_at_the_raw_fragment_boundary() {
        for fragment in [
            "<message><!-- hidden --><body>hello</body></message>",
            "<message><?client instruction?><body>hello</body></message>",
        ] {
            let error = XmlElement::new("forwarded")
                .validated_fragment(fragment)
                .unwrap_err();
            assert!(error.to_string().contains("restricted XML node"));
        }
    }

    #[test]
    fn duplicate_attributes_and_excessive_depth_are_rejected() {
        assert!(XmlElement::new("body")
            .validated_fragment("<item id='one' id='two'/>")
            .is_err());

        let too_deep = format!("{}payload{}", "<level>".repeat(129), "</level>".repeat(129));
        let error = XmlElement::new("body")
            .validated_fragment(&too_deep)
            .unwrap_err();
        assert!(error.to_string().contains("validated depth limit"));
    }

    #[test]
    fn fragment_resource_limits_fail_before_serialization() {
        let attributes = (0..129)
            .map(|index| format!(" a{index}='value'"))
            .collect::<String>();
        let too_many_attributes = format!("<item{attributes}/>");
        assert!(ValidatedXmlFragment::parse(&too_many_attributes)
            .unwrap_err()
            .to_string()
            .contains("validated attribute limit"));

        let too_many_nodes = "<item/>".repeat(65_535);
        assert!(ValidatedXmlFragment::parse(&too_many_nodes)
            .unwrap_err()
            .to_string()
            .contains("validated node limit"));

        let oversized = "x".repeat(4 * 1024 * 1024 + 1);
        assert!(ValidatedXmlFragment::parse(&oversized)
            .unwrap_err()
            .to_string()
            .contains("validated size limit"));
    }

    #[test]
    fn namespace_and_runtime_value_injection_remain_data() {
        let attack = "victim' xmlns='urn:evil' evil:flag='1";
        let xml = XmlElement::namespaced("message", "jabber:client")
            .attr("to", attack)
            .child(XmlElement::new("body").text(format!("{attack}<injected/>")))
            .finish();
        let document = Document::parse(&xml).unwrap();
        let message = document.root_element();
        assert_eq!(message.tag_name().namespace(), Some("jabber:client"));
        assert_eq!(message.attribute("to"), Some(attack));
        assert_eq!(message.attributes().len(), 1);
        let body = message.children().find(|node| node.is_element()).unwrap();
        assert_eq!(body.tag_name().namespace(), Some("jabber:client"));
        let expected_text = format!("{attack}<injected/>");
        assert_eq!(body.text(), Some(expected_text.as_str()));
        assert_eq!(body.children().filter(|node| node.is_element()).count(), 0);
    }

    #[test]
    fn extensible_protocol_names_cross_a_fallible_boundary() {
        let xml = XmlElement::dynamic("client-preferences")
            .unwrap()
            .attr("xmlns", "urn:example:preferences")
            .finish();
        assert_eq!(xml, "<client-preferences xmlns='urn:example:preferences'/>");
        for name in ["", "9bad", "bad name", "bad/name", "a:b:c"] {
            assert!(XmlElement::dynamic(name).is_err(), "accepted {name:?}");
        }
    }

    #[test]
    #[should_panic(expected = "invalid static XML element name")]
    fn invalid_static_qnames_fail_closed() {
        let _ = XmlElement::new("stream:bad:name");
    }
}
