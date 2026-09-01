//! Dependency-light validation for client stanza shapes.
//!
//! This module intentionally contains only deterministic XML/JID validation.
//! Keeping it separate from dispatch lets every transport-facing parser use
//! the exact same admission rules as the production C2S path.

use roxmltree::Node;

const MAX_STANZA_ID_BYTES: usize = 1_024;

pub(crate) fn validate_client_stanza(root: Node<'_, '_>) -> std::result::Result<(), &'static str> {
    for attribute in root.attributes() {
        match attribute.namespace() {
            None if !matches!(attribute.name(), "id" | "to" | "from" | "type") => {
                return Err("bad-request");
            }
            Some("http://www.w3.org/XML/1998/namespace") if attribute.name() == "lang" => {}
            Some(_) => {}
            None => {}
        }
    }
    if root
        .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
        .is_some_and(|language| !valid_language_tag(language))
    {
        return Err("bad-request");
    }
    if let Some(id) = root.attribute("id") {
        if id.is_empty() || id.len() > MAX_STANZA_ID_BYTES || id.chars().any(char::is_control) {
            return Err("bad-request");
        }
    }
    if root
        .attribute("to")
        .is_some_and(|to| crate::jid::canonicalize(to).is_err())
    {
        return Err("jid-malformed");
    }

    let kind = root.attribute("type");
    match root.tag_name().name() {
        "message" => {
            if kind.is_some_and(|kind| {
                !matches!(kind, "normal" | "chat" | "groupchat" | "headline" | "error")
            }) {
                return Err("bad-request");
            }
            if kind == Some("error") && direct_client_children(root, "error").len() != 1 {
                return Err("bad-request");
            }
            validate_language_elements(root, "body")?;
            validate_language_elements(root, "subject")?;
            let threads = direct_client_children(root, "thread");
            if threads.len() > 1
                || threads.first().is_some_and(|thread| {
                    thread.children().any(|node| node.is_element())
                        || thread.attributes().any(|attribute| {
                            attribute.namespace().is_none() && attribute.name() != "parent"
                        })
                })
            {
                return Err("bad-request");
            }
        }
        "presence" => {
            if kind.is_some_and(|kind| {
                !matches!(
                    kind,
                    "unavailable"
                        | "subscribe"
                        | "subscribed"
                        | "unsubscribe"
                        | "unsubscribed"
                        | "probe"
                        | "error"
                )
            }) {
                return Err("bad-request");
            }
            if matches!(
                kind,
                Some(
                    "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed" | "probe" | "error"
                )
            ) && root.attribute("to").is_none()
            {
                return Err("bad-request");
            }
            let priorities = direct_client_children(root, "priority");
            if priorities.len() > 1
                || priorities.first().is_some_and(|priority| {
                    priority.attributes().len() != 0
                        || priority.children().any(|node| node.is_element())
                        || kind.is_some()
                        || priority
                            .text()
                            .and_then(|value| value.trim().parse::<i16>().ok())
                            .is_none_or(|value| !(-128..=127).contains(&value))
                })
            {
                return Err("bad-request");
            }
            let shows = direct_client_children(root, "show");
            if shows.len() > 1
                || shows.first().is_some_and(|show| {
                    show.attributes().len() != 0
                        || show.children().any(|node| node.is_element())
                        || kind.is_some()
                        || !matches!(show.text(), Some("away" | "chat" | "dnd" | "xa"))
                })
            {
                return Err("bad-request");
            }
            validate_language_elements(root, "status")?;
            if kind == Some("error") && direct_client_children(root, "error").len() != 1 {
                return Err("bad-request");
            }
        }
        "iq" => {
            let Some(kind) = kind else {
                return Err("bad-request");
            };
            if !matches!(kind, "get" | "set" | "result" | "error") || root.attribute("id").is_none()
            {
                return Err("bad-request");
            }
            let children = root
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            match kind {
                "get" | "set" if children.len() != 1 => return Err("bad-request"),
                "result" if children.len() > 1 => return Err("bad-request"),
                "error" => {
                    let error_elements = direct_client_children(root, "error");
                    if !(1..=2).contains(&children.len())
                        || error_elements.len() != 1
                        || children.last() != error_elements.last()
                    {
                        return Err("bad-request");
                    }
                }
                _ => {}
            }
        }
        _ => return Err("bad-request"),
    }
    if kind == Some("error") {
        let Some(error) = direct_client_children(root, "error").into_iter().next() else {
            return Err("bad-request");
        };
        validate_stanza_error(error)?;
    }
    Ok(())
}

fn validate_language_elements(
    root: Node<'_, '_>,
    name: &str,
) -> std::result::Result<(), &'static str> {
    let inherited = root
        .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
        .unwrap_or_default();
    let mut languages = std::collections::HashSet::new();
    for element in direct_client_children(root, name) {
        if element.children().any(|node| node.is_element())
            || element.attributes().any(|attribute| {
                attribute.namespace() != Some("http://www.w3.org/XML/1998/namespace")
                    || attribute.name() != "lang"
            })
        {
            return Err("bad-request");
        }
        let language = element
            .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
            .unwrap_or(inherited)
            .to_ascii_lowercase();
        if !language.is_empty() && !valid_language_tag(&language) {
            return Err("bad-request");
        }
        if !languages.insert(language) {
            return Err("bad-request");
        }
    }
    Ok(())
}

fn validate_stanza_error(error: Node<'_, '_>) -> std::result::Result<(), &'static str> {
    let Some(error_type) = error.attribute("type") else {
        return Err("bad-request");
    };
    if !matches!(
        error_type,
        "auth" | "cancel" | "continue" | "modify" | "wait"
    ) || error.attributes().any(|attribute| {
        attribute.namespace().is_none() && !matches!(attribute.name(), "type" | "by" | "code")
    }) || error
        .attribute("by")
        .is_some_and(|jid| crate::jid::CanonicalJid::parse(jid).is_err())
    {
        return Err("bad-request");
    }
    let conditions = error
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
                && child.tag_name().name() != "text"
        })
        .collect::<Vec<_>>();
    // RFC 6120 requires unknown future conditions in the standard namespace
    // to be treated as undefined-condition, not rejected at the stream edge.
    if conditions.len() != 1
        || conditions[0].children().any(|node| node.is_element())
        || (!matches!(conditions[0].tag_name().name(), "gone" | "redirect")
            && conditions[0]
                .text()
                .is_some_and(|text| !text.trim().is_empty()))
        || conditions[0].text().is_some_and(|text| {
            text.len() > 3_071 || text.chars().any(|character| character.is_control())
        })
    {
        return Err("bad-request");
    }
    let mut languages = std::collections::HashSet::new();
    for text in error.children().filter(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
            && child.tag_name().name() == "text"
    }) {
        if text.children().any(|node| node.is_element())
            || text.attributes().any(|attribute| {
                attribute.namespace() != Some("http://www.w3.org/XML/1998/namespace")
                    || attribute.name() != "lang"
            })
        {
            return Err("bad-request");
        }
        let language = text
            .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !language.is_empty() && !valid_language_tag(&language) {
            return Err("bad-request");
        }
        if !languages.insert(language) {
            return Err("bad-request");
        }
    }
    Ok(())
}

fn direct_client_children<'a, 'input>(root: Node<'a, 'input>, name: &str) -> Vec<Node<'a, 'input>> {
    let root_namespace = root.tag_name().namespace();
    root.children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == name
                && (child.tag_name().namespace() == root_namespace
                    // TCP frames are parsed outside their open XML stream, so
                    // an inherited `jabber:client` namespace appears as
                    // `None`. A redundantly explicit declaration on a core
                    // child must not bypass core stanza validation.
                    || (root_namespace.is_none()
                        && child.tag_name().namespace() == Some("jabber:client")))
        })
        .collect()
}

/// Validate the RFC 5646/BCP 47 well-formed syntax used by `xml:lang`.
/// Registry membership is intentionally not required: private-use and future
/// registered subtags remain valid, while malformed/duplicate extensions and
/// variants are rejected.
pub(crate) fn valid_language_tag(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 || !value.is_ascii() {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    const GRANDFATHERED: &[&str] = &[
        "art-lojban",
        "cel-gaulish",
        "en-gb-oed",
        "i-ami",
        "i-bnn",
        "i-default",
        "i-enochian",
        "i-hak",
        "i-klingon",
        "i-lux",
        "i-mingo",
        "i-navajo",
        "i-pwn",
        "i-tao",
        "i-tay",
        "i-tsu",
        "no-bok",
        "no-nyn",
        "sgn-be-fr",
        "sgn-be-nl",
        "sgn-ch-de",
        "zh-guoyu",
        "zh-hakka",
        "zh-min",
        "zh-min-nan",
        "zh-xiang",
    ];
    if GRANDFATHERED.contains(&lower.as_str()) {
        return true;
    }
    let parts = lower.split('-').collect::<Vec<_>>();
    if parts.iter().any(|part| {
        part.is_empty() || part.len() > 8 || !part.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }) {
        return false;
    }
    if parts[0] == "x" {
        return parts.len() > 1;
    }
    let primary = parts[0];
    if !primary.bytes().all(|byte| byte.is_ascii_alphabetic()) || !matches!(primary.len(), 2..=8) {
        return false;
    }
    let mut index = 1;
    if primary.len() <= 3 {
        let mut extlangs = 0;
        while index < parts.len()
            && parts[index].len() == 3
            && parts[index].bytes().all(|byte| byte.is_ascii_alphabetic())
            && extlangs < 3
        {
            extlangs += 1;
            index += 1;
        }
    }
    if index < parts.len()
        && parts[index].len() == 4
        && parts[index].bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        index += 1;
    }
    if index < parts.len()
        && ((parts[index].len() == 2
            && parts[index].bytes().all(|byte| byte.is_ascii_alphabetic()))
            || (parts[index].len() == 3 && parts[index].bytes().all(|byte| byte.is_ascii_digit())))
    {
        index += 1;
    }
    let mut variants = std::collections::HashSet::new();
    while index < parts.len()
        && ((parts[index].len() >= 5)
            || (parts[index].len() == 4
                && parts[index]
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_digit)))
    {
        if !variants.insert(parts[index]) {
            return false;
        }
        index += 1;
    }
    let mut extensions = std::collections::HashSet::new();
    while index < parts.len() && parts[index].len() == 1 && parts[index] != "x" {
        if !extensions.insert(parts[index]) {
            return false;
        }
        index += 1;
        let start = index;
        while index < parts.len() && (2..=8).contains(&parts[index].len()) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    if index < parts.len() && parts[index] == "x" {
        index += 1;
        if index == parts.len() {
            return false;
        }
        index = parts.len();
    }
    index == parts.len()
}

#[cfg(test)]
mod tests {
    use super::{valid_language_tag, validate_client_stanza};
    use roxmltree::Document;

    fn validate(xml: &str) -> std::result::Result<(), &'static str> {
        let document = Document::parse(xml).expect("test stanza must be well-formed XML");
        validate_client_stanza(document.root_element())
    }

    #[test]
    fn shared_validator_accepts_representative_client_stanzas() {
        for xml in [
            "<message type='chat' to='alice@example.test'><body>Hello</body></message>",
            "<presence xml:lang='en'><show>away</show><status>Busy</status></presence>",
            "<iq type='get' id='ping'><ping xmlns='urn:xmpp:ping'/></iq>",
        ] {
            assert_eq!(validate(xml), Ok(()), "{xml}");
        }
    }

    #[test]
    fn shared_validator_preserves_condition_specific_errors() {
        assert_eq!(
            validate("<message to='alice@bad domain'/>"),
            Err("jid-malformed")
        );
        assert_eq!(validate("<iq type='get' id='empty'/>"), Err("bad-request"));
    }

    #[test]
    fn language_validation_remains_available_to_other_protocol_modules() {
        assert!(valid_language_tag("zh-Hant-TW"));
        assert!(valid_language_tag("x-northstr-test"));
        assert!(!valid_language_tag("en--US"));
    }
}
