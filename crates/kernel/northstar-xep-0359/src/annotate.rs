//! Rewrites the XEP-0359 authority assertions of a serialized stanza.

use northstar_xml_builder::rewrite::append_root_validated_fragment;
use roxmltree::Document;

pub fn add_stanza_id(stanza: &str, by: &str, id: uuid::Uuid) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let Ok(canonical_by) = northstar_xmpp_types::jid::CanonicalJid::parse(by) else {
        return stanza.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "stanza-id"
                && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
                && crate::parse_stanza_id(*node).is_ok_and(|existing| existing.by == canonical_by)
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut annotated = stanza.to_owned();
    for range in ranges {
        annotated.replace_range(range, "");
    }
    let Ok(extension) = crate::build_stanza_id(&id.to_string(), &canonical_by) else {
        return annotated;
    };
    append_root_validated_fragment(&annotated, &extension).unwrap_or(annotated)
}

/// Remove every XEP-0359 authority assertion for a domain controlled by this
/// server. A client or remote peer must not be able to avoid deduplication by
/// adding a second, forged local-account issuer next to the server's ID.
/// Foreign-domain IDs are preserved as forwarded provenance.
pub fn strip_stanza_ids_by_domain(stanza: &str, domain: &str) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let Ok(domain) = northstar_xmpp_types::jid::prepare_domainpart(domain) else {
        return stanza.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "stanza-id"
                && node.tag_name().namespace() == Some(crate::NAMESPACE)
                && crate::parse_stanza_id(*node)
                    .is_ok_and(|stanza_id| stanza_id.by.domainpart() == domain)
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut cleaned = stanza.to_owned();
    for range in ranges {
        cleaned.replace_range(range, "");
    }
    cleaned
}
