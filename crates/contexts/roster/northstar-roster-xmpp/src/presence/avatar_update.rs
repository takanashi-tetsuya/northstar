//! Server-authoritative XEP-0153 avatar hash in presence updates.

use northstar_xml_builder::rewrite::append_root_element;
use northstar_xml_builder::{ValidatedXmlFragment, XmlElement};
use roxmltree::{Document, Node};

/// `raw` with its XEP-0153 update replaced by the avatar `hash` the server stored.
pub fn inject_vcard_avatar_hash(raw: &str, _node: Node<'_, '_>, hash: Option<&str>) -> String {
    let Ok(document) = Document::parse(raw) else {
        return raw.to_owned();
    };
    let node = document.root_element();
    let updates = node
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "x"
                && child.tag_name().namespace() == Some("vcard-temp:x:update")
        })
        .collect::<Vec<_>>();
    // XEP-0398 preserves the sender's explicit empty-photo opt-out only when
    // it is an unambiguous, schema-shaped update. A second update, attributes,
    // extra elements or a second photo must not let a client smuggle a forged
    // hash past the server-authoritative conversion.
    if let [update] = updates.as_slice() {
        let elements = update
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        let explicit_empty = update.attributes().len() == 0
            && update
                .children()
                .filter(|child| child.is_text())
                .all(|child| child.text().is_none_or(|text| text.trim().is_empty()))
            && matches!(elements.as_slice(), [photo]
                if photo.tag_name().name() == "photo"
                    && photo.tag_name().namespace() == Some("vcard-temp:x:update")
                    && photo.attributes().len() == 0
                    && !photo.children().any(|child| child.is_element())
                    && photo.text().is_none_or(|text| text.trim().is_empty()));
        if explicit_empty {
            return raw.to_owned();
        }
    }
    let mut x_ranges = updates
        .iter()
        .map(|child| child.range())
        .collect::<Vec<_>>();

    let mut photo = XmlElement::new("photo");
    if let Some(hash) = hash {
        photo = photo.text(hash.to_owned());
    }
    let extension = XmlElement::namespaced("x", "vcard-temp:x:update").child(photo);

    let Some(first) = x_ranges.first().cloned() else {
        return append_root_element(raw, &extension).unwrap_or_else(|| raw.to_owned());
    };
    if ValidatedXmlFragment::parse(raw).is_err() {
        return raw.to_owned();
    }
    x_ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let extension = extension.finish();
    let mut rewritten = raw.to_owned();
    for range in x_ranges {
        rewritten.replace_range(range.clone(), if range == first { &extension } else { "" });
    }
    rewritten
}
