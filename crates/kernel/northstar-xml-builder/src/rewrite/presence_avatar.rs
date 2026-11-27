use super::append_root_element;
use crate::{ValidatedXmlFragment, XmlElement};
use roxmltree::Document;

const UPDATE_NS: &str = "vcard-temp:x:update";

/// Projects the authoritative avatar update, keeping a schema-shaped opt-out intact.
/// `None` omits the update; `Some(None)` emits the empty-photo wire form.
/// Malformed cached XML is not eligible for replay.
pub fn project_presence_avatar(raw: &str, authority: Option<Option<&str>>) -> Option<String> {
    let document = Document::parse(raw).ok()?;
    let updates = document
        .root_element()
        .children()
        .filter(|child| child.has_tag_name((UPDATE_NS, "x")))
        .collect::<Vec<_>>();
    if let [update] = updates.as_slice() {
        let elements = update
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        if update.attributes().len() == 0
            && update
                .children()
                .filter(|child| child.is_text())
                .all(|child| child.text().is_none_or(|text| text.trim().is_empty()))
            && matches!(elements.as_slice(), [photo]
            if photo.has_tag_name((UPDATE_NS, "photo"))
                && photo.attributes().len() == 0
                && photo.children().all(|child| {
                    !child.is_element()
                        && (!child.is_text()
                            || child.text().is_none_or(|text| text.trim().is_empty()))
                }))
        {
            return Some(raw.to_owned());
        }
    }
    ValidatedXmlFragment::parse(raw).ok()?;

    let update = authority.map(|hash| {
        let mut photo = XmlElement::new("photo");
        if let Some(hash) = hash {
            photo = photo.text(hash);
        }
        XmlElement::namespaced("x", UPDATE_NS).child(photo)
    });
    if updates.is_empty() {
        return match update {
            Some(update) => append_root_element(raw, &update),
            None => Some(raw.to_owned()),
        };
    }
    let mut projected = raw.to_owned();
    let replacement = update.map_or_else(String::new, |update| update.finish());
    for (index, update) in updates.into_iter().enumerate().rev() {
        projected.replace_range(update.range(), if index == 0 { &replacement } else { "" });
    }
    Some(projected)
}
