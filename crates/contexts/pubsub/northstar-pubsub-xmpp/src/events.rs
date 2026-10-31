//! PEP event rendering shared by the PEP and vCard handlers.

use anyhow::Result;
use northstar_xml_builder::XmlElement;

const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";

/// Removes only an `<item>` root's inherited PubSub namespace before the
/// item is embedded below `pubsub#event`. Nested payload namespace
/// declarations are deliberately preserved.
pub fn strip_pubsub_item_root_namespaces(payload: &str) -> Result<String> {
    let root = XmlElement::new("root");
    let prefix_len = root.open().len();
    let wrapped = root.validated_fragment(payload)?.finish();
    let document = roxmltree::Document::parse(&wrapped)?;
    let single = format!(" xmlns='{NS_PUBSUB}'");
    let double = format!(" xmlns=\"{NS_PUBSUB}\"");
    let mut openings = document
        .root_element()
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "item")
        .filter_map(|item| {
            let range = item.range();
            let start = range.start.checked_sub(prefix_len)?;
            let end = payload[start..].find('>').map(|end| start + end)?;
            Some((start, end))
        })
        .collect::<Vec<_>>();
    let mut output = payload.to_owned();
    openings.sort_unstable_by_key(|(start, _)| std::cmp::Reverse(*start));
    for (start, end) in openings {
        let opening = output[start..=end].to_owned();
        let cleaned = opening.replace(&single, "").replace(&double, "");
        output.replace_range(start..=end, &cleaned);
    }
    Ok(output)
}

/// Renders the `<items/>` event of one profile item published on `node`.
pub fn profile_item_event(node: &str, payload: &str) -> Result<String> {
    let payload = strip_pubsub_item_root_namespaces(payload)?;
    let mut event = XmlElement::new("items").attr("node", node);
    event.push_validated_fragment(&payload)?;
    Ok(event.finish())
}
