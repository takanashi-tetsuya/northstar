//! Validate PEP payloads and their profile, avatar, bookmark, and OMEMO representations.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use northstar_xmpp_avatar::{
    valid_avatar_data, valid_avatar_metadata, AVATAR_DATA, AVATAR_METADATA,
};
use northstar_xmpp_types::text::contains_unsafe_bidi_controls;
use roxmltree::Node;
use std::collections::HashSet;

const NS_OMEMO2: &str = "urn:xmpp:omemo:2";
const OMEMO_DEVICES: &str = "urn:xmpp:omemo:2:devices";
const OMEMO_BUNDLES: &str = "urn:xmpp:omemo:2:bundles";
const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
const VCARD4: &str = "urn:xmpp:vcard4";
const CONTACTS: &str = "urn:xmpp:contacts";

fn valid_bare_jid(value: &str) -> bool {
    northstar_xmpp_types::jid::CanonicalJid::parse_bare(value).is_ok()
}

pub(crate) fn xml_subtree_contains_unsafe_bidi_controls(node: Node<'_, '_>) -> bool {
    node.descendants().any(|descendant| {
        descendant.text().is_some_and(contains_unsafe_bidi_controls)
            || descendant
                .attributes()
                .any(|attribute| contains_unsafe_bidi_controls(attribute.value()))
    })
}

/// Whether the PEP item `item` with id `item_id` holds exactly one payload, and a valid one where `node` is
/// a profile, avatar, bookmark, contact or OMEMO node.
pub fn valid_pep_payload(node: &str, item_id: &str, item: Node<'_, '_>) -> bool {
    let payloads = item
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if payloads.len() != 1 {
        return false;
    }
    let payload = payloads[0];
    match node {
        BOOKMARKS2 => valid_bookmark(item_id, payload),
        AVATAR_DATA => valid_avatar_data(item_id, payload),
        AVATAR_METADATA => valid_avatar_metadata(item_id, payload),
        VCARD4 => valid_vcard4(payload),
        CONTACTS => valid_bare_jid(item_id) && item_id.contains('@') && valid_vcard4(payload),
        OMEMO_DEVICES => {
            if payload.tag_name().name() != "devices"
                || payload.tag_name().namespace() != Some(NS_OMEMO2)
                || payload.attributes().len() != 0
            {
                return false;
            }
            let mut ids = HashSet::new();
            let devices = payload
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            devices.len() <= 1_000
                && devices.iter().all(|device| {
                    device.tag_name().name() == "device"
                        && device.tag_name().namespace() == Some(NS_OMEMO2)
                        && !device.children().any(|child| child.is_element())
                        && device.text().is_none_or(|text| text.trim().is_empty())
                        && device.attributes().all(|attribute| {
                            attribute.namespace().is_none()
                                && matches!(attribute.name(), "id" | "label" | "labelsig")
                        })
                        && device.attribute("label").is_none_or(|label| {
                            !label.chars().any(char::is_control) && label.chars().count() <= 256
                        })
                        // `label` and `labelsig` are public presentation
                        // metadata authenticated end to end by the device
                        // identity key. XEP-0384 requires a receiving client
                        // to ignore an unsigned or invalid label; the server
                        // must not turn that into rejection of the device
                        // announcement. Keep only a transport resource bound.
                        && device
                            .attribute("labelsig")
                            .is_none_or(|signature| signature.chars().count() <= 4_096)
                        && device
                            .attribute("id")
                            .and_then(parse_positive_i32)
                            .is_some_and(|id| ids.insert(id))
                })
        }
        OMEMO_BUNDLES => {
            parse_positive_i32(item_id).is_some()
                && payload.tag_name().name() == "bundle"
                && payload.tag_name().namespace() == Some(NS_OMEMO2)
                && valid_omemo_bundle(payload)
        }
        _ => true,
    }
}

fn valid_vcard4(payload: Node<'_, '_>) -> bool {
    const VCARD4_NS: &str = "urn:ietf:params:xml:ns:vcard-4.0";
    if payload.tag_name().name() != "vcard"
        || payload.tag_name().namespace() != Some(VCARD4_NS)
        || xml_subtree_contains_unsafe_bidi_controls(payload)
        || payload.attributes().len() != 0
        || payload.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
        || payload
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(VCARD4_NS)
                    && node.tag_name().name() == "fn"
            })
            .count()
            == 0
    {
        return false;
    }

    // RFC 6351 requires core and registered xCard element names to be
    // lower-case, while also requiring parsers to preserve/ignore extension
    // namespaces they do not understand.  Validate the mandatory FN value
    // without rejecting such namespaced extensions.
    if payload.descendants().any(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(VCARD4_NS)
            && node
                .tag_name()
                .name()
                .bytes()
                .any(|byte| byte.is_ascii_uppercase())
    }) {
        return false;
    }
    payload
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(VCARD4_NS)
                && node.tag_name().name() == "fn"
        })
        .all(|formatted_name| {
            if formatted_name.children().any(|child| {
                child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
            }) {
                return false;
            }
            let children = formatted_name
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            matches!(
                children.as_slice(),
                [text]
                    if text.tag_name().namespace() == Some(VCARD4_NS)
                        && text.tag_name().name() == "text"
            ) || matches!(
                children.as_slice(),
                [parameters, text]
                    if parameters.tag_name().namespace() == Some(VCARD4_NS)
                        && parameters.tag_name().name() == "parameters"
                        && text.tag_name().namespace() == Some(VCARD4_NS)
                        && text.tag_name().name() == "text"
            )
        })
}

fn valid_bookmark(item_id: &str, conference: Node<'_, '_>) -> bool {
    if conference.tag_name().name() != "conference"
        || conference.tag_name().namespace() != Some(BOOKMARKS2)
        || conference.attribute("jid").is_some()
        || item_id.contains('/')
        || !item_id.contains('@')
        || !valid_bare_jid(item_id)
        || conference
            .attributes()
            .any(|attribute| !matches!(attribute.name(), "autojoin" | "name"))
        || conference.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }
    if conference
        .attribute("autojoin")
        .is_some_and(|value| !matches!(value, "0" | "1" | "false" | "true"))
    {
        return false;
    }
    let mut previous_order = 0_u8;
    conference
        .children()
        .filter(|child| child.is_element())
        .all(|child| {
            if child.tag_name().namespace() != Some(BOOKMARKS2) {
                return false;
            }
            let order = match child.tag_name().name() {
                "nick" => 1,
                "password" => 2,
                "extensions" => 3,
                _ => return false,
            };
            if order <= previous_order {
                return false;
            }
            previous_order = order;
            if child.attributes().len() != 0
                || child.children().any(|nested| {
                    nested.is_text()
                        && nested
                            .text()
                            .is_some_and(|text| order == 3 && !text.trim().is_empty())
                })
            {
                return false;
            }
            if order < 3 {
                !child.children().any(|nested| nested.is_element())
            } else {
                child
                    .children()
                    .filter(|nested| nested.is_element())
                    .all(|nested| nested.tag_name().namespace() != Some(BOOKMARKS2))
            }
        })
}

fn valid_omemo_bundle(bundle: Node<'_, '_>) -> bool {
    if bundle.attributes().len() != 0 {
        return false;
    }
    let children = bundle
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if children.len() != 4
        || children
            .iter()
            .any(|child| child.tag_name().namespace() != Some(NS_OMEMO2))
    {
        return false;
    }
    let exactly_one = |name: &str| {
        children
            .iter()
            .filter(|child| child.tag_name().name() == name)
            .count()
            == 1
    };
    if !["spk", "spks", "ik", "prekeys"]
        .iter()
        .all(|name| exactly_one(name))
    {
        return false;
    }
    let spk = children
        .iter()
        .find(|child| child.tag_name().name() == "spk")
        .copied()
        .expect("checked above");
    let spks = children
        .iter()
        .find(|child| child.tag_name().name() == "spks")
        .copied()
        .expect("checked above");
    let identity = children
        .iter()
        .find(|child| child.tag_name().name() == "ik")
        .copied()
        .expect("checked above");
    if spk
        .attributes()
        .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
        || spk.attribute("id").and_then(parse_positive_i32).is_none()
        || !valid_leaf_b64_exact(spk, 32)
        || spks.attributes().len() != 0
        || !valid_leaf_b64_exact(spks, 64)
        || identity.attributes().len() != 0
        || !valid_leaf_b64_exact(identity, 32)
    {
        return false;
    }
    let prekeys = children
        .iter()
        .find(|child| child.tag_name().name() == "prekeys")
        .copied()
        .expect("checked above");
    if prekeys.attributes().len() != 0 {
        return false;
    }
    let mut ids = HashSet::new();
    let keys = prekeys
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    keys.len() >= 25
        && keys.len() <= 1000
        && keys.iter().all(|key| {
            key.tag_name().name() == "pk"
                && key.tag_name().namespace() == Some(NS_OMEMO2)
                && key
                    .attributes()
                    .all(|attribute| attribute.namespace().is_none() && attribute.name() == "id")
                && valid_leaf_b64_exact(*key, 32)
                && key
                    .attribute("id")
                    .and_then(parse_positive_i32)
                    .is_some_and(|id| ids.insert(id))
        })
}

fn valid_leaf_b64_exact(node: Node<'_, '_>, decoded_len: usize) -> bool {
    !node.children().any(|child| child.is_element())
        && node
            .text()
            .is_some_and(|text| valid_b64_exact(text, decoded_len))
}

fn valid_b64_exact(value: &str, decoded_len: usize) -> bool {
    if value.len() > decoded_len.saturating_mul(2).saturating_add(16) {
        return false;
    }
    let compact = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    BASE64
        .decode(compact)
        .is_ok_and(|decoded| decoded.len() == decoded_len)
}

fn parse_positive_i32(value: &str) -> Option<i32> {
    value.parse::<i32>().ok().filter(|value| *value > 0)
}
