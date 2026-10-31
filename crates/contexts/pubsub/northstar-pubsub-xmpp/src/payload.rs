//! Validate PEP payloads and their profile, avatar, bookmark, and OMEMO representations.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use northstar_pubsub_application::profile::detected_media_type as detected_avatar_media_type;
pub use northstar_pubsub_application::profile::valid_png_image;
use northstar_xmpp_types::text::contains_unsafe_bidi_controls;
use roxmltree::Node;
use sha1::{Digest, Sha1};
use std::collections::HashSet;

const NS_OMEMO2: &str = "urn:xmpp:omemo:2";
const OMEMO_DEVICES: &str = "urn:xmpp:omemo:2:devices";
const OMEMO_BUNDLES: &str = "urn:xmpp:omemo:2:bundles";
const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";
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

/// Whether `payload` is XEP-0084 avatar data: base64 of a supported image of at most 256 KiB, a PNG
/// being well formed, whose SHA-1 is `item_id`.
pub fn valid_avatar_data(item_id: &str, payload: Node<'_, '_>) -> bool {
    decode_avatar_data(payload)
        .is_some_and(|bytes| valid_png_image(&bytes) && sha1_matches(item_id, &bytes))
}

fn decode_avatar_data(payload: Node<'_, '_>) -> Option<Vec<u8>> {
    if payload.tag_name().name() != "data"
        || payload.tag_name().namespace() != Some(AVATAR_DATA)
        || payload.attributes().len() != 0
        || payload.children().any(|child| child.is_element())
    {
        return None;
    }
    let encoded = payload
        .children()
        .filter_map(|child| child.text())
        .collect::<String>()
        .replace(|character: char| character.is_whitespace(), "");
    let bytes = BASE64.decode(encoded).ok()?;
    (!bytes.is_empty() && bytes.len() <= 256 * 1024 && detected_avatar_media_type(&bytes).is_some())
        .then_some(bytes)
}

/// Whether `payload` is valid XEP-0084 avatar metadata for the item `item_id`.
pub fn valid_avatar_metadata(item_id: &str, payload: Node<'_, '_>) -> bool {
    if payload.tag_name().name() != "metadata"
        || payload.tag_name().namespace() != Some(AVATAR_METADATA)
        || payload.attributes().len() != 0
        || payload.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }
    let children = payload
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if children.is_empty() {
        return true;
    }

    let mut saw_pointer = false;
    let mut png_matches_item = false;
    let mut has_png_representation = false;
    let mut info_count = 0usize;
    for child in children {
        if child.tag_name().namespace() != Some(AVATAR_METADATA) {
            return false;
        }
        match child.tag_name().name() {
            "info" if !saw_pointer => {
                info_count += 1;
                if child.children().any(|nested| nested.is_element())
                    || child.text().is_some_and(|text| !text.trim().is_empty())
                    || child.attributes().any(|attribute| {
                        !matches!(
                            attribute.name(),
                            "bytes" | "height" | "id" | "type" | "url" | "width"
                        )
                    })
                {
                    return false;
                }
                let Some(bytes) = child
                    .attribute("bytes")
                    .and_then(|value| value.parse::<usize>().ok())
                else {
                    return false;
                };
                let Some(hash) = child.attribute("id").filter(|hash| valid_sha1(hash)) else {
                    return false;
                };
                let Some(media_type) = child.attribute("type") else {
                    return false;
                };
                let has_url = child.attribute("url").is_some();
                if !valid_avatar_media_type(media_type, has_url) {
                    return false;
                }
                if bytes > 256 * 1024
                    || child
                        .attribute("height")
                        .is_some_and(|value| value.parse::<u16>().is_err())
                    || child
                        .attribute("width")
                        .is_some_and(|value| value.parse::<u16>().is_err())
                    || child
                        .attribute("url")
                        .is_some_and(|url| !valid_http_url(url))
                {
                    return false;
                }
                if media_type.eq_ignore_ascii_case("image/png") {
                    has_png_representation = true;
                    if hash.eq_ignore_ascii_case(item_id) {
                        png_matches_item = true;
                    }
                }
            }
            "pointer" if info_count > 0 => {
                saw_pointer = true;
                if child.attributes().any(|attribute| {
                    !matches!(
                        attribute.name(),
                        "bytes" | "height" | "id" | "type" | "width"
                    )
                }) || child
                    .attribute("bytes")
                    .is_some_and(|value| value.parse::<usize>().is_err())
                    || child
                        .attribute("height")
                        .is_some_and(|value| value.parse::<u32>().is_err())
                    || child
                        .attribute("width")
                        .is_some_and(|value| value.parse::<u32>().is_err())
                    || child
                        .attribute("id")
                        .is_some_and(|value| !valid_sha1(value))
                    || child
                        .attribute("type")
                        .is_some_and(|value| !valid_avatar_media_type(value, true))
                    || child.children().any(|nested| {
                        nested.is_text()
                            && nested.text().is_some_and(|text| !text.trim().is_empty())
                    })
                {
                    return false;
                }
                let nested = child
                    .children()
                    .filter(|nested| nested.is_element())
                    .collect::<Vec<_>>();
                if nested.len() != 1
                    || nested[0].tag_name().namespace().is_none_or(str::is_empty)
                    || nested[0].tag_name().namespace() == Some(AVATAR_METADATA)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
    // XEP-0084 binds the metadata ItemID to the mandatory PNG
    // representation. The PNG itself may be hosted at an HTTP URL; that is a
    // valid XEP-0084 publication even though it cannot be projected into
    // vCard-temp without the service becoming an HTTP fetcher.
    info_count > 0 && has_png_representation && png_matches_item
}

fn valid_sha1(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_avatar_media_type(value: &str, allow_video: bool) -> bool {
    let Some((top_level, subtype)) = value.split_once('/') else {
        return false;
    };
    value.len() <= 127
        && (top_level.eq_ignore_ascii_case("image")
            || allow_video && top_level.eq_ignore_ascii_case("video"))
        && !subtype.is_empty()
        && !subtype.contains('/')
        && subtype.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}

fn valid_http_url(value: &str) -> bool {
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once("://") else {
        return false;
    };
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    !remainder
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .is_empty()
}

/// Validate the PNG container before accepting it as an XEP-0084 image.
///
/// A magic-byte check is not sufficient: it permits arbitrary content to be
/// published under the mandatory `image/png` representation. This parser is
/// bounded by the avatar payload quota and verifies chunk bounds and CRCs, the
/// required chunk state machine, IHDR fields, critical-chunk names, and the
/// absence of trailing data. Image decompression remains the client's task.
fn sha1_matches(expected: &str, bytes: &[u8]) -> bool {
    let digest = Sha1::digest(bytes);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    actual.eq_ignore_ascii_case(expected)
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
