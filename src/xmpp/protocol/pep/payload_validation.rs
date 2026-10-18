//! Validate PEP payloads and their profile, avatar, bookmark, and OMEMO representations.

use super::*;

pub(super) fn valid_pep_payload(node: &str, item_id: &str, item: Node<'_, '_>) -> bool {
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

pub(super) fn valid_vcard4(payload: Node<'_, '_>) -> bool {
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

pub(crate) fn valid_avatar_data(item_id: &str, payload: Node<'_, '_>) -> bool {
    decode_avatar_data(payload)
        .is_some_and(|bytes| valid_png_image(&bytes) && sha1_matches(item_id, &bytes))
}

pub(super) fn decode_avatar_data(payload: Node<'_, '_>) -> Option<Vec<u8>> {
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

pub(crate) fn valid_avatar_metadata(item_id: &str, payload: Node<'_, '_>) -> bool {
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

pub(super) fn valid_sha1(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn valid_avatar_media_type(value: &str, allow_video: bool) -> bool {
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

pub(super) fn valid_http_url(value: &str) -> bool {
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
pub(crate) fn valid_png_image(bytes: &[u8]) -> bool {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if !bytes.starts_with(SIGNATURE) {
        return false;
    }

    let mut offset = SIGNATURE.len();
    let mut saw_ihdr = false;
    let mut saw_plte = false;
    let mut saw_idat = false;
    let mut left_idat_run = false;
    let mut color_type = 0_u8;

    while offset < bytes.len() {
        let Some(header_end) = offset.checked_add(8) else {
            return false;
        };
        if header_end > bytes.len() {
            return false;
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let chunk_type = &bytes[offset + 4..header_end];
        let Some(data_end) = header_end.checked_add(length) else {
            return false;
        };
        let Some(chunk_end) = data_end.checked_add(4) else {
            return false;
        };
        if chunk_end > bytes.len()
            || !chunk_type.iter().all(u8::is_ascii_alphabetic)
            || png_crc32(&bytes[offset + 4..data_end])
                != u32::from_be_bytes(bytes[data_end..chunk_end].try_into().unwrap())
        {
            return false;
        }

        match chunk_type {
            b"IHDR" => {
                if saw_ihdr || offset != SIGNATURE.len() || length != 13 {
                    return false;
                }
                let data = &bytes[header_end..data_end];
                let width = u32::from_be_bytes(data[0..4].try_into().unwrap());
                let height = u32::from_be_bytes(data[4..8].try_into().unwrap());
                let bit_depth = data[8];
                color_type = data[9];
                let valid_depth = match color_type {
                    0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
                    2 | 4 | 6 => matches!(bit_depth, 8 | 16),
                    3 => matches!(bit_depth, 1 | 2 | 4 | 8),
                    _ => false,
                };
                if width == 0
                    || height == 0
                    || !valid_depth
                    || data[10] != 0
                    || data[11] != 0
                    || data[12] > 1
                {
                    return false;
                }
                saw_ihdr = true;
            }
            b"PLTE" => {
                if !saw_ihdr
                    || saw_plte
                    || saw_idat
                    || matches!(color_type, 0 | 4)
                    || length == 0
                    || length > 768
                    || !length.is_multiple_of(3)
                {
                    return false;
                }
                saw_plte = true;
            }
            b"IDAT" => {
                if !saw_ihdr || left_idat_run || color_type == 3 && !saw_plte {
                    return false;
                }
                saw_idat = true;
            }
            b"IEND" => {
                return saw_ihdr && saw_idat && length == 0 && chunk_end == bytes.len();
            }
            // Unknown critical chunks cannot be interpreted safely. Unknown
            // ancillary chunks are explicitly forward-compatible in PNG.
            _ if chunk_type[0].is_ascii_uppercase() => return false,
            _ => {
                if !saw_ihdr {
                    return false;
                }
            }
        }
        if saw_idat && chunk_type != b"IDAT" {
            left_idat_run = true;
        }
        offset = chunk_end;
    }
    false
}

pub(super) fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

pub(super) fn sha1_matches(expected: &str, bytes: &[u8]) -> bool {
    let digest = Sha1::digest(bytes);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    actual.eq_ignore_ascii_case(expected)
}

pub(super) fn valid_bookmark(item_id: &str, conference: Node<'_, '_>) -> bool {
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

pub(super) fn valid_omemo_bundle(bundle: Node<'_, '_>) -> bool {
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

pub(super) fn valid_leaf_b64_exact(node: Node<'_, '_>, decoded_len: usize) -> bool {
    !node.children().any(|child| child.is_element())
        && node
            .text()
            .is_some_and(|text| valid_b64_exact(text, decoded_len))
}

pub(super) fn valid_b64_exact(value: &str, decoded_len: usize) -> bool {
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

pub(super) fn parse_positive_i32(value: &str) -> Option<i32> {
    value.parse::<i32>().ok().filter(|value| *value > 0)
}
