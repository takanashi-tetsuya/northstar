//! XEP-0084 User Avatar: the data and metadata namespaces, the payload checks of both nodes and
//! the image checks the vCard-temp avatar projection shares with them.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use roxmltree::Node;
use sha1::{Digest, Sha1};

/// The XEP-0084 avatar data node and payload namespace.
pub const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
/// The XEP-0084 avatar metadata node and payload namespace.
pub const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";

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
    (!bytes.is_empty() && bytes.len() <= 256 * 1024 && detected_media_type(&bytes).is_some())
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

fn sha1_matches(expected: &str, bytes: &[u8]) -> bool {
    let digest = Sha1::digest(bytes);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    actual.eq_ignore_ascii_case(expected)
}

/// The lowercase hexadecimal SHA-1 of `bytes`, the XEP-0084 avatar id.
pub fn sha1_hex(bytes: &[u8]) -> String {
    Sha1::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The image media type that the magic bytes of `bytes` announce, if it is a supported one.
pub fn detected_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"BM") {
        Some("image/bmp")
    } else if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        Some("image/tiff")
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/vnd.microsoft.icon")
    } else if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        match &bytes[8..12] {
            b"avif" | b"avis" => Some("image/avif"),
            b"heic" | b"heix" | b"hevc" | b"hevx" => Some("image/heic"),
            b"mif1" | b"msf1" => Some("image/heif"),
            _ => None,
        }
    } else {
        None
    }
}

/// Validate the PNG container before accepting it as an XEP-0084 image.
///
/// A magic-byte check is not sufficient: it permits arbitrary content to be
/// published under the mandatory `image/png` representation. This parser is
/// bounded by the avatar payload quota and verifies chunk bounds and CRCs, the
/// required chunk state machine, IHDR fields, critical-chunk names, and the
/// absence of trailing data. Image decompression remains the client's task.
///
/// Strict enough to reject truncated, reordered, CRC-corrupted or trailing
/// PNG containers used as a metadata hash oracle.
pub fn valid_png_image(bytes: &[u8]) -> bool {
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

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
