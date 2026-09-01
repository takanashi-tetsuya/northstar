use super::{Action, ProtocolSession};
use crate::services::profile::{
    AvatarPresenceUpdate, LegacyVCardWrite, ProfileAudienceSnapshot, ProfilePublishStatus,
    PublicVCard,
};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use roxmltree::Node;
use sha1::{Digest, Sha1};

const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";

struct ConvertedAvatarItems {
    data: Option<(String, String)>,
    metadata: (String, String),
}

fn converted_avatar_items(
    avatar: Option<&(String, Vec<u8>)>,
    hash: Option<&str>,
) -> ConvertedAvatarItems {
    if let (Some((media_type, bytes)), Some(hash)) = (avatar, hash) {
        let encoded = BASE64.encode(bytes);
        let data_item = XmlElement::new("item")
            .attr("id", hash)
            .child(XmlElement::namespaced("data", AVATAR_DATA).text(encoded))
            .finish();
        let metadata_item = XmlElement::new("item")
            .attr("id", hash)
            .child(
                XmlElement::namespaced("metadata", AVATAR_METADATA).child(
                    XmlElement::new("info")
                        .attr("bytes", bytes.len())
                        .attr("id", hash)
                        .attr("type", media_type),
                ),
            )
            .finish();
        ConvertedAvatarItems {
            data: Some((hash.to_owned(), data_item)),
            metadata: (hash.to_owned(), metadata_item),
        }
    } else {
        ConvertedAvatarItems {
            data: None,
            metadata: (
                "current".to_owned(),
                XmlElement::new("item")
                    .attr("id", "current")
                    .child(XmlElement::namespaced("metadata", AVATAR_METADATA))
                    .finish(),
            ),
        }
    }
}

fn sha1_hex(bytes: &[u8]) -> String {
    let digest = Sha1::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn detected_media_type(bytes: &[u8]) -> Option<&'static str> {
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

fn decoded_vcard_avatar(vcard: Node<'_, '_>) -> std::result::Result<Option<(String, Vec<u8>)>, ()> {
    let photos = vcard
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "PHOTO"
                && child.tag_name().namespace() == Some("vcard-temp")
        })
        .collect::<Vec<_>>();
    if photos.len() > 1 {
        return Err(());
    }
    let Some(photo) = photos.first() else {
        return Ok(None);
    };
    let children = photo
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    let named = |name: &str| {
        children
            .iter()
            .copied()
            .filter(|child| {
                child.tag_name().name() == name
                    && child.tag_name().namespace() == Some("vcard-temp")
            })
            .collect::<Vec<_>>()
    };
    let bins = named("BINVAL");
    if bins.is_empty() {
        return Ok(None);
    }
    let types = named("TYPE");
    if bins.len() != 1 || types.len() != 1 || !named("EXTVAL").is_empty() {
        return Err(());
    }
    for node in [bins[0], types[0]] {
        if node.attributes().len() != 0 || node.children().any(|child| child.is_element()) {
            return Err(());
        }
    }
    let encoded = bins[0]
        .children()
        .filter_map(|child| child.text())
        .collect::<String>();
    if encoded.is_empty() {
        return Ok(None);
    }
    let declared_media_type = types[0]
        .children()
        .filter_map(|child| child.text())
        .collect::<String>();
    if declared_media_type.is_empty() {
        return Err(());
    }
    let bytes = BASE64.decode(encoded).map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        return Err(());
    }
    let actual_media_type = detected_media_type(&bytes).ok_or(())?;
    if !declared_media_type.eq_ignore_ascii_case(actual_media_type) {
        return Err(());
    }
    if actual_media_type == "image/png" && !super::pep::valid_png_image(&bytes) {
        return Err(());
    }
    Ok(Some((actual_media_type.to_owned(), bytes)))
}

fn valid_vcard_temp(vcard: Node<'_, '_>) -> bool {
    if vcard.tag_name().name() != "vCard"
        || vcard.tag_name().namespace() != Some("vcard-temp")
        || xml_subtree_contains_unsafe_bidi_controls(vcard)
        || vcard.attributes().any(|attribute| {
            attribute.name() != "version" || !matches!(attribute.value(), "2.0" | "3.0")
        })
        || vcard.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }

    for element in vcard.descendants().filter(|node| node.is_element()).skip(1) {
        let name = element.tag_name().name();
        if element.tag_name().namespace() != Some("vcard-temp")
            || !name.bytes().all(|byte| !byte.is_ascii_lowercase())
            || name == "COUNTRY"
            || element.attributes().len() != 0
        {
            return false;
        }
    }

    let ordered_children = |container: Node<'_, '_>, allowed: &[&str], required: &str| {
        let mut previous = None;
        let mut required_count = 0_usize;
        for child in container.children().filter(|child| child.is_element()) {
            let Some(position) = allowed
                .iter()
                .position(|name| *name == child.tag_name().name())
            else {
                return false;
            };
            if previous.is_some_and(|previous| position <= previous)
                || child.children().any(|nested| nested.is_element())
            {
                return false;
            }
            previous = Some(position);
            if child.tag_name().name() == required {
                required_count += 1;
            }
        }
        required_count == 1
    };

    for telephone in vcard.children().filter(|child| {
        child.is_element()
            && child.tag_name().name() == "TEL"
            && child.tag_name().namespace() == Some("vcard-temp")
    }) {
        if telephone.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        }) || !ordered_children(
            telephone,
            &[
                "HOME", "WORK", "VOICE", "FAX", "PAGER", "MSG", "CELL", "VIDEO", "BBS", "MODEM",
                "ISDN", "PCS", "PREF", "NUMBER",
            ],
            "NUMBER",
        ) {
            return false;
        }
    }

    for email in vcard.children().filter(|child| {
        child.is_element()
            && child.tag_name().name() == "EMAIL"
            && child.tag_name().namespace() == Some("vcard-temp")
    }) {
        if email.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        }) || !ordered_children(
            email,
            &["HOME", "WORK", "INTERNET", "PREF", "X400", "USERID"],
            "USERID",
        ) {
            return false;
        }
    }

    let photos = vcard
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "PHOTO"
                && child.tag_name().namespace() == Some("vcard-temp")
        })
        .collect::<Vec<_>>();
    if photos.len() > 1 {
        return false;
    }
    photos.first().is_none_or(|photo| {
        if photo.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        }) {
            return false;
        }
        let names = photo
            .children()
            .filter(|child| child.is_element())
            .map(|child| child.tag_name().name())
            .collect::<Vec<_>>();
        (names.as_slice() == ["TYPE", "BINVAL"] || names.as_slice() == ["EXTVAL"])
            && photo
                .children()
                .filter(|child| child.is_element())
                .all(|child| !child.children().any(|nested| nested.is_element()))
    })
}

impl ProtocolSession {
    pub(crate) async fn vcard_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        let Some(requester) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let (owner_name, response_from, is_self) = if let Some(to) = iq.attribute("to") {
            let Ok(target) = crate::jid::CanonicalJid::parse_bare(to) else {
                return Ok(Action::Send(iq_error(id, "jid-malformed")));
            };
            if target.domainpart() != self.state.config.domain {
                return Ok(Action::Send(iq_error(id, "item-not-found")));
            }
            let Some(localpart) = target.localpart() else {
                return Ok(Action::Send(iq_error(id, "service-unavailable")));
            };
            (
                localpart.to_owned(),
                Some(target.to_string()),
                localpart == requester.username,
            )
        } else {
            (requester.username.clone(), None, true)
        };
        let profile = self
            .state
            .profile_service()
            .public_vcard(&owner_name)
            .await?;
        let payload = match profile {
            PublicVCard::Profile(Some(payload)) => payload,
            PublicVCard::Profile(None) if is_self => {
                XmlElement::namespaced("vCard", "vcard-temp").finish()
            }
            PublicVCard::MissingAccount | PublicVCard::Profile(None) => {
                // XEP-0054 requires the same response for a nonexistent
                // account and an existing account without a public vCard.
                return Ok(Action::Send(if let Some(from) = response_from.as_deref() {
                    iq_error_from(id, from, "service-unavailable")
                } else {
                    iq_error(id, "service-unavailable")
                }));
            }
        };
        if let Some(from) = response_from.as_deref() {
            Ok(Action::Send(iq_result_from(id, from, &payload)))
        } else {
            Ok(Action::Send(iq_result(id, &payload)))
        }
    }

    pub(crate) async fn vcard_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        vcard: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if !valid_vcard_temp(vcard) {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        if iq.attribute("to").is_some_and(|to| {
            !crate::jid::CanonicalJid::parse_bare(to).is_ok_and(|target| {
                target.localpart() == Some(user.username.as_str())
                    && target.domainpart() == self.state.config.domain
            })
        }) {
            return Ok(Action::Send(iq_error(id, "forbidden")));
        }
        let range = vcard.range();
        let payload = &raw[range];
        if payload.len() > 512 * 1024 {
            return Ok(Action::Send(iq_error(id, "resource-constraint")));
        }
        let avatar = match decoded_vcard_avatar(vcard) {
            Ok(avatar) => avatar,
            Err(()) => return Ok(Action::Send(iq_error(id, "not-acceptable"))),
        };
        let avatar_hash = avatar.as_ref().map(|(_, bytes)| sha1_hex(bytes));
        let converted = converted_avatar_items(avatar.as_ref(), avatar_hash.as_deref());
        let data = converted
            .data
            .as_ref()
            .map(|(item_id, item)| (item_id.as_str(), item.as_str()));
        let metadata = (converted.metadata.0.as_str(), converted.metadata.1.as_str());
        let metadata_event =
            super::pep::profile_item_event(AVATAR_METADATA, &converted.metadata.1)?;
        let audience_state = std::sync::Arc::clone(&self.state);
        let publisher_full_jid = self.full_jid.clone();
        let outcome = match self
            .state
            .profile_service()
            .set_legacy_vcard(
                LegacyVCardWrite {
                    user_id: user.id,
                    auth_generation: user.auth_generation,
                    connection_id: self.connection_id,
                    payload,
                    avatar_hash: avatar_hash.as_deref(),
                    data_item: data,
                    metadata_item: metadata,
                    max_nodes: self.state.config.pep_max_nodes_per_account,
                    max_storage_bytes: self.state.config.pep_max_storage_bytes_per_account,
                },
                &move |audience: &ProfileAudienceSnapshot| {
                    ProtocolSession::prepare_profile_audience_messages(
                        audience_state.as_ref(),
                        publisher_full_jid.as_deref(),
                        AVATAR_METADATA,
                        &metadata_event,
                        audience,
                    )
                },
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                return Ok(Action::Send(iq_error(id, "resource-constraint")));
            }
            Err(error) => return Err(error),
        };
        match outcome.status {
            ProfilePublishStatus::Published => {}
            ProfilePublishStatus::Unauthorized => {
                return Ok(Action::Send(iq_error(id, "not-authorized")));
            }
            ProfilePublishStatus::PreconditionFailed => {
                return Ok(Action::Send(iq_error(id, "conflict")));
            }
            ProfilePublishStatus::MaxItemsExceeded
            | ProfilePublishStatus::QuotaExceeded
            | ProfilePublishStatus::InvalidAvatar => {
                return Ok(Action::Send(iq_error(id, "resource-constraint")));
            }
        }
        if let AvatarPresenceUpdate::Changed(hash) = outcome.avatar_presence {
            self.refresh_local_avatar_presence(
                &format!("{}@{}", user.username, self.state.config.domain),
                hash.as_deref(),
            );
        }
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) fn refresh_local_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        for session in self.state.sessions_for(owner_bare) {
            let mut last_presence = session
                .last_presence
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let refreshed = last_presence.as_deref().and_then(|raw| {
                let document = roxmltree::Document::parse(raw).ok()?;
                Some(inject_vcard_avatar_hash(raw, document.root_element(), hash))
            });
            if let Some(refreshed) = refreshed {
                *last_presence = Some(refreshed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_pixel_png() -> Vec<u8> {
        BASE64
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgZGL+DwABFAEG1rmmRQAAAABJRU5ErkJggg==")
            .unwrap()
    }

    #[test]
    fn rejects_invalid_or_duplicate_vcard_avatars() {
        let invalid = roxmltree::Document::parse(
            "<vCard xmlns='vcard-temp'><PHOTO><TYPE>image/png</TYPE><BINVAL>not base64</BINVAL></PHOTO></vCard>",
        )
        .unwrap();
        assert!(decoded_vcard_avatar(invalid.root_element()).is_err());

        let duplicate =
            roxmltree::Document::parse("<vCard xmlns='vcard-temp'><PHOTO/><PHOTO/></vCard>")
                .unwrap();
        assert!(decoded_vcard_avatar(duplicate.root_element()).is_err());

        let ambiguous = roxmltree::Document::parse(
            "<vCard xmlns='vcard-temp'><PHOTO><TYPE>image/png</TYPE><TYPE>image/jpeg</TYPE><BINVAL>aGVsbG8=</BINVAL></PHOTO></vCard>",
        )
        .unwrap();
        assert!(decoded_vcard_avatar(ambiguous.root_element()).is_err());
    }

    #[test]
    fn hashes_decoded_bytes_not_base64_text() {
        let png_bytes = one_pixel_png();
        let encoded = BASE64.encode(&png_bytes);
        let xml = format!(
            "<vCard xmlns='vcard-temp'><PHOTO><TYPE>image/png</TYPE><BINVAL>{encoded}</BINVAL></PHOTO></vCard>"
        );
        let document = roxmltree::Document::parse(&xml).unwrap();
        let (_, bytes) = decoded_vcard_avatar(document.root_element())
            .unwrap()
            .unwrap();
        assert_eq!(sha1_hex(&bytes), sha1_hex(&png_bytes));

        let split = xml.replace(
            &encoded,
            &format!("{}<![CDATA[{}]]>", &encoded[..8], &encoded[8..]),
        );
        let document = roxmltree::Document::parse(&split).unwrap();
        assert_eq!(
            decoded_vcard_avatar(document.root_element())
                .unwrap()
                .unwrap()
                .1,
            png_bytes
        );
    }

    #[test]
    fn rejects_png_magic_without_a_valid_container() {
        let fake = BASE64.encode(b"\x89PNG\r\n\x1a\nnot-an-image");
        let xml = format!(
            "<vCard xmlns='vcard-temp'><PHOTO><TYPE>image/png</TYPE><BINVAL>{fake}</BINVAL></PHOTO></vCard>"
        );
        let document = roxmltree::Document::parse(&xml).unwrap();
        assert!(decoded_vcard_avatar(document.root_element()).is_err());
    }

    #[test]
    fn rejects_declared_type_that_does_not_match_image_bytes() {
        let jpeg = BASE64.encode([0xff, 0xd8, 0xff, 0xd9]);
        let xml = format!(
            "<vCard xmlns='vcard-temp'><PHOTO><TYPE>image/png</TYPE><BINVAL>{jpeg}</BINVAL></PHOTO></vCard>"
        );
        let document = roxmltree::Document::parse(&xml).unwrap();
        assert!(decoded_vcard_avatar(document.root_element()).is_err());
    }

    #[test]
    fn non_png_vcard_avatar_keeps_original_media_type_in_pep() {
        let jpeg = vec![0xff, 0xd8, 0xff, 0xd9];
        let hash = sha1_hex(&jpeg);
        let converted =
            converted_avatar_items(Some(&("image/jpeg".to_owned(), jpeg.clone())), Some(&hash));
        let (_, data) = converted.data.expect("non-empty avatar has a data item");
        assert!(data.contains("urn:xmpp:avatar:data"));
        assert!(data.contains(&BASE64.encode(jpeg)));
        assert!(converted.metadata.1.contains("type='image/jpeg'"));
        assert!(converted.metadata.1.contains(&format!("id='{hash}'")));

        let cleared = converted_avatar_items(None, None);
        assert!(cleared.data.is_none());
        assert!(cleared
            .metadata
            .1
            .contains("<metadata xmlns='urn:xmpp:avatar:metadata'/>"));

        let hostile_type = "image/png'/><injected xmlns='urn:evil'/>".to_owned();
        let hostile = converted_avatar_items(
            Some(&(hostile_type.clone(), vec![0xff, 0xd8, 0xff, 0xd9])),
            Some(&hash),
        );
        let document = roxmltree::Document::parse(&hostile.metadata.1).unwrap();
        let info = document
            .descendants()
            .find(|node| node.is_element() && node.tag_name().name() == "info")
            .unwrap();
        assert_eq!(info.attribute("type"), Some(hostile_type.as_str()));
        assert!(document
            .descendants()
            .all(|node| !node.is_element() || node.tag_name().name() != "injected"));
    }

    #[test]
    fn vcard_temp_accepts_interoperable_versions_and_enforces_wire_rules() {
        for xml in [
            "<vCard xmlns='vcard-temp'><FN>Alice</FN><TEL><VOICE/><NUMBER/></TEL><EMAIL><INTERNET/><USERID>a@example.test</USERID></EMAIL><ADR><CTRY>JP</CTRY></ADR></vCard>",
            "<vCard xmlns='vcard-temp' version='3.0'><FN>Alice</FN><PHOTO><EXTVAL>https://example.test/avatar.png</EXTVAL></PHOTO></vCard>",
            // Historical clients are documented as sending 2.0 even though
            // 3.0 is the correct value; accepting it preserves compatibility.
            "<vCard xmlns='vcard-temp' version='2.0'><FN>Alice</FN></vCard>",
        ] {
            let document = roxmltree::Document::parse(xml).unwrap();
            assert!(valid_vcard_temp(document.root_element()), "{xml}");
        }

        for xml in [
            "<vCard xmlns='vcard-temp'><FN>Alice\u{202e}txt.exe</FN></vCard>",
            "<vCard xmlns='vcard-temp'><NOTE>hidden\u{2066}direction\u{2069}</NOTE></vCard>",
            "<vCard xmlns='vcard-temp' version='4.0'><FN>Alice</FN></vCard>",
            "<vCard xmlns='vcard-temp'><fn>Alice</fn></vCard>",
            "<vCard xmlns='vcard-temp'><ADR><COUNTRY>JP</COUNTRY></ADR></vCard>",
            "<vCard xmlns='vcard-temp'><TEL>123</TEL></vCard>",
            "<vCard xmlns='vcard-temp'><TEL><VOICE/></TEL></vCard>",
            "<vCard xmlns='vcard-temp'><TEL><VOICE/><VOICE/><NUMBER/></TEL></vCard>",
            "<vCard xmlns='vcard-temp'><TEL><NUMBER/><VOICE/></TEL></vCard>",
            "<vCard xmlns='vcard-temp'><TEL><VOICE/><NUMBER/><FOO/></TEL></vCard>",
            "<vCard xmlns='vcard-temp'><EMAIL>a@example.test</EMAIL></vCard>",
            "<vCard xmlns='vcard-temp'><EMAIL><INTERNET/></EMAIL></vCard>",
            "<vCard xmlns='vcard-temp'><EMAIL><USERID>a@example.test</USERID><INTERNET/></EMAIL></vCard>",
            "<vCard xmlns='vcard-temp'><PHOTO/></vCard>",
            "<vCard xmlns='vcard-temp'><PHOTO><BINVAL>AA==</BINVAL><TYPE>image/png</TYPE></PHOTO></vCard>",
            "<vCard xmlns='vcard-temp'><PHOTO><TYPE>image/png</TYPE><BINVAL>AA==</BINVAL><EXTVAL>https://example.test/a</EXTVAL></PHOTO></vCard>",
            "<vCard xmlns='vcard-temp'><PHOTO><TYPE>image/png</TYPE><BINVAL><DATA>AA==</DATA></BINVAL></PHOTO></vCard>",
        ] {
            let document = roxmltree::Document::parse(xml).unwrap();
            assert!(!valid_vcard_temp(document.root_element()), "{xml}");
        }
    }
}
