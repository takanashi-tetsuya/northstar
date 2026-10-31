//! XEP-0054 vcard-temp, which reads and writes the profile and mirrors the avatar into PEP.

use crate::payload::xml_subtree_contains_unsafe_bidi_controls;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use northstar_pubsub_application::profile::{
    detected_media_type, sha1_hex, AvatarPresenceUpdate, LegacyVCardWrite, ProfileAudienceSnapshot,
    ProfilePublishStatus, ProfileRepository, ProfileService, PublicVCard,
};
use northstar_pubsub_core::{PepQuotas, PubSubAccount};
use northstar_xml_builder::stanza::{iq_error, iq_error_from, iq_result, iq_result_from};
use northstar_xml_builder::XmlElement;
use roxmltree::Node;

/// What a client session provides to the XEP-0054 handlers.
pub trait VCardSession: Sync {
    /// The authenticated account, or `None` before authentication.
    fn vcard_account(&self) -> Option<PubSubAccount>;
    /// The session's bound full JID, or `None` before resource binding.
    fn vcard_full_jid(&self) -> Option<&str>;
    /// The id of the session's connection.
    fn vcard_connection_id(&self) -> uuid::Uuid;
    /// The server's local domain.
    fn vcard_local_domain(&self) -> &str;
    /// The PEP node and storage quotas of one account.
    fn vcard_pep_quotas(&self) -> PepQuotas;
    /// The profile service, over the repository the composition root binds.
    fn vcard_profile_service(&self) -> &ProfileService<impl ProfileRepository>;
    /// The PEP notifications of `event` on `node` for the profile audience, as (recipient,
    /// stanza) pairs; `publisher_full_jid` is the resource that published.
    fn vcard_profile_audience_messages(
        &self,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &ProfileAudienceSnapshot,
    ) -> anyhow::Result<Vec<(String, String)>>;
    /// Puts the new avatar hash (or none) into the last presence of every local session of
    /// `owner_bare`.
    fn vcard_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>);
}

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
    if actual_media_type == "image/png" && !crate::payload::valid_png_image(&bytes) {
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

/// Answers an XEP-0054 vCard get request.
pub async fn vcard_get<S: VCardSession>(
    session: &S,
    id: &str,
    iq: roxmltree::Node<'_, '_>,
) -> anyhow::Result<String> {
    let Some(requester) = session.vcard_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    let (owner_name, response_from, is_self) = if let Some(to) = iq.attribute("to") {
        let Ok(target) = northstar_xmpp_types::jid::CanonicalJid::parse_bare(to) else {
            return Ok(iq_error(id, "jid-malformed"));
        };
        if target.domainpart() != session.vcard_local_domain() {
            return Ok(iq_error(id, "item-not-found"));
        }
        let Some(localpart) = target.localpart() else {
            return Ok(iq_error(id, "service-unavailable"));
        };
        (
            localpart.to_owned(),
            Some(target.to_string()),
            localpart == requester.username,
        )
    } else {
        (requester.username.clone(), None, true)
    };
    let profile = session
        .vcard_profile_service()
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
            return Ok(if let Some(from) = response_from.as_deref() {
                iq_error_from(id, from, "service-unavailable")
            } else {
                iq_error(id, "service-unavailable")
            });
        }
    };
    if let Some(from) = response_from.as_deref() {
        Ok(iq_result_from(id, from, &payload))
    } else {
        Ok(iq_result(id, &payload))
    }
}

/// Answers an XEP-0054 vCard set request.
pub async fn vcard_set<S: VCardSession>(
    session: &S,
    id: &str,
    iq: roxmltree::Node<'_, '_>,
    vcard: roxmltree::Node<'_, '_>,
    raw: &str,
) -> anyhow::Result<String> {
    let Some(user) = session.vcard_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    if !valid_vcard_temp(vcard) {
        return Ok(iq_error(id, "bad-request"));
    }
    if iq.attribute("to").is_some_and(|to| {
        !northstar_xmpp_types::jid::CanonicalJid::parse_bare(to).is_ok_and(|target| {
            target.localpart() == Some(user.username.as_str())
                && target.domainpart() == session.vcard_local_domain()
        })
    }) {
        return Ok(iq_error(id, "forbidden"));
    }
    let range = vcard.range();
    let payload = &raw[range];
    if payload.len() > 512 * 1024 {
        return Ok(iq_error(id, "resource-constraint"));
    }
    let avatar = match decoded_vcard_avatar(vcard) {
        Ok(avatar) => avatar,
        Err(()) => return Ok(iq_error(id, "not-acceptable")),
    };
    let avatar_hash = avatar.as_ref().map(|(_, bytes)| sha1_hex(bytes));
    let converted = converted_avatar_items(avatar.as_ref(), avatar_hash.as_deref());
    let data = converted
        .data
        .as_ref()
        .map(|(item_id, item)| (item_id.as_str(), item.as_str()));
    let metadata = (converted.metadata.0.as_str(), converted.metadata.1.as_str());
    let metadata_event = crate::events::profile_item_event(AVATAR_METADATA, &converted.metadata.1)?;
    let publisher_full_jid = session.vcard_full_jid();
    let quotas = session.vcard_pep_quotas();
    let outcome = match session
        .vcard_profile_service()
        .set_legacy_vcard(
            LegacyVCardWrite {
                user_id: user.id,
                auth_generation: user.auth_generation,
                connection_id: session.vcard_connection_id(),
                payload,
                avatar_hash: avatar_hash.as_deref(),
                data_item: data,
                metadata_item: metadata,
                max_nodes: quotas.max_nodes,
                max_storage_bytes: quotas.max_storage_bytes,
            },
            &move |audience: &ProfileAudienceSnapshot| {
                session.vcard_profile_audience_messages(
                    publisher_full_jid,
                    AVATAR_METADATA,
                    &metadata_event,
                    audience,
                )
            },
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
            return Ok(iq_error(id, "resource-constraint"));
        }
        Err(error) => return Err(error),
    };
    match outcome.status {
        ProfilePublishStatus::Published => {}
        ProfilePublishStatus::Unauthorized => {
            return Ok(iq_error(id, "not-authorized"));
        }
        ProfilePublishStatus::PreconditionFailed => {
            return Ok(iq_error(id, "conflict"));
        }
        ProfilePublishStatus::MaxItemsExceeded
        | ProfilePublishStatus::QuotaExceeded
        | ProfilePublishStatus::InvalidAvatar => {
            return Ok(iq_error(id, "resource-constraint"));
        }
    }
    if let AvatarPresenceUpdate::Changed(hash) = outcome.avatar_presence {
        session.vcard_refresh_avatar_presence(
            &format!("{}@{}", user.username, session.vcard_local_domain()),
            hash.as_deref(),
        );
    }
    Ok(iq_result(id, ""))
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
