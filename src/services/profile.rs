//! Profile publication policy and atomic repository operations.

use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
use sha1::{Digest, Sha1};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
pub(crate) const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";
pub(crate) const VCARD4: &str = "urn:xmpp:vcard4";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicVCard {
    MissingAccount,
    Profile(Option<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AvatarPresenceUpdate {
    Unchanged,
    Changed(Option<String>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfilePublishStatus {
    Published,
    Unauthorized,
    PreconditionFailed,
    MaxItemsExceeded,
    QuotaExceeded,
    InvalidAvatar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfilePublishResult {
    pub(crate) status: ProfilePublishStatus,
    pub(crate) content_changed: bool,
    pub(crate) avatar_presence: AvatarPresenceUpdate,
}

impl ProfilePublishResult {
    pub(crate) fn rejected(status: ProfilePublishStatus) -> Self {
        Self {
            status,
            content_changed: false,
            avatar_presence: AvatarPresenceUpdate::Unchanged,
        }
    }
}

pub(crate) struct LegacyVCardWrite<'a> {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) connection_id: Uuid,
    pub(crate) payload: &'a str,
    pub(crate) avatar_hash: Option<&'a str>,
    pub(crate) data_item: Option<(&'a str, &'a str)>,
    pub(crate) metadata_item: (&'a str, &'a str),
    pub(crate) max_nodes: i64,
    pub(crate) max_storage_bytes: i64,
}

pub(crate) struct ProfilePepWrite<'a> {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) connection_id: Uuid,
    pub(crate) node: &'a str,
    pub(crate) requested: &'a northstar_pubsub_core::PepNodeConfig,
    pub(crate) enforce_preconditions: bool,
    pub(crate) items: &'a [(&'a str, &'a str)],
    pub(crate) max_nodes: i64,
    pub(crate) max_storage_bytes: i64,
}

/// Exact durable authorization snapshot captured while the profile account,
/// PEP node and audience-policy locks are held. Online resources/caps remain
/// soft routing hints, but they can only narrow these authorized principals.
pub(crate) struct ProfileAudienceSnapshot {
    pub(crate) owner_bare_jid: String,
    pub(crate) roster_jids: Vec<String>,
    pub(crate) explicit_jids: Vec<String>,
}

impl ProfileAudienceSnapshot {
    pub(crate) fn authorizes_routed_jid(&self, recipient: &str) -> bool {
        let Ok(recipient) = crate::jid::CanonicalJid::parse(recipient) else {
            return false;
        };
        let recipient_full = recipient.to_string();
        let recipient_bare = recipient.bare();
        if recipient_bare == self.owner_bare_jid
            || self.roster_jids.iter().any(|jid| jid == &recipient_bare)
        {
            return true;
        }
        self.explicit_jids.iter().any(|jid| {
            crate::jid::CanonicalJid::parse(jid).is_ok_and(|explicit| {
                if explicit.resourcepart().is_some() {
                    explicit.to_string() == recipient_full
                } else {
                    explicit.bare() == recipient_bare
                }
            })
        })
    }
}

/// Synchronously renders a transaction-owned profile audience. The callback
/// must not perform I/O: keeping it synchronous prevents a PostgreSQL
/// transaction from spanning a network operation or a second pool wait.
pub(crate) trait ProfileOutboxFactory: Send + Sync {
    fn build(&self, audience: &ProfileAudienceSnapshot) -> Result<Vec<(String, String)>>;
}

impl<F> ProfileOutboxFactory for F
where
    F: Fn(&ProfileAudienceSnapshot) -> Result<Vec<(String, String)>> + Send + Sync,
{
    fn build(&self, audience: &ProfileAudienceSnapshot) -> Result<Vec<(String, String)>> {
        self(audience)
    }
}

/// Profile data, converted avatar items and notification audiences commit as
/// one operation. Implementations recheck the account generation under lock.
pub(crate) trait ProfileRepository: Send + Sync {
    fn public_vcard(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<PublicVCard>> + Send;
    fn set_legacy_vcard(
        &self,
        write: LegacyVCardWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> impl std::future::Future<Output = Result<ProfilePublishResult>> + Send;
    fn publish_profile_items(
        &self,
        write: ProfilePepWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
        require_content_change: bool,
    ) -> impl std::future::Future<Output = Result<ProfilePublishResult>> + Send;
    fn publish_avatar_metadata(
        &self,
        write: ProfilePepWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> impl std::future::Future<Output = Result<ProfilePublishResult>> + Send;
}

pub(crate) struct ProfileService<R> {
    repository: R,
    mutation_admission: Arc<crate::services::pubsub::PubSubMutationAdmission>,
}

impl<R: ProfileRepository> ProfileService<R> {
    pub(crate) fn with_mutation_admission(
        repository: R,
        mutation_admission: Arc<crate::services::pubsub::PubSubMutationAdmission>,
    ) -> Self {
        Self {
            repository,
            mutation_admission,
        }
    }

    pub(crate) async fn public_vcard(&self, username: &str) -> Result<PublicVCard> {
        self.repository.public_vcard(username).await
    }

    pub(crate) async fn set_legacy_vcard(
        &self,
        write: LegacyVCardWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> Result<ProfilePublishResult> {
        let owner_key = write.user_id.to_string();
        let _permit = self
            .mutation_admission
            .acquire(&[&owner_key], false)
            .await?;

        self.repository
            .set_legacy_vcard(write, explicit_factory)
            .await
    }

    pub(crate) async fn publish_profile_items(
        &self,
        write: ProfilePepWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
        require_content_change: bool,
    ) -> Result<ProfilePublishResult> {
        anyhow::ensure!(
            matches!(write.node, AVATAR_DATA | VCARD4),
            "generic profile publish supports only avatar data and vCard4"
        );
        let owner_key = write.user_id.to_string();
        let _permit = self
            .mutation_admission
            .acquire(&[&owner_key, write.node], false)
            .await?;

        self.repository
            .publish_profile_items(write, explicit_factory, require_content_change)
            .await
    }

    pub(crate) async fn publish_avatar_metadata(
        &self,
        write: ProfilePepWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> Result<ProfilePublishResult> {
        anyhow::ensure!(
            write.node == AVATAR_METADATA,
            "avatar metadata publication used the wrong node"
        );
        let owner_key = write.user_id.to_string();
        let _permit = self
            .mutation_admission
            .acquire(&[&owner_key, write.node], false)
            .await?;

        self.repository
            .publish_avatar_metadata(write, explicit_factory)
            .await
    }
}

pub(crate) fn sha1_hex(bytes: &[u8]) -> String {
    Sha1::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn detected_media_type(bytes: &[u8]) -> Option<&'static str> {
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

pub(crate) fn replace_vcard_temp_photo(
    existing: &str,
    media_type: Option<&str>,
    encoded: Option<&str>,
) -> String {
    let Ok(document) = roxmltree::Document::parse(existing) else {
        return empty_vcard_with_photo(media_type, encoded, None);
    };
    let root = document.root_element();
    if root.tag_name().name() != "vCard" || root.tag_name().namespace() != Some("vcard-temp") {
        return empty_vcard_with_photo(media_type, encoded, None);
    }
    let version = root.attribute("version").map(str::to_owned);
    let mut ranges = root
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "PHOTO"
                && child.tag_name().namespace() == Some("vcard-temp")
        })
        .map(|child| child.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut output = existing.to_owned();
    for range in ranges {
        output.replace_range(range, "");
    }
    let photo = serialized_photo(media_type, encoded);
    if let Some(end) = output.rfind("</") {
        output.insert_str(end, &photo);
        output
    } else if output.trim_end().ends_with("/>") {
        empty_vcard_with_photo(media_type, encoded, version.as_deref())
    } else {
        empty_vcard_with_photo(media_type, encoded, None)
    }
}

fn serialized_photo(media_type: Option<&str>, encoded: Option<&str>) -> String {
    match (media_type, encoded) {
        (Some(media_type), Some(encoded)) => XmlElement::new("PHOTO")
            .child(XmlElement::new("TYPE").text(media_type))
            .child(XmlElement::new("BINVAL").text(encoded))
            .finish(),
        _ => String::new(),
    }
}

fn empty_vcard_with_photo(
    media_type: Option<&str>,
    encoded: Option<&str>,
    version: Option<&str>,
) -> String {
    let mut vcard = XmlElement::namespaced("vCard", "vcard-temp").optional_attr("version", version);
    if let (Some(media_type), Some(encoded)) = (media_type, encoded) {
        vcard.push_child(
            XmlElement::new("PHOTO")
                .child(XmlElement::new("TYPE").text(media_type))
                .child(XmlElement::new("BINVAL").text(encoded)),
        );
    }
    vcard.finish()
}

/// Strict enough to reject truncated, reordered, CRC-corrupted or trailing
/// PNG containers used as a metadata hash oracle.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[derive(Default)]
    struct FaultRepository {
        calls: AtomicUsize,
        entered: Notify,
        release: Notify,
    }

    impl ProfileRepository for Arc<FaultRepository> {
        async fn public_vcard(&self, _: &str) -> Result<PublicVCard> {
            Ok(PublicVCard::MissingAccount)
        }

        async fn set_legacy_vcard(
            &self,
            _: LegacyVCardWrite<'_>,
            _: &dyn ProfileOutboxFactory,
        ) -> Result<ProfilePublishResult> {
            anyhow::bail!("unexpected legacy write")
        }

        async fn publish_profile_items(
            &self,
            _: ProfilePepWrite<'_>,
            _: &dyn ProfileOutboxFactory,
            _: bool,
        ) -> Result<ProfilePublishResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            anyhow::bail!("injected publication rollback")
        }

        async fn publish_avatar_metadata(
            &self,
            _: ProfilePepWrite<'_>,
            _: &dyn ProfileOutboxFactory,
        ) -> Result<ProfilePublishResult> {
            anyhow::bail!("unexpected metadata write")
        }
    }

    fn config() -> northstar_pubsub_core::PepNodeConfig {
        northstar_pubsub_core::PepNodeConfig {
            access_model: "open".into(),
            max_items: 1,
            persist_items: true,
            send_last_published_item: "on_sub_and_presence".into(),
            deliver_notifications: true,
            roster_groups_allowed: vec![],
            access_whitelist: vec![],
        }
    }

    fn write<'a>(
        owner: Uuid,
        node: &'a str,
        config: &'a northstar_pubsub_core::PepNodeConfig,
    ) -> ProfilePepWrite<'a> {
        ProfilePepWrite {
            user_id: owner,
            auth_generation: 1,
            connection_id: Uuid::new_v4(),
            node,
            requested: config,
            enforce_preconditions: false,
            items: &[],
            max_nodes: 10,
            max_storage_bytes: 1024,
        }
    }

    fn no_recipients(_: &ProfileAudienceSnapshot) -> Result<Vec<(String, String)>> {
        Ok(vec![])
    }

    #[tokio::test]
    async fn wrong_profile_node_is_rejected_before_repository_admission() {
        let repository = Arc::new(FaultRepository::default());
        let service = ProfileService::with_mutation_admission(
            repository.clone(),
            Arc::new(crate::services::pubsub::PubSubMutationAdmission::new(8)),
        );
        let error = service
            .publish_profile_items(
                write(Uuid::new_v4(), AVATAR_METADATA, &config()),
                &no_recipients,
                true,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("only avatar data and vCard4"));
        assert_eq!(repository.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn publication_holds_shared_admission_until_failure_or_cancellation() {
        let repository = Arc::new(FaultRepository::default());
        let admission = Arc::new(crate::services::pubsub::PubSubMutationAdmission::new(8));
        let service = Arc::new(ProfileService::with_mutation_admission(
            repository.clone(),
            admission.clone(),
        ));
        let owner = Uuid::new_v4();
        let owner_key = owner.to_string();
        for cancel in [false, true] {
            let service = service.clone();
            let task = tokio::spawn(async move {
                service
                    .publish_profile_items(write(owner, VCARD4, &config()), &no_recipients, true)
                    .await
            });
            repository.entered.notified().await;
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(20),
                admission.acquire(&[&owner_key], false),
            )
            .await
            .is_err());
            if cancel {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                repository.release.notify_one();
                assert!(task
                    .await
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("injected publication rollback"));
            }
            let permit = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                admission.acquire(&[&owner_key], false),
            )
            .await
            .unwrap()
            .unwrap();
            drop(permit);
        }
        assert_eq!(repository.calls.load(Ordering::SeqCst), 2);
    }
}
