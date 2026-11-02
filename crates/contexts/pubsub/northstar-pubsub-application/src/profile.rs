//! Profile publication policy and atomic repository operations.

use anyhow::Result;
use northstar_xml_builder::XmlElement;
use northstar_xmpp_avatar::{AVATAR_DATA, AVATAR_METADATA};
use std::sync::Arc;
use uuid::Uuid;

pub const VCARD4: &str = "urn:xmpp:vcard4";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicVCard {
    MissingAccount,
    Profile(Option<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AvatarPresenceUpdate {
    Unchanged,
    Changed(Option<String>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfilePublishStatus {
    Published,
    Unauthorized,
    PreconditionFailed,
    MaxItemsExceeded,
    QuotaExceeded,
    InvalidAvatar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePublishResult {
    pub status: ProfilePublishStatus,
    pub content_changed: bool,
    pub avatar_presence: AvatarPresenceUpdate,
}

impl ProfilePublishResult {
    pub fn rejected(status: ProfilePublishStatus) -> Self {
        Self {
            status,
            content_changed: false,
            avatar_presence: AvatarPresenceUpdate::Unchanged,
        }
    }
}

pub struct LegacyVCardWrite<'a> {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub payload: &'a str,
    pub avatar_hash: Option<&'a str>,
    pub data_item: Option<(&'a str, &'a str)>,
    pub metadata_item: (&'a str, &'a str),
    pub max_nodes: i64,
    pub max_storage_bytes: i64,
}

pub struct ProfilePepWrite<'a> {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub requested: &'a northstar_pubsub_core::PepNodeConfig,
    pub enforce_preconditions: bool,
    pub items: &'a [(&'a str, &'a str)],
    pub max_nodes: i64,
    pub max_storage_bytes: i64,
}

/// Exact durable authorization snapshot captured while the profile account,
/// PEP node and audience-policy locks are held. Online resources/caps remain
/// soft routing hints, but they can only narrow these authorized principals.
pub struct ProfileAudienceSnapshot {
    pub owner_bare_jid: String,
    pub roster_jids: Vec<String>,
    pub explicit_jids: Vec<String>,
}

impl ProfileAudienceSnapshot {
    pub fn authorizes_routed_jid(&self, recipient: &str) -> bool {
        let Ok(recipient) = northstar_xmpp_types::jid::CanonicalJid::parse(recipient) else {
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
            northstar_xmpp_types::jid::CanonicalJid::parse(jid).is_ok_and(|explicit| {
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
pub trait ProfileOutboxFactory: Send + Sync {
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
pub trait ProfileRepository: Send + Sync {
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

pub struct ProfileService<R> {
    repository: R,
    mutation_admission: Arc<crate::PubSubMutationAdmission>,
}

impl<R: ProfileRepository> ProfileService<R> {
    pub fn with_mutation_admission(
        repository: R,
        mutation_admission: Arc<crate::PubSubMutationAdmission>,
    ) -> Self {
        Self {
            repository,
            mutation_admission,
        }
    }

    pub async fn public_vcard(&self, username: &str) -> Result<PublicVCard> {
        self.repository.public_vcard(username).await
    }

    pub async fn set_legacy_vcard(
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

    pub async fn publish_profile_items(
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

    pub async fn publish_avatar_metadata(
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

pub fn replace_vcard_temp_photo(
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
            Arc::new(crate::PubSubMutationAdmission::new(8)),
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
        let admission = Arc::new(crate::PubSubMutationAdmission::new(8));
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
