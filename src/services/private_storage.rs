//! Application boundary for XEP-0049 private XML and bookmark compatibility.
//!
//! Applies storage quotas and preserves modern bookmark extensions when a
//! legacy client writes bookmarks. The repository supplies a coherent snapshot;
//! publication commits private XML, PEP and its outbox together.

use anyhow::Result;
use uuid::Uuid;

pub(crate) const LEGACY_BOOKMARKS: &str = "storage:bookmarks";
pub(crate) const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
const PRIVATE_XML_MAX_ACCOUNT_BYTES: i64 = 8 * 1024 * 1024;
pub(crate) const MAX_BOOKMARK_ITEMS: usize = northstar_pubsub_core::PEP_MAX_ITEMS as usize;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PrivateXmlEntry<'a> {
    pub(crate) element_name: &'a str,
    pub(crate) element_ns: &'a str,
    pub(crate) xml_data: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyBookmarkSnapshot {
    pub(crate) private_xml: Option<String>,
    pub(crate) modern_node_exists: bool,
    pub(crate) modern_items: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivateXmlWriteOutcome {
    Stored,
    QuotaExceeded,
}

pub(crate) trait PrivateStorageRepository: Send + Sync {
    fn get(
        &self,
        owner_id: Uuid,
        element_name: &str,
        element_ns: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn legacy_bookmark_snapshot(
        &self,
        owner_id: Uuid,
    ) -> impl std::future::Future<Output = Result<LegacyBookmarkSnapshot>> + Send;
    fn set_batch(
        &self,
        owner_id: Uuid,
        entries: &[PrivateXmlEntry<'_>],
        max_bytes: i64,
    ) -> impl std::future::Future<Output = Result<PrivateXmlWriteOutcome>> + Send;
}
#[derive(Clone)]
pub(crate) struct PrivateStorageService<R> {
    repository: R,
    pep_max_nodes: i64,
    pep_max_storage_bytes: i64,
}
impl<R: PrivateStorageRepository> PrivateStorageService<R> {
    pub(crate) fn new(repository: R, pep_max_nodes: i64, pep_max_storage_bytes: i64) -> Self {
        Self {
            repository,
            pep_max_nodes,
            pep_max_storage_bytes,
        }
    }
    pub(crate) async fn get(
        &self,
        owner_id: Uuid,
        element_name: &str,
        element_ns: &str,
    ) -> Result<Option<String>> {
        self.repository
            .get(owner_id, element_name, element_ns)
            .await
    }
    pub(crate) async fn legacy_bookmark_snapshot(
        &self,
        owner_id: Uuid,
    ) -> Result<LegacyBookmarkSnapshot> {
        self.repository.legacy_bookmark_snapshot(owner_id).await
    }
    /// Capture one optimistic revision before the protocol renders event bytes.
    pub(crate) async fn prepare_legacy_bookmark_write(
        &self,
        owner_id: Uuid,
        items: &mut [(String, String)],
    ) -> Result<Vec<(String, String)>> {
        let snapshot = self.legacy_bookmark_snapshot(owner_id).await?;
        preserve_bookmark_extensions(items, &snapshot.modern_items);
        Ok(snapshot.modern_items)
    }
    pub(crate) async fn set_batch(
        &self,
        owner_id: Uuid,
        entries: &[PrivateXmlEntry<'_>],
    ) -> Result<PrivateXmlWriteOutcome> {
        self.repository
            .set_batch(owner_id, entries, PRIVATE_XML_MAX_ACCOUNT_BYTES)
            .await
    }
    pub(crate) fn legacy_bookmark_limits(&self) -> (i64, i64, i64) {
        (
            PRIVATE_XML_MAX_ACCOUNT_BYTES,
            self.pep_max_nodes,
            self.pep_max_storage_bytes,
        )
    }
}
pub(crate) fn preserve_bookmark_extensions(
    items: &mut [(String, String)],
    previous: &[(String, String)],
) {
    let previous = previous
        .iter()
        .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
        .collect::<std::collections::HashMap<_, _>>();
    for (item_id, item_xml) in items {
        let Some(previous_xml) = previous.get(item_id.as_str()) else {
            continue;
        };
        let Ok(document) = roxmltree::Document::parse(previous_xml) else {
            continue;
        };
        let Some(extensions) = document.descendants().find(|node| {
            node.is_element()
                && node.tag_name().name() == "extensions"
                && node.tag_name().namespace() == Some("urn:xmpp:bookmarks:1")
        }) else {
            continue;
        };
        if let Some(end) = item_xml.rfind("</conference>") {
            item_xml.insert_str(end, &previous_xml[extensions.range()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnavailableSnapshot;
    impl PrivateStorageRepository for UnavailableSnapshot {
        async fn get(&self, _: Uuid, _: &str, _: &str) -> Result<Option<String>> {
            unreachable!()
        }
        async fn legacy_bookmark_snapshot(&self, _: Uuid) -> Result<LegacyBookmarkSnapshot> {
            anyhow::bail!("snapshot unavailable")
        }
        async fn set_batch(
            &self,
            _: Uuid,
            _: &[PrivateXmlEntry<'_>],
            _: i64,
        ) -> Result<PrivateXmlWriteOutcome> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn failed_snapshot_leaves_the_callers_bookmark_payload_intact() {
        let service = PrivateStorageService::new(UnavailableSnapshot, 100, 8_000_000);
        let mut items = vec![(
            "room@conference.test".to_owned(),
            "<conference xmlns='urn:xmpp:bookmarks:1'></conference>".to_owned(),
        )];
        let original = items.clone();
        assert!(service
            .prepare_legacy_bookmark_write(Uuid::new_v4(), &mut items)
            .await
            .unwrap_err()
            .to_string()
            .contains("snapshot unavailable"));
        assert_eq!(items, original);
    }
}
