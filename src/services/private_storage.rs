//! Application boundary for XEP-0049 private XML and bookmark compatibility.
//!
//! XML parsing/rendering remains in the protocol module.  This service owns
//! all persistence, the cross-table legacy/modern bookmark snapshot, quota
//! policy, extension preservation and the atomic private+PEP+outbox commit.

use crate::db;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

const LEGACY_BOOKMARKS: &str = "storage:bookmarks";
const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
const PRIVATE_XML_MAX_ACCOUNT_BYTES: i64 = 8 * 1024 * 1024;
pub(crate) const MAX_BOOKMARK_ITEMS: usize = db::PEP_MAX_ITEMS as usize;

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

#[derive(Clone)]
pub(crate) struct PrivateStorageService {
    pool: PgPool,
    pep_max_nodes: i64,
    pep_max_storage_bytes: i64,
}

impl PrivateStorageService {
    pub(crate) fn new(pool: PgPool, pep_max_nodes: i64, pep_max_storage_bytes: i64) -> Self {
        Self {
            pool,
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
        db::get_private_xml(&self.pool, owner_id, element_name, element_ns).await
    }

    pub(crate) async fn legacy_bookmark_snapshot(
        &self,
        owner_id: Uuid,
    ) -> Result<LegacyBookmarkSnapshot> {
        let snapshot = db::legacy_bookmark_snapshot(
            &self.pool,
            owner_id,
            LEGACY_BOOKMARKS,
            BOOKMARKS2,
            i64::from(db::PEP_MAX_ITEMS),
        )
        .await?;
        Ok(LegacyBookmarkSnapshot {
            private_xml: snapshot.private_xml,
            modern_node_exists: snapshot.modern_node_exists,
            modern_items: snapshot.modern_items,
        })
    }

    /// Capture the optimistic PEP revision and merge opaque modern bookmark
    /// extensions exactly once before the protocol constructs event bytes.
    pub(crate) async fn prepare_legacy_bookmark_write(
        &self,
        owner_id: Uuid,
        items: &mut [(String, String)],
    ) -> Result<Vec<(String, String)>> {
        let snapshot = self.legacy_bookmark_snapshot(owner_id).await?;
        db::private::preserve_bookmark_extensions(items, &snapshot.modern_items);
        Ok(snapshot.modern_items)
    }

    pub(crate) async fn set_batch(
        &self,
        owner_id: Uuid,
        entries: &[PrivateXmlEntry<'_>],
    ) -> Result<PrivateXmlWriteOutcome> {
        let entries = entries
            .iter()
            .map(|entry| db::PrivateXmlEntry {
                element_name: entry.element_name,
                element_ns: entry.element_ns,
                xml_data: entry.xml_data,
            })
            .collect::<Vec<_>>();
        Ok(
            match db::set_private_xml_batch(
                &self.pool,
                owner_id,
                &entries,
                PRIVATE_XML_MAX_ACCOUNT_BYTES,
            )
            .await?
            {
                db::PrivateXmlWriteOutcome::Stored => PrivateXmlWriteOutcome::Stored,
                db::PrivateXmlWriteOutcome::QuotaExceeded => PrivateXmlWriteOutcome::QuotaExceeded,
            },
        )
    }

    pub(crate) fn legacy_bookmark_limits(&self) -> (i64, i64, i64) {
        (
            PRIVATE_XML_MAX_ACCOUNT_BYTES,
            self.pep_max_nodes,
            self.pep_max_storage_bytes,
        )
    }
}
