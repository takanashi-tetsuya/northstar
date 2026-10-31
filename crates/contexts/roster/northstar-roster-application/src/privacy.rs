//! Application boundary for XEP-0016 privacy-list persistence and mutations.
//!
//! Applies live-resource policy before requesting an account-scoped mutation.
//! The protocol adapter validates XML and sends list-change notifications.

use anyhow::Result;
use uuid::Uuid;

pub use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind, MAX_PRIVACY_ITEMS,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyOverview {
    pub default: Option<String>,
    pub names: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacySelectionOutcome {
    Updated,
    Missing,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyListMutationOutcome {
    Stored,
    Removed,
    Missing,
    Conflict,
    QuotaExceeded,
}

pub trait PrivacyRepository: Send + Sync {
    fn clear_active_session(
        &self,
        owner_id: Uuid,
        connection_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    fn overview(
        &self,
        owner_id: Uuid,
    ) -> impl std::future::Future<Output = Result<PrivacyOverview>> + Send;
    fn list(
        &self,
        owner_id: Uuid,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Option<PrivacyList>>> + Send;
    fn select_active(
        &self,
        owner_id: Uuid,
        connection_id: Uuid,
        name: Option<&str>,
    ) -> impl std::future::Future<Output = Result<PrivacySelectionOutcome>> + Send;
    fn select_default(
        &self,
        owner_id: Uuid,
        name: Option<&str>,
    ) -> impl std::future::Future<Output = Result<PrivacySelectionOutcome>> + Send;
    fn replace_list(
        &self,
        owner_id: Uuid,
        list: &PrivacyList,
    ) -> impl std::future::Future<Output = Result<PrivacyListMutationOutcome>> + Send;
    fn remove_list(
        &self,
        owner_id: Uuid,
        name: &str,
    ) -> impl std::future::Future<Output = Result<PrivacyListMutationOutcome>> + Send;
    fn denies(
        &self,
        owner_id: Uuid,
        active_privacy_list: Option<&str>,
        candidate: &str,
        kind: PrivacyStanzaKind,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}
#[derive(Clone)]
pub struct PrivacyService<R> {
    repository: R,
}
impl<R: PrivacyRepository> PrivacyService<R> {
    pub async fn clear_active_session(&self, owner_id: Uuid, connection_id: Uuid) -> Result<()> {
        self.repository
            .clear_active_session(owner_id, connection_id)
            .await
    }

    pub fn new(repository: R) -> Self {
        Self { repository }
    }
    pub async fn overview(&self, owner_id: Uuid) -> Result<PrivacyOverview> {
        self.repository.overview(owner_id).await
    }
    pub async fn list(&self, owner_id: Uuid, name: &str) -> Result<Option<PrivacyList>> {
        self.repository.list(owner_id, name).await
    }
    pub async fn select_active(
        &self,
        owner_id: Uuid,
        connection_id: Uuid,
        name: Option<&str>,
    ) -> Result<PrivacySelectionOutcome> {
        self.repository
            .select_active(owner_id, connection_id, name)
            .await
    }
    /// Reject changes while another resource is connected. Durable policy
    /// checks still run under the repository's account lock.
    pub async fn select_default(
        &self,
        owner_id: Uuid,
        name: Option<&str>,
        local_resource_count: usize,
        remote_resource_exists: bool,
    ) -> Result<PrivacySelectionOutcome> {
        if default_change_conflicts(local_resource_count, remote_resource_exists) {
            return Ok(PrivacySelectionOutcome::Conflict);
        }

        self.repository.select_default(owner_id, name).await
    }
    pub async fn replace_list(
        &self,
        owner_id: Uuid,
        list: &PrivacyList,
    ) -> Result<PrivacyListMutationOutcome> {
        self.repository.replace_list(owner_id, list).await
    }
    /// A local resource can precede its durable activity row. Keep this guard
    /// in addition to the repository's default/active/resumable checks.
    pub async fn remove_list(
        &self,
        owner_id: Uuid,
        name: &str,
        active_in_process: bool,
    ) -> Result<PrivacyListMutationOutcome> {
        if active_in_process {
            return Ok(PrivacyListMutationOutcome::Conflict);
        }

        self.repository.remove_list(owner_id, name).await
    }
    pub async fn denies(
        &self,
        owner_id: Uuid,
        active_privacy_list: Option<&str>,
        candidate: &str,
        kind: PrivacyStanzaKind,
    ) -> Result<bool> {
        self.repository
            .denies(owner_id, active_privacy_list, candidate, kind)
            .await
    }
}
pub fn default_change_conflicts(local_resource_count: usize, remote_resource_exists: bool) -> bool {
    northstar_xep_0016::default_change_conflicts(local_resource_count, remote_resource_exists)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnavailableRepository(std::sync::atomic::AtomicUsize);

    impl PrivacyRepository for UnavailableRepository {
        async fn clear_active_session(&self, _: Uuid, _: Uuid) -> Result<()> {
            unreachable!()
        }

        async fn overview(&self, _: Uuid) -> Result<PrivacyOverview> {
            unreachable!()
        }
        async fn list(&self, _: Uuid, _: &str) -> Result<Option<PrivacyList>> {
            unreachable!()
        }
        async fn select_active(
            &self,
            _: Uuid,
            _: Uuid,
            _: Option<&str>,
        ) -> Result<PrivacySelectionOutcome> {
            unreachable!()
        }
        async fn select_default(
            &self,
            _: Uuid,
            _: Option<&str>,
        ) -> Result<PrivacySelectionOutcome> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            anyhow::bail!("repository unavailable")
        }
        async fn replace_list(
            &self,
            _: Uuid,
            _: &PrivacyList,
        ) -> Result<PrivacyListMutationOutcome> {
            unreachable!()
        }
        async fn remove_list(&self, _: Uuid, _: &str) -> Result<PrivacyListMutationOutcome> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            anyhow::bail!("repository unavailable")
        }
        async fn denies(
            &self,
            _: Uuid,
            _: Option<&str>,
            _: &str,
            _: PrivacyStanzaKind,
        ) -> Result<bool> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn local_conflicts_do_not_acquire_persistence_and_storage_errors_remain_errors() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let service = PrivacyService::new(UnavailableRepository(AtomicUsize::new(0)));
        let owner = Uuid::new_v4();
        for (local, remote) in [(2, false), (1, true)] {
            assert_eq!(
                service
                    .select_default(owner, Some("work"), local, remote)
                    .await
                    .unwrap(),
                PrivacySelectionOutcome::Conflict
            );
        }
        assert_eq!(
            service.remove_list(owner, "work", true).await.unwrap(),
            PrivacyListMutationOutcome::Conflict
        );
        assert_eq!(service.repository.0.load(Ordering::SeqCst), 0);
        assert!(service
            .select_default(owner, Some("work"), 1, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("repository unavailable"));
        assert!(service
            .remove_list(owner, "work", false)
            .await
            .unwrap_err()
            .to_string()
            .contains("repository unavailable"));
        assert_eq!(service.repository.0.load(Ordering::SeqCst), 2);
    }
}
