//! Application boundary for XEP-0016 privacy-list persistence and mutations.
//!
//! Applies live-resource policy before requesting an account-scoped mutation.
//! The protocol adapter validates XML and sends list-change notifications.

use anyhow::Result;
use uuid::Uuid;

pub(crate) use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind, MAX_PRIVACY_ITEMS,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrivacyOverview {
    pub(crate) default: Option<String>,
    pub(crate) names: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivacySelectionOutcome {
    Updated,
    Missing,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivacyListMutationOutcome {
    Stored,
    Removed,
    Missing,
    Conflict,
    QuotaExceeded,
}

pub(crate) trait PrivacyRepository: Send + Sync {
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
pub(crate) struct PrivacyService<R> {
    repository: R,
}
impl<R: PrivacyRepository> PrivacyService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn overview(&self, owner_id: Uuid) -> Result<PrivacyOverview> {
        self.repository.overview(owner_id).await
    }
    pub(crate) async fn list(&self, owner_id: Uuid, name: &str) -> Result<Option<PrivacyList>> {
        self.repository.list(owner_id, name).await
    }
    pub(crate) async fn select_active(
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
    pub(crate) async fn select_default(
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
    pub(crate) async fn replace_list(
        &self,
        owner_id: Uuid,
        list: &PrivacyList,
    ) -> Result<PrivacyListMutationOutcome> {
        self.repository.replace_list(owner_id, list).await
    }
    /// A local resource can precede its durable activity row. Keep this guard
    /// in addition to the repository's default/active/resumable checks.
    pub(crate) async fn remove_list(
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
    pub(crate) async fn denies(
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
pub(crate) fn default_change_conflicts(
    local_resource_count: usize,
    remote_resource_exists: bool,
) -> bool {
    northstar_xep_0016::default_change_conflicts(local_resource_count, remote_resource_exists)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    struct UnavailableRepository(std::sync::atomic::AtomicUsize);

    impl PrivacyRepository for UnavailableRepository {
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

    #[test]
    fn stanza_kind_conversions_preserve_every_stanza_classification() {
        let mappings = [
            (PrivacyStanzaKind::Message, db::PrivacyStanzaKind::Message),
            (PrivacyStanzaKind::Iq, db::PrivacyStanzaKind::Iq),
            (
                PrivacyStanzaKind::PresenceIn,
                db::PrivacyStanzaKind::PresenceIn,
            ),
            (
                PrivacyStanzaKind::PresenceOut,
                db::PrivacyStanzaKind::PresenceOut,
            ),
        ];
        for (kind, storage) in mappings {
            assert_eq!(kind, storage);
            assert_eq!(storage, kind);
        }
    }

    /// End-to-end guard for the boundary conversion: for every stanza kind the
    /// service must deny and allow exactly what the repository produced while
    /// the stanza layer passed hardcoded storage kinds. Ignored like the
    /// repository tests because it needs a disposable database.
    #[tokio::test]
    #[ignore = "requires a random-schema TEST_DATABASE_URL"]
    async fn privacy_service_boundary_preserves_stanza_kind_allow_deny_results() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a disposable random-schema xmpp_test URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let service =
            PrivacyService::new(db::privacy::PostgresPrivacyRepository::new(pool.clone()));
        let messaging = crate::services::messaging::MessageService::new(
            crate::db::messaging::PostgresMessageRepository::new(
                pool.clone(),
                crate::abuse::test_personal_message_content_keyring(),
                "example.test",
                100,
                8_000_000,
                30,
            ),
            false,
        );
        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(owner_id)
            .bind(format!("privacysvc{}", owner_id.simple()))
            .execute(&pool)
            .await
            .unwrap();

        // First match wins: the deny covers messages only, so the later
        // unfiltered allow never fires for Message but does for the rest.
        let list = PrivacyList {
            name: "boundary".to_owned(),
            items: vec![
                PrivacyItem {
                    order: 10,
                    action: PrivacyAction::Deny,
                    match_type: Some(PrivacyMatchType::Jid),
                    match_value: Some("bob@example.test".to_owned()),
                    message: true,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
                PrivacyItem {
                    order: 20,
                    action: PrivacyAction::Allow,
                    match_type: None,
                    match_value: None,
                    message: false,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
            ],
        };
        assert_eq!(
            service.replace_list(owner_id, &list).await.unwrap(),
            PrivacyListMutationOutcome::Stored
        );
        assert_eq!(
            service
                .select_default(owner_id, Some("boundary"), 1, false)
                .await
                .unwrap(),
            PrivacySelectionOutcome::Updated
        );

        for kind in [
            PrivacyStanzaKind::Message,
            PrivacyStanzaKind::Iq,
            PrivacyStanzaKind::PresenceIn,
            PrivacyStanzaKind::PresenceOut,
        ] {
            let expected_denied = matches!(kind, PrivacyStanzaKind::Message);
            assert_eq!(
                service
                    .denies(owner_id, None, "bob@example.test/Phone", kind)
                    .await
                    .unwrap(),
                expected_denied,
                "account-scoped evaluation drifted for {kind:?}"
            );
            let connection_id = Uuid::new_v4();
            assert_eq!(
                service
                    .select_active(owner_id, connection_id, Some("boundary"))
                    .await
                    .unwrap(),
                PrivacySelectionOutcome::Updated
            );
            assert_eq!(
                messaging
                    .privacy_allows_session(
                        owner_id,
                        connection_id,
                        Some("boundary"),
                        "bob@example.test/Phone",
                        kind
                    )
                    .await
                    .unwrap(),
                !expected_denied,
                "session-scoped evaluation drifted for {kind:?}"
            );
            assert_eq!(
                messaging
                    .privacy_allows_session(
                        owner_id,
                        connection_id,
                        None,
                        "bob@example.test/Phone",
                        kind
                    )
                    .await
                    .unwrap(),
                !expected_denied,
                "default-list fallback drifted for {kind:?}"
            );
        }

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
