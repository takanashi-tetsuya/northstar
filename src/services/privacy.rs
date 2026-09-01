//! Application boundary for XEP-0016 privacy-list persistence and mutations.
//!
//! The stanza layer remains responsible for XML validation and for delivering
//! list-change pushes.  This service owns PostgreSQL access and maps repository
//! outcomes into protocol-neutral business outcomes.

use crate::db;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) use crate::db::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, MAX_PRIVACY_ITEMS,
};

/// Stanza classification a XEP-0016 rule is evaluated against, as named by
/// the stanza layer. The storage-level equivalent never leaves this service
/// and the repository; the two conversions below are the only crossings and
/// both matches are exhaustive, so a new variant fails to compile until it is
/// mapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivacyStanzaKind {
    Message,
    Iq,
    PresenceIn,
    PresenceOut,
}

impl From<PrivacyStanzaKind> for db::PrivacyStanzaKind {
    fn from(kind: PrivacyStanzaKind) -> Self {
        match kind {
            PrivacyStanzaKind::Message => Self::Message,
            PrivacyStanzaKind::Iq => Self::Iq,
            PrivacyStanzaKind::PresenceIn => Self::PresenceIn,
            PrivacyStanzaKind::PresenceOut => Self::PresenceOut,
        }
    }
}

/// Federation, cluster-delivery and MUC-occupant-routing paths still hand the
/// state boundary a storage-level kind. Mapping it here keeps one owner for
/// the conversion instead of letting those callers import the storage model.
impl From<db::PrivacyStanzaKind> for PrivacyStanzaKind {
    fn from(kind: db::PrivacyStanzaKind) -> Self {
        match kind {
            db::PrivacyStanzaKind::Message => Self::Message,
            db::PrivacyStanzaKind::Iq => Self::Iq,
            db::PrivacyStanzaKind::PresenceIn => Self::PresenceIn,
            db::PrivacyStanzaKind::PresenceOut => Self::PresenceOut,
        }
    }
}

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

#[derive(Clone)]
pub(crate) struct PrivacyService {
    pool: PgPool,
}

impl PrivacyService {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn overview(&self, owner_id: Uuid) -> Result<PrivacyOverview> {
        let overview = db::privacy_overview(&self.pool, owner_id).await?;
        Ok(PrivacyOverview {
            default: overview.default,
            names: overview.names,
        })
    }

    pub(crate) async fn list(&self, owner_id: Uuid, name: &str) -> Result<Option<PrivacyList>> {
        db::privacy_list(&self.pool, owner_id, name).await
    }

    pub(crate) async fn select_active(
        &self,
        owner_id: Uuid,
        connection_id: Uuid,
        name: Option<&str>,
    ) -> Result<PrivacySelectionOutcome> {
        Ok(
            if db::set_active_privacy_list(&self.pool, owner_id, connection_id, name).await? {
                PrivacySelectionOutcome::Updated
            } else {
                PrivacySelectionOutcome::Missing
            },
        )
    }

    /// XEP-0016 only permits a default-list change from the account's sole
    /// connected resource.  The protocol/runtime layer supplies the exact
    /// local and clustered resource observation; the service owns the policy
    /// decision and the durable mutation.
    pub(crate) async fn select_default(
        &self,
        owner_id: Uuid,
        name: Option<&str>,
        local_resource_count: usize,
        remote_resource_exists: bool,
    ) -> Result<PrivacySelectionOutcome> {
        if Self::default_change_conflicts(local_resource_count, remote_resource_exists) {
            return Ok(PrivacySelectionOutcome::Conflict);
        }
        Ok(
            if db::set_default_privacy_list(&self.pool, owner_id, name).await? {
                PrivacySelectionOutcome::Updated
            } else {
                PrivacySelectionOutcome::Missing
            },
        )
    }

    pub(crate) async fn replace_list(
        &self,
        owner_id: Uuid,
        list: &PrivacyList,
    ) -> Result<PrivacyListMutationOutcome> {
        Ok(
            match db::replace_privacy_list(&self.pool, owner_id, list).await? {
                db::ReplacePrivacyListOutcome::Stored => PrivacyListMutationOutcome::Stored,
                db::ReplacePrivacyListOutcome::TooManyLists => {
                    PrivacyListMutationOutcome::QuotaExceeded
                }
            },
        )
    }

    /// `active_in_process` closes the small gap between an in-memory live
    /// resource and its renewable durable activity row.  PostgreSQL performs
    /// the authoritative default/active/resumable checks under the owner lock.
    pub(crate) async fn remove_list(
        &self,
        owner_id: Uuid,
        name: &str,
        active_in_process: bool,
    ) -> Result<PrivacyListMutationOutcome> {
        if active_in_process {
            return Ok(PrivacyListMutationOutcome::Conflict);
        }
        Ok(
            match db::remove_privacy_list(&self.pool, owner_id, name).await? {
                db::RemovePrivacyListOutcome::Removed => PrivacyListMutationOutcome::Removed,
                db::RemovePrivacyListOutcome::Missing => PrivacyListMutationOutcome::Missing,
                db::RemovePrivacyListOutcome::Conflict => PrivacyListMutationOutcome::Conflict,
            },
        )
    }

    pub(crate) fn default_change_conflicts(
        local_resource_count: usize,
        remote_resource_exists: bool,
    ) -> bool {
        local_resource_count > 1 || remote_resource_exists
    }

    /// Evaluate one connection's XEP-0016 selection (or the account default
    /// when no active list is selected) for `peer`, refreshing the durable
    /// lease of an explicitly selected active list first. Callers must apply
    /// XEP-0191 first; matching order and the fail-closed posture stay in the
    /// repository.
    pub(crate) async fn session_allows(
        &self,
        owner_id: Uuid,
        connection_id: Uuid,
        active_privacy_list: Option<&str>,
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> Result<bool> {
        if active_privacy_list.is_some() {
            db::refresh_active_privacy_session(&self.pool, owner_id, connection_id).await?;
        }
        Ok(
            !db::privacy_denies(&self.pool, owner_id, active_privacy_list, peer, kind.into())
                .await?,
        )
    }

    /// Forward the repository's account-scoped XEP-0016 evaluation so stanza
    /// handlers can check sender policy without naming a storage-level kind.
    pub(crate) async fn denies(
        &self,
        owner_id: Uuid,
        active_privacy_list: Option<&str>,
        candidate: &str,
        kind: PrivacyStanzaKind,
    ) -> Result<bool> {
        db::privacy_denies(
            &self.pool,
            owner_id,
            active_privacy_list,
            candidate,
            kind.into(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(db::PrivacyStanzaKind::from(kind), storage);
            assert_eq!(PrivacyStanzaKind::from(storage), kind);
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
        let service = PrivacyService::new(pool.clone());
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
                service
                    .session_allows(
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
                service
                    .session_allows(
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
