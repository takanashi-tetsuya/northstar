mod active_selection;
mod decision;
mod list_commands;
mod query;

pub use active_selection::{
    clear_active_privacy_session, refresh_active_privacy_session, renew_active_privacy_selection,
    set_active_privacy_list, set_active_privacy_list_in_transaction,
};
pub use decision::{
    privacy_denies, privacy_denies_from_facts, privacy_denies_in_snapshot,
    privacy_denies_in_transaction, session_privacy_denies,
};
pub use list_commands::{
    remove_privacy_list, replace_privacy_list, set_default_privacy_list, RemovePrivacyListOutcome,
    ReplacePrivacyListOutcome,
};
pub use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind,
    MAX_PRIVACY_ITEMS, MAX_PRIVACY_LISTS,
};
pub use query::{privacy_list, privacy_overview, PrivacyOverview};

// The runtime role has no UPDATE on users, so account locks go through the
// reviewed row-lock capabilities. Each returns no row for a deleted account.
const LOCK_OWNER_FOR_UPDATE_SQL: &str =
    "SELECT id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])";
const LOCK_OWNER_FOR_SHARE_SQL: &str =
    "SELECT id FROM northstar_lock_user_rows_share(ARRAY[$1::uuid])";

/// Projection for a policy snapshot whose `requested` CTE supplies owner,
/// connection, expected-active, and peer-bare columns in request order.
pub const PRIVACY_DECISION_FACTS: &str = "SELECT requested.position AS privacy_position,
           (requested.expects_active AND active.list_name IS NULL)
           OR (COALESCE(active.list_name, defaults.list_name) IS NOT NULL AND list.name IS NULL)
           AS missing_selection,
           list.name AS selected_name, roster.subscription, roster.groups,
           item.item_order, item.action, item.match_type, item.match_value,
           item.filter_message, item.filter_iq, item.filter_presence_in, item.filter_presence_out
      FROM requested
      LEFT JOIN privacy_active_sessions active
        ON active.owner_id=requested.owner_id AND active.connection_id=requested.connection_id
       AND active.expires_at>statement_timestamp()
      LEFT JOIN privacy_default_lists defaults ON defaults.owner_id=requested.owner_id
      LEFT JOIN privacy_lists list ON list.owner_id=requested.owner_id
       AND list.name=COALESCE(active.list_name, defaults.list_name)
      LEFT JOIN privacy_list_items item ON item.owner_id=list.owner_id AND item.list_name=list.name
      LEFT JOIN roster_items roster ON roster.owner_id=requested.owner_id
       AND roster.contact_jid=requested.peer_bare";

mod application_repository {
    use anyhow::Result;
    use northstar_roster_application::privacy::*;
    use sqlx::PgPool;
    use uuid::Uuid;
    #[derive(Clone)]
    pub struct PostgresPrivacyRepository {
        pool: PgPool,
    }
    impl PostgresPrivacyRepository {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }
    }
    impl PrivacyRepository for PostgresPrivacyRepository {
        async fn clear_active_session(&self, owner_id: Uuid, connection_id: Uuid) -> Result<()> {
            super::clear_active_privacy_session(&self.pool, owner_id, connection_id).await
        }

        async fn overview(&self, owner_id: Uuid) -> Result<PrivacyOverview> {
            let overview = super::privacy_overview(&self.pool, owner_id).await?;
            Ok(PrivacyOverview {
                default: overview.default,
                names: overview.names,
            })
        }
        async fn list(&self, owner_id: Uuid, name: &str) -> Result<Option<PrivacyList>> {
            super::privacy_list(&self.pool, owner_id, name).await
        }
        async fn select_active(
            &self,
            owner_id: Uuid,
            connection_id: Uuid,
            name: Option<&str>,
        ) -> Result<PrivacySelectionOutcome> {
            Ok(
                if super::set_active_privacy_list(&self.pool, owner_id, connection_id, name).await?
                {
                    PrivacySelectionOutcome::Updated
                } else {
                    PrivacySelectionOutcome::Missing
                },
            )
        }
        async fn select_default(
            &self,
            owner_id: Uuid,
            name: Option<&str>,
        ) -> Result<PrivacySelectionOutcome> {
            Ok(
                if super::set_default_privacy_list(&self.pool, owner_id, name).await? {
                    PrivacySelectionOutcome::Updated
                } else {
                    PrivacySelectionOutcome::Missing
                },
            )
        }
        async fn replace_list(
            &self,
            owner_id: Uuid,
            list: &PrivacyList,
        ) -> Result<PrivacyListMutationOutcome> {
            Ok(
                match super::replace_privacy_list(&self.pool, owner_id, list).await? {
                    super::ReplacePrivacyListOutcome::Stored => PrivacyListMutationOutcome::Stored,
                    super::ReplacePrivacyListOutcome::TooManyLists => {
                        PrivacyListMutationOutcome::QuotaExceeded
                    }
                },
            )
        }
        async fn remove_list(
            &self,
            owner_id: Uuid,
            name: &str,
        ) -> Result<PrivacyListMutationOutcome> {
            Ok(
                match super::remove_privacy_list(&self.pool, owner_id, name).await? {
                    super::RemovePrivacyListOutcome::Removed => PrivacyListMutationOutcome::Removed,
                    super::RemovePrivacyListOutcome::Missing => PrivacyListMutationOutcome::Missing,
                    super::RemovePrivacyListOutcome::Conflict => {
                        PrivacyListMutationOutcome::Conflict
                    }
                },
            )
        }
        async fn denies(
            &self,
            owner_id: Uuid,
            active_privacy_list: Option<&str>,
            candidate: &str,
            kind: PrivacyStanzaKind,
        ) -> Result<bool> {
            super::privacy_denies(&self.pool, owner_id, active_privacy_list, candidate, kind).await
        }
    }
}
pub use application_repository::PostgresPrivacyRepository;
