//! Application-service boundary for RFC 6121 presence and subscriptions.
//!
//! Protocol handlers own stanza validation, recipient fan-out and the
//! notification-before-roster-push ordering required by RFC 6121. This
//! service applies outbound policy and requests complete subscription
//! transitions through its repository port.

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub(crate) use northstar_roster_core::{
    InboundRemotePresenceEffect, LocalPresenceEffect, PresencePolicyDenial, RosterChange,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PresenceAccount {
    pub(crate) id: Uuid,
    pub(crate) username: String,
    pub(crate) auth_generation: i64,
}

/// An administrative notice with the revision, date and token needed to
/// acknowledge its exact delivery claim.
#[derive(Clone, Debug)]
pub(crate) struct ServiceMessageClaim {
    repository_claim: ServiceMessageDeliveryClaim,
}

impl ServiceMessageClaim {
    pub(crate) fn from_lease(repository_claim: ServiceMessageDeliveryClaim) -> Self {
        Self { repository_claim }
    }
    pub(crate) fn lease(&self) -> &ServiceMessageDeliveryClaim {
        &self.repository_claim
    }

    pub(crate) fn kind(&self) -> &str {
        &self.repository_claim.kind
    }

    pub(crate) fn body(&self) -> &str {
        &self.repository_claim.body
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PresenceMutation<T> {
    Unauthorized,
    PolicyDenied(PresencePolicyDenial),
    Missing,
    Transition(T),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LocalSubscriptionTransition {
    pub(crate) actor: PresenceAccount,
    pub(crate) target: PresenceAccount,
    pub(crate) effect: LocalPresenceEffect,
    pub(crate) actor_subscription: String,
    pub(crate) actor_change: Option<RosterChange>,
    pub(crate) target_change: Option<RosterChange>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RemoteSubscriptionTransition {
    pub(crate) actor: PresenceAccount,
    pub(crate) subscription: String,
    pub(crate) change: Option<RosterChange>,
    pub(crate) routed: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InboundSubscriptionTransition {
    pub(crate) recipient: PresenceAccount,
    pub(crate) effect: InboundRemotePresenceEffect,
    pub(crate) subscription: String,
    pub(crate) change: Option<RosterChange>,
    pub(crate) auto_reply: Option<&'static str>,
    pub(crate) send_unavailable: bool,
}

/// The complete authority and stanza input for one local subscription
/// mutation. Keeping these values together prevents call sites from swapping
/// the two generations, identities, or domains in a positional argument list.
pub(crate) struct LocalSubscriptionRequest<'a> {
    pub(crate) actor_id: Uuid,
    pub(crate) expected_auth_generation: i64,
    pub(crate) connection_id: Uuid,
    pub(crate) local_domain: &'a str,
    pub(crate) target_username: &'a str,
    pub(crate) kind: &'a str,
    pub(crate) stanza: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceMessageDeliveryClaim {
    pub kind: String,
    pub body: String,
    pub revision: Uuid,
    pub delivery_date: chrono::NaiveDate,
    pub claim_id: Uuid,
}

pub(crate) trait PresenceRepository: Send + Sync {
    fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn privacy_denies(
        &self,
        owner_id: Uuid,
        active_list: Option<&str>,
        candidate: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn avatar_hash(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn find_enabled_user(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<PresenceAccount>>> + Send;
    fn roster_subscription(
        &self,
        owner_id: Uuid,
        contact: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn replay_cutoff(&self) -> impl std::future::Future<Output = Result<DateTime<Utc>>> + Send;
    fn claim_service_messages(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<ServiceMessageClaim>>> + Send;
    fn complete_service_message_claim(
        &self,
        user_id: Uuid,
        claim: &ServiceMessageClaim,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn transition_remote_with_outbox(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: northstar_federation_core::S2sOutboxPolicy,
    ) -> impl std::future::Future<Output = Result<PresenceMutation<RemoteSubscriptionTransition>>> + Send;
    fn transition_remote(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
    ) -> impl std::future::Future<Output = Result<PresenceMutation<RemoteSubscriptionTransition>>> + Send;
    fn transition_local(
        &self,
        request: LocalSubscriptionRequest<'_>,
    ) -> impl std::future::Future<Output = Result<PresenceMutation<LocalSubscriptionTransition>>> + Send;
    fn transition_inbound(
        &self,
        recipient_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        stanza: &str,
    ) -> impl std::future::Future<Output = Result<PresenceMutation<InboundSubscriptionTransition>>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn cluster_authority_is_current(
        &self,
        local_domain: &str,
        owner_jid: &str,
        owner_id: Uuid,
        owner_auth_generation: i64,
        recipient_jid: &str,
        recipient_id: Uuid,
        recipient_auth_generation: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

#[derive(Clone)]
pub(crate) struct PresenceService<R> {
    repository: R,
}
impl<R: PresenceRepository> PresenceService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        self.repository
            .is_blocked_for_account(owner_id, owner_bare_jid, candidate)
            .await
    }

    pub(crate) async fn privacy_denies(
        &self,
        owner_id: Uuid,
        active_list: Option<&str>,
        candidate: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> Result<bool> {
        self.repository
            .privacy_denies(owner_id, active_list, candidate, kind)
            .await
    }

    /// Blocking takes precedence over the active/default privacy list.
    pub(crate) async fn outbound_denied(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        active_list: Option<&str>,
        candidate: &str,
    ) -> Result<bool> {
        if self
            .is_blocked_for_account(owner_id, owner_bare_jid, candidate)
            .await?
        {
            return Ok(true);
        }
        self.privacy_denies(
            owner_id,
            active_list,
            candidate,
            northstar_xep_0016::PrivacyStanzaKind::PresenceOut,
        )
        .await
    }

    pub(crate) async fn avatar_hash(&self, user_id: Uuid) -> Result<Option<String>> {
        self.repository.avatar_hash(user_id).await
    }

    pub(crate) async fn find_enabled_user(
        &self,
        username: &str,
    ) -> Result<Option<PresenceAccount>> {
        self.repository.find_enabled_user(username).await
    }

    pub(crate) async fn roster_subscription(
        &self,
        owner_id: Uuid,
        contact: &str,
    ) -> Result<Option<String>> {
        self.repository.roster_subscription(owner_id, contact).await
    }

    /// Use the repository clock as the durable replay fence.
    pub(crate) async fn replay_cutoff(&self) -> Result<DateTime<Utc>> {
        self.repository.replay_cutoff().await
    }

    pub(crate) async fn claim_service_messages(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ServiceMessageClaim>> {
        self.repository.claim_service_messages(user_id).await
    }

    pub(crate) async fn complete_service_message_claim(
        &self,
        user_id: Uuid,
        claim: &ServiceMessageClaim,
    ) -> Result<bool> {
        self.repository
            .complete_service_message_claim(user_id, claim)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn transition_remote_with_outbox(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: northstar_federation_core::S2sOutboxPolicy,
    ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
        self.repository
            .transition_remote_with_outbox(
                actor_id,
                expected_auth_generation,
                connection_id,
                local_domain,
                contact,
                kind,
                target_domain,
                stanza,
                bounce_to,
                policy,
            )
            .await
    }

    pub(crate) async fn transition_remote(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
    ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
        self.repository
            .transition_remote(
                actor_id,
                expected_auth_generation,
                connection_id,
                local_domain,
                contact,
                kind,
            )
            .await
    }

    pub(crate) async fn transition_local(
        &self,
        request: LocalSubscriptionRequest<'_>,
    ) -> Result<PresenceMutation<LocalSubscriptionTransition>> {
        self.repository.transition_local(request).await
    }

    pub(crate) async fn transition_inbound(
        &self,
        recipient_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        stanza: &str,
    ) -> Result<PresenceMutation<InboundSubscriptionTransition>> {
        self.repository
            .transition_inbound(recipient_id, local_domain, contact, kind, stanza)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn cluster_authority_is_current(
        &self,
        local_domain: &str,
        owner_jid: &str,
        owner_id: Uuid,
        owner_auth_generation: i64,
        recipient_jid: &str,
        recipient_id: Uuid,
        recipient_auth_generation: i64,
    ) -> Result<bool> {
        self.repository
            .cluster_authority_is_current(
                local_domain,
                owner_jid,
                owner_id,
                owner_auth_generation,
                recipient_jid,
                recipient_id,
                recipient_auth_generation,
            )
            .await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use sqlx::PgPool;
    use std::sync::Arc;
    use std::time::Duration;

    struct IsolatedDatabase {
        admin: PgPool,
        pool: PgPool,
        schema: String,
    }

    impl IsolatedDatabase {
        async fn create(label: &str) -> Self {
            let url = std::env::var("TEST_DATABASE_URL")
                .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
            let admin = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .unwrap();
            let schema = format!("presence_{label}_{}", Uuid::new_v4().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .unwrap();
            let connection_schema = schema.clone();
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .after_connect(move |connection, _| {
                    let statement = format!("SET search_path TO {connection_schema}");
                    Box::pin(async move {
                        sqlx::query(&statement).execute(connection).await?;
                        Ok(())
                    })
                })
                .connect(&url)
                .await
                .unwrap();
            crate::db::migrate(&pool).await.unwrap();
            Self {
                admin,
                pool,
                schema,
            }
        }

        async fn finish(self) {
            self.pool.close().await;
            sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .execute(&self.admin)
                .await
                .unwrap();
            self.admin.close().await;
        }
    }

    async fn insert_user(pool: &PgPool, prefix: &str) -> (Uuid, String, i64) {
        let id = Uuid::new_v4();
        let username = format!("{prefix}{}", &id.simple().to_string()[..10]);
        let generation = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
             RETURNING auth_generation",
        )
        .bind(id)
        .bind(&username)
        .fetch_one(pool)
        .await
        .unwrap();
        (id, username, generation)
    }

    fn policy() -> db::S2sOutboxPolicy {
        db::S2sOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 100,
            max_bytes: 1024 * 1024,
            max_per_domain: 100,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn password_change_and_disable_win_the_client_subscription_fence() {
        let database = IsolatedDatabase::create("auth_fence").await;
        let (actor_id, actor_name, generation) = insert_user(&database.pool, "actor").await;
        let (_, target_name, _) = insert_user(&database.pool, "target").await;
        let service = Arc::new(PresenceService::new(
            db::presence_repository::PostgresPresenceRepository::new(database.pool.clone()),
        ));

        let mut password_change = database.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(actor_id)
            .execute(&mut *password_change)
            .await
            .unwrap();
        let waiting_service = Arc::clone(&service);
        let mut waiting = tokio::spawn(async move {
            waiting_service
                .transition_remote_with_outbox(
                    actor_id,
                    generation,
                    Uuid::new_v4(),
                    "example.test",
                    "peer@remote.test",
                    "subscribe",
                    "remote.test",
                    "<presence xmlns='jabber:client' from='actor@example.test' to='peer@remote.test' type='subscribe'/>",
                    Some("actor@example.test"),
                    policy(),
                )
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting)
                .await
                .is_err()
        );
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(actor_id)
            .execute(&mut *password_change)
            .await
            .unwrap();
        password_change.commit().await.unwrap();
        assert!(matches!(
            waiting.await.unwrap().unwrap(),
            PresenceMutation::Unauthorized
        ));
        assert!(matches!(
            service
                .transition_local(LocalSubscriptionRequest {
                    actor_id,
                    expected_auth_generation: generation,
                    connection_id: Uuid::new_v4(),
                    local_domain: "example.test",
                    target_username: &target_name,
                    kind: "subscribe",
                    stanza: &format!(
                        "<presence xmlns='jabber:client' from='{actor_name}@example.test' to='{target_name}@example.test' type='subscribe'/>"
                    ),
                })
                .await
                .unwrap(),
            PresenceMutation::Unauthorized
        ));

        let current_generation: i64 =
            sqlx::query_scalar("SELECT auth_generation FROM users WHERE id=$1")
                .bind(actor_id)
                .fetch_one(&database.pool)
                .await
                .unwrap();
        let mut disable = database.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(actor_id)
            .execute(&mut *disable)
            .await
            .unwrap();
        let waiting_service = Arc::clone(&service);
        let mut waiting = tokio::spawn(async move {
            waiting_service
                .transition_remote(
                    actor_id,
                    current_generation,
                    Uuid::new_v4(),
                    "example.test",
                    "component@component.test",
                    "subscribe",
                )
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting)
                .await
                .is_err()
        );
        sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
            .bind(actor_id)
            .execute(&mut *disable)
            .await
            .unwrap();
        disable.commit().await.unwrap();
        assert!(matches!(
            waiting.await.unwrap().unwrap(),
            PresenceMutation::Unauthorized
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM roster_items")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
        );
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn target_delete_recreate_does_not_inherit_an_inflight_subscription() {
        let database = IsolatedDatabase::create("target_aba").await;
        let (actor_id, actor_name, generation) = insert_user(&database.pool, "actor").await;
        let (old_target_id, target_name, _) = insert_user(&database.pool, "target").await;
        let (resolved_tx, resolved_rx) = tokio::sync::oneshot::channel();
        let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();
        let pool = database.pool.clone();
        let target_for_task = target_name.clone();
        let waiting = tokio::spawn(async move {
            db::roster::transition_local_presence_subscription_authorized_test_hook(
                &pool,
                actor_id,
                generation,
                Uuid::new_v4(),
                "example.test",
                &target_for_task,
                "subscribe",
                &format!(
                    "<presence xmlns='jabber:client' from='{actor_name}@example.test' to='{target_for_task}@example.test' type='subscribe'/>"
                ),
                move || async move {
                    let _ = resolved_tx.send(());
                    let _ = continue_rx.await;
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), resolved_rx)
            .await
            .expect("target resolution signal timed out")
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(old_target_id)
            .execute(&database.pool)
            .await
            .unwrap();
        let new_target_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(new_target_id)
            .bind(&target_name)
            .execute(&database.pool)
            .await
            .unwrap();
        continue_tx.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .expect("target incarnation subscription task timed out")
                .unwrap()
                .unwrap(),
            db::AuthorizedLocalPresenceTransition::Missing
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM roster_items WHERE owner_id=$1 OR owner_id=$2",
            )
            .bind(actor_id)
            .bind(new_target_id)
            .fetch_one(&database.pool)
            .await
            .unwrap(),
            0
        );
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn inverse_local_requests_share_uuid_lock_order_and_commit_both() {
        let database = IsolatedDatabase::create("inverse").await;
        let (alice_id, alice, alice_generation) = insert_user(&database.pool, "alice").await;
        let (bob_id, bob, bob_generation) = insert_user(&database.pool, "bob").await;
        let service = PresenceService::new(
            db::presence_repository::PostgresPresenceRepository::new(database.pool.clone()),
        );
        let alice_request = format!(
            "<presence xmlns='jabber:client' from='{alice}@example.test' to='{bob}@example.test' type='subscribe'/>"
        );
        let bob_request = format!(
            "<presence xmlns='jabber:client' from='{bob}@example.test' to='{alice}@example.test' type='subscribe'/>"
        );
        let (alice_result, bob_result) = tokio::join!(
            service.transition_local(LocalSubscriptionRequest {
                actor_id: alice_id,
                expected_auth_generation: alice_generation,
                connection_id: Uuid::new_v4(),
                local_domain: "example.test",
                target_username: &bob,
                kind: "subscribe",
                stanza: &alice_request,
            }),
            service.transition_local(LocalSubscriptionRequest {
                actor_id: bob_id,
                expected_auth_generation: bob_generation,
                connection_id: Uuid::new_v4(),
                local_domain: "example.test",
                target_username: &alice,
                kind: "subscribe",
                stanza: &bob_request,
            })
        );
        assert!(matches!(
            alice_result.unwrap(),
            PresenceMutation::Transition(LocalSubscriptionTransition {
                effect: LocalPresenceEffect::Forward,
                ..
            })
        ));
        assert!(matches!(
            bob_result.unwrap(),
            PresenceMutation::Transition(LocalSubscriptionTransition {
                effect: LocalPresenceEffect::Forward,
                ..
            })
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pending_presence_subscriptions",)
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            2
        );
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn remote_outbox_failure_rolls_back_the_roster_transition() {
        let database = IsolatedDatabase::create("outbox_rollback").await;
        let (actor_id, actor, generation) = insert_user(&database.pool, "actor").await;
        sqlx::query(
            "CREATE FUNCTION fail_presence_outbox() RETURNS trigger LANGUAGE plpgsql
             AS $$ BEGIN RAISE EXCEPTION 'forced outbox failure'; END $$",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_presence_outbox BEFORE INSERT ON s2s_outbox
             FOR EACH ROW EXECUTE FUNCTION fail_presence_outbox()",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let service = PresenceService::new(
            db::presence_repository::PostgresPresenceRepository::new(database.pool.clone()),
        );
        let stanza = format!(
            "<presence xmlns='jabber:client' from='{actor}@example.test' to='peer@remote.test' type='subscribe'/>"
        );
        assert!(service
            .transition_remote_with_outbox(
                actor_id,
                generation,
                Uuid::new_v4(),
                "example.test",
                "peer@remote.test",
                "subscribe",
                "remote.test",
                &stanza,
                Some(&format!("{actor}@example.test")),
                policy(),
            )
            .await
            .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM roster_items")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
        );
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn duplicate_local_subscribe_is_a_true_state_noop() {
        let database = IsolatedDatabase::create("duplicate").await;
        let (actor_id, actor, generation) = insert_user(&database.pool, "actor").await;
        let (_, target, _) = insert_user(&database.pool, "target").await;
        let service = PresenceService::new(
            db::presence_repository::PostgresPresenceRepository::new(database.pool.clone()),
        );
        let stanza = format!(
            "<presence xmlns='jabber:client' from='{actor}@example.test' to='{target}@example.test' type='subscribe'/>"
        );
        let first = service
            .transition_local(LocalSubscriptionRequest {
                actor_id,
                expected_auth_generation: generation,
                connection_id: Uuid::new_v4(),
                local_domain: "example.test",
                target_username: &target,
                kind: "subscribe",
                stanza: &stanza,
            })
            .await
            .unwrap();
        assert!(matches!(
            first,
            PresenceMutation::Transition(LocalSubscriptionTransition {
                effect: LocalPresenceEffect::Forward,
                ..
            })
        ));
        let version_after_first: i64 =
            sqlx::query_scalar("SELECT roster_version FROM users WHERE id=$1")
                .bind(actor_id)
                .fetch_one(&database.pool)
                .await
                .unwrap();
        let duplicate = service
            .transition_local(LocalSubscriptionRequest {
                actor_id,
                expected_auth_generation: generation,
                connection_id: Uuid::new_v4(),
                local_domain: "example.test",
                target_username: &target,
                kind: "subscribe",
                stanza: &stanza,
            })
            .await
            .unwrap();
        assert!(matches!(
            duplicate,
            PresenceMutation::Transition(LocalSubscriptionTransition {
                effect: LocalPresenceEffect::Suppressed,
                actor_change: None,
                target_change: None,
                ..
            })
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT roster_version FROM users WHERE id=$1")
                .bind(actor_id)
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            version_after_first
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pending_presence_subscriptions",)
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            1
        );
        database.finish().await;
    }

    fn privacy_list(name: &str, action: db::PrivacyAction) -> db::PrivacyList {
        db::PrivacyList {
            name: name.to_owned(),
            items: vec![db::PrivacyItem {
                order: 1,
                action,
                match_type: None,
                match_value: None,
                message: false,
                iq: false,
                presence_in: true,
                presence_out: true,
            }],
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn exact_connection_privacy_and_default_change_fence_subscription_mutation() {
        let database = IsolatedDatabase::create("privacy_fence").await;
        let (actor_id, actor, generation) = insert_user(&database.pool, "actor").await;
        let (_, target, _) = insert_user(&database.pool, "target").await;
        let deny_connection = Uuid::new_v4();
        let allow_connection = Uuid::new_v4();
        db::replace_privacy_list(
            &database.pool,
            actor_id,
            &privacy_list("deny", db::PrivacyAction::Deny),
        )
        .await
        .unwrap();
        db::replace_privacy_list(
            &database.pool,
            actor_id,
            &privacy_list("allow", db::PrivacyAction::Allow),
        )
        .await
        .unwrap();
        assert!(
            db::set_default_privacy_list(&database.pool, actor_id, Some("allow"))
                .await
                .unwrap()
        );
        assert!(db::set_active_privacy_list(
            &database.pool,
            actor_id,
            deny_connection,
            Some("deny"),
        )
        .await
        .unwrap());
        assert!(db::set_active_privacy_list(
            &database.pool,
            actor_id,
            allow_connection,
            Some("allow"),
        )
        .await
        .unwrap());
        let stanza = format!(
            "<presence xmlns='jabber:client' from='{actor}@example.test' to='{target}@example.test' type='subscribe'/>"
        );
        let service = Arc::new(PresenceService::new(
            db::presence_repository::PostgresPresenceRepository::new(database.pool.clone()),
        ));
        assert!(matches!(
            service
                .transition_local(LocalSubscriptionRequest {
                    actor_id,
                    expected_auth_generation: generation,
                    connection_id: deny_connection,
                    local_domain: "example.test",
                    target_username: &target,
                    kind: "subscribe",
                    stanza: &stanza,
                })
                .await
                .unwrap(),
            PresenceMutation::PolicyDenied(PresencePolicyDenial::Privacy)
        ));

        // Hold the same account row every privacy mutation uses, start the
        // subscription, then commit a new deny default. The waiting mutation
        // must observe the committed policy in its own transaction rather
        // than an earlier protocol-layer snapshot.
        let mut change = database.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(actor_id)
            .execute(&mut *change)
            .await
            .unwrap();
        sqlx::query("UPDATE privacy_default_lists SET list_name='deny' WHERE owner_id=$1")
            .bind(actor_id)
            .execute(&mut *change)
            .await
            .unwrap();
        let waiting_service = Arc::clone(&service);
        let mut waiting = tokio::spawn(async move {
            waiting_service
                .transition_remote(
                    actor_id,
                    generation,
                    Uuid::new_v4(),
                    "example.test",
                    "peer@remote.test",
                    "subscribe",
                )
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting)
                .await
                .is_err()
        );
        change.commit().await.unwrap();
        assert!(matches!(
            waiting.await.unwrap().unwrap(),
            PresenceMutation::PolicyDenied(PresencePolicyDenial::Privacy)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM roster_items")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
        );
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn block_commit_and_inbound_default_policy_win_subscription_races() {
        let database = IsolatedDatabase::create("block_inbound").await;
        let (actor_id, actor, generation) = insert_user(&database.pool, "actor").await;
        let (target_id, target, _) = insert_user(&database.pool, "target").await;
        let service = Arc::new(PresenceService::new(
            db::presence_repository::PostgresPresenceRepository::new(database.pool.clone()),
        ));
        let mut blocker = database.pool.begin().await.unwrap();
        // Production block/unblock takes the exact enabled owner row before
        // the block-policy advisory lock. Reproduce that order here so the
        // race proves committed policy visibility without constructing the
        // former advisory -> FK/user AB/BA deadlock.
        sqlx::query(
            "SELECT id FROM users
              WHERE id=$1 AND NOT is_disabled FOR UPDATE",
        )
        .bind(actor_id)
        .execute(&mut *blocker)
        .await
        .unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))")
            .bind(actor_id)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let waiting_service = Arc::clone(&service);
        let target_for_task = target.clone();
        let stanza = format!(
            "<presence xmlns='jabber:client' from='{actor}@example.test' to='{target}@example.test' type='subscribe'/>"
        );
        let mut waiting = tokio::spawn(async move {
            waiting_service
                .transition_local(LocalSubscriptionRequest {
                    actor_id,
                    expected_auth_generation: generation,
                    connection_id: Uuid::new_v4(),
                    local_domain: "example.test",
                    target_username: &target_for_task,
                    kind: "subscribe",
                    stanza: &stanza,
                })
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting)
                .await
                .is_err()
        );
        sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
            .bind(actor_id)
            .bind(format!("{target}@example.test"))
            .execute(&mut *blocker)
            .await
            .unwrap();
        blocker.commit().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .expect("blocked subscription race timed out")
                .unwrap()
                .unwrap(),
            PresenceMutation::PolicyDenied(PresencePolicyDenial::Blocking)
        ));

        db::replace_privacy_list(
            &database.pool,
            target_id,
            &privacy_list("inbound-deny", db::PrivacyAction::Deny),
        )
        .await
        .unwrap();
        assert!(
            db::set_default_privacy_list(&database.pool, target_id, Some("inbound-deny"),)
                .await
                .unwrap()
        );
        assert!(matches!(
            service
                .transition_inbound(
                    target_id,
                    "example.test",
                    "sender@remote.test",
                    "subscribe",
                    &format!(
                        "<presence xmlns='jabber:client' from='sender@remote.test' to='{target}@example.test' type='subscribe'/>"
                    ),
                )
                .await
                .unwrap(),
            PresenceMutation::PolicyDenied(PresencePolicyDenial::Privacy)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pending_presence_subscriptions")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM federated_presence_pending")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
        );
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn cluster_presence_authority_rejects_generation_change_and_same_name_recreation() {
        let database = IsolatedDatabase::create("cluster_presence_authority").await;
        let (owner_id, owner, owner_generation) = insert_user(&database.pool, "owner").await;
        let (recipient_id, recipient, recipient_generation) =
            insert_user(&database.pool, "recipient").await;
        let service = PresenceService::new(
            db::presence_repository::PostgresPresenceRepository::new(database.pool.clone()),
        );
        let owner_jid = format!("{owner}@example.test/Phone");
        let recipient_jid = format!("{recipient}@example.test");
        assert!(service
            .cluster_authority_is_current(
                "example.test",
                &owner_jid,
                owner_id,
                owner_generation,
                &recipient_jid,
                recipient_id,
                recipient_generation,
            )
            .await
            .unwrap());

        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(owner_id)
            .execute(&database.pool)
            .await
            .unwrap();
        assert!(!service
            .cluster_authority_is_current(
                "example.test",
                &owner_jid,
                owner_id,
                owner_generation,
                &recipient_jid,
                recipient_id,
                recipient_generation,
            )
            .await
            .unwrap());

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient_id)
            .execute(&database.pool)
            .await
            .unwrap();
        let recreated_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recreated_id)
            .bind(&recipient)
            .execute(&database.pool)
            .await
            .unwrap();
        assert!(!service
            .cluster_authority_is_current(
                "example.test",
                &owner_jid,
                owner_id,
                owner_generation + 1,
                &recipient_jid,
                recipient_id,
                recipient_generation,
            )
            .await
            .unwrap());
        database.finish().await;
    }
}
