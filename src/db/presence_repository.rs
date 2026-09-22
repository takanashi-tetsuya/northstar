//! PostgreSQL presence policy snapshots and complete subscription mutations.
use crate::{db, services::presence::*};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresPresenceRepository {
    pool: PgPool,
}
impl PostgresPresenceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl PresenceRepository for PostgresPresenceRepository {
    async fn roster_subscriptions(&self, owner_id: Uuid) -> Result<Vec<(String, String)>> {
        Ok(db::roster(&self.pool, owner_id)
            .await?
            .into_iter()
            .map(|(jid, _, subscription, _)| (jid, subscription))
            .collect())
    }

    async fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        db::is_blocked_for_account(&self.pool, owner_id, owner_bare_jid, candidate).await
    }

    async fn privacy_denies(
        &self,
        owner_id: Uuid,
        active_list: Option<&str>,
        candidate: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> Result<bool> {
        db::privacy_denies(&self.pool, owner_id, active_list, candidate, kind).await
    }

    async fn avatar_hash(&self, user_id: Uuid) -> Result<Option<String>> {
        Ok(db::get_vcard(&self.pool, user_id).await?.avatar_hash)
    }

    async fn find_enabled_user(&self, username: &str) -> Result<Option<PresenceAccount>> {
        Ok(db::find_enabled_user(&self.pool, username)
            .await?
            .map(|user| PresenceAccount {
                id: user.id,
                username: user.username,
                auth_generation: user.auth_generation,
            }))
    }

    async fn roster_subscription(&self, owner_id: Uuid, contact: &str) -> Result<Option<String>> {
        Ok(db::roster_item(&self.pool, owner_id, contact)
            .await?
            .map(|item| item.2))
    }

    async fn replay_cutoff(&self) -> Result<DateTime<Utc>> {
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    async fn claim_service_messages(&self, user_id: Uuid) -> Result<Vec<ServiceMessageClaim>> {
        Ok(db::claim_admin_service_messages(&self.pool, user_id)
            .await?
            .into_iter()
            .map(ServiceMessageClaim::from_lease)
            .collect())
    }

    async fn complete_service_message_claim(
        &self,
        user_id: Uuid,
        claim: &ServiceMessageClaim,
    ) -> Result<bool> {
        db::complete_admin_service_message_claim(&self.pool, user_id, claim.lease()).await
    }

    async fn transition_remote_with_outbox(
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
        let outcome = db::transition_remote_presence_subscription_with_outbox_authorized(
            &self.pool,
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
        .await?;
        Ok(map_remote_transition(outcome))
    }

    async fn transition_remote(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
    ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
        let outcome = db::transition_remote_presence_subscription_authorized(
            &self.pool,
            actor_id,
            expected_auth_generation,
            connection_id,
            local_domain,
            contact,
            kind,
        )
        .await?;
        Ok(map_remote_transition(outcome))
    }

    async fn transition_local(
        &self,
        request: LocalSubscriptionRequest<'_>,
    ) -> Result<PresenceMutation<LocalSubscriptionTransition>> {
        let LocalSubscriptionRequest {
            actor_id,
            expected_auth_generation,
            connection_id,
            local_domain,
            target_username,
            kind,
            stanza,
        } = request;
        let outcome = db::transition_local_presence_subscription_authorized(
            &self.pool,
            actor_id,
            expected_auth_generation,
            connection_id,
            local_domain,
            target_username,
            kind,
            stanza,
        )
        .await?;
        Ok(match outcome {
            db::AuthorizedLocalPresenceTransition::Unauthorized => PresenceMutation::Unauthorized,
            db::AuthorizedLocalPresenceTransition::PolicyDenied(reason) => {
                PresenceMutation::PolicyDenied(reason)
            }
            db::AuthorizedLocalPresenceTransition::Missing => PresenceMutation::Missing,
            db::AuthorizedLocalPresenceTransition::Transition(authorized) => {
                let db::AuthorizedLocalPresence {
                    actor,
                    target,
                    transition,
                } = *authorized;
                PresenceMutation::Transition(LocalSubscriptionTransition {
                    actor: map_account(actor),
                    target: map_account(target),
                    effect: transition.effect,
                    actor_subscription: transition.actor_subscription,
                    actor_change: transition.actor_change,
                    target_change: transition.target_change,
                })
            }
        })
    }

    async fn transition_inbound(
        &self,
        recipient_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        stanza: &str,
    ) -> Result<PresenceMutation<InboundSubscriptionTransition>> {
        Ok(
            match db::transition_inbound_remote_presence_subscription(
                &self.pool,
                recipient_id,
                local_domain,
                contact,
                kind,
                stanza,
            )
            .await?
            {
                db::AuthorizedInboundRemotePresenceTransition::Missing => PresenceMutation::Missing,
                db::AuthorizedInboundRemotePresenceTransition::PolicyDenied(reason) => {
                    PresenceMutation::PolicyDenied(reason)
                }
                db::AuthorizedInboundRemotePresenceTransition::Transition(authorized) => {
                    let db::AuthorizedInboundRemotePresence {
                        recipient,
                        transition,
                    } = *authorized;
                    PresenceMutation::Transition(InboundSubscriptionTransition {
                        recipient: map_account(recipient),
                        effect: transition.effect,
                        subscription: transition.subscription,
                        change: transition.change,
                        auto_reply: transition.auto_reply,
                        send_unavailable: transition.send_unavailable,
                    })
                }
            },
        )
    }

    async fn cluster_authority_is_current(
        &self,
        local_domain: &str,
        owner_jid: &str,
        owner_id: Uuid,
        owner_auth_generation: i64,
        recipient_jid: &str,
        recipient_id: Uuid,
        recipient_auth_generation: i64,
    ) -> Result<bool> {
        let domain = crate::jid::prepare_domainpart(local_domain)?;
        let owner = crate::jid::CanonicalJid::parse(owner_jid)?;
        let recipient = crate::jid::CanonicalJid::parse(recipient_jid)?;
        if owner.domainpart() != domain || recipient.domainpart() != domain {
            return Ok(false);
        }
        let (Some(owner_username), Some(recipient_username)) =
            (owner.localpart(), recipient.localpart())
        else {
            return Ok(false);
        };
        let mut ids = vec![owner_id, recipient_id];
        ids.sort_unstable();
        ids.dedup();
        let rows = sqlx::query(
            "SELECT id,username,auth_generation,is_disabled
               FROM users WHERE id=ANY($1)",
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await?;
        let matches = |id: Uuid, username: &str, generation: i64| {
            rows.iter().any(|row| {
                row.get::<Uuid, _>("id") == id
                    && row.get::<String, _>("username") == username
                    && row.get::<i64, _>("auth_generation") == generation
                    && !row.get::<bool, _>("is_disabled")
            })
        };
        Ok(matches(owner_id, owner_username, owner_auth_generation)
            && matches(recipient_id, recipient_username, recipient_auth_generation))
    }
}

fn map_account(account: db::PresenceAccount) -> PresenceAccount {
    PresenceAccount {
        id: account.id,
        username: account.username,
        auth_generation: account.auth_generation,
    }
}

fn map_remote_transition(
    outcome: db::AuthorizedRemotePresenceTransition,
) -> PresenceMutation<RemoteSubscriptionTransition> {
    match outcome {
        db::AuthorizedRemotePresenceTransition::Unauthorized => PresenceMutation::Unauthorized,
        db::AuthorizedRemotePresenceTransition::PolicyDenied(reason) => {
            PresenceMutation::PolicyDenied(reason)
        }
        db::AuthorizedRemotePresenceTransition::Transition(authorized) => {
            let db::AuthorizedRemotePresence { actor, transition } = *authorized;
            PresenceMutation::Transition(RemoteSubscriptionTransition {
                actor: map_account(actor),
                subscription: transition.subscription,
                change: transition.change,
                routed: transition.routed,
            })
        }
    }
}
