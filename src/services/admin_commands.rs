//! XEP-0133/XEP-0050 administrative command authority.
//!
//! XML handlers may parse forms and map these typed outcomes to stanza errors,
//! but they do not receive the PostgreSQL pool. Session ownership,
//! authorization generations, operation claims and terminal audit persistence
//! stay behind this boundary.

use crate::{db, jid::CanonicalJid};
use anyhow::Result;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

const MAX_ADMIN_ACCOUNT_PAGE_SIZE: i64 = 200;
const MAX_ADMIN_ACCOUNT_PAGE_OFFSET: i64 = 10_000;
const MAX_ADMIN_ROSTER_ITEMS: usize = 10_000;
const MAX_FEDERATION_RULES_PER_KIND: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdminActor {
    pub user_id: Uuid,
    pub username: String,
    pub auth_generation: i64,
}

impl AdminActor {
    pub(crate) fn new(user_id: Uuid, username: String, auth_generation: i64) -> Self {
        Self {
            user_id,
            username,
            auth_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandSessionOutcome {
    Finished,
    Expired,
    Invalid,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CommandExecutionOutcome {
    Started(AdminExecutionClaim),
    Busy,
    Completed(String),
    Expired,
    Invalid,
}

#[derive(Eq, PartialEq)]
pub(crate) struct AdminExecutionClaim {
    inner: db::AdminCommandClaim,
    actor_id: Uuid,
    actor_generation: i64,
    node: String,
    target_digest: [u8; 32],
}

impl std::fmt::Debug for AdminExecutionClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminExecutionClaim")
            .field("operation_id", &self.inner.operation_id)
            .field("actor_id", &self.actor_id)
            .field("actor_generation", &self.actor_generation)
            .field("node", &self.node)
            .field("claim_token", &"[REDACTED]")
            .field("target_digest", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutionReleaseOutcome {
    Released,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminWriteOutcome {
    Applied,
    Unauthorized,
    TargetChanged,
    SelfMutation,
    Conflict,
}

#[derive(Debug, thiserror::Error)]
#[error("administrative database transaction must be retried")]
pub(crate) struct AdminCommandRetryable;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AccountMutationOutcome {
    Applied,
    Unauthorized,
    TargetChanged,
    SelfMutation,
    LastAdministrator,
    Retryable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CreateAccountOutcome {
    Created,
    UsernameTaken,
    CapacityExhausted,
    Unauthorized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedAccountList {
    pub usernames: Vec<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct AnnouncementPageCursor {
    snapshot_at: chrono::DateTime<chrono::Utc>,
    after_username: String,
    after_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct AnnouncementAccountPage {
    pub usernames: Vec<String>,
    pub next: Option<AnnouncementPageCursor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccountCommandAction {
    Delete,
    Disable,
    Reenable,
    EndSessions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountCommandTarget {
    pub username: String,
    pub exact_full_jid: Option<CanonicalJid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountCommandView {
    pub user_id: Uuid,
    pub username: String,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub(crate) struct AccountRosterView {
    pub account: AccountCommandView,
    pub items: Vec<(String, Option<String>, String, Option<String>)>,
}

#[derive(Clone, Debug)]
pub(crate) struct AccountStatistics {
    pub account: AccountCommandView,
    pub roster_size: i64,
    pub archived_stanzas: i64,
    pub offline_stanzas: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FederationRuleSet {
    pub blacklist: Vec<String>,
    pub whitelist: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct AdminCommandService {
    pool: PgPool,
    command_pool: PgPool,
}

impl AdminCommandService {
    pub(crate) fn new(pool: PgPool, command_pool: PgPool) -> Self {
        Self { pool, command_pool }
    }

    fn fence<'a>(
        &'a self,
        actor: &'a AdminActor,
        claim: &'a AdminExecutionClaim,
        node: &'a str,
        payload: &'a str,
    ) -> Result<db::AdminCommandFence<'a>> {
        anyhow::ensure!(
            claim.actor_id == actor.user_id
                && claim.actor_generation == actor.auth_generation
                && claim.node == node,
            "administrative claim binding mismatch"
        );
        Ok(db::AdminCommandFence {
            claim_token: claim.inner.token.as_str(),
            actor_id: actor.user_id,
            actor_username: &actor.username,
            actor_generation: actor.auth_generation,
            node,
            target_digest: &claim.target_digest,
            result_payload: payload,
        })
    }

    /// Re-read the authenticated account instead of trusting the stream cache.
    /// Mutating methods repeat this generation/admin check in their own
    /// transaction, closing demotion and credential-rotation races.
    pub(crate) async fn current_admin(&self, cached: &AdminActor) -> Result<Option<AdminActor>> {
        let current = sqlx::query(
            "SELECT username,auth_generation FROM users
             WHERE id=$1 AND username=$2 AND auth_generation=$3
               AND is_admin AND NOT is_disabled",
        )
        .bind(cached.user_id)
        .bind(&cached.username)
        .bind(cached.auth_generation)
        .fetch_optional(&self.pool)
        .await?;
        Ok(current.map(|row| AdminActor {
            user_id: cached.user_id,
            username: row.get("username"),
            auth_generation: row.get("auth_generation"),
        }))
    }

    /// Establish the authorization linearization point for a sensitive read.
    ///
    /// The exact authenticated incarnation is locked before any protected data
    /// is read. Demotion, disablement, password rotation and account deletion
    /// all update this row and therefore either commit before this check (the
    /// read is rejected) or wait until the snapshot has been consumed. Every
    /// caller must execute its data query and commit through this transaction;
    /// going back to `self.pool` would reopen the TOCTOU window.
    async fn begin_authorized_read<'a>(
        &'a self,
        actor: &AdminActor,
    ) -> Result<Option<Transaction<'a, Postgres>>> {
        // A concurrent account update can win after PostgreSQL establishes the
        // first repeatable-read snapshot but before `FOR SHARE` acquires the
        // tuple lock. PostgreSQL reports 40001 in that case. Retry the
        // authorization snapshot once so a committed demotion/rotation maps
        // to `None` rather than leaking data or surfacing a spurious 500.
        for attempt in 0..=1 {
            let mut tx = self.pool.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL lock_timeout = '2s'")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL statement_timeout = '5s'")
                .execute(&mut *tx)
                .await?;
            let authorized = sqlx::query_scalar::<_, bool>(
                "SELECT TRUE FROM users
                 WHERE id=$1 AND username=$2 AND auth_generation=$3
                   AND is_admin AND NOT is_disabled
                 FOR SHARE",
            )
            .bind(actor.user_id)
            .bind(&actor.username)
            .bind(actor.auth_generation)
            .fetch_optional(&mut *tx)
            .await;
            let authorized = match authorized {
                Ok(row) => row.is_some(),
                Err(error) if attempt == 0 && is_serialization_failure(&error) => {
                    tx.rollback().await?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if !authorized {
                tx.rollback().await?;
                return Ok(None);
            }
            return Ok(Some(tx));
        }
        unreachable!("admin read authorization loop always returns")
    }

    pub(crate) async fn registered_account_count(&self, actor: &AdminActor) -> Result<Option<i64>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let users = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(users))
    }

    pub(crate) async fn disabled_account_count(&self, actor: &AdminActor) -> Result<Option<i64>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let count = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_disabled")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(count))
    }

    pub(crate) async fn registered_account_usernames(
        &self,
        actor: &AdminActor,
        limit: i64,
        offset: i64,
    ) -> Result<Option<Vec<String>>> {
        validate_account_page(limit, offset)?;
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let usernames = sqlx::query_scalar(
            "SELECT username FROM users
             ORDER BY created_at DESC,id LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(usernames))
    }

    pub(crate) async fn disabled_account_usernames(
        &self,
        actor: &AdminActor,
        limit: i64,
        offset: i64,
    ) -> Result<Option<Vec<String>>> {
        validate_account_page(limit, offset)?;
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let usernames = sqlx::query_scalar(
            "SELECT username FROM users
             WHERE is_disabled ORDER BY created_at,id LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(usernames))
    }

    pub(crate) async fn announcement_account_page(
        &self,
        actor: &AdminActor,
        cursor: Option<&AnnouncementPageCursor>,
    ) -> Result<Option<AnnouncementAccountPage>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let snapshot_at = match cursor {
            Some(cursor) => cursor.snapshot_at,
            None => {
                sqlx::query_scalar("SELECT clock_timestamp()")
                    .fetch_one(&mut *tx)
                    .await?
            }
        };
        let after_username = cursor.map(|cursor| cursor.after_username.as_str());
        let after_id = cursor.map(|cursor| cursor.after_id);
        let mut rows = sqlx::query(
            "SELECT id,username FROM users
             WHERE NOT is_disabled AND created_at <= $1
               AND ($2::text IS NULL OR (username,id) > ($2,$3))
             ORDER BY username,id LIMIT 257",
        )
        .bind(snapshot_at)
        .bind(after_username)
        .bind(after_id)
        .fetch_all(&mut *tx)
        .await?;
        let has_more = rows.len() > 256;
        rows.truncate(256);
        let next = has_more.then(|| {
            let last = rows.last().expect("continued page cannot be empty");
            AnnouncementPageCursor {
                snapshot_at,
                after_username: last.get("username"),
                after_id: last.get("id"),
            }
        });
        let page = AnnouncementAccountPage {
            usernames: rows.into_iter().map(|row| row.get("username")).collect(),
            next,
        };
        tx.commit().await?;
        Ok(Some(page))
    }

    pub(crate) async fn administrator_usernames(
        &self,
        actor: &AdminActor,
    ) -> Result<Option<BoundedAccountList>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let mut usernames = sqlx::query_scalar(
            "SELECT username FROM users WHERE is_admin ORDER BY username LIMIT 201",
        )
        .fetch_all(&mut *tx)
        .await?;
        let truncated = usernames.len() > 200;
        usernames.truncate(200);
        tx.commit().await?;
        Ok(Some(BoundedAccountList {
            usernames,
            truncated,
        }))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the application capability keeps the exact admin execution fence and credential policy explicit"
    )]
    pub(crate) async fn create_account(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        username: &str,
        password: &str,
        scram_iterations: u32,
        scram_sha1_enabled: bool,
        result_payload: &str,
    ) -> Result<CreateAccountOutcome> {
        let fence = self.fence(actor, claim, node, result_payload)?;
        let outcome = db::create_admin_account_authorized(
            &self.pool,
            fence,
            username,
            password,
            scram_iterations,
            scram_sha1_enabled,
        )
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) if is_retryable_database_error(&error) => {
                return Err(AdminCommandRetryable.into());
            }
            Err(error) => return Err(error),
        };
        Ok(match outcome {
            db::AdminCreateAccountOutcome::Created => CreateAccountOutcome::Created,
            db::AdminCreateAccountOutcome::UsernameTaken => CreateAccountOutcome::UsernameTaken,
            db::AdminCreateAccountOutcome::CapacityExhausted => {
                CreateAccountOutcome::CapacityExhausted
            }
            db::AdminCreateAccountOutcome::Unauthorized => CreateAccountOutcome::Unauthorized,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the application capability keeps the exact admin execution fence and account mutation scope explicit"
    )]
    pub(crate) async fn mutate_accounts(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        targets: &[AccountCommandTarget],
        action: AccountCommandAction,
        domain: &str,
        result_payload: &str,
    ) -> Result<AccountMutationOutcome> {
        let usernames = targets
            .iter()
            .map(|target| target.username.clone())
            .collect::<Vec<_>>();
        let Some(identities) = db::resolve_admin_account_identities(&self.pool, &usernames).await?
        else {
            return Ok(AccountMutationOutcome::TargetChanged);
        };
        let exact = identities
            .into_iter()
            .zip(targets)
            .map(|(identity, target)| db::AdminAccountMutationTarget {
                id: identity.id,
                username: identity.username,
                exact_full_jid: target.exact_full_jid.as_ref().map(ToString::to_string),
            })
            .collect::<Vec<_>>();
        let action = match action {
            AccountCommandAction::Delete => db::AdminAccountMutationAction::Delete,
            AccountCommandAction::Disable => db::AdminAccountMutationAction::Disable,
            AccountCommandAction::Reenable => db::AdminAccountMutationAction::Reenable,
            AccountCommandAction::EndSessions => db::AdminAccountMutationAction::EndSessions,
        };
        let outcome = db::mutate_admin_accounts_authorized(
            &self.pool,
            self.fence(actor, claim, node, result_payload)?,
            &exact,
            action,
            domain,
        )
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) if is_retryable_database_error(&error) => {
                return Ok(AccountMutationOutcome::Retryable);
            }
            Err(error) => return Err(error),
        };
        Ok(match outcome {
            db::AdminBatchAccountWriteOutcome::Applied(_) => AccountMutationOutcome::Applied,
            db::AdminBatchAccountWriteOutcome::Unauthorized => AccountMutationOutcome::Unauthorized,
            db::AdminBatchAccountWriteOutcome::TargetChanged => {
                AccountMutationOutcome::TargetChanged
            }
            db::AdminBatchAccountWriteOutcome::SelfMutation => AccountMutationOutcome::SelfMutation,
            db::AdminBatchAccountWriteOutcome::LastAdministrator => {
                AccountMutationOutcome::LastAdministrator
            }
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the application capability keeps the exact admin execution fence, credential policy, and account authority explicit"
    )]
    pub(crate) async fn reset_account_password(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        username: &str,
        password: &str,
        scram_iterations: u32,
        scram_sha1_enabled: bool,
        domain: &str,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        let Some(mut identities) =
            db::resolve_admin_account_identities(&self.pool, &[username.to_owned()]).await?
        else {
            return Ok(AdminWriteOutcome::TargetChanged);
        };
        let target = identities.pop().expect("one requested account identity");
        let bare_jid = canonical_account_jid(&target.username, domain)?.to_string();
        let outcome = db::reset_admin_account_password_authorized(
            &self.pool,
            self.fence(actor, claim, node, result_payload)?,
            &target,
            password,
            scram_iterations,
            scram_sha1_enabled,
            &bare_jid,
        )
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) if is_retryable_database_error(&error) => {
                return Err(AdminCommandRetryable.into());
            }
            Err(error) => return Err(error),
        };
        Ok(map_account_write(outcome))
    }

    pub(crate) async fn account_last_login(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> Result<Option<AccountCommandView>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let account = sqlx::query("SELECT id,username,last_login_at FROM users WHERE username=$1")
            .bind(username)
            .fetch_optional(&mut *tx)
            .await?
            .map(|row| AccountCommandView {
                user_id: row.get("id"),
                username: row.get("username"),
                last_login_at: row.get("last_login_at"),
            });
        tx.commit().await?;
        Ok(account)
    }

    pub(crate) async fn account_roster(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> Result<Option<AccountRosterView>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let Some(row) =
            sqlx::query("SELECT id,username,last_login_at FROM users WHERE username=$1")
                .bind(username)
                .fetch_optional(&mut *tx)
                .await?
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let account = AccountCommandView {
            user_id: row.get("id"),
            username: row.get("username"),
            last_login_at: row.get("last_login_at"),
        };
        let rows = sqlx::query(
            "SELECT contact_jid,display_name,subscription,ask
             FROM roster_items WHERE owner_id=$1
             ORDER BY contact_jid LIMIT $2",
        )
        .bind(account.user_id)
        .bind((MAX_ADMIN_ROSTER_ITEMS + 1) as i64)
        .fetch_all(&mut *tx)
        .await?;
        anyhow::ensure!(
            rows.len() <= MAX_ADMIN_ROSTER_ITEMS,
            "account roster exceeds the administrative response bound"
        );
        let items = rows
            .into_iter()
            .map(|row| {
                (
                    row.get("contact_jid"),
                    row.get("display_name"),
                    row.get("subscription"),
                    row.get("ask"),
                )
            })
            .collect();
        tx.commit().await?;
        Ok(Some(AccountRosterView { account, items }))
    }

    pub(crate) async fn account_statistics(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> Result<Option<AccountStatistics>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let Some(row) =
            sqlx::query("SELECT id,username,last_login_at FROM users WHERE username=$1")
                .bind(username)
                .fetch_optional(&mut *tx)
                .await?
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let account = AccountCommandView {
            user_id: row.get("id"),
            username: row.get("username"),
            last_login_at: row.get("last_login_at"),
        };
        let (roster_size, archived_stanzas, offline_stanzas): (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM roster_items WHERE owner_id=$1),
                        (SELECT COUNT(*) FROM message_archive WHERE owner_id=$1),
                        (SELECT COUNT(*) FROM offline_messages WHERE recipient_id=$1)",
        )
        .bind(account.user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(AccountStatistics {
            account,
            roster_size,
            archived_stanzas,
            offline_stanzas,
        }))
    }

    pub(crate) async fn replace_administrators(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        usernames: &[String],
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        let Some(expected) = db::resolve_admin_account_identities(&self.pool, usernames).await?
        else {
            return Ok(AdminWriteOutcome::TargetChanged);
        };
        let outcome = db::replace_admins_authorized(
            &self.pool,
            self.fence(actor, claim, node, result_payload)?,
            &expected,
        )
        .await;
        match outcome {
            Ok(outcome) => Ok(map_account_write(outcome)),
            Err(error) if is_retryable_database_error(&error) => Err(AdminCommandRetryable.into()),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn record_announcement(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        recipients: usize,
        bytes: usize,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        Ok(
            if db::record_admin_announcement_command(
                &self.pool,
                self.fence(actor, claim, node, result_payload)?,
                recipients,
                bytes,
            )
            .await?
            {
                AdminWriteOutcome::Applied
            } else {
                AdminWriteOutcome::Unauthorized
            },
        )
    }

    pub(crate) async fn set_service_message(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        kind: &str,
        body: Option<&str>,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        Ok(
            if db::set_admin_service_message_command(
                &self.pool,
                self.fence(actor, claim, node, result_payload)?,
                kind,
                body,
            )
            .await?
            {
                AdminWriteOutcome::Applied
            } else {
                AdminWriteOutcome::Unauthorized
            },
        )
    }

    pub(crate) async fn service_message_body(
        &self,
        actor: &AdminActor,
        kind: &str,
    ) -> Result<Option<String>> {
        anyhow::ensure!(
            matches!(kind, "motd" | "welcome"),
            "invalid service message kind"
        );
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let body = sqlx::query_scalar("SELECT body FROM admin_service_messages WHERE kind=$1")
            .bind(kind)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(body)
    }

    pub(crate) async fn replace_federation_rules(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        kind: &str,
        entities: &[String],
        result_payload: &str,
    ) -> Result<Option<FederationRuleSet>> {
        let Some((blacklist, whitelist)) = db::replace_federation_runtime_rules_command(
            &self.pool,
            self.fence(actor, claim, node, result_payload)?,
            kind,
            entities,
        )
        .await?
        else {
            return Ok(None);
        };
        Ok(Some(FederationRuleSet {
            blacklist,
            whitelist,
        }))
    }

    pub(crate) async fn federation_rule_domains(
        &self,
        actor: &AdminActor,
        kind: &str,
    ) -> Result<Option<Vec<String>>> {
        anyhow::ensure!(
            matches!(kind, "blacklist" | "whitelist"),
            "invalid federation rule kind"
        );
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let domains = sqlx::query_scalar(
            "SELECT domain FROM federation_runtime_rules WHERE kind=$1 ORDER BY domain LIMIT 1001",
        )
        .bind(kind)
        .fetch_all(&mut *tx)
        .await?;
        anyhow::ensure!(
            domains.len() <= MAX_FEDERATION_RULES_PER_KIND,
            "federation rule list exceeds the administrative response bound"
        );
        tx.commit().await?;
        Ok(Some(domains))
    }

    pub(crate) async fn cancel_service_control(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        action: &str,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        Ok(
            if db::apply_admin_service_control_command(
                &self.pool,
                self.fence(actor, claim, node, result_payload)?,
                action,
                5,
                None,
                true,
            )
            .await?
            .is_some()
            {
                AdminWriteOutcome::Applied
            } else {
                AdminWriteOutcome::Conflict
            },
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the application capability keeps the exact admin execution fence and delayed service-control payload explicit"
    )]
    pub(crate) async fn schedule_service_control(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        action: &str,
        delay_seconds: i64,
        announcement: Option<&str>,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        Ok(
            if db::apply_admin_service_control_command(
                &self.pool,
                self.fence(actor, claim, node, result_payload)?,
                action,
                delay_seconds,
                announcement,
                false,
            )
            .await?
            .is_some()
            {
                AdminWriteOutcome::Applied
            } else {
                AdminWriteOutcome::Conflict
            },
        )
    }

    pub(crate) async fn create_session(
        &self,
        actor: &AdminActor,
        owner_full_jid: &str,
        server_domain: &str,
        node: &str,
        stage: &str,
    ) -> Result<Option<zeroize::Zeroizing<String>>> {
        db::create_admin_command_session(
            &self.command_pool,
            actor.user_id,
            owner_full_jid,
            server_domain,
            actor.auth_generation,
            node,
            stage,
        )
        .await
    }

    pub(crate) async fn finish_session(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        final_stage: &str,
    ) -> Result<CommandSessionOutcome> {
        Ok(map_session_outcome(
            db::finish_admin_command_session(
                &self.command_pool,
                bearer,
                actor.user_id,
                owner_full_jid,
                actor.auth_generation,
                node,
                final_stage,
            )
            .await?,
        ))
    }

    pub(crate) async fn complete_count_session(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        payload: &str,
    ) -> Result<CommandSessionOutcome> {
        Ok(map_session_outcome(
            db::complete_admin_count_command_session(
                &self.command_pool,
                bearer,
                actor.user_id,
                owner_full_jid,
                actor.auth_generation,
                node,
                payload,
            )
            .await?,
        ))
    }

    pub(crate) async fn begin_execution(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        target_digest: &[u8; 32],
    ) -> Result<CommandExecutionOutcome> {
        Ok(
            match db::begin_admin_command_execution(
                &self.command_pool,
                bearer,
                actor.user_id,
                owner_full_jid,
                actor.auth_generation,
                node,
                target_digest,
            )
            .await?
            {
                db::AdminCommandExecutionState::Started(inner) => {
                    CommandExecutionOutcome::Started(AdminExecutionClaim {
                        inner,
                        actor_id: actor.user_id,
                        actor_generation: actor.auth_generation,
                        node: node.to_owned(),
                        target_digest: *target_digest,
                    })
                }
                db::AdminCommandExecutionState::Busy => CommandExecutionOutcome::Busy,
                db::AdminCommandExecutionState::Completed(payload) => {
                    CommandExecutionOutcome::Completed(payload)
                }
                db::AdminCommandExecutionState::Expired => CommandExecutionOutcome::Expired,
                db::AdminCommandExecutionState::Invalid => CommandExecutionOutcome::Invalid,
            },
        )
    }

    pub(crate) async fn release_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
    ) -> Result<ExecutionReleaseOutcome> {
        self.fence(actor, claim, node, "")?;
        Ok(
            if db::release_admin_command_execution(
                &self.command_pool,
                claim.inner.token.as_str(),
                actor.user_id,
                &actor.username,
                actor.auth_generation,
                node,
                &claim.target_digest,
            )
            .await?
            {
                ExecutionReleaseOutcome::Released
            } else {
                ExecutionReleaseOutcome::Stale
            },
        )
    }

    pub(crate) async fn renew_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
    ) -> Result<bool> {
        self.fence(actor, claim, node, "")?;
        db::renew_admin_command_execution(
            &self.command_pool,
            claim.inner.token.as_str(),
            actor.user_id,
            &actor.username,
            actor.auth_generation,
            node,
            &claim.target_digest,
        )
        .await
    }

    pub(crate) async fn complete_read_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        payload: &str,
    ) -> Result<AdminWriteOutcome> {
        self.fence(actor, claim, node, payload)?;
        Ok(
            if db::complete_admin_command_read_execution(
                &self.command_pool,
                claim.inner.token.as_str(),
                actor.user_id,
                &actor.username,
                actor.auth_generation,
                node,
                &claim.target_digest,
                payload,
            )
            .await?
            {
                AdminWriteOutcome::Applied
            } else {
                AdminWriteOutcome::Unauthorized
            },
        )
    }

    pub(crate) async fn cleanup_sessions(&self) -> Result<u64> {
        db::cleanup_admin_command_sessions(&self.command_pool).await
    }
}

fn validate_account_page(limit: i64, offset: i64) -> Result<()> {
    anyhow::ensure!(
        (1..=MAX_ADMIN_ACCOUNT_PAGE_SIZE).contains(&limit),
        "invalid account page size"
    );
    anyhow::ensure!(
        (0..=MAX_ADMIN_ACCOUNT_PAGE_OFFSET).contains(&offset),
        "account page offset exceeds the administrative query bound"
    );
    Ok(())
}

/// Construct account JIDs at the service boundary so protocol handlers never
/// pass an unvalidated `username@domain` string into an authority mutation.
fn canonical_account_jid(username: &str, domain: &str) -> Result<CanonicalJid> {
    let jid = CanonicalJid::parse_bare(&format!("{username}@{domain}"))?;
    anyhow::ensure!(
        jid.localpart() == Some(username) && jid.domainpart() == domain,
        "account identity changed during JID preparation"
    );
    Ok(jid)
}

fn is_serialization_failure(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database) => database.code().as_deref() == Some("40001"),
        _ => false,
    }
}

fn map_session_outcome(value: db::AdminCommandSessionState) -> CommandSessionOutcome {
    match value {
        db::AdminCommandSessionState::Finished => CommandSessionOutcome::Finished,
        db::AdminCommandSessionState::Expired => CommandSessionOutcome::Expired,
        db::AdminCommandSessionState::Invalid => CommandSessionOutcome::Invalid,
    }
}

fn map_account_write(value: db::AdminAccountWriteOutcome) -> AdminWriteOutcome {
    match value {
        db::AdminAccountWriteOutcome::Applied => AdminWriteOutcome::Applied,
        db::AdminAccountWriteOutcome::Unauthorized => AdminWriteOutcome::Unauthorized,
        db::AdminAccountWriteOutcome::TargetChanged => AdminWriteOutcome::TargetChanged,
        db::AdminAccountWriteOutcome::SelfMutation => AdminWriteOutcome::SelfMutation,
    }
}

fn is_retryable_database_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<sqlx::Error>().is_some_and(|error| {
            matches!(error, sqlx::Error::PoolTimedOut)
                || match error {
                    sqlx::Error::Database(database) => database.code().is_some_and(|code| {
                        matches!(
                            code.as_ref(),
                            "40001" | "40P01" | "53300" | "55P03" | "57014"
                        )
                    }),
                    _ => false,
                }
        })
    })
}

#[cfg(test)]
mod read_authorization_tests {
    use super::*;
    use std::time::Duration;

    async fn database() -> PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        pool
    }

    async fn insert_admin(pool: &PgPool, id: Uuid, username: &str) -> AdminActor {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin,auth_generation)
             VALUES($1,$2,'test-only',TRUE,0)",
        )
        .bind(id)
        .bind(username)
        .execute(pool)
        .await
        .unwrap();
        AdminActor::new(id, username.to_owned(), 0)
    }

    #[test]
    fn administrative_account_pages_have_hard_size_and_offset_bounds() {
        assert!(validate_account_page(1, 0).is_ok());
        assert!(validate_account_page(MAX_ADMIN_ACCOUNT_PAGE_SIZE, 10_000).is_ok());
        assert!(validate_account_page(0, 0).is_err());
        assert!(validate_account_page(MAX_ADMIN_ACCOUNT_PAGE_SIZE + 1, 0).is_err());
        assert!(validate_account_page(1, -1).is_err());
        assert!(validate_account_page(1, MAX_ADMIN_ACCOUNT_PAGE_OFFSET + 1).is_err());
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_read_snapshot_blocks_post_authorization_demotion_until_commit() {
        let pool = database().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let actor_id = Uuid::new_v4();
        let actor = insert_admin(&pool, actor_id, &format!("read-lock-{}", &suffix[..12])).await;
        let service = AdminCommandService::new(pool.clone(), pool.clone());
        let (authorized_tx, authorized_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let read = tokio::spawn(async move {
            let mut tx = service
                .begin_authorized_read(&actor)
                .await
                .unwrap()
                .expect("fresh administrator must authorize");
            authorized_tx.send(()).unwrap();
            release_rx.await.unwrap();
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            count
        });
        authorized_rx.await.unwrap();

        let mutation_pool = pool.clone();
        let (mutation_started_tx, mutation_started_rx) = tokio::sync::oneshot::channel();
        let mut demotion = tokio::spawn(async move {
            mutation_started_tx.send(()).unwrap();
            sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
                .bind(actor_id)
                .execute(&mutation_pool)
                .await
                .unwrap()
                .rows_affected()
        });
        mutation_started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut demotion)
                .await
                .is_err(),
            "demotion committed while the authorized read still held FOR SHARE"
        );

        release_tx.send(()).unwrap();
        assert!(read.await.unwrap() >= 1);
        assert_eq!(demotion.await.unwrap(), 1);
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT is_admin FROM users WHERE id=$1")
                .bind(actor_id)
                .fetch_one(&pool)
                .await
                .unwrap()
        );
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_reads_reject_demotion_and_rotation_that_win_the_authorization_race() {
        let pool = database().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let actor_id = Uuid::new_v4();
        let username = format!("read-fence-{}", &suffix[..12]);
        let actor = insert_admin(&pool, actor_id, &username).await;
        let service = AdminCommandService::new(pool.clone(), pool.clone());

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(actor_id)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let demotion_read = {
            let service = service.clone();
            let actor = actor.clone();
            tokio::spawn(async move { service.registered_account_count(&actor).await.unwrap() })
        };
        sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
            .bind(actor_id)
            .execute(&mut *blocker)
            .await
            .unwrap();
        blocker.commit().await.unwrap();
        assert_eq!(demotion_read.await.unwrap(), None);

        sqlx::query("UPDATE users SET is_admin=TRUE WHERE id=$1")
            .bind(actor_id)
            .execute(&pool)
            .await
            .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(actor_id)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let rotation_read = {
            let service = service.clone();
            tokio::spawn(async move { service.registered_account_count(&actor).await.unwrap() })
        };
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(actor_id)
            .execute(&mut *blocker)
            .await
            .unwrap();
        blocker.commit().await.unwrap();
        assert_eq!(rotation_read.await.unwrap(), None);
        pool.close().await;
    }
}
