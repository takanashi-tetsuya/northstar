//! Generation-fenced administrative reads and atomic command mutations.
use crate::{db, services::admin_commands::*};
use anyhow::Result;
use sqlx::{PgPool, Postgres, Row, Transaction};

#[derive(Clone)]
pub(crate) struct PostgresAdminCommandRepository {
    pool: PgPool,
    command_pool: PgPool,
}
impl PostgresAdminCommandRepository {
    pub(crate) fn new(pool: PgPool, command_pool: PgPool) -> Self {
        Self { pool, command_pool }
    }
    fn fence<'a>(
        &self,
        actor: &'a AdminActor,
        claim: &'a AdminExecutionClaim,
        node: &'a str,
        payload: &'a str,
    ) -> Result<db::AdminCommandFence<'a>> {
        let value = claim.fence(actor, node, payload)?;
        Ok(db::AdminCommandFence {
            claim_token: value.claim_token,
            actor_id: value.actor_id,
            actor_username: value.actor_username,
            actor_generation: value.actor_generation,
            node: value.node,
            target_digest: value.target_digest,
            result_payload: value.result_payload,
        })
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

    #[cfg(test)]
    pub(crate) async fn authorized_count_with_hook<F, Fut>(
        &self,
        actor: &AdminActor,
        after_authorized: F,
    ) -> Result<Option<i64>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        after_authorized().await;
        let count = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(count))
    }
}
impl AdminCommandRepository for PostgresAdminCommandRepository {
    async fn current_admin(&self, cached: &AdminActor) -> Result<Option<AdminActor>> {
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
    async fn registered_account_count(&self, actor: &AdminActor) -> Result<Option<i64>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let users = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(users))
    }
    async fn disabled_account_count(&self, actor: &AdminActor) -> Result<Option<i64>> {
        let Some(mut tx) = self.begin_authorized_read(actor).await? else {
            return Ok(None);
        };
        let count = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_disabled")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(count))
    }
    async fn registered_account_usernames(
        &self,
        actor: &AdminActor,
        limit: i64,
        offset: i64,
    ) -> Result<Option<Vec<String>>> {
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
    async fn disabled_account_usernames(
        &self,
        actor: &AdminActor,
        limit: i64,
        offset: i64,
    ) -> Result<Option<Vec<String>>> {
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
    async fn announcement_account_page(
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
    async fn administrator_usernames(
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
    #[allow(clippy::too_many_arguments)]
    async fn create_account(
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
    #[allow(clippy::too_many_arguments)]
    async fn mutate_accounts(
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
    #[allow(clippy::too_many_arguments)]
    async fn reset_account_password(
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
    async fn account_last_login(
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
    async fn account_roster(
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
    async fn account_statistics(
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
    async fn replace_administrators(
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
    async fn record_announcement(
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
    async fn set_service_message(
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
    async fn service_message_body(&self, actor: &AdminActor, kind: &str) -> Result<Option<String>> {
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
    async fn replace_federation_rules(
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
    async fn federation_rule_domains(
        &self,
        actor: &AdminActor,
        kind: &str,
    ) -> Result<Option<Vec<String>>> {
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
    async fn cancel_service_control(
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
    #[allow(clippy::too_many_arguments)]
    async fn schedule_service_control(
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
    async fn create_session(
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
    async fn finish_session(
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
    async fn complete_count_session(
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
    async fn begin_execution(
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
                    CommandExecutionOutcome::Started(AdminExecutionClaim::new(
                        inner.operation_id,
                        inner.token,
                        actor,
                        node.to_owned(),
                        *target_digest,
                    ))
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
    async fn release_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
    ) -> Result<ExecutionReleaseOutcome> {
        self.fence(actor, claim, node, "")?;
        Ok(
            if db::release_admin_command_execution(
                &self.command_pool,
                claim.token(),
                actor.user_id,
                &actor.username,
                actor.auth_generation,
                node,
                claim.target_digest(),
            )
            .await?
            {
                ExecutionReleaseOutcome::Released
            } else {
                ExecutionReleaseOutcome::Stale
            },
        )
    }
    async fn renew_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
    ) -> Result<bool> {
        self.fence(actor, claim, node, "")?;
        db::renew_admin_command_execution(
            &self.command_pool,
            claim.token(),
            actor.user_id,
            &actor.username,
            actor.auth_generation,
            node,
            claim.target_digest(),
        )
        .await
    }
    async fn complete_read_execution(
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
                claim.token(),
                actor.user_id,
                &actor.username,
                actor.auth_generation,
                node,
                claim.target_digest(),
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
    async fn cleanup_sessions(&self) -> Result<u64> {
        db::cleanup_admin_command_sessions(&self.command_pool).await
    }
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
