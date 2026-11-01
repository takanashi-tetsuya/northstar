//! XEP-0133/XEP-0050 administrative command authority.
//!
//! XML handlers may parse forms and map these typed outcomes to stanza errors,
//! but they do not receive the PostgreSQL pool. Session ownership,
//! authorization generations, operation claims and terminal audit persistence
//! stay behind this boundary.

use anyhow::Result;
use northstar_xmpp_types::jid::CanonicalJid;
use uuid::Uuid;

const MAX_ADMIN_ACCOUNT_PAGE_SIZE: i64 = 200;
const MAX_ADMIN_ACCOUNT_PAGE_OFFSET: i64 = 10_000;
pub const MAX_ADMIN_ROSTER_ITEMS: usize = 10_000;
pub const MAX_FEDERATION_RULES_PER_KIND: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminActor {
    pub user_id: Uuid,
    pub username: String,
    pub auth_generation: i64,
}

impl AdminActor {
    pub fn new(user_id: Uuid, username: String, auth_generation: i64) -> Self {
        Self {
            user_id,
            username,
            auth_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandSessionOutcome {
    Finished,
    Expired,
    Invalid,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CommandExecutionOutcome {
    Started(AdminExecutionClaim),
    Busy,
    Completed(String),
    Expired,
    Invalid,
}

#[derive(Eq, PartialEq)]
pub struct AdminExecutionClaim {
    operation_id: Uuid,
    token: zeroize::Zeroizing<String>,
    actor_id: Uuid,
    actor_generation: i64,
    node: String,
    target_digest: [u8; 32],
}

impl std::fmt::Debug for AdminExecutionClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminExecutionClaim")
            .field("operation_id", &self.operation_id)
            .field("actor_id", &self.actor_id)
            .field("actor_generation", &self.actor_generation)
            .field("node", &self.node)
            .field("claim_token", &"[REDACTED]")
            .field("target_digest", &"[REDACTED]")
            .finish()
    }
}

pub struct AdminExecutionFence<'a> {
    pub claim_token: &'a str,
    pub actor_id: Uuid,
    pub actor_username: &'a str,
    pub actor_generation: i64,
    pub node: &'a str,
    pub target_digest: &'a [u8; 32],
    pub result_payload: &'a str,
}

impl AdminExecutionClaim {
    pub fn new(
        operation_id: Uuid,
        token: zeroize::Zeroizing<String>,
        actor: &AdminActor,
        node: String,
        target_digest: [u8; 32],
    ) -> Self {
        Self {
            operation_id,
            token,
            actor_id: actor.user_id,
            actor_generation: actor.auth_generation,
            node,
            target_digest,
        }
    }
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
    pub fn target_digest(&self) -> &[u8; 32] {
        &self.target_digest
    }
    pub fn fence<'a>(
        &'a self,
        actor: &'a AdminActor,
        node: &'a str,
        payload: &'a str,
    ) -> Result<AdminExecutionFence<'a>> {
        anyhow::ensure!(
            self.actor_id == actor.user_id
                && self.actor_generation == actor.auth_generation
                && self.node == node,
            "administrative claim binding mismatch"
        );
        Ok(AdminExecutionFence {
            claim_token: self.token.as_str(),
            actor_id: actor.user_id,
            actor_username: &actor.username,
            actor_generation: actor.auth_generation,
            node,
            target_digest: &self.target_digest,
            result_payload: payload,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionReleaseOutcome {
    Released,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminWriteOutcome {
    Applied,
    Unauthorized,
    TargetChanged,
    SelfMutation,
    Conflict,
}

#[derive(Debug, thiserror::Error)]
#[error("administrative database transaction must be retried")]
pub struct AdminCommandRetryable;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountMutationOutcome {
    Applied,
    Unauthorized,
    TargetChanged,
    SelfMutation,
    LastAdministrator,
    Retryable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateAccountOutcome {
    Created,
    UsernameTaken,
    CapacityExhausted,
    Unauthorized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedAccountList {
    pub usernames: Vec<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
pub struct AnnouncementPageCursor {
    pub snapshot_at: chrono::DateTime<chrono::Utc>,
    pub after_username: String,
    pub after_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct AnnouncementAccountPage {
    pub usernames: Vec<String>,
    pub next: Option<AnnouncementPageCursor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountCommandAction {
    Delete,
    Disable,
    Reenable,
    EndSessions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCommandTarget {
    pub username: String,
    pub exact_full_jid: Option<CanonicalJid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCommandView {
    pub user_id: Uuid,
    pub username: String,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct AccountRosterView {
    pub account: AccountCommandView,
    pub items: Vec<(String, Option<String>, String, Option<String>)>,
}

#[derive(Clone, Debug)]
pub struct AccountStatistics {
    pub account: AccountCommandView,
    pub roster_size: i64,
    pub archived_stanzas: i64,
    pub offline_stanzas: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationRuleSet {
    pub blacklist: Vec<String>,
    pub whitelist: Vec<String>,
}

#[derive(Clone)]
pub struct AdminCommandService<R> {
    repository: R,
}

/// Stretching parameters of the verifiers the commands derive.
#[derive(Clone, Copy)]
pub struct AdminScramPolicy {
    pub iterations: u32,
    pub sha1_enabled: bool,
}

pub trait AdminCommandRepository: Send + Sync {
    fn current_admin(
        &self,
        cached: &AdminActor,
    ) -> impl std::future::Future<Output = Result<Option<AdminActor>>> + Send;
    fn registered_account_count(
        &self,
        actor: &AdminActor,
    ) -> impl std::future::Future<Output = Result<Option<i64>>> + Send;
    fn disabled_account_count(
        &self,
        actor: &AdminActor,
    ) -> impl std::future::Future<Output = Result<Option<i64>>> + Send;
    fn registered_account_usernames(
        &self,
        actor: &AdminActor,
        limit: i64,
        offset: i64,
    ) -> impl std::future::Future<Output = Result<Option<Vec<String>>>> + Send;
    fn disabled_account_usernames(
        &self,
        actor: &AdminActor,
        limit: i64,
        offset: i64,
    ) -> impl std::future::Future<Output = Result<Option<Vec<String>>>> + Send;
    fn announcement_account_page(
        &self,
        actor: &AdminActor,
        cursor: Option<&AnnouncementPageCursor>,
    ) -> impl std::future::Future<Output = Result<Option<AnnouncementAccountPage>>> + Send;
    fn administrator_usernames(
        &self,
        actor: &AdminActor,
    ) -> impl std::future::Future<Output = Result<Option<BoundedAccountList>>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn create_account(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        username: &str,
        password: &str,
        scram_iterations: u32,
        scram_sha1_enabled: bool,
        result_payload: &str,
    ) -> impl std::future::Future<Output = Result<CreateAccountOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn mutate_accounts(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        targets: &[AccountCommandTarget],
        action: AccountCommandAction,
        domain: &str,
        result_payload: &str,
    ) -> impl std::future::Future<Output = Result<AccountMutationOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn reset_account_password(
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
    ) -> impl std::future::Future<Output = Result<AdminWriteOutcome>> + Send;
    fn account_last_login(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<AccountCommandView>>> + Send;
    fn account_roster(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<AccountRosterView>>> + Send;
    fn account_statistics(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<AccountStatistics>>> + Send;
    fn replace_administrators(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        usernames: &[String],
        result_payload: &str,
    ) -> impl std::future::Future<Output = Result<AdminWriteOutcome>> + Send;
    fn record_announcement(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        recipients: usize,
        bytes: usize,
        result_payload: &str,
    ) -> impl std::future::Future<Output = Result<AdminWriteOutcome>> + Send;
    fn set_service_message(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        kind: &str,
        body: Option<&str>,
        result_payload: &str,
    ) -> impl std::future::Future<Output = Result<AdminWriteOutcome>> + Send;
    fn service_message_body(
        &self,
        actor: &AdminActor,
        kind: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn replace_federation_rules(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        kind: &str,
        entities: &[String],
        result_payload: &str,
    ) -> impl std::future::Future<Output = Result<Option<FederationRuleSet>>> + Send;
    fn federation_rule_domains(
        &self,
        actor: &AdminActor,
        kind: &str,
    ) -> impl std::future::Future<Output = Result<Option<Vec<String>>>> + Send;
    fn cancel_service_control(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        action: &str,
        result_payload: &str,
    ) -> impl std::future::Future<Output = Result<AdminWriteOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn schedule_service_control(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        action: &str,
        delay_seconds: i64,
        announcement: Option<&str>,
        result_payload: &str,
    ) -> impl std::future::Future<Output = Result<AdminWriteOutcome>> + Send;
    fn create_session(
        &self,
        actor: &AdminActor,
        owner_full_jid: &str,
        server_domain: &str,
        node: &str,
        stage: &str,
    ) -> impl std::future::Future<Output = Result<Option<zeroize::Zeroizing<String>>>> + Send;
    fn finish_session(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        final_stage: &str,
    ) -> impl std::future::Future<Output = Result<CommandSessionOutcome>> + Send;
    fn complete_count_session(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        payload: &str,
    ) -> impl std::future::Future<Output = Result<CommandSessionOutcome>> + Send;
    fn begin_execution(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        target_digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<CommandExecutionOutcome>> + Send;
    fn release_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
    ) -> impl std::future::Future<Output = Result<ExecutionReleaseOutcome>> + Send;
    fn renew_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn complete_read_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        payload: &str,
    ) -> impl std::future::Future<Output = Result<AdminWriteOutcome>> + Send;
    fn cleanup_sessions(&self) -> impl std::future::Future<Output = Result<u64>> + Send;
}

impl<R: AdminCommandRepository> AdminCommandService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
    pub async fn current_admin(&self, cached: &AdminActor) -> Result<Option<AdminActor>> {
        self.repository.current_admin(cached).await
    }
    pub async fn registered_account_count(&self, actor: &AdminActor) -> Result<Option<i64>> {
        self.repository.registered_account_count(actor).await
    }
    pub async fn disabled_account_count(&self, actor: &AdminActor) -> Result<Option<i64>> {
        self.repository.disabled_account_count(actor).await
    }
    pub async fn registered_account_usernames(
        &self,
        actor: &AdminActor,
        limit: i64,
        offset: i64,
    ) -> Result<Option<Vec<String>>> {
        validate_account_page(limit, offset)?;
        self.repository
            .registered_account_usernames(actor, limit, offset)
            .await
    }
    pub async fn disabled_account_usernames(
        &self,
        actor: &AdminActor,
        limit: i64,
        offset: i64,
    ) -> Result<Option<Vec<String>>> {
        validate_account_page(limit, offset)?;
        self.repository
            .disabled_account_usernames(actor, limit, offset)
            .await
    }
    pub async fn announcement_account_page(
        &self,
        actor: &AdminActor,
        cursor: Option<&AnnouncementPageCursor>,
    ) -> Result<Option<AnnouncementAccountPage>> {
        self.repository
            .announcement_account_page(actor, cursor)
            .await
    }
    pub async fn administrator_usernames(
        &self,
        actor: &AdminActor,
    ) -> Result<Option<BoundedAccountList>> {
        self.repository.administrator_usernames(actor).await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn create_account(
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
        claim.fence(actor, node, result_payload)?;
        self.repository
            .create_account(
                actor,
                claim,
                node,
                username,
                password,
                scram_iterations,
                scram_sha1_enabled,
                result_payload,
            )
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn mutate_accounts(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        targets: &[AccountCommandTarget],
        action: AccountCommandAction,
        domain: &str,
        result_payload: &str,
    ) -> Result<AccountMutationOutcome> {
        claim.fence(actor, node, result_payload)?;
        self.repository
            .mutate_accounts(actor, claim, node, targets, action, domain, result_payload)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn reset_account_password(
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
        claim.fence(actor, node, result_payload)?;
        self.repository
            .reset_account_password(
                actor,
                claim,
                node,
                username,
                password,
                scram_iterations,
                scram_sha1_enabled,
                domain,
                result_payload,
            )
            .await
    }
    pub async fn account_last_login(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> Result<Option<AccountCommandView>> {
        self.repository.account_last_login(actor, username).await
    }
    pub async fn account_roster(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> Result<Option<AccountRosterView>> {
        self.repository.account_roster(actor, username).await
    }
    pub async fn account_statistics(
        &self,
        actor: &AdminActor,
        username: &str,
    ) -> Result<Option<AccountStatistics>> {
        self.repository.account_statistics(actor, username).await
    }
    pub async fn replace_administrators(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        usernames: &[String],
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        claim.fence(actor, node, result_payload)?;
        self.repository
            .replace_administrators(actor, claim, node, usernames, result_payload)
            .await
    }
    pub async fn record_announcement(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        recipients: usize,
        bytes: usize,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        claim.fence(actor, node, result_payload)?;
        self.repository
            .record_announcement(actor, claim, node, recipients, bytes, result_payload)
            .await
    }
    pub async fn set_service_message(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        kind: &str,
        body: Option<&str>,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        claim.fence(actor, node, result_payload)?;
        self.repository
            .set_service_message(actor, claim, node, kind, body, result_payload)
            .await
    }
    pub async fn service_message_body(
        &self,
        actor: &AdminActor,
        kind: &str,
    ) -> Result<Option<String>> {
        anyhow::ensure!(
            matches!(kind, "motd" | "welcome"),
            "invalid service message kind"
        );
        self.repository.service_message_body(actor, kind).await
    }
    pub async fn replace_federation_rules(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        kind: &str,
        entities: &[String],
        result_payload: &str,
    ) -> Result<Option<FederationRuleSet>> {
        claim.fence(actor, node, result_payload)?;
        self.repository
            .replace_federation_rules(actor, claim, node, kind, entities, result_payload)
            .await
    }
    pub async fn federation_rule_domains(
        &self,
        actor: &AdminActor,
        kind: &str,
    ) -> Result<Option<Vec<String>>> {
        anyhow::ensure!(
            matches!(kind, "blacklist" | "whitelist"),
            "invalid federation rule kind"
        );
        self.repository.federation_rule_domains(actor, kind).await
    }
    pub async fn cancel_service_control(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        action: &str,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        claim.fence(actor, node, result_payload)?;
        self.repository
            .cancel_service_control(actor, claim, node, action, result_payload)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn schedule_service_control(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        action: &str,
        delay_seconds: i64,
        announcement: Option<&str>,
        result_payload: &str,
    ) -> Result<AdminWriteOutcome> {
        claim.fence(actor, node, result_payload)?;
        self.repository
            .schedule_service_control(
                actor,
                claim,
                node,
                action,
                delay_seconds,
                announcement,
                result_payload,
            )
            .await
    }
    pub async fn create_session(
        &self,
        actor: &AdminActor,
        owner_full_jid: &str,
        server_domain: &str,
        node: &str,
        stage: &str,
    ) -> Result<Option<zeroize::Zeroizing<String>>> {
        self.repository
            .create_session(actor, owner_full_jid, server_domain, node, stage)
            .await
    }
    pub async fn finish_session(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        final_stage: &str,
    ) -> Result<CommandSessionOutcome> {
        self.repository
            .finish_session(bearer, actor, owner_full_jid, node, final_stage)
            .await
    }
    pub async fn complete_count_session(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        payload: &str,
    ) -> Result<CommandSessionOutcome> {
        self.repository
            .complete_count_session(bearer, actor, owner_full_jid, node, payload)
            .await
    }
    pub async fn begin_execution(
        &self,
        bearer: &str,
        actor: &AdminActor,
        owner_full_jid: &str,
        node: &str,
        target_digest: &[u8; 32],
    ) -> Result<CommandExecutionOutcome> {
        self.repository
            .begin_execution(bearer, actor, owner_full_jid, node, target_digest)
            .await
    }
    pub async fn release_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
    ) -> Result<ExecutionReleaseOutcome> {
        claim.fence(actor, node, "")?;
        self.repository.release_execution(actor, claim, node).await
    }
    pub async fn renew_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
    ) -> Result<bool> {
        claim.fence(actor, node, "")?;
        self.repository.renew_execution(actor, claim, node).await
    }
    pub async fn complete_read_execution(
        &self,
        actor: &AdminActor,
        claim: &AdminExecutionClaim,
        node: &str,
        payload: &str,
    ) -> Result<AdminWriteOutcome> {
        claim.fence(actor, node, payload)?;
        self.repository
            .complete_read_execution(actor, claim, node, payload)
            .await
    }
    pub async fn cleanup_sessions(&self) -> Result<u64> {
        self.repository.cleanup_sessions().await
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
pub fn canonical_account_jid(username: &str, domain: &str) -> Result<CanonicalJid> {
    let jid = CanonicalJid::parse_bare(&format!("{username}@{domain}"))?;
    anyhow::ensure!(
        jid.localpart() == Some(username) && jid.domainpart() == domain,
        "account identity changed during JID preparation"
    );
    Ok(jid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrative_account_pages_have_hard_size_and_offset_bounds() {
        assert!(validate_account_page(1, 0).is_ok());
        assert!(validate_account_page(MAX_ADMIN_ACCOUNT_PAGE_SIZE, 10_000).is_ok());
        assert!(validate_account_page(0, 0).is_err());
        assert!(validate_account_page(MAX_ADMIN_ACCOUNT_PAGE_SIZE + 1, 0).is_err());
        assert!(validate_account_page(1, -1).is_err());
        assert!(validate_account_page(1, MAX_ADMIN_ACCOUNT_PAGE_OFFSET + 1).is_err());
    }
}
