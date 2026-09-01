//! Application boundary for personal-message policy and durable admission.
//!
//! Protocol handlers own XML validation, routing and stanza-error mapping.
//! This service owns the PostgreSQL capability for account communication
//! policy and the atomic MAM/outbox/C2S/offline admission workflows. Keeping
//! those concerns together prevents a handler from checking one policy and
//! then committing through an unrelated database path with different limits.

use super::{
    muc::{ClusterMucInviteAuthority, DurableMucInviteOutcome},
    privacy::{PrivacyService, PrivacyStanzaKind},
    retractions::FederationOutboxPolicy,
};
use crate::{
    abuse::{MessageDedupeIdentity, PersonalMessageContentKeyring},
    db,
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// One enabled personal MAM projection of an accepted message.
///
/// The protocol layer supplies already-sanitized stanza text; canonical JID,
/// size and identity validation remain enforced by the repository transaction.
pub(crate) use super::retractions::ArchiveWrite;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundPolicyDecision {
    Allowed,
    Blocked,
    PrivacyDenied,
}

#[derive(Debug)]
pub(crate) enum LocalRecipientDecision {
    Missing,
    Blocked,
    Deliver(LocalRecipient),
}

/// Minimum identity required by the personal-message pipeline. In particular,
/// password hashes and SCRAM verifiers from the persistence model never cross
/// into stanza parsing or live routing code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalRecipient {
    pub(crate) id: Uuid,
    pub(crate) username: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableAdmissionOutcome {
    Stored { archive_written: bool },
    Replay,
    AccountUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineAdmissionOutcome {
    Stored,
    Replay,
    QuotaExceeded,
    RecipientUnavailable,
}

#[derive(Clone, Copy)]
struct OfflineLimits {
    max_messages: i64,
    max_bytes: i64,
    ttl_days: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct MessageIdentity<'a> {
    pub(crate) actor_scope_raw: &'a str,
    pub(crate) actor_scope: &'a str,
    pub(crate) target_scope: &'a str,
    pub(crate) value: &'a str,
    pub(crate) payload: &'a str,
}

pub(crate) struct RemoteMessageAdmission<'a> {
    pub(crate) local_actor_id: Uuid,
    pub(crate) identity: Option<MessageIdentity<'a>>,
    pub(crate) archives: &'a [ArchiveWrite<'a>],
    pub(crate) target_domain: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) bounce_to: Option<&'a str>,
    pub(crate) outbox_policy: FederationOutboxPolicy,
}

pub(crate) struct RemoteMucInviteAdmission<'a> {
    pub(crate) local_actor_id: Uuid,
    pub(crate) identity: Option<MessageIdentity<'a>>,
    pub(crate) archives: &'a [ArchiveWrite<'a>],
    pub(crate) room_id: Uuid,
    pub(crate) invitee_bare_jid: &'a str,
    pub(crate) target_domain: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) bounce_to: Option<&'a str>,
    pub(crate) outbox_policy: FederationOutboxPolicy,
    pub(crate) cluster_authority: Option<&'a ClusterMucInviteAuthority>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteMucInviteAdmissionOutcome {
    Stored,
    Replay,
    AccountUnavailable,
    Rejected,
    Stale,
    Conflict,
}

pub(crate) struct LocalMessageAdmission<'a> {
    pub(crate) local_actor_id: Option<Uuid>,
    pub(crate) identity: Option<MessageIdentity<'a>>,
    pub(crate) archives: &'a [ArchiveWrite<'a>],
    pub(crate) delivery_id: Uuid,
    pub(crate) recipient_id: Uuid,
    pub(crate) recipient_bare_jid: &'a str,
    pub(crate) sender_jid: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) encrypted: bool,
    pub(crate) mam_backed: bool,
}

pub(crate) struct OfflineMessageAdmission<'a> {
    pub(crate) recipient_id: Uuid,
    pub(crate) recipient_bare_jid: &'a str,
    pub(crate) sender_jid: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) encrypted: bool,
    pub(crate) mam_backed: bool,
    pub(crate) identity: Option<&'a MessageDedupeIdentity>,
}

/// One application-level members-only direct invitation admission. The
/// service owns the transaction spanning personal history, origin identity,
/// recoverable C2S delivery and MUC affiliation authorization.
pub(crate) struct LocalMucInviteAdmission<'a> {
    pub(crate) local_actor_id: Uuid,
    pub(crate) identity: Option<MessageIdentity<'a>>,
    pub(crate) archives: &'a [ArchiveWrite<'a>],
    pub(crate) delivery_id: Uuid,
    pub(crate) recipient_id: Uuid,
    pub(crate) recipient_bare_jid: &'a str,
    pub(crate) sender_jid: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) encrypted: bool,
    pub(crate) mam_backed: bool,
    pub(crate) room_id: Uuid,
    pub(crate) cluster_authority: Option<&'a ClusterMucInviteAuthority>,
}

#[derive(Clone)]
pub(crate) struct MessageService {
    pool: PgPool,
    content_identity: PersonalMessageContentKeyring,
    configured_domain: String,
    require_encrypted_archive: bool,
    offline: OfflineLimits,
}

impl MessageService {
    pub(crate) fn new(
        pool: PgPool,
        content_identity: PersonalMessageContentKeyring,
        configured_domain: impl Into<String>,
        require_encrypted_archive: bool,
        offline_max_messages: i64,
        offline_max_bytes: i64,
        offline_ttl_days: i64,
    ) -> Self {
        Self {
            pool,
            content_identity,
            configured_domain: configured_domain.into(),
            require_encrypted_archive,
            offline: OfflineLimits {
                max_messages: offline_max_messages,
                max_bytes: offline_max_bytes,
                ttl_days: offline_ttl_days,
            },
        }
    }

    /// Apply the non-overridable XEP-0191 rule before the selected XEP-0016
    /// list. The typed result preserves the different protocol errors without
    /// exposing either repository call to the stanza handler.
    pub(crate) async fn authorize_outbound_message(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        active_privacy_list: Option<&str>,
        target: &str,
    ) -> Result<OutboundPolicyDecision> {
        if db::is_blocked_for_account(&self.pool, owner_id, owner_bare_jid, target).await? {
            return Ok(OutboundPolicyDecision::Blocked);
        }
        if db::privacy_denies(
            &self.pool,
            owner_id,
            active_privacy_list,
            target,
            db::PrivacyStanzaKind::Message,
        )
        .await?
        {
            return Ok(OutboundPolicyDecision::PrivacyDenied);
        }
        Ok(OutboundPolicyDecision::Allowed)
    }

    /// Resolve a local target and apply its account-scoped block rule as one
    /// business decision. Missing and blocked accounts stay distinguishable
    /// internally while the protocol may deliberately map both to the same
    /// privacy-preserving stanza error.
    pub(crate) async fn resolve_local_recipient(
        &self,
        username: &str,
        local_domain: &str,
        sender_jid: &str,
    ) -> Result<LocalRecipientDecision> {
        let Some(recipient) = db::find_enabled_user(&self.pool, username).await? else {
            return Ok(LocalRecipientDecision::Missing);
        };
        let recipient_bare = format!("{}@{local_domain}", recipient.username);
        if db::is_blocked_for_account(&self.pool, recipient.id, &recipient_bare, sender_jid).await?
        {
            return Ok(LocalRecipientDecision::Blocked);
        }
        Ok(LocalRecipientDecision::Deliver(LocalRecipient {
            id: recipient.id,
            username: recipient.username,
        }))
    }

    pub(crate) async fn default_recipient_privacy_denies(
        &self,
        recipient_id: Uuid,
        sender_jid: &str,
    ) -> Result<bool> {
        db::privacy_denies(
            &self.pool,
            recipient_id,
            None,
            sender_jid,
            db::PrivacyStanzaKind::Message,
        )
        .await
    }

    /// Refresh the lease of an explicitly selected privacy list before using
    /// it. A stale active-list row must never silently fall back to the account
    /// default during a live session.
    pub(crate) async fn privacy_allows_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
        active_privacy_list: Option<&str>,
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> Result<bool> {
        PrivacyService::new(self.pool.clone())
            .session_allows(user_id, connection_id, active_privacy_list, peer, kind)
            .await
    }

    /// Combine stanza storage semantics, deployment encryption policy and the
    /// account's MAM preference. Retractions are always history mutations and
    /// therefore bypass ordinary content-storage eligibility.
    pub(crate) async fn archive_enabled(
        &self,
        owner_id: Uuid,
        peer_jid: &str,
        stanza_storage_eligible: bool,
        encrypted: bool,
        retraction: bool,
    ) -> Result<bool> {
        if retraction {
            return Ok(true);
        }
        if !stanza_storage_eligible || (self.require_encrypted_archive && !encrypted) {
            return Ok(false);
        }
        db::archive_allowed(&self.pool, owner_id, peer_jid).await
    }

    pub(crate) async fn admit_remote_message(
        &self,
        request: &RemoteMessageAdmission<'_>,
    ) -> Result<DurableAdmissionOutcome> {
        let identity = request
            .identity
            .as_ref()
            .map(|identity| self.db_identity(identity, "local-origin"))
            .transpose()?;
        let archives = persistence_archive_writes(request.archives);
        let outbox = db::PersonalS2sOutboxAdmission {
            local_actor_id: request.local_actor_id,
            target_domain: request.target_domain,
            stanza: request.stanza,
            bounce_to: request.bounce_to,
            policy: request.outbox_policy.into(),
        };
        map_history_outcome(
            db::admit_outbound_personal_history(&self.pool, identity.as_ref(), &archives, &outbox)
                .await?,
            !request.archives.is_empty(),
        )
    }

    /// Atomically admit a local-room invitation addressed to a federated
    /// account. The sender's origin identity/MAM projection, S2S outbox and
    /// members-only affiliation share one transaction. Exact replay therefore
    /// cannot enqueue a second federation copy, while a changed payload with
    /// the same origin-id conflicts before any room mutation. Without a
    /// client-provided stable identity, byte-identical sends remain distinct:
    /// collapsing them by payload would discard legitimate repeated messages.
    pub(crate) async fn admit_remote_muc_invite(
        &self,
        request: &RemoteMucInviteAdmission<'_>,
    ) -> Result<RemoteMucInviteAdmissionOutcome> {
        let identity = request
            .identity
            .as_ref()
            .map(|identity| self.db_identity(identity, "local-origin"))
            .transpose()?;
        let archives = persistence_archive_writes(request.archives);
        let outbox = db::PersonalS2sOutboxAdmission {
            local_actor_id: request.local_actor_id,
            target_domain: request.target_domain,
            stanza: request.stanza,
            bounce_to: request.bounce_to,
            policy: request.outbox_policy.into(),
        };
        let mut transaction = self.pool.begin().await?;
        let history = match db::admit_personal_history_in_transaction(
            &mut transaction,
            identity.as_ref(),
            &archives,
            Some(&outbox),
            None,
        )
        .await
        {
            Ok(history) => history,
            Err(error)
                if error
                    .downcast_ref::<db::PersonalHistoryIdentityConflict>()
                    .is_some() =>
            {
                transaction.rollback().await?;
                return Ok(RemoteMucInviteAdmissionOutcome::Conflict);
            }
            Err(error) => {
                transaction.rollback().await?;
                return Err(error);
            }
        };
        if matches!(history, db::PersonalHistoryAdmission::AccountUnavailable) {
            transaction.rollback().await?;
            return Ok(RemoteMucInviteAdmissionOutcome::AccountUnavailable);
        }
        if matches!(history, db::PersonalHistoryAdmission::Replay(_)) {
            // No room mutation has happened yet. Commit so a migration-0104
            // legacy digest upgrade performed by the history repository is
            // durable; a keyed replay commits only read locks.
            transaction.commit().await?;
            return Ok(RemoteMucInviteAdmissionOutcome::Replay);
        }
        let cluster_authority = request.cluster_authority.map(Into::into);
        let affiliation = match db::grant_federated_muc_invite_affiliation_in_transaction(
            &mut transaction,
            request.room_id,
            request.invitee_bare_jid,
            cluster_authority.as_ref(),
        )
        .await
        {
            Ok(affiliation) => affiliation,
            Err(error) => {
                transaction.rollback().await?;
                return Err(error);
            }
        };
        let outcome = match affiliation {
            db::FederatedMucInviteAffiliationOutcome::Stored => {
                transaction.commit().await?;
                RemoteMucInviteAdmissionOutcome::Stored
            }
            db::FederatedMucInviteAffiliationOutcome::Replay => {
                transaction.rollback().await?;
                RemoteMucInviteAdmissionOutcome::Replay
            }
            db::FederatedMucInviteAffiliationOutcome::Rejected => {
                transaction.rollback().await?;
                RemoteMucInviteAdmissionOutcome::Rejected
            }
            db::FederatedMucInviteAffiliationOutcome::Stale => {
                transaction.rollback().await?;
                RemoteMucInviteAdmissionOutcome::Stale
            }
        };
        Ok(outcome)
    }

    /// Atomically commit every enabled MAM projection and the recoverable C2S
    /// delivery fence. The origin identity cannot become a history-only ghost
    /// and an exact retry cannot fan out a second live copy.
    pub(crate) async fn admit_local_message(
        &self,
        request: &LocalMessageAdmission<'_>,
    ) -> Result<DurableAdmissionOutcome> {
        self.admit_c2s_message(request, "local-origin").await
    }

    /// Federated stanza IDs use the authenticated remote domain as their
    /// authority and therefore occupy a distinct identity namespace from a
    /// client origin-id. The same application transaction remains responsible
    /// for its optional MAM and recoverable C2S projections.
    pub(crate) async fn admit_inbound_federated_message(
        &self,
        request: &LocalMessageAdmission<'_>,
    ) -> Result<DurableAdmissionOutcome> {
        self.admit_c2s_message(request, "remote-stanza").await
    }

    async fn admit_c2s_message(
        &self,
        request: &LocalMessageAdmission<'_>,
        identity_kind: &'static str,
    ) -> Result<DurableAdmissionOutcome> {
        self.validate_local_recipient_authority(request.recipient_bare_jid)?;
        let identity = request
            .identity
            .as_ref()
            .map(|identity| self.db_identity(identity, identity_kind))
            .transpose()?;
        let archives = persistence_archive_writes(request.archives);
        let target_full_jid = durable_target_full_jid(request.stanza)?;
        let delivery = db::PersonalC2sDeliveryAdmission {
            id: request.delivery_id,
            recipient_id: request.recipient_id,
            recipient_bare_jid: request.recipient_bare_jid,
            local_actor_id: request.local_actor_id,
            sender_jid: request.sender_jid,
            stanza: request.stanza,
            target_full_jid: target_full_jid.as_deref(),
            encrypted: request.encrypted,
            policy: self.offline_policy(request.mam_backed),
        };
        map_history_outcome(
            db::admit_personal_history_and_c2s_delivery(
                &self.pool,
                identity.as_ref(),
                &archives,
                &delivery,
            )
            .await?,
            !request.archives.is_empty(),
        )
    }

    /// Commit a local members-only direct invitation as one state change.
    ///
    /// Lock ordering intentionally extends the ordinary durable message path:
    /// identity/archive -> global capacity -> recipient capacity -> room/user.
    /// No room lock is held while waiting for a capacity lock, so the legacy
    /// global -> recipient -> room invite path cannot form a cycle with this
    /// transaction.
    pub(crate) async fn admit_local_muc_invite(
        &self,
        request: &LocalMucInviteAdmission<'_>,
    ) -> Result<DurableMucInviteOutcome> {
        self.validate_local_recipient_authority(request.recipient_bare_jid)?;
        let identity = request
            .identity
            .as_ref()
            .map(|identity| self.db_identity(identity, "local-origin"))
            .transpose()?;
        let archives = persistence_archive_writes(request.archives);
        let target_full_jid = durable_target_full_jid(request.stanza)?;
        let delivery = db::PersonalC2sDeliveryAdmission {
            id: request.delivery_id,
            recipient_id: request.recipient_id,
            recipient_bare_jid: request.recipient_bare_jid,
            local_actor_id: Some(request.local_actor_id),
            sender_jid: request.sender_jid,
            stanza: request.stanza,
            target_full_jid: target_full_jid.as_deref(),
            encrypted: request.encrypted,
            policy: self.offline_policy(request.mam_backed),
        };
        let mut transaction = self.pool.begin().await?;
        let history = match db::admit_personal_history_in_transaction(
            &mut transaction,
            identity.as_ref(),
            &archives,
            None,
            Some(&delivery),
        )
        .await
        {
            Ok(history) => history,
            Err(error)
                if error
                    .downcast_ref::<db::C2sDeliveryCapacityExceeded>()
                    .is_some() =>
            {
                transaction.rollback().await?;
                return Ok(DurableMucInviteOutcome::QuotaExceeded);
            }
            Err(error) => {
                transaction.rollback().await?;
                return Err(error);
            }
        };
        if matches!(history, db::PersonalHistoryAdmission::Replay(_)) {
            // The affiliation path has not run, so the only possible write is
            // a safe legacy-content-evidence upgrade.
            transaction.commit().await?;
            return Ok(DurableMucInviteOutcome::Replay {
                id: request.delivery_id,
            });
        }

        let cluster_authority = request.cluster_authority.map(Into::into);
        let affiliation = match db::grant_local_muc_invite_affiliation_in_transaction(
            &mut transaction,
            request.delivery_id,
            request.room_id,
            request.recipient_id,
            cluster_authority.as_ref(),
        )
        .await
        {
            Ok(affiliation) => affiliation,
            Err(error) => {
                transaction.rollback().await?;
                return Err(error);
            }
        };
        match affiliation {
            db::DurableMucInviteOutcome::Stored { .. } => {
                transaction.commit().await?;
            }
            db::DurableMucInviteOutcome::Replay { .. }
            | db::DurableMucInviteOutcome::QuotaExceeded
            | db::DurableMucInviteOutcome::RecipientUnavailable
            | db::DurableMucInviteOutcome::Outcast
            | db::DurableMucInviteOutcome::AuthorityRejected
            | db::DurableMucInviteOutcome::Stale => {
                transaction.rollback().await?;
            }
        }
        Ok(affiliation.into())
    }

    pub(crate) async fn admit_history(&self, writes: &[ArchiveWrite<'_>]) -> Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
        let writes = persistence_archive_writes(writes);
        db::admit_personal_history(&self.pool, None, &writes)
            .await
            .map(|_| ())
    }

    pub(crate) async fn store_offline(
        &self,
        admission: OfflineMessageAdmission<'_>,
    ) -> Result<OfflineAdmissionOutcome> {
        let OfflineMessageAdmission {
            recipient_id,
            recipient_bare_jid,
            sender_jid,
            stanza,
            encrypted,
            mam_backed,
            identity,
        } = admission;
        self.validate_local_recipient_authority(recipient_bare_jid)?;
        match db::store_offline_idempotent_for_recipient(
            &self.pool,
            recipient_id,
            recipient_bare_jid,
            sender_jid,
            stanza,
            encrypted,
            self.offline_policy(mam_backed),
            identity,
        )
        .await?
        {
            db::OfflineStoreOutcome::Stored => Ok(OfflineAdmissionOutcome::Stored),
            db::OfflineStoreOutcome::Replay => Ok(OfflineAdmissionOutcome::Replay),
            db::OfflineStoreOutcome::QuotaExceeded => Ok(OfflineAdmissionOutcome::QuotaExceeded),
            db::OfflineStoreOutcome::RecipientUnavailable => {
                Ok(OfflineAdmissionOutcome::RecipientUnavailable)
            }
        }
    }

    /// Bind every local durable projection to this server's configured XMPP
    /// authority before the repository checks the recipient UUID/localpart.
    /// Keeping the domain in the service prevents an internal caller from
    /// smuggling an otherwise well-formed `username@other-domain` target into
    /// the local replay queue.
    fn validate_local_recipient_authority(&self, recipient_bare_jid: &str) -> Result<()> {
        validate_local_recipient_authority_for_domain(recipient_bare_jid, &self.configured_domain)
    }

    fn offline_policy(&self, mam_backed: bool) -> db::OfflineStorePolicy {
        db::OfflineStorePolicy {
            max_messages: self.offline.max_messages,
            max_bytes: self.offline.max_bytes,
            ttl_days: self.offline.ttl_days,
            mam_backed,
        }
    }

    fn db_identity<'a>(
        &self,
        identity: &'a MessageIdentity<'a>,
        kind: &'static str,
    ) -> Result<db::PersonalHistoryIdentity<'a>> {
        anyhow::ensure!(
            !identity.payload.is_empty() && identity.payload.len() <= 1_048_576,
            "personal history payload must contain 1 byte to 1 MiB"
        );
        let commitment = personal_message_commitment(kind, identity);
        Ok(db::PersonalHistoryIdentity {
            kind,
            actor_scope_raw: identity.actor_scope_raw,
            actor_scope: identity.actor_scope,
            target_scope: identity.target_scope,
            identity_value: identity.value,
            payload_authenticators: self.content_identity.authenticators(&commitment),
            legacy_payload_digest: Sha256::digest(identity.payload.as_bytes()).into(),
        })
    }
}

fn validate_local_recipient_authority_for_domain(
    recipient_bare_jid: &str,
    configured_domain: &str,
) -> Result<()> {
    let recipient = crate::jid::CanonicalJid::parse_bare(recipient_bare_jid)?;
    let configured_domain = crate::jid::prepare_domainpart(configured_domain)?;
    anyhow::ensure!(
        recipient.to_string() == recipient_bare_jid,
        "local durable recipient authority must already be canonical"
    );
    anyhow::ensure!(
        recipient.localpart().is_some() && recipient.domainpart() == configured_domain,
        "local durable recipient authority does not belong to the configured domain"
    );
    Ok(())
}

fn persistence_archive_writes<'a>(
    writes: &[ArchiveWrite<'a>],
) -> Vec<db::PersonalArchiveWrite<'a>> {
    writes
        .iter()
        .map(|write| db::PersonalArchiveWrite {
            id: write.id,
            owner_id: write.owner_id,
            peer_jid: write.peer_jid,
            stanza: write.stanza,
            encrypted: write.encrypted,
            stanza_id: write.stanza_id,
        })
        .collect()
}

/// Derive the only delivery class whose RFC 6121 resource selection must
/// survive process/transport failure. Chat full-JID routing may fall back to
/// the bare account, while bare and missing destinations are account scoped.
fn durable_target_full_jid(stanza: &str) -> Result<Option<String>> {
    let document = roxmltree::Document::parse(stanza)?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "durable C2S projection must contain one message stanza"
    );
    match root.attribute("to") {
        Some(to) if root.attribute("type").unwrap_or("normal") == "normal" => {
            let target = crate::jid::CanonicalJid::parse(to)?;
            Ok(target.resourcepart().is_some().then(|| target.to_string()))
        }
        _ => Ok(None),
    }
}

fn personal_message_commitment(kind: &str, identity: &MessageIdentity<'_>) -> Vec<u8> {
    fn field(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        output.extend_from_slice(value);
    }

    let mut commitment = b"northstar/personal-message-content/v2\0".to_vec();
    for value in [
        kind.as_bytes(),
        identity.actor_scope_raw.as_bytes(),
        identity.actor_scope.as_bytes(),
        identity.target_scope.as_bytes(),
        identity.value.as_bytes(),
        identity.payload.as_bytes(),
    ] {
        field(&mut commitment, value);
    }
    commitment
}

fn map_history_outcome(
    outcome: db::PersonalHistoryAdmission,
    archive_written: bool,
) -> Result<DurableAdmissionOutcome> {
    Ok(match outcome {
        db::PersonalHistoryAdmission::Stored(_) => {
            DurableAdmissionOutcome::Stored { archive_written }
        }
        db::PersonalHistoryAdmission::Replay(_) => DurableAdmissionOutcome::Replay,
        db::PersonalHistoryAdmission::AccountUnavailable => {
            DurableAdmissionOutcome::AccountUnavailable
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn downgrade_personal_evidence(pool: &PgPool, identity_value: &str, payload: &str) {
        sqlx::query(
            "UPDATE personal_message_admissions
                SET payload_key_id=NULL,payload_mac=NULL,payload_digest=$2
              WHERE identity_value=$1",
        )
        .bind(identity_value)
        .bind(Sha256::digest(payload.as_bytes()).to_vec())
        .execute(pool)
        .await
        .unwrap();
    }

    async fn assert_personal_evidence_is_keyed(pool: &PgPool, identity_value: &str) {
        let row: (Option<String>, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT payload_key_id,payload_mac,payload_digest
               FROM personal_message_admissions WHERE identity_value=$1",
        )
        .bind(identity_value)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(row.0.is_some());
        assert_eq!(row.1.as_deref().map(|value| value.len()), Some(32));
        assert_eq!(row.2, None);
    }

    #[test]
    fn durable_results_do_not_expose_repository_row_ids() {
        assert_eq!(
            map_history_outcome(
                db::PersonalHistoryAdmission::Stored(vec![Uuid::new_v4()]),
                true
            )
            .unwrap(),
            DurableAdmissionOutcome::Stored {
                archive_written: true
            }
        );
        assert_eq!(
            map_history_outcome(db::PersonalHistoryAdmission::Replay(vec![]), false).unwrap(),
            DurableAdmissionOutcome::Replay
        );
    }

    #[test]
    fn only_explicit_full_normal_messages_receive_resource_affinity() {
        assert_eq!(
            durable_target_full_jid(
                "<message to='alice@example.test/Phone'><body>normal</body></message>"
            )
            .unwrap()
            .as_deref(),
            Some("alice@example.test/Phone")
        );
        for stanza in [
            "<message to='alice@example.test'><body>bare</body></message>",
            "<message type='chat' to='alice@example.test/Phone'><body>fallback</body></message>",
            "<message><body>implicit self</body></message>",
        ] {
            assert_eq!(durable_target_full_jid(stanza).unwrap(), None);
        }
    }

    #[test]
    fn durable_recipient_authority_is_canonical_and_local() {
        assert!(validate_local_recipient_authority_for_domain(
            "alice@example.test",
            "example.test"
        )
        .is_ok());
        assert!(
            validate_local_recipient_authority_for_domain("alice@evil.test", "example.test")
                .is_err()
        );
        assert!(validate_local_recipient_authority_for_domain(
            "Alice@example.test",
            "example.test"
        )
        .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn members_only_invite_is_one_replay_safe_transaction() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("message_invite_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(60))
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

        let marker = Uuid::new_v4().simple().to_string();
        let sender_id = Uuid::new_v4();
        let recipient_id = Uuid::new_v4();
        let failure_recipient_id = Uuid::new_v4();
        let quota_recipient_id = Uuid::new_v4();
        let concurrent_recipient_id = Uuid::new_v4();
        for (id, username) in [
            (sender_id, format!("sender-{}", &marker[..8])),
            (recipient_id, format!("recipient-{}", &marker[..8])),
            (failure_recipient_id, format!("failure-{}", &marker[..8])),
            (quota_recipient_id, format!("quota-{}", &marker[..8])),
            (
                concurrent_recipient_id,
                format!("concurrent-{}", &marker[..8]),
            ),
        ] {
            sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
                .bind(id)
                .bind(username)
                .execute(&pool)
                .await
                .unwrap();
        }
        let sender = format!("sender-{}@local.test/Phone", &marker[..8]);
        let recipient = format!("recipient-{}@local.test", &marker[..8]);
        let failure_recipient = format!("failure-{}@local.test", &marker[..8]);
        let quota_recipient = format!("quota-{}@local.test", &marker[..8]);
        let concurrent_recipient = format!("concurrent-{}@local.test", &marker[..8]);
        let (room, _) = db::get_or_create_muc_room(
            &pool,
            &format!("invite-{}", &marker[..8]),
            sender_id,
            &sender,
        )
        .await
        .unwrap();
        let (failure_room, _) = db::get_or_create_muc_room(
            &pool,
            &format!("invite-failure-{}", &marker[..8]),
            sender_id,
            &sender,
        )
        .await
        .unwrap();
        let (quota_room, _) = db::get_or_create_muc_room(
            &pool,
            &format!("invite-quota-{}", &marker[..8]),
            sender_id,
            &sender,
        )
        .await
        .unwrap();
        let (concurrent_room, _) = db::get_or_create_muc_room(
            &pool,
            &format!("invite-concurrent-{}", &marker[..8]),
            sender_id,
            &sender,
        )
        .await
        .unwrap();
        let service = MessageService::new(
            pool.clone(),
            crate::abuse::test_personal_message_content_keyring(),
            "local.test",
            false,
            100,
            8_000_000,
            30,
        );

        let delivery_id = Uuid::new_v4();
        let sender_archive_id = Uuid::new_v4();
        let recipient_archive_id = Uuid::new_v4();
        let payload = format!("<message id='invite-{marker}'/>");
        let sender_archive = format!("<message to='{recipient}'><body>invite</body></message>");
        let recipient_archive = format!("<message from='{sender}'><body>invite</body></message>");
        let delayed = format!(
            "<message from='{sender}' to='{recipient}'><body>invite</body><delay xmlns='urn:xmpp:delay'/></message>"
        );
        let writes = [
            ArchiveWrite {
                id: sender_archive_id,
                owner_id: sender_id,
                peer_jid: &recipient,
                stanza: &sender_archive,
                encrypted: true,
                stanza_id: Some("invite-client-id"),
            },
            ArchiveWrite {
                id: recipient_archive_id,
                owner_id: recipient_id,
                peer_jid: &sender,
                stanza: &recipient_archive,
                encrypted: true,
                stanza_id: Some("invite-client-id"),
            },
        ];
        let request = LocalMucInviteAdmission {
            local_actor_id: sender_id,
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &recipient,
                value: "origin-invite-success",
                payload: &payload,
            }),
            archives: &writes,
            delivery_id,
            recipient_id,
            recipient_bare_jid: &recipient,
            sender_jid: &sender,
            stanza: &delayed,
            encrypted: true,
            mam_backed: true,
            room_id: room.id,
            cluster_authority: None,
        };
        assert_eq!(
            service.admit_local_muc_invite(&request).await.unwrap(),
            DurableMucInviteOutcome::Stored {
                id: delivery_id,
                affiliation_changed: true,
            }
        );
        let committed: (i64, i64, i64, i64, bool) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 AND affiliation='member'),
                 (SELECT COUNT(*) FROM message_archive WHERE id IN ($3,$4)),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-invite-success'),
                 (SELECT COUNT(*) FROM offline_messages WHERE id=$5),
                 (SELECT mam_backed FROM offline_messages WHERE id=$5)",
        )
        .bind(room.id)
        .bind(recipient_id)
        .bind(sender_archive_id)
        .bind(recipient_archive_id)
        .bind(delivery_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(committed, (1, 2, 1, 1, true));
        let admission_plaintext_marker: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM personal_message_admissions AS admission
              WHERE row_to_json(admission)::TEXT LIKE '%' || $1 || '%'",
        )
        .bind(&marker)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            admission_plaintext_marker, 0,
            "a database dump of the admission table must not contain the original stanza marker"
        );

        downgrade_personal_evidence(&pool, "origin-invite-success", &payload).await;
        assert_eq!(
            service.admit_local_muc_invite(&request).await.unwrap(),
            DurableMucInviteOutcome::Replay { id: delivery_id }
        );
        assert_personal_evidence_is_keyed(&pool, "origin-invite-success").await;
        let replay_counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM message_archive WHERE id IN ($1,$2)),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-invite-success'),
                 (SELECT COUNT(*) FROM offline_messages WHERE id=$3)",
        )
        .bind(sender_archive_id)
        .bind(recipient_archive_id)
        .bind(delivery_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(replay_counts, (2, 1, 1));
        sqlx::query(
            "UPDATE personal_message_admissions
                SET payload_mac=decode(repeat('cc',32),'hex')
              WHERE identity_value='origin-invite-success'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            service
                .admit_local_muc_invite(&request)
                .await
                .unwrap_err()
                .to_string()
                .contains("conflicting personal history identity"),
            "a known key ID with a changed MAC must fail closed"
        );
        downgrade_personal_evidence(&pool, "origin-invite-success", &payload).await;
        assert_eq!(
            service.admit_local_muc_invite(&request).await.unwrap(),
            DurableMucInviteOutcome::Replay { id: delivery_id }
        );
        assert_personal_evidence_is_keyed(&pool, "origin-invite-success").await;
        sqlx::query(
            "UPDATE personal_message_admissions
                SET payload_key_id='BBBBBBBBBBBBBBBB'
              WHERE identity_value='origin-invite-success'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(service
            .admit_local_muc_invite(&request)
            .await
            .unwrap_err()
            .to_string()
            .contains("conflicting personal history identity"));
        assert!(
            sqlx::query(
                "UPDATE personal_message_admissions
                SET payload_key_id=NULL,payload_digest=NULL
              WHERE identity_value='origin-invite-success'",
            )
            .execute(&pool)
            .await
            .is_err(),
            "partial content evidence must fail the database constraint"
        );

        // Bind 2 receives the recipient projection from MAM. The transient
        // queue row is acknowledged without sending a second wire copy.
        let (outbound, mut receiver) = tokio::sync::mpsc::channel(1);
        let outbound = crate::outbound::OutboundSender::new(outbound);
        assert_eq!(
            db::deliver_bind2_offline(&pool, recipient_id, 30, &outbound, None)
                .await
                .unwrap(),
            0
        );
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(delivery_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );

        // A MAM write failure rolls back the origin identity, membership and
        // durable queue projection together.
        sqlx::query(
            "CREATE FUNCTION fail_invite_archive() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced invite archive failure'; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("CREATE TRIGGER fail_invite_archive BEFORE INSERT ON message_archive FOR EACH ROW EXECUTE FUNCTION fail_invite_archive()")
            .execute(&pool)
            .await
            .unwrap();
        let failure_delivery_id = Uuid::new_v4();
        let failure_archive_id = Uuid::new_v4();
        let failure_stanza = format!("<message from='{sender}' to='{failure_recipient}'/>");
        let failure_writes = [ArchiveWrite {
            id: failure_archive_id,
            owner_id: failure_recipient_id,
            peer_jid: &sender,
            stanza: &failure_stanza,
            encrypted: true,
            stanza_id: None,
        }];
        let failure_request = LocalMucInviteAdmission {
            local_actor_id: sender_id,
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &failure_recipient,
                value: "origin-invite-failure",
                payload: &failure_stanza,
            }),
            archives: &failure_writes,
            delivery_id: failure_delivery_id,
            recipient_id: failure_recipient_id,
            recipient_bare_jid: &failure_recipient,
            sender_jid: &sender,
            stanza: &failure_stanza,
            encrypted: true,
            mam_backed: true,
            room_id: failure_room.id,
            cluster_authority: None,
        };
        assert!(service
            .admit_local_muc_invite(&failure_request)
            .await
            .is_err());
        let failed_halves: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND user_id=$2),
                 (SELECT COUNT(*) FROM message_archive WHERE id=$3),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-invite-failure'),
                 (SELECT COUNT(*) FROM offline_messages WHERE id=$4)",
        )
        .bind(failure_room.id)
        .bind(failure_recipient_id)
        .bind(failure_archive_id)
        .bind(failure_delivery_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(failed_halves, (0, 0, 0, 0));
        sqlx::query("DROP TRIGGER fail_invite_archive ON message_archive")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION fail_invite_archive()")
            .execute(&pool)
            .await
            .unwrap();

        // Capacity rejection is typed for the stanza layer and leaves no MAM
        // or affiliation prefix committed.
        let quota_service = MessageService::new(
            pool.clone(),
            crate::abuse::test_personal_message_content_keyring(),
            "local.test",
            false,
            1,
            8_000_000,
            30,
        );
        sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed) VALUES($1,$2,$3,'<message/>',TRUE,FALSE)")
            .bind(Uuid::new_v4())
            .bind(quota_recipient_id)
            .bind(&sender)
            .execute(&pool)
            .await
            .unwrap();
        let quota_delivery_id = Uuid::new_v4();
        let quota_archive_id = Uuid::new_v4();
        let quota_stanza = format!("<message from='{sender}' to='{quota_recipient}'/>");
        let quota_writes = [ArchiveWrite {
            id: quota_archive_id,
            owner_id: quota_recipient_id,
            peer_jid: &sender,
            stanza: &quota_stanza,
            encrypted: true,
            stanza_id: None,
        }];
        let quota_request = LocalMucInviteAdmission {
            local_actor_id: sender_id,
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &quota_recipient,
                value: "origin-invite-quota",
                payload: &quota_stanza,
            }),
            archives: &quota_writes,
            delivery_id: quota_delivery_id,
            recipient_id: quota_recipient_id,
            recipient_bare_jid: &quota_recipient,
            sender_jid: &sender,
            stanza: &quota_stanza,
            encrypted: true,
            mam_backed: true,
            room_id: quota_room.id,
            cluster_authority: None,
        };
        assert_eq!(
            quota_service
                .admit_local_muc_invite(&quota_request)
                .await
                .unwrap(),
            DurableMucInviteOutcome::QuotaExceeded
        );
        let quota_halves: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND user_id=$2),
                 (SELECT COUNT(*) FROM message_archive WHERE id=$3),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-invite-quota'),
                 (SELECT COUNT(*) FROM offline_messages WHERE id=$4)",
        )
        .bind(quota_room.id)
        .bind(quota_recipient_id)
        .bind(quota_archive_id)
        .bind(quota_delivery_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(quota_halves, (0, 0, 0, 0));

        // A combined invite and an ordinary durable message for the same
        // account must complete under the shared lock ordering rather than
        // deadlocking while each holds a different prefix lock.
        let concurrent_invite_id = Uuid::new_v4();
        let concurrent_message_id = Uuid::new_v4();
        let concurrent_invite_archive = Uuid::new_v4();
        let concurrent_message_archive = Uuid::new_v4();
        let concurrent_invite_stanza =
            format!("<message from='{sender}' to='{concurrent_recipient}' id='invite'/>");
        let concurrent_message_stanza =
            format!("<message from='{sender}' to='{concurrent_recipient}' id='message'/>");
        let invite_writes = [ArchiveWrite {
            id: concurrent_invite_archive,
            owner_id: concurrent_recipient_id,
            peer_jid: &sender,
            stanza: &concurrent_invite_stanza,
            encrypted: true,
            stanza_id: None,
        }];
        let message_writes = [ArchiveWrite {
            id: concurrent_message_archive,
            owner_id: concurrent_recipient_id,
            peer_jid: &sender,
            stanza: &concurrent_message_stanza,
            encrypted: true,
            stanza_id: None,
        }];
        let concurrent_invite = LocalMucInviteAdmission {
            local_actor_id: sender_id,
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &concurrent_recipient,
                value: "origin-concurrent-invite",
                payload: &concurrent_invite_stanza,
            }),
            archives: &invite_writes,
            delivery_id: concurrent_invite_id,
            recipient_id: concurrent_recipient_id,
            recipient_bare_jid: &concurrent_recipient,
            sender_jid: &sender,
            stanza: &concurrent_invite_stanza,
            encrypted: true,
            mam_backed: true,
            room_id: concurrent_room.id,
            cluster_authority: None,
        };
        let concurrent_message = LocalMessageAdmission {
            local_actor_id: Some(sender_id),
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &concurrent_recipient,
                value: "origin-concurrent-message",
                payload: &concurrent_message_stanza,
            }),
            archives: &message_writes,
            delivery_id: concurrent_message_id,
            recipient_id: concurrent_recipient_id,
            recipient_bare_jid: &concurrent_recipient,
            sender_jid: &sender,
            stanza: &concurrent_message_stanza,
            encrypted: true,
            mam_backed: true,
        };
        let (invite_result, message_result) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                service.admit_local_muc_invite(&concurrent_invite),
                service.admit_local_message(&concurrent_message)
            )
        })
        .await
        .expect("invite and normal C2S admission deadlocked");
        assert!(matches!(
            invite_result.unwrap(),
            DurableMucInviteOutcome::Stored { .. }
        ));
        assert!(matches!(
            message_result.unwrap(),
            DurableAdmissionOutcome::Stored { .. }
        ));
        downgrade_personal_evidence(
            &pool,
            "origin-concurrent-message",
            &concurrent_message_stanza,
        )
        .await;
        assert_eq!(
            service
                .admit_local_message(&concurrent_message)
                .await
                .unwrap(),
            DurableAdmissionOutcome::Replay
        );
        assert_personal_evidence_is_keyed(&pool, "origin-concurrent-message").await;

        // The federated form uses the same personal identity transaction, but
        // projects recovery into S2S instead of the local offline queue.
        let remote_target = format!("invitee-{}@remote.test", &marker[..8]);
        let remote_stanza = format!(
            "<message from='{sender}' to='{remote_target}' id='remote-invite'><body>invite</body></message>"
        );
        let remote_archive_id = Uuid::new_v4();
        let remote_archive =
            format!("<message from='{sender}' to='{remote_target}'><body>invite</body></message>");
        let remote_writes = [ArchiveWrite {
            id: remote_archive_id,
            owner_id: sender_id,
            peer_jid: &remote_target,
            stanza: &remote_archive,
            encrypted: true,
            stanza_id: Some("remote-invite"),
        }];
        let outbox_policy = db::S2sOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 10_000,
            max_bytes: 64 * 1_048_576,
            max_per_domain: 10_000,
        };
        let remote_request = RemoteMucInviteAdmission {
            local_actor_id: sender_id,
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &remote_target,
                value: "origin-remote-invite",
                payload: &remote_stanza,
            }),
            archives: &remote_writes,
            room_id: room.id,
            invitee_bare_jid: &remote_target,
            target_domain: "remote.test",
            stanza: &remote_stanza,
            bounce_to: Some(&sender),
            outbox_policy: outbox_policy.into(),
            cluster_authority: None,
        };
        assert_eq!(
            service
                .admit_remote_muc_invite(&remote_request)
                .await
                .unwrap(),
            RemoteMucInviteAdmissionOutcome::Stored
        );
        let remote_halves: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 AND affiliation='member'),
                 (SELECT COUNT(*) FROM message_archive WHERE id=$3),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-remote-invite'),
                 (SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test')",
        )
        .bind(room.id)
        .bind(&remote_target)
        .bind(remote_archive_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remote_halves, (1, 1, 1, 1));
        downgrade_personal_evidence(&pool, "origin-remote-invite", &remote_stanza).await;
        assert_eq!(
            service
                .admit_remote_muc_invite(&remote_request)
                .await
                .unwrap(),
            RemoteMucInviteAdmissionOutcome::Replay
        );
        assert_personal_evidence_is_keyed(&pool, "origin-remote-invite").await;
        let remote_replay_counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM message_archive WHERE id=$1),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-remote-invite'),
                 (SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test')",
        )
        .bind(remote_archive_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remote_replay_counts, (1, 1, 1));

        let changed_remote_stanza = format!(
            "<message from='{sender}' to='{remote_target}' id='remote-invite'><body>changed</body></message>"
        );
        let changed_remote = RemoteMucInviteAdmission {
            local_actor_id: sender_id,
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &remote_target,
                value: "origin-remote-invite",
                payload: &changed_remote_stanza,
            }),
            archives: &remote_writes,
            room_id: room.id,
            invitee_bare_jid: &remote_target,
            target_domain: "remote.test",
            stanza: &changed_remote_stanza,
            bounce_to: Some(&sender),
            outbox_policy: outbox_policy.into(),
            cluster_authority: None,
        };
        assert_eq!(
            service
                .admit_remote_muc_invite(&changed_remote)
                .await
                .unwrap(),
            RemoteMucInviteAdmissionOutcome::Conflict
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );

        // Without an origin-id there is no protocol-safe exact-retry key.
        // Two identical sends are retained as two user actions instead of
        // being guessed into one message by a payload hash.
        let no_identity_target = format!("repeat-{}@repeat.remote.test", &marker[..8]);
        let no_identity_stanza = format!(
            "<message from='{sender}' to='{no_identity_target}'><body>same</body></message>"
        );
        let no_identity_request = RemoteMucInviteAdmission {
            local_actor_id: sender_id,
            identity: None,
            archives: &[],
            room_id: room.id,
            invitee_bare_jid: &no_identity_target,
            target_domain: "repeat.remote.test",
            stanza: &no_identity_stanza,
            bounce_to: Some(&sender),
            outbox_policy: outbox_policy.into(),
            cluster_authority: None,
        };
        for _ in 0..2 {
            assert_eq!(
                service
                    .admit_remote_muc_invite(&no_identity_request)
                    .await
                    .unwrap(),
                RemoteMucInviteAdmissionOutcome::Stored
            );
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='repeat.remote.test'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            2
        );

        // An outbox failure must not leave a sender MAM row, origin identity
        // or federated affiliation behind.
        sqlx::query(
            "CREATE FUNCTION fail_remote_invite_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced remote invite outbox failure'; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("CREATE TRIGGER fail_remote_invite_outbox BEFORE INSERT ON s2s_outbox FOR EACH ROW EXECUTE FUNCTION fail_remote_invite_outbox()")
            .execute(&pool)
            .await
            .unwrap();
        let failed_remote_target = format!("failed-{}@failure.remote.test", &marker[..8]);
        let failed_remote_stanza =
            format!("<message from='{sender}' to='{failed_remote_target}'/>");
        let failed_remote_archive_id = Uuid::new_v4();
        let failed_remote_writes = [ArchiveWrite {
            id: failed_remote_archive_id,
            owner_id: sender_id,
            peer_jid: &failed_remote_target,
            stanza: &failed_remote_stanza,
            encrypted: true,
            stanza_id: None,
        }];
        let failed_remote = RemoteMucInviteAdmission {
            local_actor_id: sender_id,
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &failed_remote_target,
                value: "origin-remote-failure",
                payload: &failed_remote_stanza,
            }),
            archives: &failed_remote_writes,
            room_id: room.id,
            invitee_bare_jid: &failed_remote_target,
            target_domain: "failure.remote.test",
            stanza: &failed_remote_stanza,
            bounce_to: Some(&sender),
            outbox_policy: outbox_policy.into(),
            cluster_authority: None,
        };
        assert!(service
            .admit_remote_muc_invite(&failed_remote)
            .await
            .is_err());
        let failed_remote_halves: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2),
                 (SELECT COUNT(*) FROM message_archive WHERE id=$3),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-remote-failure'),
                 (SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='failure.remote.test')",
        )
        .bind(room.id)
        .bind(&failed_remote_target)
        .bind(failed_remote_archive_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(failed_remote_halves, (0, 0, 0, 0));
        sqlx::query("DROP TRIGGER fail_remote_invite_outbox ON s2s_outbox")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION fail_remote_invite_outbox()")
            .execute(&pool)
            .await
            .unwrap();

        // Both the legacy repository admission and the combined personal
        // admission acquire outbox before room, so concurrent calls cannot
        // deadlock by holding opposite prefixes.
        let concurrent_remote_stanza =
            format!("<message from='{sender}' to='{remote_target}' id='combined-concurrent'/>",);
        let legacy_remote_stanza =
            format!("<message from='{sender}' to='{remote_target}' id='legacy-concurrent'/>",);
        let concurrent_remote_archive_id = Uuid::new_v4();
        let concurrent_remote_writes = [ArchiveWrite {
            id: concurrent_remote_archive_id,
            owner_id: sender_id,
            peer_jid: &remote_target,
            stanza: &concurrent_remote_stanza,
            encrypted: true,
            stanza_id: None,
        }];
        let concurrent_remote = RemoteMucInviteAdmission {
            local_actor_id: sender_id,
            identity: Some(MessageIdentity {
                actor_scope_raw: &sender,
                actor_scope: &sender,
                target_scope: &remote_target,
                value: "origin-remote-concurrent",
                payload: &concurrent_remote_stanza,
            }),
            archives: &concurrent_remote_writes,
            room_id: room.id,
            invitee_bare_jid: &remote_target,
            target_domain: "remote.test",
            stanza: &concurrent_remote_stanza,
            bounce_to: Some(&sender),
            outbox_policy: outbox_policy.into(),
            cluster_authority: None,
        };
        let (combined_remote_result, legacy_remote_result) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    service.admit_remote_muc_invite(&concurrent_remote),
                    db::admit_federated_muc_invite(
                        &pool,
                        room.id,
                        &remote_target,
                        "remote.test",
                        &legacy_remote_stanza,
                        Some(&sender),
                        outbox_policy,
                        None,
                    )
                )
            })
            .await
            .expect("combined and legacy federated invite admission deadlocked");
        assert_eq!(
            combined_remote_result.unwrap(),
            RemoteMucInviteAdmissionOutcome::Stored
        );
        assert!(legacy_remote_result.unwrap());

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
