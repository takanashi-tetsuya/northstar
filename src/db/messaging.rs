//! PostgreSQL transactions for personal messages and members-only invitations.

use crate::{
    cluster::{ClusterAdmission, DirectPostCommitMode, DirectSpoolEligibility},
    db,
    services::{messaging::*, muc::DurableMucInviteOutcome},
};
use anyhow::Result;
use northstar_abuse_application::guard::PersonalMessageContentKeyring;
use northstar_message_application::direct_commit::{DirectCommitObserver, DirectCommitRepository};
use northstar_message_application::PersonalMessageCommitRepository;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Copy)]
struct OfflineLimits {
    max_messages: i64,
    max_bytes: i64,
    ttl_days: i64,
}

#[derive(Clone)]
pub(crate) struct PostgresMessageRepository {
    pool: PgPool,
    content_identity: PersonalMessageContentKeyring,
    configured_domain: String,
    offline: OfflineLimits,
    cluster: Option<ClusterAdmission>,
}

impl PersonalMessageCommitRepository for PostgresMessageRepository {
    type Error = anyhow::Error;

    async fn commit<'a>(
        &'a self,
        request: &'a ValidatedPersonalMessage<'a>,
    ) -> Result<DurableAdmissionOutcome> {
        Ok(self
            .commit_with_mode(request, DirectSpoolEligibility::LiveOnly, None)
            .await?
            .commit)
    }
}

impl DirectCommitRepository for PostgresMessageRepository {
    type Error = anyhow::Error;
    async fn commit_direct<'a>(
        &'a self,
        request: &'a ValidatedPersonalMessage<'a>,
        eligibility: DirectSpoolEligibility,
        observer: Option<&'a dyn DirectCommitObserver>,
    ) -> Result<DirectPersonalMessageAdmission> {
        self.commit_with_mode(request, eligibility, observer).await
    }
}

impl PostgresMessageRepository {
    async fn commit_with_mode(
        &self,
        request: &ValidatedPersonalMessage<'_>,
        eligibility: DirectSpoolEligibility,
        observer: Option<&dyn DirectCommitObserver>,
    ) -> Result<DirectPersonalMessageAdmission> {
        let identity = request
            .identity
            .as_ref()
            .map(|identity| db_history_identity(&self.content_identity, identity))
            .transpose()?;
        let archives = persistence_archive_writes(request.archives);
        let (outcome, post_commit, post_commit_mode, live_claim_id) = match request.destination {
            PersonalMessageDestination::Federation(destination) => {
                anyhow::ensure!(
                    observer.is_none(),
                    "local direct observer cannot witness federation"
                );
                let outbox = db::PersonalS2sOutboxAdmission {
                    local_actor_id: destination.local_actor_id,
                    target_domain: destination.target_domain,
                    stanza: destination.stanza,
                    bounce_to: destination.bounce_to,
                    policy: db::S2sOutboxPolicy {
                        ttl_seconds: destination.limits.ttl_seconds,
                        max_rows: destination.limits.max_rows,
                        max_bytes: destination.limits.max_bytes,
                        max_per_domain: destination.limits.max_per_domain,
                    },
                };
                let (outcome, mode, live_claim_id) = self
                    .admit_direct_history(
                        &self.pool,
                        identity.as_ref(),
                        &archives,
                        Some(&outbox),
                        None,
                        (eligibility, None),
                    )
                    .await?;
                (
                    outcome,
                    MessagePostCommit::WakeFederationOutbox,
                    mode,
                    live_claim_id,
                )
            }
            PersonalMessageDestination::Local(destination) => {
                validate_local_recipient_authority_for_domain(
                    destination.recipient_bare_jid,
                    &self.configured_domain,
                )?;
                let target_full_jid = durable_target_full_jid(destination.stanza)?;
                let delivery = db::PersonalC2sDeliveryAdmission {
                    id: destination.delivery_id,
                    recipient_id: destination.recipient_id,
                    recipient_bare_jid: destination.recipient_bare_jid,
                    local_actor_id: request.local_actor_id,
                    sender_jid: destination.sender_jid,
                    stanza: destination.stanza,
                    target_full_jid: target_full_jid.as_deref(),
                    encrypted: destination.encrypted,
                    policy: offline_store_policy(self.offline, destination.mam_backed),
                };
                let (outcome, mode, live_claim_id) = self
                    .admit_direct_history(
                        &self.pool,
                        identity.as_ref(),
                        &archives,
                        None,
                        Some(&delivery),
                        (eligibility, observer),
                    )
                    .await?;
                (
                    outcome,
                    MessagePostCommit::RouteLocalDelivery {
                        delivery_id: destination.delivery_id,
                        recipient_id: destination.recipient_id,
                    },
                    mode,
                    live_claim_id,
                )
            }
        };
        Ok(DirectPersonalMessageAdmission {
            commit: map_history_outcome(outcome, request.writes_history(), post_commit)?,
            mode: post_commit_mode,
            live_claim_id,
        })
    }

    async fn admit_direct_history(
        &self,
        pool: &PgPool,
        identity: Option<&db::PersonalHistoryIdentity<'_>>,
        archives: &[db::PersonalArchiveWrite<'_>],
        outbox: Option<&db::PersonalS2sOutboxAdmission<'_>>,
        delivery: Option<&db::PersonalC2sDeliveryAdmission<'_>>,
        admission: (DirectSpoolEligibility, Option<&dyn DirectCommitObserver>),
    ) -> Result<(
        db::PersonalHistoryAdmission,
        DirectPostCommitMode,
        Option<Uuid>,
    )> {
        let (eligibility, observer) = admission;
        if let Some(observer) = observer {
            anyhow::ensure!(
                outbox.is_none(),
                "local direct observer cannot witness an outbox"
            );
            let delivery = delivery
                .ok_or_else(|| anyhow::anyhow!("local direct observer requires delivery"))?;
            return db::archive::admit_personal_history_observed_direct(
                pool,
                identity,
                archives,
                delivery,
                self.cluster.as_ref(),
                eligibility,
                observer,
            )
            .await;
        }
        let Some(cluster) = self.cluster.as_ref() else {
            // Standalone repository fixtures and single-node operation retain
            // the existing transaction behavior without a cluster fence.
            let outcome = match (outbox, delivery) {
                (Some(outbox), None) => {
                    db::admit_outbound_personal_history(pool, identity, archives, outbox).await?
                }
                (None, Some(delivery)) => {
                    db::admit_personal_history_and_c2s_delivery(pool, identity, archives, delivery)
                        .await?
                }
                _ => anyhow::bail!("personal message requires exactly one durable destination"),
            };
            return Ok((outcome, DirectPostCommitMode::Live, None));
        };
        db::admit_personal_history_with_direct_fence(
            pool,
            identity,
            archives,
            outbox,
            delivery,
            cluster,
            eligibility,
        )
        .await
    }

    async fn fence_live_invite(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<()> {
        if let Some(cluster) = self.cluster.as_ref() {
            if let Some(authority) =
                cluster.check_direct_eligibility(DirectSpoolEligibility::LiveOnly)?
            {
                db::fence_direct_message_authority_in_transaction(tx, authority).await?;
            }
        }
        Ok(())
    }

    /// Keep cluster health stable through the acknowledged commit. The final
    /// PostgreSQL fence runs after all invitation writes, including a replay
    /// that upgraded legacy identity evidence.
    async fn commit_live_invite(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        wake_delivery: Option<(Uuid, Uuid)>,
    ) -> Result<Option<Uuid>> {
        if let Some(cluster) = self.cluster.as_ref() {
            let (turn, authority) =
                cluster.begin_direct_commit_turn(DirectSpoolEligibility::LiveOnly)?;
            let mut live_claim_id = None;
            if let Some(authority) = authority {
                db::fence_direct_message_authority_in_transaction(&mut tx, authority).await?;
                if let Some((recipient_id, message_id)) = wake_delivery {
                    db::archive::reserve_cluster_live_delivery_in_transaction(
                        &mut tx,
                        recipient_id,
                        message_id,
                    )
                    .await?;
                    live_claim_id = Some(message_id);
                    db::direct_spool_wake_repository::record_direct_spool_wake_in_transaction(
                        &mut tx,
                        &authority.key_identity.xmpp_domain,
                        recipient_id,
                    )
                    .await?;
                }
            }
            tx.commit().await?;
            let _mode = turn.finish();
            Ok(live_claim_id)
        } else {
            tx.commit().await?;
            Ok(None)
        }
    }

    pub(crate) fn new(
        pool: PgPool,
        content_identity: PersonalMessageContentKeyring,
        configured_domain: impl Into<String>,
        max_messages: i64,
        max_bytes: i64,
        ttl_days: i64,
    ) -> Self {
        Self {
            pool,
            content_identity,
            configured_domain: configured_domain.into(),
            offline: OfflineLimits {
                max_messages,
                max_bytes,
                ttl_days,
            },
            cluster: None,
        }
    }

    pub(crate) fn with_cluster_admission(mut self, cluster: ClusterAdmission) -> Self {
        self.cluster = Some(cluster);
        self
    }
}

impl MessageRepository for PostgresMessageRepository {
    fn direct_mode(&self) -> DirectPostCommitMode {
        self.cluster
            .as_ref()
            .map_or(DirectPostCommitMode::Live, ClusterAdmission::direct_mode)
    }

    fn clustered_direct_admission_enabled(&self) -> bool {
        self.cluster
            .as_ref()
            .is_some_and(ClusterAdmission::is_enabled)
    }

    async fn release_live_direct_claim(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
        claim_id: Uuid,
    ) -> Result<bool> {
        db::archive::release_cluster_live_delivery_reservation_and_rearm(
            &self.pool,
            &self.configured_domain,
            recipient_id,
            message_id,
            claim_id,
        )
        .await
    }
    async fn authorize_outbound_message(
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
    async fn resolve_local_recipient(
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

    async fn default_recipient_privacy_denies(
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
    async fn privacy_allows_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
        active_privacy_list: Option<&str>,
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> Result<bool> {
        if active_privacy_list.is_some() {
            db::refresh_active_privacy_session(&self.pool, user_id, connection_id).await?;
        }
        Ok(!db::privacy_denies(&self.pool, user_id, active_privacy_list, peer, kind).await?)
    }

    async fn archive_allowed(&self, owner_id: Uuid, peer_jid: &str) -> Result<bool> {
        db::archive_allowed(&self.pool, owner_id, peer_jid).await
    }

    /// Atomically admit a local-room invitation addressed to a federated
    /// account. The sender's origin identity/MAM projection, S2S outbox and
    /// members-only affiliation share one transaction. Exact replay therefore
    /// cannot enqueue a second federation copy, while a changed payload with
    /// the same origin-id conflicts before any room mutation. Without a
    /// client-provided stable identity, byte-identical sends remain distinct:
    /// collapsing them by payload would discard legitimate repeated messages.
    async fn admit_remote_muc_invite(
        &self,
        request: &RemoteMucInviteAdmission<'_>,
    ) -> Result<RemoteMucInviteAdmissionOutcome> {
        let identity = request
            .identity
            .as_ref()
            .map(|identity| self.db_identity(identity))
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
        self.fence_live_invite(&mut transaction).await?;
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
            self.commit_live_invite(transaction, None).await?;
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
                self.commit_live_invite(transaction, None).await?;
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

    /// Commit a local members-only direct invitation as one state change.
    ///
    /// Lock ordering intentionally extends the ordinary durable message path:
    /// identity/archive -> global capacity -> recipient capacity -> room/user.
    /// No room lock is held while waiting for a capacity lock, so the legacy
    /// global -> recipient -> room invite path cannot form a cycle with this
    /// transaction.
    async fn admit_local_muc_invite(
        &self,
        request: &LocalMucInviteAdmission<'_>,
    ) -> Result<DurableMucInviteOutcome> {
        self.validate_local_recipient_authority(request.recipient_bare_jid)?;
        let identity = request
            .identity
            .as_ref()
            .map(|identity| self.db_identity(identity))
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
        if self.cluster.is_some() {
            db::cluster_keys::lock_direct_spool_instance_claims_in_transaction(&mut transaction)
                .await?;
        }
        self.fence_live_invite(&mut transaction).await?;
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
            self.commit_live_invite(transaction, None).await?;
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
                let live_claim_id = self
                    .commit_live_invite(
                        transaction,
                        Some((request.recipient_id, request.delivery_id)),
                    )
                    .await?;
                return Ok(DurableMucInviteOutcome::Stored {
                    id: request.delivery_id,
                    affiliation_changed: matches!(
                        affiliation,
                        db::DurableMucInviteOutcome::Stored {
                            affiliation_changed: true,
                            ..
                        }
                    ),
                    live_claim_id,
                });
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

    async fn admit_history(&self, writes: &[ArchiveWrite<'_>]) -> Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
        let writes = persistence_archive_writes(writes);
        if let Some(cluster) = self.cluster.as_ref() {
            db::admit_personal_history_with_direct_fence(
                &self.pool,
                None,
                &writes,
                None,
                None,
                cluster,
                DirectSpoolEligibility::LiveOnly,
            )
            .await
            .map(|_| ())
        } else {
            db::admit_personal_history(&self.pool, None, &writes)
                .await
                .map(|_| ())
        }
    }

    async fn store_offline(
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
        match db::store_offline_idempotent_for_recipient_with_direct_fence(
            &self.pool,
            recipient_id,
            recipient_bare_jid,
            sender_jid,
            stanza,
            encrypted,
            self.offline_policy(mam_backed),
            identity,
            self.cluster.as_ref(),
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
}

impl PostgresMessageRepository {
    /// Bind every local durable projection to this server's configured XMPP
    /// authority before the repository checks the recipient UUID/localpart.
    /// Keeping the configured domain in the repository prevents a caller from
    /// smuggling an otherwise well-formed `username@other-domain` target into
    /// the local replay queue.
    fn validate_local_recipient_authority(&self, recipient_bare_jid: &str) -> Result<()> {
        validate_local_recipient_authority_for_domain(recipient_bare_jid, &self.configured_domain)
    }

    fn offline_policy(&self, mam_backed: bool) -> db::OfflineStorePolicy {
        offline_store_policy(self.offline, mam_backed)
    }

    fn db_identity<'a>(
        &self,
        identity: &'a MessageIdentity<'a>,
    ) -> Result<db::PersonalHistoryIdentity<'a>> {
        db_history_identity(&self.content_identity, identity)
    }
}

fn offline_store_policy(limits: OfflineLimits, mam_backed: bool) -> db::OfflineStorePolicy {
    db::OfflineStorePolicy {
        max_messages: limits.max_messages,
        max_bytes: limits.max_bytes,
        ttl_days: limits.ttl_days,
        mam_backed,
    }
}

fn db_history_identity<'a>(
    content_identity: &PersonalMessageContentKeyring,
    identity: &'a MessageIdentity<'a>,
) -> Result<db::PersonalHistoryIdentity<'a>> {
    anyhow::ensure!(
        !identity.payload.is_empty() && identity.payload.len() <= 1_048_576,
        "personal history payload must contain 1 byte to 1 MiB"
    );
    let kind = identity.authority.persistence_kind();
    let commitment = personal_message_commitment(kind, identity);
    Ok(db::PersonalHistoryIdentity {
        kind,
        actor_scope_raw: identity.actor_scope_raw,
        actor_scope: identity.actor_scope,
        target_scope: identity.target_scope,
        identity_value: identity.value,
        payload_authenticators: content_identity.authenticators(&commitment),
        legacy_payload_digest: Sha256::digest(identity.payload.as_bytes()).into(),
    })
}

fn validate_local_recipient_authority_for_domain(
    recipient_bare_jid: &str,
    configured_domain: &str,
) -> Result<()> {
    let recipient = northstar_xmpp_types::jid::CanonicalJid::parse_bare(recipient_bare_jid)?;
    let configured_domain = northstar_xmpp_types::jid::prepare_domainpart(configured_domain)?;
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
            let target = northstar_xmpp_types::jid::CanonicalJid::parse(to)?;
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
    post_commit: MessagePostCommit,
) -> Result<DurableAdmissionOutcome> {
    Ok(match outcome {
        db::PersonalHistoryAdmission::Stored(_) => DurableAdmissionOutcome::Stored {
            archive_written,
            post_commit,
        },
        db::PersonalHistoryAdmission::Replay(_) => DurableAdmissionOutcome::Replay,
        db::PersonalHistoryAdmission::AccountUnavailable => {
            DurableAdmissionOutcome::AccountUnavailable
        }
    })
}

#[cfg(test)]
mod tests;
