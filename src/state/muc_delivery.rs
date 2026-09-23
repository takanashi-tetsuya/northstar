//! Purpose-limited MUC delivery: privacy, SM handoff, federation, and exact endpoints.

use super::{
    muc_actor_identity_matches, session_entries_for_in, AppState, JoinedMucMembership, MucOccupant,
    MucOccupantEndpoint, OnlineSession, SuspendedMucEndpoint, SuspendedMucPhase, SuspendedMucRoute,
    SuspendedMucStanza,
};
use crate::{
    db,
    db::muc_delivery_repository::PostgresMucDeliveryRepository,
    s2s::FederationRouter,
    services::{
        cluster_muc_receipt_claim::ClusterMucReceiptClaimService,
        muc_delivery::MucDeliveryRepository,
    },
};
use dashmap::DashMap;
use std::{sync::Arc, time::Duration};

pub(crate) struct MucDeliveryContext {
    repository: PostgresMucDeliveryRepository,
    receipt_claim: ClusterMucReceiptClaimService<
        db::cluster_muc_receipt_claim_repository::PostgresClusterMucReceiptClaimRepository,
    >,
    local_domain: String,
    sessions: Arc<DashMap<String, OnlineSession>>,
    muc_occupants: Arc<DashMap<String, MucOccupant>>,
    suspended_muc_sessions: Arc<DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>>,
    sm_memory_governor: Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    sm_max_unacked_stanzas: usize,
    sm_max_unacked_bytes: usize,
    federation_outbox: FederationRouter,
    message_service:
        crate::services::messaging::MessageService<db::messaging::PostgresMessageRepository>,
}

impl AppState {
    pub(crate) fn muc_delivery_context(&self) -> MucDeliveryContext {
        MucDeliveryContext {
            repository: PostgresMucDeliveryRepository::new(self.pool.clone()),
            receipt_claim: ClusterMucReceiptClaimService::new(
                db::cluster_muc_receipt_claim_repository::PostgresClusterMucReceiptClaimRepository::new(
                    self.pool.clone(),
                ),
            ),
            local_domain: self.config.domain.clone(),
            sessions: Arc::clone(&self.sessions),
            muc_occupants: Arc::clone(&self.muc_occupants),
            suspended_muc_sessions: Arc::clone(&self.suspended_muc_sessions),
            sm_memory_governor: Arc::clone(&self.sm_memory_governor),
            sm_max_unacked_stanzas: self.config.sm_max_unacked_stanzas,
            sm_max_unacked_bytes: self.config.sm_max_unacked_bytes,
            federation_outbox: self.federation_outbox.clone(),
            message_service: self.message_service.clone(),
        }
    }
}

impl MucDeliveryContext {
    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        session_entries_for_in(&self.sessions, jid)
            .into_iter()
            .map(|(_, session)| session)
            .collect()
    }

    async fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: db::PrivacyStanzaKind,
    ) -> anyhow::Result<bool> {
        let active = session
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.message_service
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                peer,
                kind,
            )
            .await
    }

    fn validated_local_muc_occupant(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        room_jid: &str,
        membership: &JoinedMucMembership,
    ) -> Option<MucOccupant> {
        if connection_id.is_nil() || membership.cluster_epoch.is_nil() {
            return None;
        }
        let full_jid = crate::jid::canonical_session_key(full_jid).ok()?;
        let room_jid = crate::jid::canonicalize_bare(room_jid).ok()?;
        let session = self.sessions.get(&full_jid)?;
        if session.connection_id != connection_id
            || !session
                .muc_memberships
                .get(&room_jid)
                .is_some_and(|current| current.value() == membership)
        {
            return None;
        }
        drop(session);
        let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &membership.nick);
        self.muc_occupants
            .get(&key)
            .filter(|occupant| {
                muc_actor_identity_matches(
                    occupant,
                    &full_jid,
                    connection_id,
                    &room_jid,
                    membership,
                )
            })
            .map(|occupant| occupant.value().clone())
    }

    pub(crate) async fn deliver_to_muc_occupant(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> bool {
        self.deliver_to_muc_occupant_inner(occupant, stanza, None, None)
            .await
    }

    /// Deliver one durable clustered policy event and wait until the endpoint
    /// owns it recoverably (SM/BOSH/suspended storage) or its socket write has
    /// completed. A successful `try_send` alone is deliberately insufficient.
    pub(crate) async fn deliver_to_muc_occupant_with_receipt(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        delivery: &db::ClusterMucOutboxDelivery,
    ) -> anyhow::Result<bool> {
        let (receipt, mut received) = tokio::sync::mpsc::unbounded_channel();
        let accepted = self
            .deliver_to_muc_occupant_inner(occupant, stanza, Some(receipt), None)
            .await;
        if !accepted {
            return Ok(false);
        }
        let mut renew = tokio::time::interval(Duration::from_secs(10));
        renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                result = received.recv() => return Ok(result.is_some()),
                _ = renew.tick() => {
                    self.receipt_claim.renew_exact(delivery, Duration::from_secs(30)).await?;
                }
            }
        }
    }

    pub(super) async fn deliver_to_muc_occupant_inner(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> bool {
        let senders = roxmltree::Document::parse(&stanza)
            .ok()
            .map(|document| {
                let root = document.root_element();
                let mut senders = root
                    .attribute("from")
                    .and_then(|sender| crate::jid::canonicalize(sender).ok())
                    .into_iter()
                    .collect::<Vec<_>>();
                if root.tag_name().name() == "presence" {
                    senders.extend(root.descendants().filter_map(|node| {
                        (node.is_element()
                            && node.tag_name().name() == "item"
                            && node.tag_name().namespace()
                                == Some("http://jabber.org/protocol/muc#user"))
                        .then(|| node.attribute("jid"))
                        .flatten()
                        .and_then(|jid| crate::jid::canonicalize(jid).ok())
                    }));
                }
                senders.sort_unstable();
                senders.dedup();
                senders
            })
            .unwrap_or_default();
        if !senders.is_empty() {
            let blocked = self
                .blocked_muc_recipient_accounts(std::slice::from_ref(occupant), &senders)
                .await;
            if crate::jid::canonical_bare_key(&occupant.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                return false;
            }
        }
        self.deliver_to_muc_occupant_unchecked_result_with_receipt(
            occupant,
            stanza,
            receipt,
            write_receipt,
        )
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(?error, "failed to deliver a MUC stanza");
            false
        })
    }

    /// Batch XEP-0191 filter for MUC fan-out. Database failure is fail-closed
    /// for local occupants so a transient outage cannot leak a blocked room or
    /// real sender; remote occupants remain the responsibility of their home
    /// server.
    pub(crate) async fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> std::collections::HashSet<String> {
        let occupant_jids = occupants
            .iter()
            .map(|occupant| occupant.full_jid.clone())
            .collect::<Vec<_>>();
        match self
            .repository
            .blocked_local_accounts(&self.local_domain, &occupant_jids, stanza_senders)
            .await
        {
            Ok(blocked) => blocked,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "failed MUC recipient blocklist lookup; denying local delivery"
                );
                occupant_jids
                    .iter()
                    .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
                    .filter(|jid| jid.domainpart() == self.local_domain.as_str())
                    .map(|jid| jid.bare())
                    .collect()
            }
        }
    }

    /// Use only after `blocked_muc_recipient_accounts` covered the exact
    /// visible and real senders for this fan-out batch.
    pub(crate) async fn deliver_to_muc_occupant_unchecked(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> bool {
        self.deliver_to_muc_occupant_unchecked_result(occupant, stanza)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(?error, "failed to deliver a MUC stanza");
                false
            })
    }

    pub(super) async fn deliver_to_muc_occupant_unchecked_result(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> anyhow::Result<bool> {
        self.deliver_to_muc_occupant_unchecked_result_with_receipt(occupant, stanza, None, None)
            .await
    }

    async fn deliver_to_muc_occupant_unchecked_result_with_receipt(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> anyhow::Result<bool> {
        // Installing the session gate precedes the per-room endpoint swaps.
        // Consulting it first makes that multi-entry transition atomic from
        // every delivery path's point of view and preserves one cross-room
        // FIFO from the first quiesced stanza onward.
        let session_gate = if matches!(
            &occupant.endpoint,
            MucOccupantEndpoint::Local(_) | MucOccupantEndpoint::Suspended(_)
        ) {
            let sm_session_id = occupant.sm_session_id.or_else(|| {
                self.sessions.get(&occupant.full_jid).and_then(|session| {
                    if session.connection_id != occupant.connection_id {
                        return None;
                    }
                    let sm_session_id = *session
                        .sm_session_id
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    sm_session_id
                })
            });
            sm_session_id.and_then(|sm_session_id| {
                self.suspended_muc_sessions
                    .get(&sm_session_id)
                    .map(|endpoint| Arc::clone(&endpoint))
            })
        } else {
            None
        };
        let privacy_peer_kind = roxmltree::Document::parse(&stanza)
            .ok()
            .and_then(|document| {
                let root = document.root_element();
                let kind = match root.tag_name().name() {
                    "message" => db::PrivacyStanzaKind::Message,
                    "iq" => db::PrivacyStanzaKind::Iq,
                    "presence" => db::PrivacyStanzaKind::PresenceIn,
                    _ => return None,
                };
                let peer = root
                    .attribute("from")
                    .and_then(|from| crate::jid::canonicalize(from).ok())?;
                Some((peer, kind))
            });
        if let Some((peer, kind)) = privacy_peer_kind.as_ref() {
            if let Some(suspended) = &session_gate {
                if self
                    .repository
                    .suspended_privacy_denies(suspended.sm_session_id, peer, *kind)
                    .await?
                    .unwrap_or(true)
                {
                    return Ok(false);
                }
            } else {
                match &occupant.endpoint {
                    MucOccupantEndpoint::Local(_) => {
                        let Some(session) =
                            self.sessions_for(&occupant.full_jid).into_iter().next()
                        else {
                            return Ok(false);
                        };
                        if !self.privacy_allows_session(&session, peer, *kind).await? {
                            return Ok(false);
                        }
                    }
                    MucOccupantEndpoint::Suspended(suspended) => {
                        if self
                            .repository
                            .suspended_privacy_denies(suspended.sm_session_id, peer, *kind)
                            .await?
                            .unwrap_or(true)
                        {
                            return Ok(false);
                        }
                    }
                    MucOccupantEndpoint::Federated { .. } => {}
                }
            }
        }
        if write_receipt.is_some() {
            let membership = JoinedMucMembership {
                nick: occupant.nick.clone(),
                cluster_epoch: occupant.cluster_epoch,
            };
            if self
                .validated_local_muc_occupant(
                    &occupant.full_jid,
                    occupant.connection_id,
                    &occupant.room_jid,
                    &membership,
                )
                .is_none()
            {
                return Ok(false);
            }
        }
        if let Some(suspended) = session_gate {
            return self
                .deliver_to_suspended_muc_endpoint(&suspended, stanza, receipt, write_receipt)
                .await;
        }
        match &occupant.endpoint {
            MucOccupantEndpoint::Local(sender) if write_receipt.is_some() => {
                let receipt = write_receipt.expect("write receipt was present");
                match sender.try_send_with_transport_write_receipt(stanza, receipt) {
                    Ok(()) => Ok(true),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        anyhow::bail!("local MUC shutdown recipient queue is full")
                    }
                }
            }
            MucOccupantEndpoint::Local(sender) => match receipt {
                Some(receipt) => match sender.try_send_with_transport_receipt(stanza, receipt) {
                    Ok(()) => Ok(true),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        anyhow::bail!("local MUC recipient queue is full")
                    }
                },
                None => match sender.try_send(stanza) {
                    Ok(()) => Ok(true),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        anyhow::bail!("local MUC recipient queue is full")
                    }
                },
            },
            MucOccupantEndpoint::Suspended(suspended) => {
                self.deliver_to_suspended_muc_endpoint(suspended, stanza, receipt, None)
                    .await
            }
            MucOccupantEndpoint::Federated {
                authenticated_domain,
                ..
            } => {
                anyhow::ensure!(
                    self.federation_outbox
                        .send(authenticated_domain, stanza, None)
                        .await,
                    "federation queue rejected MUC stanza"
                );
                if let Some(receipt) = receipt {
                    let _ = receipt.send(());
                }
                Ok(true)
            }
        }
    }

    async fn deliver_to_suspended_muc_endpoint(
        &self,
        suspended: &Arc<SuspendedMucEndpoint>,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> anyhow::Result<bool> {
        if let Some(receipt) = write_receipt {
            return suspended.try_send_live_write_notification(stanza, receipt);
        }
        let mut stanza = Some(stanza);
        let mut receipt = receipt;
        let volatile_source_id = uuid::Uuid::new_v4();
        loop {
            // Live delivery and Live->Transitioning use this exact synchronous
            // mutex. There is no check/send window in which cleanup can install
            // a fence behind an already-approved old transport write.
            let wait_for_route = {
                let route = suspended
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match &*route {
                    SuspendedMucRoute::Live(sender) => {
                        let stanza = stanza.take().expect("MUC delivery owns one stanza");
                        return match receipt.take() {
                            Some(receipt) => sender
                                .try_send_with_transport_receipt(stanza, receipt)
                                .map(|_| true)
                                .map_err(|error| {
                                    anyhow::anyhow!(
                                        "resuming MUC recipient queue rejected stanza: {error}"
                                    )
                                }),
                            None => match sender.try_send(stanza) {
                                Ok(()) => Ok(true),
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    anyhow::bail!("resuming MUC recipient queue is full")
                                }
                            },
                        };
                    }
                    SuspendedMucRoute::Transitioning => true,
                    SuspendedMucRoute::Suspended => false,
                }
            };
            if wait_for_route {
                // Transitioning is a synchronous critical section; yielding is
                // sufficient and avoids a lost-wakeup window around Notify.
                tokio::task::yield_now().await;
                continue;
            }

            let mut buffer = suspended.buffer.lock().await;
            match buffer.phase.clone() {
                SuspendedMucPhase::Dormant => {
                    // Commit publishes Dormant before switching the synchronous
                    // route to Live. Loop through the route fence once more.
                    drop(buffer);
                }
                SuspendedMucPhase::Collecting | SuspendedMucPhase::Resuming => {
                    anyhow::ensure!(
                        receipt.is_none(),
                        "cluster MUC outbox cannot transfer ownership to a volatile suspended buffer"
                    );
                    let stanza_ref = stanza.as_deref().expect("MUC delivery owns one stanza");
                    let next_bytes = buffer
                        .bytes
                        .checked_add(stanza_ref.len())
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC byte count overflow"))?;
                    let total_stanzas = buffer
                        .base_stanzas
                        .checked_add(buffer.stanzas.len() + 1)
                        .ok_or_else(|| {
                        anyhow::anyhow!("suspended MUC stanza count overflow")
                    })?;
                    let total_bytes = buffer
                        .base_bytes
                        .checked_add(next_bytes)
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC byte count overflow"))?;
                    anyhow::ensure!(
                        total_stanzas <= self.sm_max_unacked_stanzas
                            && total_bytes <= self.sm_max_unacked_bytes,
                        "suspended MUC recipient queue is unavailable or full"
                    );
                    let capacity = suspended
                        .sm_capacity
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone()
                        .ok_or_else(|| {
                            self.sm_memory_governor.mark_invariant_failure();
                            anyhow::anyhow!("suspended MUC route has no SM memory reservation")
                        })?;
                    let growth = std::mem::size_of::<SuspendedMucStanza>()
                        .checked_add(stanza_ref.len())
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC allocation overflow"))?;
                    capacity.try_grow_by(growth).map_err(|error| {
                        anyhow::anyhow!("suspended MUC memory admission rejected: {error}")
                    })?;
                    anyhow::ensure!(
                        buffer.enqueue_volatile(
                            stanza.take().expect("MUC delivery owns one stanza"),
                            self.sm_max_unacked_stanzas,
                            self.sm_max_unacked_bytes,
                        ),
                        "suspended MUC recipient queue is unavailable or full"
                    );
                    return Ok(true);
                }
                SuspendedMucPhase::Durable => {
                    // Keep the session-global endpoint mutex across the append.
                    // A resume claim cannot overtake this stanza, and every room
                    // shares the same SM sequence owner.
                    let stored = self
                        .repository
                        .append_suspended_stanza(
                            suspended.sm_session_id,
                            volatile_source_id,
                            stanza.as_deref().expect("MUC delivery owns one stanza"),
                            self.sm_max_unacked_stanzas,
                            self.sm_max_unacked_bytes,
                        )
                        .await?;
                    if stored {
                        stanza.take();
                        if let Some(receipt) = receipt.take() {
                            let _ = receipt.send(());
                        }
                    }
                    return Ok(stored);
                }
                SuspendedMucPhase::Waiting
                | SuspendedMucPhase::Reserved
                | SuspendedMucPhase::Committing
                | SuspendedMucPhase::CheckpointOwned
                | SuspendedMucPhase::Sealed => {
                    // These are ownership transitions, not delivery failures.
                    // Register the waiter while the phase mutex is still held
                    // so a concurrent notification cannot be missed.
                    let notified = suspended.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    drop(buffer);
                    notified.await;
                }
            }
        }
    }
}
