//! Purpose-limited MUC delivery: privacy, SM handoff, federation, and exact endpoints.

use crate::local_routes::muc::{
    MucOccupant, MucOccupantEndpoint, SuspendedMucEndpoint, SuspendedMucPhase, SuspendedMucRoute,
    SuspendedMucStanza,
};
use crate::local_routes::muc_table::{
    validated_local_muc_occupant_in, with_local_muc_occupant_exact,
};
use crate::local_routes::session::OnlineSession;
use crate::local_routes::session_table::session_entries_for_in;
use dashmap::DashMap;
use northstar_federation_core::FederationRoute;
use northstar_room_application::cluster_muc_receipt_claim::ClusterMucReceiptClaimRepository;
use northstar_room_application::cluster_muc_receipt_claim::ClusterMucReceiptClaimService;
use northstar_room_application::muc_delivery::MucDeliveryRepository;
use northstar_room_application::room_delivery_policy::{
    PrivacyStanzaKind, RoomDeliveryPolicyQuery, RoomPolicyLiveSession, RoomPolicyRoute,
    RoomPolicySubject,
};
use northstar_room_core::ClusterMucOutboxDelivery;
use northstar_session_core::JoinedMucMembership;
use std::{sync::Arc, time::Duration};

mod room_policy;
use self::room_policy::stanza_policy_facts;

pub struct MucDeliveryContext<R, C, F> {
    pub repository: R,
    pub receipt_claim: ClusterMucReceiptClaimService<C>,
    pub local_domain: String,
    pub sessions: Arc<DashMap<String, OnlineSession>>,
    pub muc_occupants: Arc<DashMap<String, MucOccupant>>,
    pub suspended_muc_sessions: Arc<DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>>,
    pub sm_memory_governor: Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
    pub sm_max_unacked_stanzas: usize,
    pub sm_max_unacked_bytes: usize,
    pub federation_outbox: F,
}

impl<R, C, F> MucDeliveryContext<R, C, F>
where
    R: MucDeliveryRepository,
    C: ClusterMucReceiptClaimRepository<Delivery = ClusterMucOutboxDelivery>,
    F: FederationRoute,
{
    fn validated_local_muc_occupant(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        room_jid: &str,
        membership: &JoinedMucMembership,
    ) -> Option<MucOccupant> {
        validated_local_muc_occupant_in(
            &self.sessions,
            &self.muc_occupants,
            full_jid,
            connection_id,
            room_jid,
            membership,
        )
    }

    pub async fn deliver_to_muc_occupant(&self, occupant: &MucOccupant, stanza: String) -> bool {
        self.deliver_to_muc_occupant_inner(occupant, stanza, None, None)
            .await
    }

    /// Deliver an item already reserved against its exact outbox claim and wait until the endpoint
    /// owns it recoverably (SM/BOSH/suspended storage) or its socket write has
    /// completed. A successful `try_send` alone is deliberately insufficient.
    /// A federation receipt confirms durable enqueue, not deduplication of a retry.
    pub async fn deliver_reserved_muc_item_with_receipt(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        real_peer: Option<&str>,
        delivery: &ClusterMucOutboxDelivery,
    ) -> anyhow::Result<bool> {
        let (receipt, mut received) = tokio::sync::mpsc::unbounded_channel();
        let accepted = self
            .deliver_with_policy(occupant, stanza, (None, real_peer), Some(receipt), None)
            .await?;
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

    pub async fn deliver_to_muc_occupant_inner(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> bool {
        self.deliver_with_policy(occupant, stanza, (None, None), receipt, write_receipt)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(?error, "failed to deliver a MUC stanza");
                false
            })
    }

    /// Carry the server-known sender alongside the stanza without exposing it on the wire.
    pub async fn deliver_to_muc_occupant_from(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        visible_peer: Option<&str>,
        real_peer: Option<&str>,
    ) -> bool {
        self.deliver_with_policy(occupant, stanza, (visible_peer, real_peer), None, None)
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
    pub async fn blocked_muc_recipient_accounts(
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
                    .filter_map(|jid| northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok())
                    .filter(|jid| jid.domainpart() == self.local_domain.as_str())
                    .map(|jid| jid.bare())
                    .collect()
            }
        }
    }

    /// Compatibility entry point for callers that already supplied their block candidates.
    pub async fn deliver_to_muc_occupant_unchecked(
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

    pub async fn deliver_to_muc_occupant_unchecked_result(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> anyhow::Result<bool> {
        self.deliver_with_policy(occupant, stanza, (None, None), None, None)
            .await
    }

    async fn deliver_with_policy(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        peers: (Option<&str>, Option<&str>),
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
        let facts = stanza_policy_facts(&stanza);
        let mut policy_route = None;
        if let Some(facts) = &facts {
            if !matches!(&occupant.endpoint, MucOccupantEndpoint::Federated { .. }) {
                let live = session_entries_for_in(&self.sessions, &occupant.full_jid)
                    .into_iter()
                    .find(|(_, session)| session.connection_id == occupant.connection_id)
                    .map(|(_, session)| session);
                let suspended = session_gate.as_ref().or(match &occupant.endpoint {
                    MucOccupantEndpoint::Suspended(endpoint) => Some(endpoint),
                    _ => None,
                });
                let sm_id = suspended.and_then(|endpoint| {
                    let route = endpoint
                        .route
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    (!matches!(&*route, SuspendedMucRoute::Live(_)))
                        .then_some(endpoint.sm_session_id)
                });
                let route = if let Some(id) = sm_id {
                    RoomPolicyRoute {
                        account_id: live
                            .as_ref()
                            .map_or(uuid::Uuid::nil(), |session| session.user_id),
                        auth_generation: live.as_ref().map(|session| session.auth_generation),
                        subject: RoomPolicySubject::Suspended { id },
                    }
                } else if let Some(session) = &live {
                    session.room_policy_route()
                } else {
                    return Ok(false);
                };
                let decisions = self
                    .repository
                    .read_room_delivery_policies(&[RoomDeliveryPolicyQuery {
                        route,
                        visible_peer: peers.0.unwrap_or(&facts.visible_peer),
                        real_peer: peers.1.or(facts.real_peer.as_deref()),
                        kind: Some(facts.kind),
                        recipient_jid: &occupant.full_jid,
                    }])
                    .await?;
                if !matches!(decisions.as_slice(), [decision] if decision.allows()) {
                    return Ok(false);
                }
                if suspended.is_none()
                    && !self.live_policy_route_is_current(&occupant.full_jid, route)
                {
                    return Ok(false);
                }
                policy_route = Some((occupant.full_jid.as_str(), route));
            }
        }
        let stanza = if receipt.is_none()
            && write_receipt.is_none()
            && (peers.0.is_some()
                || facts
                    .as_ref()
                    .is_some_and(|facts| facts.kind == PrivacyStanzaKind::Iq))
        {
            let mut pending = Some(stanza);
            let exact = with_local_muc_occupant_exact(
                &self.muc_occupants,
                occupant.into(),
                |current| match (&current.endpoint, session_gate.is_some()) {
                    (MucOccupantEndpoint::Local(sender), false) => Some(try_send_muc(
                        sender,
                        pending.take().expect("MUC stanza not yet queued"),
                    )),
                    _ => None,
                },
            );
            match exact {
                None => return Ok(false),
                Some(Some(sent)) => return sent,
                Some(None)
                    if session_gate.is_none()
                        && matches!(&occupant.endpoint, MucOccupantEndpoint::Local(_)) =>
                {
                    return Ok(false);
                }
                Some(None) => pending.expect("MUC stanza not yet queued"),
            }
        } else {
            stanza
        };
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
                .deliver_to_suspended_muc_endpoint(
                    &suspended,
                    stanza,
                    receipt,
                    write_receipt,
                    policy_route,
                )
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
                None => try_send_muc(sender, stanza),
            },
            MucOccupantEndpoint::Suspended(suspended) => {
                self.deliver_to_suspended_muc_endpoint(
                    suspended,
                    stanza,
                    receipt,
                    None,
                    policy_route,
                )
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

    fn live_policy_route_is_current(&self, full_jid: &str, sampled: RoomPolicyRoute) -> bool {
        self.sessions.get(full_jid).is_some_and(|current| {
            current.routable.load(std::sync::atomic::Ordering::Acquire)
                && current.room_policy_route() == sampled
        })
    }

    async fn deliver_to_suspended_muc_endpoint(
        &self,
        suspended: &Arc<SuspendedMucEndpoint>,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        policy_route: Option<(&str, RoomPolicyRoute)>,
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
                if let Some((jid, sampled)) = policy_route {
                    let current = match (&*route, sampled.subject) {
                        (SuspendedMucRoute::Live(_), RoomPolicySubject::Connection { .. }) => {
                            self.live_policy_route_is_current(jid, sampled)
                        }
                        (
                            SuspendedMucRoute::Transitioning | SuspendedMucRoute::Suspended,
                            RoomPolicySubject::Suspended { id },
                        ) => id == suspended.sm_session_id,
                        _ => false,
                    };
                    if !current {
                        return Ok(false);
                    }
                }
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

fn try_send_muc(sender: &crate::outbound::OutboundSender, stanza: String) -> anyhow::Result<bool> {
    match sender.try_send(stanza) {
        Ok(()) => Ok(true),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            anyhow::bail!("local MUC recipient queue is full")
        }
    }
}
