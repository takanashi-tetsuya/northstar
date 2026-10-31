//! Application boundary for durable resource binding and XEP-0198 ownership.

pub(crate) mod ownership;

use crate::services::authentication::publication::{CredentialInvocation, PreparedCredential};
use anyhow::Result;
use dashmap::mapref::entry::Entry;
use northstar_config::SmIpPolicy;
pub(crate) use northstar_session_core::finalization::{
    ActivatedSmSession, BindingFinalizationOutcome, SmResumeFinalizationCommit,
    SmResumeFinalizationOutcome, SmResumeFinalizationRequest,
};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Weak,
    },
};
use tokio::sync::watch;
use uuid::Uuid;

/// Application-layer proof that one already-authorized C2S lifecycle may
/// claim a cluster route. Protocol code never receives a database DTO.
pub(crate) use northstar_session_core::{SessionRouteClaimProof, SmMucMembership};

#[derive(Clone, Debug)]
pub(crate) struct SmSessionSnapshot {
    pub(crate) inbound_h: u32,
    pub(crate) outbound_h: u32,
    pub(crate) acked_h: u32,
    pub(crate) available: bool,
    pub(crate) carbons: bool,
    pub(crate) priority: i16,
    pub(crate) blocklist_requested: bool,
    pub(crate) roster_requested: bool,
    pub(crate) active_privacy_list: Option<String>,
    pub(crate) privacy_requested: bool,
    pub(crate) peer_ip: IpAddr,
    pub(crate) user_agent_id: Option<Uuid>,
    pub(crate) joined_rooms: Vec<SmMucMembership>,
    pub(crate) directed_presence: Vec<String>,
    pub(crate) last_presence: Option<String>,
    pub(crate) unacked: Vec<northstar_delivery_core::SmUnackedStanza>,
}

impl SmSessionSnapshot {
    /// Conservative logical resident size used by the process-local SM
    /// capacity authority. Count structural entries as well as UTF-8 payload
    /// bytes so thousands of short JIDs cannot bypass a byte-only limit.
    pub(crate) fn resident_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>();
        let mut add = |value: usize| {
            bytes = bytes.checked_add(value)?;
            Some(())
        };
        if let Some(value) = &self.active_privacy_list {
            add(value.len())?;
        }
        if let Some(value) = &self.last_presence {
            add(value.len())?;
        }
        add(self
            .joined_rooms
            .len()
            .checked_mul(std::mem::size_of::<SmMucMembership>())?)?;
        for membership in &self.joined_rooms {
            add(membership.room_jid.len())?;
            add(membership.nick.len())?;
        }
        add(self
            .directed_presence
            .len()
            .checked_mul(std::mem::size_of::<String>())?)?;
        for jid in &self.directed_presence {
            add(jid.len())?;
        }
        add(self
            .unacked
            .len()
            .checked_mul(std::mem::size_of::<northstar_delivery_core::SmUnackedStanza>())?)?;
        for stanza in &self.unacked {
            add(stanza.stanza.len())?;
        }
        Some(bytes)
    }
}

#[derive(Debug)]
pub(crate) struct SmResumeClaim {
    pub(crate) session_id: Uuid,
    pub(crate) claim_token: Uuid,
    pub(crate) claim_deadline: std::time::Instant,
    pub(crate) full_jid: String,
    pub(crate) resource: String,
    pub(crate) resume_timeout_seconds: u64,
    pub(crate) inbound_h: u32,
    pub(crate) acked_h: u32,
    pub(crate) available: bool,
    pub(crate) carbons: bool,
    pub(crate) priority: i16,
    pub(crate) blocklist_requested: bool,
    pub(crate) roster_requested: bool,
    pub(crate) active_privacy_list: Option<String>,
    pub(crate) privacy_requested: bool,
    pub(crate) user_agent_id: Option<Uuid>,
    pub(crate) joined_rooms: Vec<SmMucMembership>,
    pub(crate) directed_presence: Vec<String>,
    pub(crate) last_presence: Option<String>,
    pub(crate) unacked: Vec<northstar_delivery_core::SmUnackedStanza>,
}

impl SmResumeClaim {
    /// Exact process-resident charge for the materialized database claim.
    /// The pre-claim maximum reservation is shrunk to this value before any
    /// route is installed, so a concurrent resume cannot overcommit memory.
    pub(crate) fn resident_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>();
        let mut add = |value: usize| {
            bytes = bytes.checked_add(value)?;
            Some(())
        };
        add(self.full_jid.len())?;
        add(self.resource.len())?;
        if let Some(value) = &self.active_privacy_list {
            add(value.len())?;
        }
        if let Some(value) = &self.last_presence {
            add(value.len())?;
        }
        add(self
            .joined_rooms
            .len()
            .checked_mul(std::mem::size_of::<SmMucMembership>())?)?;
        for membership in &self.joined_rooms {
            add(membership.room_jid.len())?;
            add(membership.nick.len())?;
        }
        add(self
            .directed_presence
            .len()
            .checked_mul(std::mem::size_of::<String>())?)?;
        for jid in &self.directed_presence {
            add(jid.len())?;
        }
        add(self
            .unacked
            .len()
            .checked_mul(std::mem::size_of::<northstar_delivery_core::SmUnackedStanza>())?)?;
        for stanza in &self.unacked {
            add(stanza.stanza.len())?;
        }
        Some(bytes)
    }
}

pub(crate) struct SmSessionCreationRequest<'a> {
    pub token_hash: &'a [u8; 32],
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub full_jid: &'a str,
    pub resource: &'a str,
    pub server_domain: &'a str,
    pub connection_id: Uuid,
    pub snapshot: &'a SmSessionSnapshot,
    pub ttl_seconds: u64,
    pub live_lease_seconds: u64,
    pub max_per_account: usize,
    pub max_global: usize,
}

/// A committed source-capability rewrite which the protocol must apply to its
/// in-memory XEP-0198 FIFO before a later checkpoint or client acknowledgement.
/// C2S identities remain stable; only MIX hand-offs rotate their lease token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SmMixLeaseRotation {
    pub(crate) previous: northstar_delivery_core::MixDelivery,
    pub(crate) current: northstar_delivery_core::MixDelivery,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SmQueueOwnershipResolution {
    pub(crate) mix_rotations: Vec<SmMixLeaseRotation>,
}

impl SmQueueOwnershipResolution {
    pub(crate) fn resolve_source(
        &self,
        source: Option<northstar_delivery_core::TransportOwnershipSource>,
    ) -> Option<northstar_delivery_core::TransportOwnershipSource> {
        match source {
            Some(northstar_delivery_core::TransportOwnershipSource::Mix(previous)) => self
                .mix_rotations
                .iter()
                .find(|rotation| rotation.previous == previous)
                .map(|rotation| {
                    northstar_delivery_core::TransportOwnershipSource::Mix(rotation.current)
                })
                .or(Some(
                    northstar_delivery_core::TransportOwnershipSource::Mix(previous),
                )),
            other => other,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum SmSessionCreationOutcome {
    Created {
        id: Uuid,
        ownership: SmQueueOwnershipResolution,
    },
    CapacityExhausted,
}

#[derive(Clone, Debug)]
pub(crate) struct SmCheckpointOutcome {
    pub(crate) updated: bool,
    pub(crate) ownership: SmQueueOwnershipResolution,
}

pub(crate) struct SmResumeClaimRequest<'a> {
    pub token_hash: &'a [u8; 32],
    pub user_id: Uuid,
    pub peer_ip: IpAddr,
    pub user_agent_id: Option<Uuid>,
    pub ip_binding: &'a str,
    pub require_same_device: bool,
    pub claim_lease_seconds: u64,
}

#[derive(Debug)]
pub(crate) enum SmResumeClaimOutcome {
    Claimed(Box<SmResumeClaim>),
    Pending(SmResumePending),
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SmPendingReason {
    Live,
    Claim,
    LiveAndClaim,
}

/// Authoritative reason and wake boundary for a valid, but not yet claimable,
/// XEP-0198 resume epoch. These values are produced under the same row lock as
/// the claim decision; protocol code never guesses a retry interval.
#[derive(Clone, Debug)]
pub(crate) struct SmResumePending {
    pub(crate) session_id: Uuid,
    pub(crate) old_connection_id: Uuid,
    pub(crate) full_jid: String,
    pub(crate) state_version: i64,
    pub(crate) reason: SmPendingReason,
    pub(crate) retry_at: std::time::Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SmAuthorityStamp {
    state_version: i64,
    listener_generation: u64,
    /// Process-local edge counter for accepted notification hints. Unlike the
    /// untrusted NOTIFY payload's state version, this value is consumed once
    /// per authority probe and cannot leave a receiver permanently ahead of
    /// PostgreSQL.
    notification_sequence: u64,
}

/// One session-scoped notification receiver. A reconnect changes the same
/// stamp as a durable row transition, so a waiter has one lossless wake source
/// and always follows it with an authoritative claim probe.
pub(crate) struct SmAuthoritySubscription {
    receiver: watch::Receiver<SmAuthorityStamp>,
    session_id: Uuid,
    slot: Arc<SmAuthoritySlot>,
    broker: Weak<SmAuthorityBroker>,
}

impl SmAuthoritySubscription {
    pub(crate) fn probe_stamp(&self) -> SmAuthorityStamp {
        *self.receiver.borrow()
    }

    /// Consume every wake visible when an authoritative database probe
    /// completed. An edge which arrived after `before_probe` asks for at most
    /// one more probe, unless this probe's authoritative state version already
    /// identifies that exact notification. A retained or forged high version
    /// cannot spin the caller forever. `borrow_and_update` also makes
    /// `changed()` wait for a genuinely later edge.
    pub(crate) fn acknowledge_probe(
        &mut self,
        pending_state_version: i64,
        before_probe: SmAuthorityStamp,
    ) -> bool {
        let current = *self.receiver.borrow_and_update();
        let notification_changed =
            current.notification_sequence != before_probe.notification_sequence;
        let listener_changed = current.listener_generation != before_probe.listener_generation;
        let exact_notification_observed =
            notification_changed && current.state_version == pending_state_version;
        if notification_changed && !exact_notification_observed {
            // An old or forged version earns at most this one authoritative
            // read; it never becomes a durable fact or a sticky reprobe
            // condition. Equality is only an exact-event optimization: the
            // database version remains authoritative.
            tracing::trace!(
                notification_state_version = current.state_version,
                pending_state_version,
                "consumed an SM authority notification hint not observed by this probe"
            );
        }
        listener_changed || (notification_changed && !exact_notification_observed)
    }

    pub(crate) async fn changed(&mut self) {
        // A closed sender is also an authority-boundary transition: the
        // owning service is shutting down or being rebuilt, and the caller's
        // connection cancellation branch will decide whether it may continue.
        let _ = self.receiver.changed().await;
    }
}

impl Drop for SmAuthoritySubscription {
    fn drop(&mut self) {
        let Some(broker) = self.broker.upgrade() else {
            let previous = self.slot.participants.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0, "SM authority participant count underflow");
            return;
        };
        broker.release_participant(self.session_id, &self.slot);
    }
}

/// RAII ownership between incrementing the explicit participant count and
/// constructing the watch receiver. Test barriers and future fallible setup
/// cannot strand a zero-receiver slot in the broker if construction unwinds.
struct SmAuthorityParticipantRegistration {
    session_id: Uuid,
    slot: Option<Arc<SmAuthoritySlot>>,
    broker: Weak<SmAuthorityBroker>,
}

impl SmAuthorityParticipantRegistration {
    fn into_subscription(
        mut self,
        receiver: watch::Receiver<SmAuthorityStamp>,
    ) -> SmAuthoritySubscription {
        let slot = self
            .slot
            .take()
            .expect("SM authority participant registration was already consumed");
        SmAuthoritySubscription {
            receiver,
            session_id: self.session_id,
            slot,
            broker: self.broker.clone(),
        }
    }
}

impl Drop for SmAuthorityParticipantRegistration {
    fn drop(&mut self) {
        let Some(slot) = self.slot.take() else {
            return;
        };
        let Some(broker) = self.broker.upgrade() else {
            let previous = slot.participants.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0, "SM authority participant count underflow");
            return;
        };
        broker.release_participant(self.session_id, &slot);
    }
}

#[derive(Debug)]
struct SmAuthoritySlot {
    state: watch::Sender<SmAuthorityStamp>,
    participants: std::sync::atomic::AtomicUsize,
}

#[derive(Debug)]
pub(crate) struct SmAuthorityBroker {
    schema: String,
    listener_generation: AtomicU64,
    notification_sequence: AtomicU64,
    sessions: dashmap::DashMap<Uuid, Arc<SmAuthoritySlot>>,
}

impl SmAuthorityBroker {
    pub(crate) fn schema(&self) -> &str {
        &self.schema
    }
    pub(crate) fn accept_notification(&self, payload: &str) -> bool {
        if payload.len() > 256 {
            return false;
        }
        let Ok(event) = serde_json::from_str::<SmAuthorityNotification>(payload) else {
            return false;
        };
        if event.schema != self.schema || event.state_version <= 0 {
            return false;
        }
        self.publish_state(event.session_id, event.state_version);
        true
    }

    fn new(schema: String) -> Result<Arc<Self>> {
        anyhow::ensure!(
            !schema.is_empty() && schema.len() <= 63 && !schema.contains('\0'),
            "invalid PostgreSQL schema for SM authority listener"
        );
        Ok(Arc::new(Self {
            schema,
            listener_generation: AtomicU64::new(0),
            notification_sequence: AtomicU64::new(0),
            sessions: dashmap::DashMap::new(),
        }))
    }

    fn subscribe(self: &Arc<Self>, session_id: Uuid) -> SmAuthoritySubscription {
        self.subscribe_after_participant(session_id, || {})
    }

    fn subscribe_after_participant(
        self: &Arc<Self>,
        session_id: Uuid,
        after_participant: impl FnOnce(),
    ) -> SmAuthoritySubscription {
        let generation = self.listener_generation.load(Ordering::Acquire);
        let notification_sequence = self.notification_sequence.load(Ordering::Acquire);
        let slot = match self.sessions.entry(session_id) {
            Entry::Occupied(entry) => {
                entry.get().participants.fetch_add(1, Ordering::AcqRel);
                Arc::clone(entry.get())
            }
            Entry::Vacant(entry) => {
                let (state, _) = watch::channel(SmAuthorityStamp {
                    state_version: 0,
                    listener_generation: generation,
                    notification_sequence,
                });
                Arc::clone(&entry.insert(Arc::new(SmAuthoritySlot {
                    state,
                    participants: std::sync::atomic::AtomicUsize::new(1),
                })))
            }
        };
        let participant = SmAuthorityParticipantRegistration {
            session_id,
            slot: Some(Arc::clone(&slot)),
            broker: Arc::downgrade(self),
        };
        after_participant();
        let receiver = slot.state.subscribe();
        participant.into_subscription(receiver)
    }

    fn release_participant(&self, session_id: Uuid, slot: &Arc<SmAuthoritySlot>) {
        let previous = slot.participants.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "SM authority participant count underflow");
        if previous != 1 {
            return;
        }
        // Compare both Arc identity and the explicit participant count under
        // the entry lock. A new subscriber increments under that same lock
        // before it constructs its receiver, closing the clone-before-receiver
        // removal race.
        if let Entry::Occupied(entry) = self.sessions.entry(session_id) {
            if Arc::ptr_eq(entry.get(), slot) && slot.participants.load(Ordering::Acquire) == 0 {
                entry.remove();
            }
        };
    }

    fn publish_state(&self, session_id: Uuid, state_version: i64) {
        if state_version <= 0 {
            return;
        }
        let Some(slot) = self.sessions.get(&session_id) else {
            return;
        };
        let current = *slot.state.borrow();
        // Every delivery is a fresh one-shot edge, while the retained payload
        // is monotonic. The payload is not trusted for deduplication, so a
        // forged value cannot pre-play and suppress a later real notification;
        // retaining the maximum also prevents a forged lower value from
        // masking a real edge which was coalesced into this watch update.
        let notification_sequence = self
            .notification_sequence
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        slot.state.send_replace(SmAuthorityStamp {
            state_version: current.state_version.max(state_version),
            notification_sequence,
            ..current
        });
    }

    /// A listener start, transparent reconnect, or terminal receive error may
    /// have lost notifications. Advance a process-global generation and wake
    /// every actual waiter; the waiter immediately re-reads PostgreSQL.
    pub(crate) fn publish_listener_transition(&self) {
        let generation = self
            .listener_generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let mut unused = Vec::new();
        for entry in &self.sessions {
            if entry.participants.load(Ordering::Acquire) == 0 {
                unused.push(*entry.key());
                continue;
            }
            let current = *entry.state.borrow();
            entry.state.send_replace(SmAuthorityStamp {
                listener_generation: generation,
                ..current
            });
        }
        for session_id in unused {
            if let Entry::Occupied(entry) = self.sessions.entry(session_id) {
                if entry.get().participants.load(Ordering::Acquire) == 0 {
                    entry.remove();
                }
            }
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SmAuthorityNotification {
    schema: String,
    session_id: Uuid,
    state_version: i64,
}

fn same_device_binding_matches(
    stored: Option<Uuid>,
    requested: Option<Uuid>,
    require_same_device: bool,
) -> bool {
    !require_same_device
        || matches!((stored, requested), (Some(left), Some(right)) if left == right)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BindingReservationOutcome {
    Reserved,
    CredentialsExpired,
    Conflict,
    CapacityExhausted,
}

#[derive(Clone)]
pub(crate) struct SmService<R> {
    repository: R,
    authority: Arc<SmAuthorityBroker>,
}

pub(crate) trait SmRepository: Send + Sync {
    fn revoke_session(
        &self,
        session_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn create_session(
        &self,
        request: SmSessionCreationRequest<'_>,
    ) -> impl std::future::Future<Output = Result<SmSessionCreationOutcome>> + Send;
    fn claim_resume(
        &self,
        request: SmResumeClaimRequest<'_>,
        ip_policy: SmIpPolicy,
    ) -> impl std::future::Future<Output = Result<SmResumeClaimOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn checkpoint_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        snapshot: &SmSessionSnapshot,
        ttl_seconds: u64,
        live_lease_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
        observation: Option<&ownership::PreparedCheckpoint<'_>>,
    ) -> impl std::future::Future<Output = Result<SmCheckpointOutcome>> + Send;
    fn remove_live_muc_memberships(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        memberships: &[SmMucMembership],
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn checkpoint_and_acknowledge(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        snapshot: &SmSessionSnapshot,
        acknowledged: &[northstar_delivery_core::SmUnackedStanza],
        ttl_seconds: u64,
        live_lease_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
        observation: Option<&ownership::PreparedCheckpoint<'_>>,
    ) -> impl std::future::Future<Output = Result<SmCheckpointOutcome>> + Send;
    fn acknowledge_delivery_batch(
        &self,
        sources: &[northstar_delivery_core::TransportOwnershipSource],
        observation: Option<&ownership::PreparedBatch<'_>>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn reserve_binding(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
    ) -> impl std::future::Future<Output = Result<BindingReservationOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn finalize_binding(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
        device_id: Option<Uuid>,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
    ) -> impl std::future::Future<Output = Result<BindingFinalizationOutcome>> + Send;
    fn finalize_resume(
        &self,
        request: SmResumeFinalizationRequest<'_>,
    ) -> impl std::future::Future<Output = Result<SmResumeFinalizationOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn finalize_binding_observed(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
        device_id: Option<Uuid>,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
        invocation: &CredentialInvocation<'_>,
    ) -> impl std::future::Future<Output = Result<BindingFinalizationOutcome>> + Send;
    fn finalize_resume_observed(
        &self,
        request: SmResumeFinalizationRequest<'_>,
        invocation: &CredentialInvocation<'_>,
    ) -> impl std::future::Future<Output = Result<SmResumeFinalizationOutcome>> + Send;
    fn release_claim(
        &self,
        session_id: Uuid,
        claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn release_live_session(
        &self,
        connection_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn suspend_exact_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        snapshot: &SmSessionSnapshot,
        ttl_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

impl<R: SmRepository> SmService<R> {
    pub(crate) async fn revoke_session(&self, session_id: Uuid) -> Result<()> {
        self.repository.revoke_session(session_id).await
    }

    pub(crate) fn new(repository: R, schema: String) -> Result<Self> {
        Ok(Self {
            repository,
            authority: SmAuthorityBroker::new(schema)?,
        })
    }
    pub(crate) fn authority_broker(&self) -> Arc<SmAuthorityBroker> {
        Arc::clone(&self.authority)
    }
    pub(crate) fn subscribe_authority(&self, session_id: Uuid) -> SmAuthoritySubscription {
        self.authority.subscribe(session_id)
    }
    pub(crate) async fn create_session(
        &self,
        request: SmSessionCreationRequest<'_>,
    ) -> Result<SmSessionCreationOutcome> {
        self.repository.create_session(request).await
    }
    pub(crate) async fn claim_resume(
        &self,
        request: SmResumeClaimRequest<'_>,
    ) -> Result<SmResumeClaimOutcome> {
        let ip_policy = SmIpPolicy::parse(request.ip_binding)
            .ok_or_else(|| anyhow::anyhow!("invalid configured SM IP binding"))?;
        let requested_device = request.user_agent_id;
        let require_same_device = request.require_same_device;
        let outcome = self.repository.claim_resume(request, ip_policy).await?;
        if let SmResumeClaimOutcome::Claimed(claim) = &outcome {
            if !same_device_binding_matches(
                claim.user_agent_id,
                requested_device,
                require_same_device,
            ) {
                self.repository
                    .release_claim(claim.session_id, claim.claim_token)
                    .await?;
                return Ok(SmResumeClaimOutcome::Rejected);
            }
        }
        Ok(outcome)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn checkpoint_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        snapshot: &SmSessionSnapshot,
        ttl_seconds: u64,
        live_lease_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
        observation: Option<&ownership::PreparedCheckpoint<'_>>,
    ) -> Result<SmCheckpointOutcome> {
        self.repository
            .checkpoint_session(
                session_id,
                connection_id,
                snapshot,
                ttl_seconds,
                live_lease_seconds,
                max_stanzas,
                max_bytes,
                observation,
            )
            .await
    }
    pub(crate) async fn remove_live_muc_memberships(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        memberships: &[SmMucMembership],
    ) -> Result<bool> {
        self.repository
            .remove_live_muc_memberships(session_id, connection_id, memberships)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn checkpoint_and_acknowledge(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        snapshot: &SmSessionSnapshot,
        acknowledged: &[northstar_delivery_core::SmUnackedStanza],
        ttl_seconds: u64,
        live_lease_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
        observation: Option<&ownership::PreparedCheckpoint<'_>>,
    ) -> Result<SmCheckpointOutcome> {
        self.repository
            .checkpoint_and_acknowledge(
                session_id,
                connection_id,
                snapshot,
                acknowledged,
                ttl_seconds,
                live_lease_seconds,
                max_stanzas,
                max_bytes,
                observation,
            )
            .await
    }
    pub(crate) async fn acknowledge_delivery_batch(
        &self,
        sources: &[northstar_delivery_core::TransportOwnershipSource],
        observation: Option<&ownership::PreparedBatch<'_>>,
    ) -> Result<()> {
        self.repository
            .acknowledge_delivery_batch(sources, observation)
            .await
    }
    pub(crate) async fn reserve_binding(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
    ) -> Result<BindingReservationOutcome> {
        self.repository
            .reserve_binding(
                connection_id,
                user_id,
                expected_auth_generation,
                full_jid,
                lease_seconds,
            )
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_binding(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
        device_id: Option<Uuid>,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
    ) -> Result<BindingFinalizationOutcome> {
        self.repository
            .finalize_binding(
                connection_id,
                user_id,
                expected_auth_generation,
                full_jid,
                lease_seconds,
                device_id,
                fast_plan,
            )
            .await
    }
    pub(crate) async fn finalize_resume(
        &self,
        request: SmResumeFinalizationRequest<'_>,
    ) -> Result<SmResumeFinalizationOutcome> {
        self.repository.finalize_resume(request).await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_binding_observed(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
        device_id: Option<Uuid>,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
        prepared: Option<&PreparedCredential>,
    ) -> Result<BindingFinalizationOutcome> {
        let Some(prepared) = prepared else {
            return self
                .finalize_binding(
                    connection_id,
                    user_id,
                    expected_auth_generation,
                    full_jid,
                    lease_seconds,
                    device_id,
                    fast_plan,
                )
                .await;
        };
        let invocation = prepared.binding(
            connection_id,
            user_id,
            expected_auth_generation,
            full_jid,
            lease_seconds,
            device_id,
            fast_plan,
        )?;
        let result = self
            .repository
            .finalize_binding_observed(
                connection_id,
                user_id,
                expected_auth_generation,
                full_jid,
                lease_seconds,
                device_id,
                fast_plan,
                &invocation,
            )
            .await;
        invocation.binding_returned(&result);
        result
    }
    pub(crate) async fn finalize_resume_observed(
        &self,
        request: SmResumeFinalizationRequest<'_>,
        prepared: Option<&PreparedCredential>,
    ) -> Result<SmResumeFinalizationOutcome> {
        let Some(prepared) = prepared else {
            return self.finalize_resume(request).await;
        };
        let invocation = prepared.resume(&request)?;
        let result = self
            .repository
            .finalize_resume_observed(request, &invocation)
            .await;
        invocation.resume_returned(&result);
        result
    }
    pub(crate) async fn release_claim(&self, session_id: Uuid, claim_token: Uuid) -> Result<()> {
        self.repository.release_claim(session_id, claim_token).await
    }
    pub(crate) async fn release_live_session(&self, connection_id: Uuid) -> Result<bool> {
        self.repository.release_live_session(connection_id).await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn suspend_exact_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        snapshot: &SmSessionSnapshot,
        ttl_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> Result<bool> {
        self.repository
            .suspend_exact_session(
                session_id,
                connection_id,
                user_id,
                expected_auth_generation,
                snapshot,
                ttl_seconds,
                max_stanzas,
                max_bytes,
            )
            .await
    }
}

#[cfg(test)]
mod tests;
