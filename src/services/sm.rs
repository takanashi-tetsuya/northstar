//! Application boundary for durable resource binding and XEP-0198 ownership.

use anyhow::Result;
use dashmap::mapref::entry::Entry;
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
    pub(crate) unacked: Vec<crate::outbound::SmUnackedStanza>,
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
            .checked_mul(std::mem::size_of::<crate::outbound::SmUnackedStanza>())?)?;
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
    pub(crate) unacked: Vec<crate::outbound::SmUnackedStanza>,
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
            .checked_mul(std::mem::size_of::<crate::outbound::SmUnackedStanza>())?)?;
        for stanza in &self.unacked {
            add(stanza.stanza.len())?;
        }
        Some(bytes)
    }
}

#[derive(Debug)]
pub(crate) struct ActivatedSmSession {
    pub(crate) outbound_h: u32,
    pub(crate) unacked: Vec<crate::outbound::SmUnackedStanza>,
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
    pub(crate) previous: crate::outbound::MixDelivery,
    pub(crate) current: crate::outbound::MixDelivery,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SmQueueOwnershipResolution {
    pub(crate) mix_rotations: Vec<SmMixLeaseRotation>,
}

impl SmQueueOwnershipResolution {
    pub(crate) fn resolve_source(
        &self,
        source: Option<crate::outbound::TransportOwnershipSource>,
    ) -> Option<crate::outbound::TransportOwnershipSource> {
        match source {
            Some(crate::outbound::TransportOwnershipSource::Mix(previous)) => self
                .mix_rotations
                .iter()
                .find(|rotation| rotation.previous == previous)
                .map(|rotation| crate::outbound::TransportOwnershipSource::Mix(rotation.current))
                .or(Some(crate::outbound::TransportOwnershipSource::Mix(
                    previous,
                ))),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmIpPolicy {
    None,
    Exact,
    Subnet,
}

impl SmIpPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "exact" => Some(Self::Exact),
            "subnet" => Some(Self::Subnet),
            _ => None,
        }
    }
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

#[derive(Debug)]
pub(crate) enum BindingFinalizationOutcome {
    Committed {
        receipt: crate::services::authentication::CredentialCommitReceipt,
    },
    CredentialsExpired,
    ReservationLost,
}

pub(crate) struct SmResumeFinalizationRequest<'a> {
    pub session_id: Uuid,
    pub claim_token: Uuid,
    pub connection_id: Uuid,
    pub user_id: Uuid,
    pub expected_auth_generation: i64,
    pub client_h: u32,
    pub acknowledged_count: usize,
    pub peer_ip: IpAddr,
    pub user_agent_id: Option<Uuid>,
    pub active_privacy_list: Option<&'a str>,
    pub ttl_seconds: u64,
    pub live_lease_seconds: u64,
    pub max_stanzas: usize,
    pub max_bytes: usize,
    pub fast_plan: Option<&'a crate::services::authentication::FastCommitPlan>,
}

#[derive(Debug)]
pub(crate) struct SmResumeFinalizationCommit {
    pub(crate) activated: ActivatedSmSession,
    pub(crate) receipt: crate::services::authentication::CredentialCommitReceipt,
}

#[derive(Debug)]
pub(crate) enum SmResumeFinalizationOutcome {
    Committed(Box<SmResumeFinalizationCommit>),
    CredentialsExpired,
    ClaimLost,
    PrivacySelectionMissing,
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
        acknowledged: &[crate::outbound::SmUnackedStanza],
        ttl_seconds: u64,
        live_lease_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<SmCheckpointOutcome>> + Send;
    fn acknowledge_delivery_batch(
        &self,
        sources: &[crate::outbound::TransportOwnershipSource],
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
        acknowledged: &[crate::outbound::SmUnackedStanza],
        ttl_seconds: u64,
        live_lease_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
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
            )
            .await
    }
    pub(crate) async fn acknowledge_delivery_batch(
        &self,
        sources: &[crate::outbound::TransportOwnershipSource],
    ) -> Result<()> {
        self.repository.acknowledge_delivery_batch(sources).await
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
mod tests {
    use super::{
        same_device_binding_matches, BindingFinalizationOutcome, BindingReservationOutcome,
        SmAuthorityBroker, SmAuthorityNotification, SmResumeFinalizationOutcome,
        SmResumeFinalizationRequest, SmService,
    };
    use crate::db::{self, DeploymentCapacityConfiguration, SmClaimStatus, SmSessionSnapshot};
    use anyhow::Result;
    use sqlx::postgres::PgPoolOptions;
    use std::{
        net::IpAddr,
        str::FromStr,
        sync::{Arc, Barrier},
        time::Duration,
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn authority_subscription_retains_state_and_reconnect_wakes() {
        let broker = SmAuthorityBroker::new("public".to_owned()).unwrap();
        let session_id = Uuid::new_v4();
        let mut subscription = broker.subscribe(session_id);
        let before = subscription.probe_stamp();
        broker.publish_state(session_id, 7);
        subscription.changed().await;
        assert!(subscription.acknowledge_probe(6, before));
        let after_probe = subscription.probe_stamp();
        assert!(!subscription.acknowledge_probe(7, after_probe));

        let before_reconnect = subscription.probe_stamp();
        broker.publish_listener_transition();
        subscription.changed().await;
        assert!(subscription.acknowledge_probe(7, before_reconnect));
        drop(subscription);
        assert!(broker.sessions.is_empty());
    }

    #[test]
    fn authority_notification_is_consumed_once_and_high_hint_cannot_stick() {
        let broker = SmAuthorityBroker::new("public".to_owned()).unwrap();
        let session_id = Uuid::new_v4();
        let mut subscription = broker.subscribe(session_id);

        let before_forged = subscription.probe_stamp();
        broker.publish_state(session_id, i64::MAX);
        assert!(subscription.acknowledge_probe(7, before_forged));
        let after_forged = subscription.probe_stamp();
        assert!(
            !subscription.acknowledge_probe(7, after_forged),
            "a retained high hint must not force another database probe"
        );

        // A later delivery with the same payload is still a fresh edge: an
        // attacker cannot pre-play a future state version and suppress its
        // real notification.
        let before_replayed = subscription.probe_stamp();
        broker.publish_state(session_id, i64::MAX);
        assert!(subscription.acknowledge_probe(7, before_replayed));

        // A later real version below the forged value is also a fresh edge.
        let before_real = subscription.probe_stamp();
        broker.publish_state(session_id, 8);
        assert!(subscription.acknowledge_probe(7, before_real));
        let after_real = subscription.probe_stamp();
        assert!(!subscription.acknowledge_probe(8, after_real));

        // A notification delivered during the probe needs no extra read when
        // the authoritative result identifies that exact event.
        let exact_session_id = Uuid::new_v4();
        let mut exact_subscription = broker.subscribe(exact_session_id);
        let before_exact = exact_subscription.probe_stamp();
        broker.publish_state(exact_session_id, 9);
        assert!(!exact_subscription.acknowledge_probe(9, before_exact));

        // A forged lower delivery cannot overwrite a coalesced real edge and
        // make a stale database result look exact.
        let masked_session_id = Uuid::new_v4();
        let mut masked_subscription = broker.subscribe(masked_session_id);
        let before_masked = masked_subscription.probe_stamp();
        broker.publish_state(masked_session_id, 8);
        broker.publish_state(masked_session_id, 7);
        assert!(masked_subscription.acknowledge_probe(7, before_masked));
    }

    #[tokio::test]
    async fn authority_participant_registration_closes_receiver_construction_race() {
        let broker = SmAuthorityBroker::new("public".to_owned()).unwrap();
        let session_id = Uuid::new_v4();
        let old = broker.subscribe(session_id);
        let participant_registered = Arc::new(Barrier::new(2));
        let construct_receiver = Arc::new(Barrier::new(2));
        let task = {
            let broker = Arc::clone(&broker);
            let participant_registered = Arc::clone(&participant_registered);
            let construct_receiver = Arc::clone(&construct_receiver);
            std::thread::spawn(move || {
                broker.subscribe_after_participant(session_id, || {
                    participant_registered.wait();
                    construct_receiver.wait();
                })
            })
        };
        participant_registered.wait();
        drop(old);
        assert!(broker.sessions.contains_key(&session_id));
        construct_receiver.wait();
        let mut replacement = task.join().unwrap();
        broker.publish_state(session_id, 9);
        replacement.changed().await;
        assert!(replacement.acknowledge_probe(8, Default::default()));
        drop(replacement);
        assert!(broker.sessions.is_empty());
    }

    #[test]
    fn authority_participant_registration_unwinds_without_leaking_a_slot() {
        let broker = SmAuthorityBroker::new("public".to_owned()).unwrap();
        let session_id = Uuid::new_v4();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let broker = Arc::clone(&broker);
            move || {
                let _ = broker.subscribe_after_participant(session_id, || {
                    panic!("controlled receiver-construction interruption");
                });
            }
        }));
        assert!(result.is_err());
        assert!(broker.sessions.is_empty());
    }

    #[test]
    fn authority_notification_payload_is_minimal_and_schema_scoped() {
        let session_id = Uuid::new_v4();
        let accepted =
            format!(r#"{{"schema":"tenant_a","session_id":"{session_id}","state_version":8}}"#);
        let event: SmAuthorityNotification = serde_json::from_str(&accepted).unwrap();
        assert_eq!(event.schema, "tenant_a");
        assert_eq!(event.session_id, session_id);
        assert_eq!(event.state_version, 8);
        let broker = SmAuthorityBroker::new("tenant_a".to_owned()).unwrap();
        let mut subscription = broker.subscribe(session_id);
        for invalid in [
            accepted.replace("tenant_a", "tenant_b"),
            accepted.replace(":8", ":0"),
            accepted.replace(":8", ":-1"),
            accepted.replace('}', ",\"extra\":true}"),
            "x".repeat(257),
            "not JSON".to_owned(),
        ] {
            assert!(!broker.accept_notification(&invalid));
            assert!(!subscription.acknowledge_probe(7, Default::default()));
        }
        let before = subscription.probe_stamp();
        assert!(broker.accept_notification(&accepted));
        assert!(subscription.acknowledge_probe(7, before));
        assert!(serde_json::from_str::<SmAuthorityNotification>(&format!(
            r#"{{"schema":"tenant_a","session_id":"{session_id}","state_version":8,"full_jid":"secret@example.test/resource"}}"#
        ))
        .is_err());
    }

    #[test]
    fn strict_same_device_precheck_rejects_every_unprovable_binding() {
        let device = Uuid::new_v4();
        assert!(same_device_binding_matches(
            Some(device),
            Some(device),
            true
        ));
        assert!(!same_device_binding_matches(None, Some(device), true));
        assert!(!same_device_binding_matches(Some(device), None, true));
        assert!(!same_device_binding_matches(
            Some(device),
            Some(Uuid::new_v4()),
            true
        ));
        // Compatibility is an explicit operator choice, not an implicit
        // exception inside strict mode.
        assert!(same_device_binding_matches(None, None, false));
        assert!(same_device_binding_matches(None, Some(device), false));
    }

    struct ResumeRepository {
        device: Uuid,
        session: Uuid,
        token: Uuid,
        fail_release: bool,
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    impl super::SmRepository for ResumeRepository {
        async fn revoke_session(&self, _: Uuid) -> anyhow::Result<()> {
            unreachable!()
        }

        async fn claim_resume(
            &self,
            _request: super::SmResumeClaimRequest<'_>,
            policy: super::SmIpPolicy,
        ) -> anyhow::Result<super::SmResumeClaimOutcome> {
            assert_eq!(policy, super::SmIpPolicy::Exact);
            self.calls.lock().unwrap().push("claim");
            Ok(super::SmResumeClaimOutcome::Claimed(Box::new(
                super::SmResumeClaim {
                    session_id: self.session,
                    claim_token: self.token,
                    claim_deadline: std::time::Instant::now() + Duration::from_secs(10),
                    full_jid: "alice@example.test/phone".into(),
                    resource: "phone".into(),
                    resume_timeout_seconds: 30,
                    inbound_h: 0,
                    acked_h: 0,
                    available: false,
                    carbons: false,
                    priority: 0,
                    blocklist_requested: false,
                    roster_requested: false,
                    active_privacy_list: None,
                    privacy_requested: false,
                    user_agent_id: Some(self.device),
                    joined_rooms: vec![],
                    directed_presence: vec![],
                    last_presence: None,
                    unacked: vec![],
                },
            )))
        }
        async fn release_claim(&self, session: Uuid, token: Uuid) -> anyhow::Result<()> {
            assert_eq!((session, token), (self.session, self.token));
            self.calls.lock().unwrap().push("release");
            anyhow::ensure!(!self.fail_release, "release failed");
            Ok(())
        }
        async fn create_session(
            &self,
            _request: super::SmSessionCreationRequest<'_>,
        ) -> Result<super::SmSessionCreationOutcome> {
            panic!("unexpected persistence operation")
        }
        #[allow(clippy::too_many_arguments)]
        async fn checkpoint_session(
            &self,
            _session_id: Uuid,
            _connection_id: Uuid,
            _snapshot: &super::SmSessionSnapshot,
            _ttl_seconds: u64,
            _live_lease_seconds: u64,
            _max_stanzas: usize,
            _max_bytes: usize,
        ) -> Result<super::SmCheckpointOutcome> {
            panic!("unexpected persistence operation")
        }
        async fn remove_live_muc_memberships(
            &self,
            _session_id: Uuid,
            _connection_id: Uuid,
            _memberships: &[super::SmMucMembership],
        ) -> Result<bool> {
            panic!("unexpected persistence operation")
        }
        #[allow(clippy::too_many_arguments)]
        async fn checkpoint_and_acknowledge(
            &self,
            _session_id: Uuid,
            _connection_id: Uuid,
            _snapshot: &super::SmSessionSnapshot,
            _acknowledged: &[crate::outbound::SmUnackedStanza],
            _ttl_seconds: u64,
            _live_lease_seconds: u64,
            _max_stanzas: usize,
            _max_bytes: usize,
        ) -> Result<super::SmCheckpointOutcome> {
            panic!("unexpected persistence operation")
        }
        async fn acknowledge_delivery_batch(
            &self,
            _sources: &[crate::outbound::TransportOwnershipSource],
        ) -> Result<()> {
            panic!("unexpected persistence operation")
        }
        async fn reserve_binding(
            &self,
            _connection_id: Uuid,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _full_jid: &str,
            _lease_seconds: u64,
        ) -> Result<BindingReservationOutcome> {
            panic!("unexpected persistence operation")
        }
        #[allow(clippy::too_many_arguments)]
        async fn finalize_binding(
            &self,
            _connection_id: Uuid,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _full_jid: &str,
            _lease_seconds: u64,
            _device_id: Option<Uuid>,
            _fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
        ) -> Result<BindingFinalizationOutcome> {
            panic!("unexpected persistence operation")
        }
        async fn finalize_resume(
            &self,
            _request: SmResumeFinalizationRequest<'_>,
        ) -> Result<SmResumeFinalizationOutcome> {
            panic!("unexpected persistence operation")
        }
        async fn release_live_session(&self, _connection_id: Uuid) -> Result<bool> {
            panic!("unexpected persistence operation")
        }
        #[allow(clippy::too_many_arguments)]
        async fn suspend_exact_session(
            &self,
            _session_id: Uuid,
            _connection_id: Uuid,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _snapshot: &super::SmSessionSnapshot,
            _ttl_seconds: u64,
            _max_stanzas: usize,
            _max_bytes: usize,
        ) -> Result<bool> {
            panic!("unexpected persistence operation")
        }
    }

    #[tokio::test]
    async fn resume_policy_releases_only_the_exact_mismatched_claim() {
        let device = Uuid::new_v4();
        let requested_device = Uuid::new_v4();
        for fail_release in [false, true] {
            let service = SmService::new(
                ResumeRepository {
                    device,
                    session: Uuid::new_v4(),
                    token: Uuid::new_v4(),
                    fail_release,
                    calls: std::sync::Mutex::new(Vec::new()),
                },
                "public".into(),
            )
            .unwrap();
            let request = |user_agent_id, ip_binding| super::SmResumeClaimRequest {
                token_hash: &[7; 32],
                user_id: Uuid::new_v4(),
                peer_ip: "127.0.0.1".parse().unwrap(),
                user_agent_id,
                ip_binding,
                require_same_device: true,
                claim_lease_seconds: 10,
            };
            assert!(service
                .claim_resume(request(Some(device), "invalid"))
                .await
                .is_err());
            assert!(service.repository.calls.lock().unwrap().is_empty());
            assert!(matches!(
                service
                    .claim_resume(request(Some(device), "exact"))
                    .await
                    .unwrap(),
                super::SmResumeClaimOutcome::Claimed(_)
            ));
            assert_eq!(*service.repository.calls.lock().unwrap(), ["claim"]);
            service.repository.calls.lock().unwrap().clear();
            let result = service
                .claim_resume(request(Some(requested_device), "exact"))
                .await;
            if fail_release {
                assert!(
                    result.is_err(),
                    "failed release must not be reported as a clean rejection"
                );
            } else {
                assert!(matches!(
                    result.unwrap(),
                    super::SmResumeClaimOutcome::Rejected
                ));
            }
            assert_eq!(
                *service.repository.calls.lock().unwrap(),
                ["claim", "release"]
            );
        }
    }

    async fn migrated_pool(max_connections: u32) -> sqlx::PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        pool
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn binding_reservation_is_bounded_leased_and_rechecks_auth_generation() {
        let pool = migrated_pool(4).await;
        db::reconcile_deployment_capacity(
            &pool,
            DeploymentCapacityConfiguration {
                epoch: 1,
                accounts: 8,
                muc_rooms: 8,
                muc_rooms_per_owner: 4,
                live_sessions: 1,
                sessions_per_account: 1,
                resumable_sessions: 8,
            },
        )
        .await
        .unwrap();
        let user_id = Uuid::new_v4();
        let username = format!("smphase{}", user_id.simple());
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,auth_generation) VALUES($1,$2,'test',0)",
        )
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
        let schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&pool)
            .await
            .unwrap();
        let service = SmService::new(
            crate::db::sm_repository::PostgresSmRepository::new(
                pool.clone(),
                Arc::new(zeroize::Zeroizing::new(vec![7_u8; 32])),
            ),
            schema,
        )
        .unwrap();
        let first_connection = Uuid::new_v4();
        let first_jid = format!("{username}@example.test/first");
        assert_eq!(
            service
                .reserve_binding(first_connection, user_id, 0, &first_jid, 30)
                .await
                .unwrap(),
            BindingReservationOutcome::Reserved
        );
        let bounded_lease: bool = sqlx::query_scalar(
            "SELECT lease_until>clock_timestamp()+INTERVAL '20 seconds'
                    AND lease_until<=clock_timestamp()+INTERVAL '31 seconds'
               FROM deployment_session_leases WHERE connection_id=$1",
        )
        .bind(first_connection)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(bounded_lease);
        assert_eq!(
            service
                .reserve_binding(
                    Uuid::new_v4(),
                    user_id,
                    0,
                    &format!("{username}@example.test/second"),
                    30,
                )
                .await
                .unwrap(),
            BindingReservationOutcome::CapacityExhausted
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployment_session_leases")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );

        // Phase one has committed and released every DB guard. A credential
        // mutation therefore cannot be stalled by the caller pausing on a
        // Redis/cluster await between the two service calls.
        tokio::time::timeout(
            Duration::from_secs(1),
            sqlx::query("UPDATE users SET auth_generation=1 WHERE id=$1")
                .bind(user_id)
                .execute(&pool),
        )
        .await
        .expect("phase-one reservation retained a user-row lock")
        .unwrap();
        assert!(matches!(
            service
                .finalize_binding(first_connection, user_id, 0, &first_jid, 30, None, None,)
                .await
                .unwrap(),
            BindingFinalizationOutcome::CredentialsExpired
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_agent_login_epochs WHERE user_id=$1",
            )
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert!(service
            .release_live_session(first_connection)
            .await
            .unwrap());
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn sm_activation_and_privacy_selection_commit_or_roll_back_together() {
        let pool = migrated_pool(4).await;
        let user_id = Uuid::new_v4();
        let username = format!("smprivacy{}", user_id.simple());
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,auth_generation) VALUES($1,$2,'test',0)",
        )
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO privacy_lists(owner_id,name) VALUES($1,'resume-list')")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let peer_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let old_connection = Uuid::new_v4();
        let full_jid = format!("{username}@example.test/device");
        let snapshot = SmSessionSnapshot {
            inbound_h: 3,
            outbound_h: 4,
            acked_h: 4,
            available: true,
            carbons: true,
            priority: 0,
            blocklist_requested: true,
            roster_requested: true,
            active_privacy_list: Some("resume-list".to_owned()),
            privacy_requested: true,
            peer_ip,
            user_agent_id: None,
            joined_rooms: Vec::new(),
            directed_presence: Vec::new(),
            last_presence: None,
            unacked: Vec::new(),
        };
        let service_snapshot = super::SmSessionSnapshot::from(&snapshot);
        let token_hash = [19_u8; 32];
        let session_id = db::create_sm_session(
            &pool,
            &token_hash,
            user_id,
            0,
            &full_jid,
            "device",
            "example.test",
            old_connection,
            &snapshot,
            300,
            30,
            8,
            64,
        )
        .await
        .unwrap();
        assert!(db::suspend_sm_session(
            &pool,
            session_id,
            old_connection,
            &snapshot,
            300,
            64,
            65_536,
        )
        .await
        .unwrap());
        let claim = match db::claim_sm_session_status(
            &pool,
            &token_hash,
            user_id,
            peer_ip,
            None,
            db::SmIpPolicy::Exact,
            false,
            30,
        )
        .await
        .unwrap()
        {
            SmClaimStatus::Claimed(claim) => *claim,
            status => panic!("unexpected claim status: {status:?}"),
        };
        sqlx::query(
            "CREATE FUNCTION fail_sm_privacy_activation() RETURNS trigger
             LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced privacy failure'; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_sm_privacy_activation
             BEFORE INSERT OR UPDATE ON privacy_active_sessions
             FOR EACH ROW EXECUTE FUNCTION fail_sm_privacy_activation()",
        )
        .execute(&pool)
        .await
        .unwrap();
        let new_connection = Uuid::new_v4();
        let schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&pool)
            .await
            .unwrap();
        let service = SmService::new(
            crate::db::sm_repository::PostgresSmRepository::new(
                pool.clone(),
                Arc::new(zeroize::Zeroizing::new(vec![9_u8; 32])),
            ),
            schema,
        )
        .unwrap();
        let request = || SmResumeFinalizationRequest {
            session_id,
            claim_token: claim.claim_token,
            connection_id: new_connection,
            user_id,
            expected_auth_generation: 0,
            client_h: 4,
            acknowledged_count: 0,
            peer_ip,
            user_agent_id: None,
            active_privacy_list: Some("resume-list"),
            ttl_seconds: 300,
            live_lease_seconds: 30,
            max_stanzas: 64,
            max_bytes: 65_536,
            fast_plan: None,
        };
        assert!(service.finalize_resume(request()).await.is_err());
        let rolled_back: (Uuid, Option<Uuid>, bool) = sqlx::query_as(
            "SELECT connection_id,claim_token,resumable FROM sm_resume_sessions WHERE id=$1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rolled_back, (old_connection, Some(claim.claim_token), true));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM privacy_active_sessions WHERE owner_id=$1",
            )
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

        sqlx::query("DROP TRIGGER fail_sm_privacy_activation ON privacy_active_sessions")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION fail_sm_privacy_activation()")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            service.finalize_resume(request()).await.unwrap(),
            SmResumeFinalizationOutcome::Committed(_)
        ));
        let committed: (Uuid, Option<Uuid>, Option<String>) = sqlx::query_as(
            "SELECT s.connection_id,s.claim_token,p.list_name
               FROM sm_resume_sessions s
               LEFT JOIN privacy_active_sessions p
                 ON p.owner_id=s.user_id AND p.connection_id=s.connection_id
              WHERE s.id=$1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            committed,
            (new_connection, None, Some("resume-list".to_owned()))
        );
        assert!(!service
            .suspend_exact_session(
                session_id,
                Uuid::new_v4(),
                user_id,
                0,
                &service_snapshot,
                300,
                64,
                65_536,
            )
            .await
            .unwrap());
        sqlx::query("UPDATE users SET auth_generation=1 WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!service
            .suspend_exact_session(
                session_id,
                new_connection,
                user_id,
                0,
                &service_snapshot,
                300,
                64,
                65_536,
            )
            .await
            .unwrap());
        let revocation_won: (Uuid, bool) =
            sqlx::query_as("SELECT connection_id,resumable FROM sm_resume_sessions WHERE id=$1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(revocation_won, (new_connection, false));

        // Restore only the fixture's generation to exercise the successful
        // exact post-commit abort path. Production never decrements it.
        sqlx::query("UPDATE users SET auth_generation=0 WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(service
            .suspend_exact_session(
                session_id,
                new_connection,
                user_id,
                0,
                &service_snapshot,
                300,
                64,
                65_536,
            )
            .await
            .unwrap());
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT resumable FROM sm_resume_sessions WHERE id=$1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM privacy_active_sessions
                  WHERE owner_id=$1 AND connection_id=$2",
            )
            .bind(user_id)
            .bind(new_connection)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "exact suspension must atomically clear the live privacy selection"
        );
        assert!(
            service
                .suspend_exact_session(
                    session_id,
                    new_connection,
                    user_id,
                    0,
                    &service_snapshot,
                    300,
                    64,
                    65_536,
                )
                .await
                .unwrap(),
            "a lost COMMIT response must replay as the same exact suspension"
        );
        let volatile_source_id = Uuid::new_v4();
        let before: (i64, i64) = sqlx::query_as(
            "SELECT s.outbound_h, COUNT(q.position)
               FROM sm_resume_sessions s
               LEFT JOIN sm_resume_stanzas q ON q.session_id=s.id
              WHERE s.id=$1 GROUP BY s.outbound_h",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        for _ in 0..2 {
            assert!(db::append_suspended_sm_stanza(
                &pool,
                session_id,
                volatile_source_id,
                "<message id='ambiguous-commit'/>",
                64,
                65_536,
            )
            .await
            .unwrap());
        }
        let after: (i64, i64) = sqlx::query_as(
            "SELECT s.outbound_h, COUNT(q.position)
               FROM sm_resume_sessions s
               LEFT JOIN sm_resume_stanzas q ON q.session_id=s.id
              WHERE s.id=$1 GROUP BY s.outbound_h",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after, (before.0 + 1, before.1 + 1));
        db::revoke_sm_session(&pool, session_id).await.unwrap();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn resumable_binding_lease_transfers_only_after_transport_publication() {
        let pool = migrated_pool(4).await;
        db::reconcile_deployment_capacity(
            &pool,
            DeploymentCapacityConfiguration {
                epoch: 1,
                accounts: 8,
                muc_rooms: 8,
                muc_rooms_per_owner: 4,
                // Keep the isolated SM suite on one authoritative capacity
                // snapshot. This scenario exercises resumable replacement,
                // which must work without raising the deployment ceiling.
                live_sessions: 1,
                sessions_per_account: 1,
                resumable_sessions: 8,
            },
        )
        .await
        .unwrap();
        let user_id = Uuid::new_v4();
        let username = format!("smpublish{}", user_id.simple());
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,auth_generation) VALUES($1,$2,'test',0)",
        )
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
        let full_jid = format!("{username}@example.test/device");
        let peer_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let old_connection = Uuid::new_v4();
        let snapshot = SmSessionSnapshot {
            inbound_h: 0,
            outbound_h: 0,
            acked_h: 0,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip,
            user_agent_id: None,
            joined_rooms: Vec::new(),
            directed_presence: Vec::new(),
            last_presence: None,
            unacked: Vec::new(),
        };
        let sm_session_id = db::create_sm_session(
            &pool,
            &[0x45; 32],
            user_id,
            0,
            &full_jid,
            "device",
            "example.test",
            old_connection,
            &snapshot,
            300,
            120,
            8,
            8,
        )
        .await
        .unwrap();
        assert!(db::suspend_sm_session(
            &pool,
            sm_session_id,
            old_connection,
            &snapshot,
            300,
            64,
            65_536,
        )
        .await
        .unwrap());

        let schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&pool)
            .await
            .unwrap();
        let sm = SmService::new(
            crate::db::sm_repository::PostgresSmRepository::new(
                pool.clone(),
                Arc::new(zeroize::Zeroizing::new(vec![0x56; 32])),
            ),
            schema,
        )
        .unwrap();
        let device_id = Uuid::new_v4();

        // A completed phase two whose response never reaches the transport
        // leaves only a bounded claim/stage. Releasing the new connection must
        // not delete or transfer the old resumable stream's live lease.
        let abandoned_connection = Uuid::new_v4();
        assert_eq!(
            sm.reserve_binding(abandoned_connection, user_id, 0, &full_jid, 120)
                .await
                .unwrap(),
            BindingReservationOutcome::Reserved
        );
        let abandoned_receipt = match sm
            .finalize_binding(
                abandoned_connection,
                user_id,
                0,
                &full_jid,
                120,
                Some(device_id),
                None,
            )
            .await
            .unwrap()
        {
            BindingFinalizationOutcome::Committed { receipt } => receipt,
            other => panic!("unexpected abandoned binding outcome: {other:?}"),
        };
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
            )
            .bind(&full_jid)
            .fetch_one(&pool)
            .await
            .unwrap(),
            old_connection
        );
        drop(abandoned_receipt);
        assert!(sm.release_live_session(abandoned_connection).await.unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
            )
            .bind(&full_jid)
            .fetch_one(&pool)
            .await
            .unwrap(),
            old_connection
        );

        let published_connection = Uuid::new_v4();
        assert_eq!(
            sm.reserve_binding(published_connection, user_id, 0, &full_jid, 120)
                .await
                .unwrap(),
            BindingReservationOutcome::Reserved
        );
        let receipt = match sm
            .finalize_binding(
                published_connection,
                user_id,
                0,
                &full_jid,
                120,
                Some(device_id),
                None,
            )
            .await
            .unwrap()
        {
            BindingFinalizationOutcome::Committed { receipt } => receipt,
            other => panic!("unexpected publishable binding outcome: {other:?}"),
        };
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
            )
            .bind(&full_jid)
            .fetch_one(&pool)
            .await
            .unwrap(),
            old_connection,
            "phase two must retain the old resumable lease"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_agent_login_epochs WHERE user_id=$1 AND device_id=$2",
            )
            .bind(user_id)
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

        let authentication = crate::services::authentication::AuthenticationService::new(
            crate::db::authentication::PostgresAuthenticationRepository::new(
                pool.clone(),
                std::sync::Arc::new(zeroize::Zeroizing::new(vec![0x56; 32])),
            ),
            std::sync::Arc::new(zeroize::Zeroizing::new(vec![0xa7; 32])),
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        );
        assert!(matches!(
            authentication.publish_credential_commit(&receipt).await,
            crate::services::authentication::AuthenticationResult::Authenticated(Some(2))
        ));
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
            )
            .bind(&full_jid)
            .fetch_one(&pool)
            .await
            .unwrap(),
            published_connection
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM deployment_session_binding_claims WHERE connection_id=$1",
            )
            .bind(published_connection)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT resumable FROM sm_resume_sessions WHERE id=$1",
        )
        .bind(sm_session_id)
        .fetch_one(&pool)
        .await
        .unwrap());
    }
}
