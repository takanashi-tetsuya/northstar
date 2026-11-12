//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`, and the handlers the root's client IQ route table calls on
//! it.

use crate::presence::{
    announced_priority, announced_show, broadcast_presence, deliver_service_messages,
    directed_presence_gate, inject_vcard_avatar_hash, route_directed_presence, PresenceGate,
};
use crate::roster::RosterGetOutcome;
use crate::PostAcceptFailureTelemetry;
use crate::PresenceRouting;
use crate::RosterSessionHost;
use anyhow::Result;
use northstar_federation_core::FederationRoute as _;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_application::presence::{PresenceRepository, PresenceService};
use northstar_roster_application::privacy::{PrivacyRepository, PrivacyService};
use northstar_roster_application::{
    BeginRosterSyncError, RosterRepository, RosterService, RosterSyncPermit, S2sOutboxPolicy,
};
use northstar_roster_application::{RosterFlushBatch, RosterSyncGate};
use northstar_roster_core::PresenceAccount;
use northstar_roster_core::{LocalRosterContact, RosterChange};
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use northstar_xml_builder::stanza::stanza_error;
use roxmltree::Node;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

// From src/xmpp/protocol/roster_identity.rs.
impl<H: SessionHost> crate::SessionIdentity for ProtocolSession<H> {
    fn session_account(&self) -> Option<PresenceAccount> {
        self.authenticated.as_ref().map(|user| PresenceAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn session_local_domain(&self) -> &str {
        self.host().local_domain()
    }
}

// From src/xmpp/protocol/blocking.rs.
impl<H: SessionHost + RosterSessionHost> crate::blocking::BlockingSession for ProtocolSession<H> {
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository> {
        self.host().blocking_service()
    }

    fn blocking_mark_requested(&self) {
        self.blocklist_requested.store(true, Ordering::Release);
    }

    async fn blocking_push_change(&self, owner: &str, payload: &str) {
        self.host().push_blocklist_change(owner, payload).await;
    }

    async fn blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) {
        self.host()
            .deliver_blocking_presence_change(owner, targets, changed_patterns, available)
            .await;
    }
}

/// The blocking handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait BlockingHandlers {
    async fn blocklist(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _blocklist: Node<'_, '_>,
    ) -> Result<Action>;

    async fn block(&self, id: &str, root: Node<'_, '_>, _block: Node<'_, '_>) -> Result<Action>;

    async fn unblock(&self, id: &str, root: Node<'_, '_>, _unblock: Node<'_, '_>)
        -> Result<Action>;
}

impl<H: SessionHost + RosterSessionHost> BlockingHandlers for ProtocolSession<H> {
    async fn blocklist(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _blocklist: Node<'_, '_>,
    ) -> Result<Action> {
        crate::blocking::blocklist(self, id, root)
            .await
            .map(Action::Send)
    }

    async fn block(&self, id: &str, root: Node<'_, '_>, _block: Node<'_, '_>) -> Result<Action> {
        crate::blocking::block(self, id, root)
            .await
            .map(Action::Send)
    }

    async fn unblock(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _unblock: Node<'_, '_>,
    ) -> Result<Action> {
        crate::blocking::unblock(self, id, root)
            .await
            .map(Action::Send)
    }
}

// From src/xmpp/protocol/privacy.rs.
impl<H: SessionHost + RosterSessionHost> crate::privacy::PrivacySession for ProtocolSession<H> {
    fn privacy_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn privacy_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn privacy_service(&self) -> &PrivacyService<impl PrivacyRepository> {
        self.host().privacy_service()
    }

    fn privacy_mark_requested(&self) {
        self.privacy_requested.store(true, Ordering::Release);
    }

    fn privacy_active_list(&self) -> Option<String> {
        self.privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn privacy_set_active_list(&self, name: Option<String>) {
        *self
            .privacy_active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = name;
    }

    fn privacy_local_resources(&self, account: &str) -> usize {
        self.host().local_resource_count(account)
    }

    async fn privacy_has_remote_resources(&self, account: &str) -> Result<bool> {
        self.host().account_has_remote_resources(account).await
    }

    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool {
        self.host().privacy_list_active_locally(account, name)
    }

    async fn privacy_push_change(&self, account: &str, name: &str, base: &str) -> Option<String> {
        self.host()
            .push_privacy_change(account, name, base, self.connection_id)
            .await
    }
}

/// The privacy list handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait PrivacyHandlers {
    async fn privacy_get(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn privacy_set(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;
}

impl<H: SessionHost + RosterSessionHost> PrivacyHandlers for ProtocolSession<H> {
    async fn privacy_get(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        crate::privacy::privacy_get(self, id, root, query)
            .await
            .map(Action::Send)
    }

    async fn privacy_set(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let (response, current_push) = crate::privacy::privacy_set(self, id, root, query).await?;
        Ok(match current_push {
            Some(push) => Action::SendMany(vec![response, push]),
            None => Action::Send(response),
        })
    }
}

// From src/xmpp/protocol/presence/session.rs.
impl<H: SessionHost + RosterSessionHost> crate::presence::PresenceSession for ProtocolSession<H> {
    fn presence_service(&self) -> &PresenceService<impl PresenceRepository> {
        self.host().presence_service()
    }

    fn presence_is_available(&self) -> bool {
        self.available
            .as_ref()
            .is_some_and(|available| available.load(Ordering::Relaxed))
    }

    fn presence_set_last(&self, presence: Option<String>) {
        *self
            .last_presence
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = presence;
    }

    fn presence_try_send(&self, stanza: String) {
        let _ = self.outbound.try_send(stanza);
    }

    async fn presence_send(&self, stanza: String) -> Result<()> {
        self.outbound
            .send(stanza)
            .await
            .map_err(|_| anyhow::anyhow!("client delivery queue closed"))
    }

    fn presence_directed_contains(&self, target: &str) -> bool {
        self.directed_presence.contains(target)
    }

    fn presence_directed_count(&self) -> usize {
        self.directed_presence.len()
    }

    fn presence_directed_insert(&self, target: String) {
        self.directed_presence.insert(target);
    }

    fn presence_directed_remove(&self, target: &str) {
        self.directed_presence.remove(target);
    }

    fn presence_directed_retain(&self, keep: impl Fn(&str) -> bool) {
        self.directed_presence.retain(|target| keep(target));
    }

    fn presence_directed_take(&self) -> Vec<String> {
        let targets = self
            .directed_presence
            .iter()
            .map(|target| target.key().clone())
            .collect::<Vec<_>>();
        self.directed_presence.clear();
        targets
    }

    fn presence_route_allowed(&self, domain: &str) -> bool {
        self.host().xmpp_external_route_domain_allowed(domain)
    }

    fn presence_is_component_domain(&self, domain: &str) -> bool {
        self.host().presence_component_domain(domain)
    }

    async fn presence_send_federated(
        &self,
        domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> bool {
        self.host()
            .federation_outbox()
            .send(domain, stanza, bounce_to)
            .await
    }

    async fn presence_deliver_directed(
        &self,
        to: &str,
        canonical_to: &str,
        from: &str,
        stanza: &str,
        bare_target: bool,
    ) -> Result<bool> {
        self.host()
            .deliver_directed_presence(to, canonical_to, from, stanza, bare_target)
            .await
    }

    async fn presence_deliver_subscription(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        stanza: &str,
    ) -> Result<()> {
        self.host()
            .deliver_subscription_presence(owner, recipient, owner_bare, recipient_bare, stanza)
            .await
    }

    async fn presence_deliver_approval(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        approved: &str,
    ) -> Result<()> {
        self.host()
            .deliver_subscription_approval(
                owner,
                recipient,
                owner_bare,
                recipient_bare,
                approved,
                self.full_jid.as_deref(),
            )
            .await
    }

    async fn presence_deliver_to_contact(
        &self,
        contact: &str,
        from: &str,
        stanza: &str,
    ) -> Result<()> {
        self.host()
            .deliver_contact_presence(contact, from, stanza)
            .await
    }

    async fn presence_echo_to_account(&self, account: &str, from: &str, stanza: &str) {
        self.host()
            .echo_account_presence(account, from, stanza)
            .await;
    }

    async fn presence_deliver_directed_unavailable(
        &self,
        target: &str,
        bare_target: bool,
        from: &str,
        stanza: &str,
    ) {
        self.host()
            .deliver_directed_unavailable(target, bare_target, from, stanza)
            .await;
    }

    fn presence_has_available_resource(&self, bare: &str) -> bool {
        self.host().account_has_available_resource(bare)
    }

    async fn presence_probe_has_remote_owner(&self, bare: &str) -> Result<bool> {
        self.host().probe_has_remote_owner(bare).await
    }

    fn presence_directed_recipient(&self, owner_full: &str, requester: &str) -> bool {
        self.host()
            .directed_presence_recipient(owner_full, requester)
    }

    async fn presence_answer_full_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<()> {
        if let Some(reply) = self
            .host()
            .answer_full_presence_probe(owner_full, owner_bare, requester, probe_id)
            .await?
        {
            let _ = self.outbound.try_send(reply);
        }
        Ok(())
    }

    async fn presence_send_current(&self, owner: &str, recipient: &str) {
        self.host().send_current_presence(owner, recipient).await;
    }

    async fn presence_send_current_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) {
        self.host()
            .send_current_presence_exact(owner, recipient, owner_bare, recipient_bare)
            .await;
    }

    async fn presence_full_target_routed(&self, full_jid: &str) -> bool {
        self.host().full_presence_target_routed(full_jid).await
    }

    async fn presence_notify_offline(&self, user_id: uuid::Uuid) -> Result<()> {
        self.host().notify_offline_account(user_id).await
    }
}

// From src/xmpp/protocol/roster.rs.
impl<H: SessionHost + RosterSessionHost> crate::roster::RosterSession for ProtocolSession<H> {
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>> {
        self.host().roster_service()
    }

    fn roster_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn roster_begin_sync(
        &self,
        annotations_requested: bool,
    ) -> std::result::Result<RosterSyncPermit, BeginRosterSyncError> {
        self.roster_sync.begin(
            &self.roster_requested,
            &self.mix_roster_annotations,
            annotations_requested,
        )
    }

    fn roster_fail_sync(&self, permit: RosterSyncPermit) {
        self.roster_sync.fail(permit);
    }

    fn roster_disconnect(&self) {
        self.disconnect.cancel();
    }

    fn roster_is_hosted_domain(&self, domain: &str) -> bool {
        domain == self.host().muc_domain()
            || domain == self.host().upload_domain()
            || domain == self.host().pubsub_domain()
    }

    fn roster_outbox_policy(&self) -> S2sOutboxPolicy {
        self.host().roster_outbox_policy()
    }

    fn roster_wake_outbox(&self) {
        self.host().roster_wake_outbox();
    }

    async fn roster_deliver_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) {
        self.host()
            .deliver_roster_removal_presence(owner, recipient, target_bare, stanza)
            .await;
    }

    async fn roster_push_change(
        &self,
        owner_id: uuid::Uuid,
        owner: &str,
        change: &RosterChange,
    ) -> Result<()> {
        self.host()
            .deliver_committed_roster_change(owner_id, owner, change, None)
            .await
    }
}

/// The roster handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait RosterHandlers {
    async fn roster_get(
        &mut self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn roster_set(&self, id: &str, iq: Node<'_, '_>, query: Node<'_, '_>) -> Result<Action>;
}

impl<H: SessionHost + RosterSessionHost> RosterHandlers for ProtocolSession<H> {
    async fn roster_get(
        &mut self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(
            match crate::roster::roster_get(&*self, id, iq, query).await? {
                RosterGetOutcome::Reply(response) => Action::Send(response),
                RosterGetOutcome::Synchronize {
                    response,
                    permit,
                    snapshot_version,
                    initial_delta,
                    target,
                } => {
                    let failure_telemetry = self.host().post_accept_failure_telemetry();
                    let outbound = self.outbound.clone();
                    let gate = Arc::clone(&self.roster_sync);
                    let disconnect = self.disconnect.clone();
                    self.defer_after_transport("roster-initial-sync", async move {
                        flush_roster_sync(RosterSyncFlush {
                            failure_telemetry,
                            outbound,
                            gate,
                            disconnect,
                            permit,
                            snapshot_version,
                            initial_delta,
                            target,
                        })
                        .await;
                    })?;
                    Action::Send(response)
                }
            },
        )
    }

    async fn roster_set(&self, id: &str, iq: Node<'_, '_>, query: Node<'_, '_>) -> Result<Action> {
        crate::roster::roster_set(self, id, iq, query)
            .await
            .map(Action::Send)
    }
}

struct RosterSyncFlush {
    failure_telemetry: PostAcceptFailureTelemetry,
    outbound: northstar_stream::outbound::OutboundSender,
    gate: Arc<RosterSyncGate>,
    disconnect: tokio_util::sync::CancellationToken,
    permit: RosterSyncPermit,
    snapshot_version: i64,
    initial_delta: Vec<String>,
    target: String,
}

async fn flush_roster_sync(request: RosterSyncFlush) {
    let RosterSyncFlush {
        failure_telemetry,
        outbound,
        gate,
        disconnect,
        permit,
        snapshot_version,
        initial_delta,
        target,
    } = request;
    async fn enqueue(
        outbound: &northstar_stream::outbound::OutboundSender,
        stanza: String,
    ) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), outbound.send(stanza)).await,
            Ok(Ok(()))
        )
    }

    for stanza in initial_delta {
        if !enqueue(&outbound, stanza).await {
            gate.fail(permit);
            outbound.disconnect_backpressured_transport();
            disconnect.cancel();
            failure_telemetry.record_failure();
            tracing::warn!(%target, "roster delta could not enter the transport; forcing a full resync");
            return;
        }
    }

    let mut batch = gate.start_flush(permit, snapshot_version);
    loop {
        match batch {
            RosterFlushBatch::Batch(pushes) => {
                for (version, stanza) in pushes {
                    if !enqueue(&outbound, stanza).await {
                        gate.fail(permit);
                        outbound.disconnect_backpressured_transport();
                        disconnect.cancel();
                        failure_telemetry.record_failure();
                        tracing::warn!(%target, version, "buffered roster push could not enter the transport; forcing a full resync");
                        return;
                    }
                }
                batch = gate.next_flush_batch(permit);
            }
            RosterFlushBatch::Complete => return,
            RosterFlushBatch::Failed | RosterFlushBatch::Superseded => {
                outbound.disconnect_backpressured_transport();
                disconnect.cancel();
                failure_telemetry.record_failure();
                tracing::warn!(%target, "roster synchronization fence failed; forcing a full resync");
                return;
            }
        }
    }
}

// From src/xmpp/protocol/presence.rs.
/// The presence handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait PresenceHandlers {
    async fn presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action>;
}

impl<H: RosterSessionHost + PresenceRouting> PresenceHandlers for ProtocolSession<H> {
    async fn presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        if self.authenticated.is_none() {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        }
        let Some(from) = self.full_jid.clone() else {
            return Ok(Action::None);
        };
        let kind = root.attribute("type").unwrap_or("available");
        if let Some(raw_to) = root.attribute("to") {
            let target_jid = match northstar_xmpp_types::jid::CanonicalJid::parse(raw_to) {
                Ok(target) => target,
                Err(_) => return Ok(Action::Send(stanza_error(root, "modify", "jid-malformed"))),
            };
            if let PresenceGate::Closed(reply) =
                directed_presence_gate(&*self, root, &target_jid, kind, &from).await?
            {
                return Ok(reply.map_or(Action::None, Action::Send));
            }
            if let Some(action) = H::route_mix_presence(self, root, raw).await? {
                return Ok(action);
            }
            if target_jid.resourcepart().is_none()
                && target_jid.localpart().is_none()
                && target_jid.domainpart() == self.host().pubsub_domain()
            {
                return H::route_pubsub_presence(self, kind, &from).await;
            }
            if target_jid.domainpart() == self.host().muc_domain() {
                if kind == "available" {
                    let user = self.authenticated.as_ref().expect("authenticated session");
                    let avatar_hash = self.host().presence_service().avatar_hash(user.id).await?;
                    let injected = inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref());
                    let document = roxmltree::Document::parse(&injected)?;
                    return H::route_muc_presence(self, document.root_element(), &injected).await;
                }
                return H::route_muc_presence(self, root, raw).await;
            }
            let reply =
                route_directed_presence(&*self, root, raw, &target_jid, kind, &from).await?;
            return Ok(reply.map_or(Action::None, Action::Send));
        }

        // MIX presence is an account/resource epoch, not a best-effort
        // side effect. Serialize the database projection with the exact
        // in-memory availability/generation transition, then release the
        // per-resource gate before roster, federation and replay work.
        let mix_presence_epoch = Arc::clone(&self.presence.mix_presence_gate)
            .lock_owned()
            .await;
        if !H::forward_presence_to_mix(self, root, kind, &from, raw).await? {
            return Ok(Action::None);
        }
        if matches!(kind, "available" | "unavailable") {
            // A broadcast transition supersedes every earlier directed
            // per-channel suppression for this resource.
            self.presence.mix_presence_fallback_suppressed.clear();
        }
        let user = self.authenticated.as_ref().expect("authenticated session");
        let now_available = kind == "available";
        let was_available = self
            .available
            .as_ref()
            .is_some_and(|available| available.load(Ordering::Acquire));
        let first_available = now_available && !was_available;
        let previous_priority = self.priority.load(Ordering::Relaxed);
        let availability_generation = if was_available != now_available {
            self.presence
                .availability_generation
                .fetch_add(1, Ordering::AcqRel)
                + 1
        } else {
            self.presence
                .availability_generation
                .load(Ordering::Acquire)
        };
        if let Some(available) = &self.available {
            available.store(now_available, Ordering::Release);
        }
        self.commit_caps_observation(root, &from);
        drop(mix_presence_epoch);
        let show = announced_show(root, kind);
        self.show.store(show, Ordering::Relaxed);
        let priority = announced_priority(root, kind);
        self.priority.store(priority, Ordering::Relaxed);
        // XEP-0160 delivers the offline queue on the first available
        // presence whose priority is nonnegative. A resource is allowed
        // to announce priority -1 first and later raise it without an
        // intervening unavailable presence, so availability alone is not
        // sufficient to identify this transition.
        let newly_offline_eligible = northstar_presence_core::offline_replay_became_eligible(
            was_available,
            previous_priority,
            now_available,
            priority,
        );
        // Capture the PostgreSQL clock at the actual XEP-0160
        // availability transition. Roster/presence fanout below may wait
        // on a degraded cluster control plane; a later replay worker must
        // not absorb messages inserted during those waits.
        let offline_replay_cutoff = if newly_offline_eligible && !self.bind2_mam_catchup {
            Some(self.host().presence_service().replay_cutoff().await?)
        } else {
            None
        };

        broadcast_presence(&*self, root, raw, kind, &from, first_available).await?;

        if first_available {
            deliver_service_messages(&*self, &from).await?;
            let replay_service = self.host().replay_service().clone();
            let outbound = self.outbound.clone();
            let active_privacy_list = self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let available = self
                .available
                .as_ref()
                .expect("a bound resource has availability state")
                .clone();
            let generation = self.presence.availability_generation.clone();
            let recipient_id = user.id;
            let full_jid = from.clone();
            let account = format!(
                "{}@{}",
                user.username,
                SessionHost::local_domain(&**self.host())
            );
            let bind2_mam_catchup = self.bind2_mam_catchup;
            let include_offline = priority >= 0 && !bind2_mam_catchup;
            self.defer_after_transport("available-offline-replay", async move {
                northstar_stream::replay::replay_newly_available_resource(
                    replay_service,
                    outbound,
                    recipient_id,
                    account,
                    full_jid,
                    active_privacy_list,
                    bind2_mam_catchup,
                    include_offline,
                    available,
                    generation,
                    availability_generation,
                    offline_replay_cutoff,
                )
                .await;
            })?;
            // The generic PubSub service advertises last-published, so a
            // subscriber's first broadcast available presence must
            // trigger the same bounded replay as directed presence to the
            // service. The worker starts only after this presence action
            // reaches the transport and applies awaited backpressure.
            let _ = H::route_pubsub_presence(self, "available", &from).await?;
        } else if newly_offline_eligible && !self.bind2_mam_catchup {
            let replay_service = self.host().replay_service().clone();
            let outbound = self.outbound.clone();
            let active_privacy_list = self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let available = self
                .available
                .as_ref()
                .expect("a bound resource has availability state")
                .clone();
            let generation = self.presence.availability_generation.clone();
            let recipient_id = user.id;
            let full_jid = from.clone();
            let offline_replay_cutoff = offline_replay_cutoff
                .expect("newly eligible legacy replay captured a database cutoff");
            self.defer_after_transport("nonnegative-offline-replay", async move {
                northstar_stream::replay::replay_newly_nonnegative_resource(
                    replay_service,
                    outbound,
                    recipient_id,
                    full_jid,
                    active_privacy_list,
                    available,
                    generation,
                    availability_generation,
                    offline_replay_cutoff,
                )
                .await;
            })?;
        }
        Ok(Action::None)
    }
}
