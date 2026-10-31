use super::{Action, ProtocolSession};
use crate::services::xml_util::set_to;
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_application::{
    BeginRosterSyncError, RosterFlushBatch, RosterPushDisposition, RosterRepository, RosterService,
    RosterSyncGate, RosterSyncPermit, S2sOutboxPolicy,
};
use northstar_roster_core::{LocalRosterContact, PresenceAccount, RosterChange};
use northstar_roster_xmpp::roster::{
    roster_change_item_element, roster_push_xml, RosterGetOutcome,
};
use roxmltree::Node;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

impl ProtocolSession {
    pub(crate) async fn roster_get(
        &mut self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(
            match northstar_roster_xmpp::roster::roster_get(&*self, id, iq, query).await? {
                RosterGetOutcome::Reply(response) => Action::Send(response),
                RosterGetOutcome::Synchronize {
                    response,
                    permit,
                    snapshot_version,
                    initial_delta,
                    target,
                } => {
                    let failure_telemetry = self.state.post_accept_failure_telemetry();
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

    pub(crate) async fn roster_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::roster::roster_set(self, id, iq, query)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn push_roster_change(
        &self,
        owner_id: uuid::Uuid,
        owner: &str,
        change: &RosterChange,
        participant_id: Option<&str>,
    ) -> Result<()> {
        deliver_roster_change(&self.state, owner_id, owner, change, participant_id).await
    }
}

impl northstar_roster_xmpp::roster::RosterSession for ProtocolSession {
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>> {
        self.state.roster_service()
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
        domain == self.muc_domain()
            || domain == self.upload_domain()
            || domain == self.pubsub_domain()
    }

    fn roster_outbox_policy(&self) -> S2sOutboxPolicy {
        self.state.federation_outbox().outbox_policy()
    }

    fn roster_wake_outbox(&self) {
        self.state.federation_outbox().wake_outbox();
    }

    async fn roster_deliver_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) {
        deliver_roster_removal_presence(
            &self.state,
            owner.id,
            owner.auth_generation,
            recipient.id,
            recipient.auth_generation,
            target_bare,
            stanza,
        )
        .await;
    }

    async fn roster_push_change(
        &self,
        owner_id: uuid::Uuid,
        owner: &str,
        change: &RosterChange,
    ) -> Result<()> {
        self.push_roster_change(owner_id, owner, change, None).await
    }
}

struct RosterSyncFlush {
    failure_telemetry: crate::xmpp::capabilities::PostAcceptFailureTelemetry,
    outbound: crate::xmpp::outbound::OutboundSender,
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
    async fn enqueue(outbound: &crate::xmpp::outbound::OutboundSender, stanza: String) -> bool {
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

async fn deliver_roster_removal_presence(
    state: &crate::state::AppState,
    owner_id: uuid::Uuid,
    owner_auth_generation: i64,
    recipient_id: uuid::Uuid,
    recipient_auth_generation: i64,
    target_bare: &str,
    stanza: &str,
) {
    let Some(owner_bare) = roxmltree::Document::parse(stanza)
        .ok()
        .and_then(|document| {
            document
                .root_element()
                .attribute("from")
                .and_then(|value| northstar_xmpp_types::jid::canonicalize_bare(value).ok())
        })
    else {
        // This is an internally constructed stanza. A malformed source must
        // fail closed instead of bypassing the recipient resource's active
        // XEP-0016 list.
        return;
    };
    for (target_full, session) in state.session_entries_for(target_bare) {
        // RFC 6121 section 2.2 distinguishes an "available resource" from
        // an "interested resource".  Subscription-related presence is sent
        // to every available resource; only the roster push which follows it
        // is restricted to resources that requested the roster.
        if session.user_id == recipient_id
            && session.auth_generation == recipient_auth_generation
            && session.available.load(Ordering::Acquire)
            && state
                .privacy_allows_session(&session, &owner_bare, PrivacyStanzaKind::PresenceIn)
                .await
                .unwrap_or(false)
        {
            let _ = session.sender.try_send(set_to(stanza, &target_full));
        }
    }
    state
        .route_remote_roster_removal_presence(
            target_bare,
            stanza,
            crate::cluster::ClusterPresenceAuthority {
                owner_id,
                owner_auth_generation,
                recipient_id,
                recipient_auth_generation,
            },
        )
        .await;
}

pub(crate) async fn deliver_roster_change(
    state: &crate::state::AppState,
    owner_id: uuid::Uuid,
    owner: &str,
    change: &RosterChange,
    participant_id: Option<&str>,
) -> Result<()> {
    deliver_roster_change_with(
        &state.roster_push_delivery(),
        owner_id,
        owner,
        change,
        participant_id,
    )
    .await
}

pub(crate) async fn deliver_roster_change_with(
    delivery: &crate::state::account_deletion_recovery::RosterPushDelivery,
    owner_id: uuid::Uuid,
    owner: &str,
    change: &RosterChange,
    participant_id: Option<&str>,
) -> Result<()> {
    let item = roster_change_item_element(change, None);
    let annotated = participant_id
        .map(|participant_id| roster_change_item_element(change, Some(participant_id)));
    let owner_jid = format!("{}@{}", owner, delivery.local_domain());
    for (target_jid, target) in delivery.local_sessions(&owner_jid) {
        if target.user_id != owner_id {
            continue;
        }
        let plain_push = roster_push_xml(&owner_jid, &target_jid, change.version, item.clone());
        let annotated_push = annotated.as_ref().map(|annotated| {
            roster_push_xml(&owner_jid, &target_jid, change.version, annotated.clone())
        });
        match target.roster_sync.route(
            &target.roster_requested,
            &target.mix_roster_annotations,
            change.version,
            plain_push,
            annotated_push,
        ) {
            RosterPushDisposition::NotInterested | RosterPushDisposition::Buffered => {}
            RosterPushDisposition::Deliver(push) => {
                if let Err(error) = target.sender.try_send(push) {
                    target.sender.disconnect_backpressured_transport();
                    target.disconnect.cancel();
                    delivery.record_failure();
                    tracing::warn!(owner = %owner_jid, target = %target_jid, version = change.version, ?error, "committed roster push did not enter the local resource queue; forcing a full resync");
                }
            }
            RosterPushDisposition::Overflow => {
                target.sender.disconnect_backpressured_transport();
                target.disconnect.cancel();
                delivery.record_failure();
                tracing::warn!(owner = %owner_jid, target = %target_jid, version = change.version, "roster synchronization buffer overflowed; forcing a full resync");
            }
        }
    }
    // The immutable journal snapshot and exact committed version cross node
    // boundaries together; remote resources add their exact full-JID target.
    let push = roster_push_xml(&owner_jid, &owner_jid, change.version, item);
    let annotated_push = annotated
        .map(|annotated| roster_push_xml(&owner_jid, &owner_jid, change.version, annotated));
    match delivery
        .route_remote_push(
            &owner_jid,
            owner_id,
            change.version,
            &push,
            annotated_push.as_deref(),
        )
        .await
    {
        Ok(failures) => {
            for failure in failures {
                delivery.record_failure();
                match failure {
                    crate::state::cluster_routing::RemoteRosterPushFailure::NotAccepted {
                        node_id,
                    } => {
                        tracing::warn!(owner = %owner_jid, remote_node = %node_id, version = change.version, "committed roster push was not accepted by the remote node; roster version recovery remains authoritative");
                    }
                    crate::state::cluster_routing::RemoteRosterPushFailure::Delivery(failure) => {
                        tracing::warn!(owner = %owner_jid, remote_node = %failure.node_id, version = change.version, error=?failure.error, "committed roster push failed across the cluster; roster version recovery remains authoritative");
                    }
                }
            }
        }
        Err(error) => {
            delivery.record_failure();
            tracing::warn!(owner = %owner_jid, version = change.version, ?error, "could not discover remote resources for a committed roster push; roster version recovery remains authoritative");
        }
    }
    Ok(())
}
