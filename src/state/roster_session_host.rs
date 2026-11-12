//! The node's side of the roster context's session handlers.

use super::AppState;
use crate::xmpp::protocol::ClientSession;
use anyhow::Result;
use northstar_mix_xmpp::MixHandlers;
use northstar_muc_xmpp::MucHandlers;
use northstar_pubsub_xmpp::PubSubHandlers;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_application::{
    RosterPushDisposition, RosterRepository, RosterService, S2sOutboxPolicy,
};
use northstar_roster_core::{LocalRosterContact, PresenceAccount, RosterChange};
use northstar_roster_xmpp::roster::{roster_change_item_element, roster_push_xml};
use northstar_roster_xmpp::{
    FederatedPresenceHost, PostAcceptFailureTelemetry, PresenceRouting, RosterSessionHost,
};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::transport::Action;
use northstar_xml_builder::rewrite::set_to;
use northstar_xml_builder::stream::stream_id;
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;
use uuid::Uuid;

const BLOCKING_PUSH_TIMEOUT: Duration = Duration::from_secs(2);

impl RosterSessionHost for AppState {
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>> {
        AppState::roster_service(self)
    }

    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository> {
        AppState::blocking_service(self)
    }

    fn post_accept_failure_telemetry(&self) -> PostAcceptFailureTelemetry {
        AppState::post_accept_failure_telemetry(self)
    }

    fn roster_outbox_policy(&self) -> S2sOutboxPolicy {
        self.federation_outbox().outbox_policy()
    }

    fn roster_wake_outbox(&self) {
        self.federation_outbox().wake_outbox();
    }

    async fn deliver_committed_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
        participant_id: Option<&str>,
    ) -> Result<()> {
        deliver_roster_change(self, owner_id, owner, change, participant_id).await
    }

    async fn deliver_roster_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) {
        deliver_roster_removal_presence(
            self,
            owner.id,
            owner.auth_generation,
            recipient.id,
            recipient.auth_generation,
            target_bare,
            stanza,
        )
        .await;
    }

    async fn push_blocklist_change(&self, owner: &str, payload: &str) {
        for (jid, session) in self.session_entries_for(owner) {
            if !session.blocklist_requested.load(Ordering::Acquire) {
                continue;
            }
            let push = blocking_push_stanza(&jid, payload);
            match tokio::time::timeout(BLOCKING_PUSH_TIMEOUT, session.sender.send(push)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    // A committed block-list mutation must not be followed by
                    // newer traffic on a resource which missed its ordered
                    // push.  Disconnecting forces the client to query the
                    // server-authoritative list again after reconnect.
                    session.sender.disconnect_backpressured_transport();
                    session.disconnect.cancel();
                    self.post_accept_failure_telemetry().record_failure();
                    tracing::warn!(%jid, ?error, "XEP-0191 blocklist push queue closed; disconnecting stale resource");
                }
                Err(_) => {
                    session.sender.disconnect_backpressured_transport();
                    session.disconnect.cancel();
                    self.post_accept_failure_telemetry().record_failure();
                    tracing::warn!(%jid, "timed out delivering XEP-0191 blocklist push; disconnecting stale resource");
                }
            }
        }
        match self
            .route_remote_blocklist_push(owner, || blocking_push_stanza(owner, payload))
            .await
        {
            Ok(failures) => {
                for failure in failures {
                    tracing::warn!(error=?failure.error, node_id=%failure.node_id,
                        "failed clustered XEP-0191 push");
                }
            }
            Err(error) => tracing::warn!(?error, "failed to locate clustered account resources"),
        }
    }

    async fn deliver_blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) {
        deliver_blocking_presence_change(self, owner, targets, changed_patterns, available).await;
        match self
            .route_remote_blocking_presence_change(owner, targets, changed_patterns, available)
            .await
        {
            Ok(failures) => {
                for failure in failures {
                    tracing::warn!(error=?failure.error, node_id=%failure.node_id,
                        "failed clustered blocking presence update");
                }
            }
            Err(error) => tracing::warn!(?error, "failed to locate clustered presence resources"),
        }
    }

    fn local_resource_count(&self, account: &str) -> usize {
        self.sessions_for(account).len()
    }

    async fn account_has_remote_resources(&self, account: &str) -> Result<bool> {
        AppState::account_has_remote_resources(self, account).await
    }

    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool {
        self.sessions_for(account).iter().any(|session| {
            session
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_deref()
                == Some(name)
        })
    }

    async fn push_privacy_change(
        &self,
        account: &str,
        name: &str,
        base: &str,
        current_connection: Uuid,
    ) -> Option<String> {
        let mut current_push = None;
        for (jid, session) in self.session_entries_for(account) {
            if !session.privacy_requested.load(Ordering::Acquire) {
                continue;
            }
            let push = set_to(base, &jid);
            if session.connection_id == current_connection {
                current_push = Some(push);
            } else if let Err(error) = session.sender.try_send(push) {
                // The mutation has already committed.  Keeping this resource
                // alive after dropping its ordered IQ push would let the
                // client continue with a stale privacy-list view.  Force a
                // reconnect so its next query observes the authoritative
                // state instead of allowing later pushes to cross this gap.
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                self.post_accept_failure_telemetry().record_failure();
                tracing::warn!(
                    %jid,
                    list = %name,
                    ?error,
                    "XEP-0016 privacy-list push queue was unavailable; disconnecting stale resource"
                );
            }
        }
        match self.route_remote_privacy_push(account, base).await {
            Ok(failures) => {
                for failure in failures {
                    tracing::warn!(
                        error = ?failure.error,
                        node_id = %failure.node_id,
                        list = %name,
                        "clustered XEP-0016 push failed"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(?error, list = %name, "could not enumerate nodes for XEP-0016 push")
            }
        }
        current_push
    }

    fn presence_component_domain(&self, domain: &str) -> bool {
        self.xmpp_component_domain_configured(domain)
    }

    async fn deliver_directed_presence(
        &self,
        to: &str,
        canonical_to: &str,
        from: &str,
        stanza: &str,
        bare_target: bool,
    ) -> Result<bool> {
        AppState::deliver_directed_presence(self, to, canonical_to, from, stanza, bare_target).await
    }

    async fn deliver_subscription_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        stanza: &str,
    ) -> Result<()> {
        AppState::deliver_subscription_presence(
            self,
            owner,
            recipient,
            owner_bare,
            recipient_bare,
            stanza,
        )
        .await
    }

    async fn deliver_subscription_approval(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        approved: &str,
        skip_full: Option<&str>,
    ) -> Result<()> {
        AppState::deliver_subscription_approval(
            self,
            owner,
            recipient,
            owner_bare,
            recipient_bare,
            approved,
            skip_full,
        )
        .await
    }

    async fn deliver_contact_presence(
        &self,
        contact: &str,
        from: &str,
        stanza: &str,
    ) -> Result<()> {
        AppState::deliver_contact_presence(self, contact, from, stanza).await
    }

    async fn echo_account_presence(&self, account: &str, from: &str, stanza: &str) {
        AppState::echo_account_presence(self, account, from, stanza).await
    }

    async fn deliver_directed_unavailable(
        &self,
        target: &str,
        bare_target: bool,
        from: &str,
        stanza: &str,
    ) {
        AppState::deliver_directed_unavailable(self, target, bare_target, from, stanza).await
    }

    fn account_has_available_resource(&self, bare: &str) -> bool {
        AppState::account_has_available_resource(self, bare)
    }

    async fn probe_has_remote_owner(&self, bare: &str) -> Result<bool> {
        self.presence_probe_has_remote_owner(bare).await
    }

    fn directed_presence_recipient(&self, owner_full: &str, requester: &str) -> bool {
        AppState::directed_presence_recipient(self, owner_full, requester)
    }

    async fn answer_full_presence_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<Option<String>> {
        AppState::answer_full_presence_probe(self, owner_full, owner_bare, requester, probe_id)
            .await
    }

    async fn send_current_presence(&self, owner: &str, recipient: &str) {
        self.send_current_availability(owner, recipient).await
    }

    async fn send_current_presence_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) {
        self.send_current_availability_exact(
            owner_bare,
            owner.id,
            owner.auth_generation,
            recipient_bare,
            recipient.id,
            recipient.auth_generation,
        )
        .await
    }

    async fn full_presence_target_routed(&self, full_jid: &str) -> bool {
        self.subscription_full_target_has_route(full_jid).await
    }

    async fn notify_offline_account(&self, user_id: Uuid) -> Result<()> {
        self.dispatch_push_notification(user_id).await
    }
}

async fn deliver_roster_removal_presence(
    state: &AppState,
    owner_id: Uuid,
    owner_auth_generation: i64,
    recipient_id: Uuid,
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
    state: &AppState,
    owner_id: Uuid,
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
    delivery: &super::account_deletion_recovery::RosterPushDelivery,
    owner_id: Uuid,
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
                    super::cluster_routing::RemoteRosterPushFailure::NotAccepted { node_id } => {
                        tracing::warn!(owner = %owner_jid, remote_node = %node_id, version = change.version, "committed roster push was not accepted by the remote node; roster version recovery remains authoritative");
                    }
                    super::cluster_routing::RemoteRosterPushFailure::Delivery(failure) => {
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

fn blocking_push_stanza(target: &str, payload: &str) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("to", target)
        .attr("type", "set")
        .attr("id", format!("block-{}", stream_id()))
        .validated_fragment(payload)
        .expect("blocking payload was constructed structurally")
        .finish()
}

/// Runs on every node that owns at least one resource of `owner`. This keeps
/// polite-blocking presence transitions complete without duplicating any one
/// resource's presence.
pub(crate) async fn deliver_blocking_presence_change(
    state: &AppState,
    owner: &str,
    roster_targets: &[String],
    changed_patterns: &[String],
    available: bool,
) {
    let _ = deliver_blocking_presence_change_with_remote(
        state,
        owner,
        roster_targets,
        changed_patterns,
        available,
        |node_id, target, delivery| async move {
            let _ = state
                .route_remote_available_presence_to_node(&node_id, &target, &delivery)
                .await;
            Ok(())
        },
    )
    .await;
}

/// The cluster listener prepares remote replies in its current command turn,
/// then waits for their receipts without blocking the PubSub reader.
pub(crate) async fn deliver_blocking_presence_change_with_remote<F, Fut>(
    state: &AppState,
    owner: &str,
    roster_targets: &[String],
    changed_patterns: &[String],
    available: bool,
    mut send_remote: F,
) -> Result<()>
where
    F: FnMut(String, String, String) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    for (from, session) in state
        .session_entries_for(owner)
        .into_iter()
        .filter(|(_, session)| session.available.load(Ordering::Acquire))
    {
        let base_presence = if available {
            session
                .last_presence
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        } else {
            Some(
                XmlElement::namespaced("presence", "jabber:client")
                    .attr("from", &from)
                    .attr("type", "unavailable")
                    .finish(),
            )
        };
        let Some(base_presence) = base_presence else {
            continue;
        };
        let mut targets = roster_targets.iter().cloned().collect::<HashSet<_>>();
        for directed in session.directed_presence.iter() {
            if changed_patterns.iter().any(|pattern| {
                northstar_roster_application::blocking::matches(pattern, directed.key())
            }) {
                targets.insert(directed.key().clone());
            }
        }
        for target in targets {
            let Ok(target_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(&target) else {
                continue;
            };
            let delivery = set_to(&base_presence, &target);
            if target_jid.domainpart() == state.local_domain() {
                let mut recipients = state.session_entries_for(&target);
                if target_jid.resourcepart().is_none() {
                    recipients.retain(|(_, recipient)| recipient.available.load(Ordering::Acquire));
                }
                for (_, recipient) in recipients {
                    let _ = recipient.sender.try_send(delivery.clone());
                }
                if let Ok(nodes) = state.remote_resource_nodes(&target).await {
                    for node_id in nodes {
                        send_remote(node_id, target.clone(), delivery.clone()).await?;
                    }
                }
            } else if state.xmpp_external_route_domain_allowed(target_jid.domainpart()) {
                let _ = state
                    .federation_outbox()
                    .send(target_jid.domainpart(), delivery, Some(from.clone()))
                    .await;
            }
        }
    }
    Ok(())
}

impl PresenceRouting for AppState {
    async fn route_mix_presence(
        session: &ClientSession,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        session.try_mix_presence(root, raw).await
    }

    async fn route_pubsub_presence(
        session: &mut ClientSession,
        kind: &str,
        from: &str,
    ) -> Result<Action> {
        session.pubsub_presence(kind, from).await
    }

    async fn route_muc_presence(
        session: &mut ClientSession,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        session.muc_presence(root, raw).await
    }

    async fn forward_presence_to_mix(
        session: &ClientSession,
        root: Node<'_, '_>,
        kind: &str,
        from: &str,
        raw: &str,
    ) -> Result<bool> {
        if !northstar_mix_xmpp::mix_presence_route_is_current(
            session.host().as_ref(),
            from,
            session.connection_id,
            &session.presence.mix_presence_gate,
            false,
        ) {
            return Ok(false);
        }
        let advertised_mix_capability = session.advertised_mix_capability(root, from);
        session
            .forward_presence_to_mix_channels(kind, advertised_mix_capability, raw)
            .await?;
        Ok(true)
    }
}

impl FederatedPresenceHost for AppState {
    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        AppState::sessions_for(self, jid)
    }

    async fn dispatch_push_notification(&self, user_id: Uuid) -> Result<()> {
        AppState::dispatch_push_notification(self, user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_targets_an_exact_resource() {
        let push = blocking_push_stanza(
            "alice@example.test/Phone",
            "<unblock xmlns='urn:xmpp:blocking'/>",
        );
        assert!(push.contains("to='alice@example.test/Phone'"));
        assert!(push.contains("<unblock xmlns='urn:xmpp:blocking'/>"));
    }
}
