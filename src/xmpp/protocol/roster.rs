use super::{Action, ProtocolSession};
use crate::services::privacy::PrivacyStanzaKind;
use crate::services::roster::{
    BeginRosterSyncError, RosterAuthorization, RosterChange, RosterFlushBatch,
    RosterPushDisposition, RosterReadSnapshot, RosterRemovalRoute, RosterSyncGate,
    RosterSyncPermit,
};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;
use roxmltree::Node;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

const MIX_ROSTER_NS: &str = "urn:xmpp:mix:roster:0";

#[cfg(test)]
pub(crate) fn roster_item_xml(
    jid: &str,
    name: Option<&str>,
    subscription: &str,
    ask: Option<&str>,
    approved: bool,
    groups: &[String],
    participant_id: Option<&str>,
) -> String {
    roster_item_element(
        jid,
        name,
        subscription,
        ask,
        approved,
        groups,
        participant_id,
    )
    .finish()
}

fn roster_item_element(
    jid: &str,
    name: Option<&str>,
    subscription: &str,
    ask: Option<&str>,
    approved: bool,
    groups: &[String],
    participant_id: Option<&str>,
) -> XmlElement {
    let mut item = XmlElement::new("item")
        .attr("jid", jid)
        .attr("subscription", subscription)
        .optional_attr("name", name)
        .optional_attr("ask", ask);
    if approved {
        item = item.attr("approved", "true");
    }
    for group in groups {
        item.push_child(XmlElement::new("group").text(group.clone()));
    }
    if let Some(participant_id) = participant_id {
        item.push_child(
            XmlElement::namespaced("channel", MIX_ROSTER_NS).attr("participant-id", participant_id),
        );
    }
    item
}

fn removed_roster_item_element(jid: &str) -> XmlElement {
    XmlElement::new("item")
        .attr("jid", jid)
        .attr("subscription", "remove")
}

fn roster_change_item_element(change: &RosterChange, participant_id: Option<&str>) -> XmlElement {
    if change.removed {
        return removed_roster_item_element(&change.contact_jid);
    }
    roster_item_element(
        &change.contact_jid,
        change.display_name.as_deref(),
        change.subscription.as_deref().unwrap_or("none"),
        change.ask.as_deref(),
        change.approved,
        &change.groups,
        participant_id,
    )
}

impl ProtocolSession {
    pub(crate) async fn roster_get(
        &mut self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if let Some(condition) = roster_target_error(
            iq.attribute("to"),
            &user.username,
            &self.state.config.domain,
            false,
        ) {
            return Ok(Action::Send(iq_error(id, condition)));
        }
        let annotations_requested = match validate_roster_get(query) {
            Ok(requested) => requested,
            Err(condition) => return Ok(Action::Send(iq_error(id, condition))),
        };
        let permit = match self.roster_sync.begin(
            &self.roster_requested,
            &self.mix_roster_annotations,
            annotations_requested,
        ) {
            Ok(permit) => permit,
            Err(BeginRosterSyncError::AlreadySynchronizing) => {
                return Ok(Action::Send(iq_error(id, "resource-constraint")));
            }
            Err(BeginRosterSyncError::Failed) => {
                self.disconnect.cancel();
                return Ok(Action::Send(iq_error(id, "resource-constraint")));
            }
        };
        let requested_version = query
            .attribute("ver")
            .and_then(|version| version.parse::<i64>().ok());
        let snapshot = match self
            .state
            .roster_service()
            .read_snapshot(
                user.id,
                user.auth_generation,
                requested_version,
                annotations_requested,
            )
            .await
        {
            Ok(RosterAuthorization::Authorized(snapshot)) => snapshot,
            Ok(RosterAuthorization::Unauthorized) => {
                self.roster_sync.fail(permit);
                self.disconnect.cancel();
                return Ok(Action::Send(iq_error(id, "not-authorized")));
            }
            Err(error) => {
                self.roster_sync.fail(permit);
                self.disconnect.cancel();
                return Err(error);
            }
        };
        let RosterReadSnapshot {
            version: current_version,
            items,
            changes,
            mix_participants,
        } = snapshot;
        let owner_jid = format!("{}@{}", user.username, self.state.config.domain);
        // A version-only empty result cannot convey newly requested MIX
        // annotations for cached items, so an opt-in request receives a full
        // roster snapshot. Unannotated requests keep normal XEP-0237 deltas.
        let target = self.full_jid.as_deref().unwrap_or_default().to_owned();
        let (response, initial_delta) = if let Some(changes) = changes {
            let pushes = changes
                .into_iter()
                .map(|change| {
                    let item = roster_change_item_element(&change, None);
                    roster_push_xml(&owner_jid, &target, change.version, item)
                })
                .collect::<Vec<_>>();
            (iq_result_from(id, &owner_jid, ""), pushes)
        } else {
            let mut query =
                XmlElement::namespaced("query", "jabber:iq:roster").attr("ver", current_version);
            for change in items {
                query.push_child(roster_item_element(
                    &change.contact_jid,
                    change.display_name.as_deref(),
                    change.subscription.as_deref().unwrap_or("none"),
                    change.ask.as_deref(),
                    change.approved,
                    &change.groups,
                    mix_participants
                        .get(&change.contact_jid)
                        .map(String::as_str),
                ));
            }
            let payload = query.finish();
            (iq_result_from(id, &owner_jid, &payload), Vec::new())
        };

        let state = Arc::clone(&self.state);
        let outbound = self.outbound.clone();
        let gate = Arc::clone(&self.roster_sync);
        let disconnect = self.disconnect.clone();
        self.defer_after_transport("roster-initial-sync", async move {
            flush_roster_sync(RosterSyncFlush {
                state,
                outbound,
                gate,
                disconnect,
                permit,
                snapshot_version: current_version,
                initial_delta,
                target,
            })
            .await;
        })?;
        Ok(Action::Send(response))
    }

    pub(crate) async fn roster_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if let Some(condition) = roster_target_error(
            iq.attribute("to"),
            &user.username,
            &self.state.config.domain,
            true,
        ) {
            return Ok(Action::Send(iq_error(id, condition)));
        }
        if query.attributes().len() != 0 || has_non_whitespace_text(query) {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let elements = query
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if elements.len() != 1
            || elements[0].tag_name().name() != "item"
            || elements[0].tag_name().namespace() != Some("jabber:iq:roster")
        {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let parsed = match parse_roster_set_item(elements[0]) {
            Ok(parsed) => parsed,
            Err(condition) => return Ok(Action::Send(iq_error(id, condition))),
        };
        if parsed.remove {
            let owner_jid = format!("{}@{}", user.username, self.state.config.domain);
            let contact_jid = crate::jid::CanonicalJid::parse_bare(&parsed.contact)?;
            let hosted_service = contact_jid.domainpart() == self.muc_domain()
                || contact_jid.domainpart() == self.upload_domain()
                || contact_jid.domainpart() == self.pubsub_domain();
            let unsubscribe = roster_removal_presence(&owner_jid, &parsed.contact, "unsubscribe");
            let unsubscribed = roster_removal_presence(&owner_jid, &parsed.contact, "unsubscribed");
            let remote = contact_jid.domainpart() != self.state.config.domain && !hosted_service;
            let route = if remote {
                RosterRemovalRoute::Remote {
                    target_domain: contact_jid.domainpart(),
                    unsubscribe_stanza: &unsubscribe,
                    unsubscribed_stanza: &unsubscribed,
                    bounce_to: Some(&owner_jid),
                    policy: self.state.federation.outbox_policy(),
                }
            } else {
                RosterRemovalRoute::Local {
                    owner_jid: &owner_jid,
                    contact_username: (contact_jid.domainpart() == self.state.config.domain)
                        .then(|| contact_jid.localpart())
                        .flatten(),
                }
            };
            let removal = match self
                .state
                .roster_service()
                .remove(user.id, user.auth_generation, &parsed.contact, route)
                .await?
            {
                RosterAuthorization::Authorized(Some(removal)) => removal,
                RosterAuthorization::Authorized(None) => {
                    return Ok(Action::Send(iq_error(id, "item-not-found")));
                }
                RosterAuthorization::Unauthorized => {
                    self.disconnect.cancel();
                    return Ok(Action::Send(iq_error(id, "not-authorized")));
                }
            };

            if remote && (removal.send_unsubscribe || removal.send_unsubscribed) {
                // Both cancellation rows committed with the roster removal;
                // this wake is only an edge trigger and restart recovery is
                // provided by the periodic durable-outbox poll.
                self.state.federation.wake_outbox();
            }
            if let Some(contact) = removal.local_contact.as_ref() {
                let target_jid = format!("{}@{}", contact.username, self.state.config.domain);
                // RFC 6121 subscription notifications precede the roster
                // state they caused. Preserve that order for every local and
                // clustered interested resource.
                if removal.send_unsubscribe {
                    deliver_roster_removal_presence(
                        &self.state,
                        user.id,
                        user.auth_generation,
                        contact.id,
                        contact.auth_generation,
                        &target_jid,
                        &unsubscribe,
                    )
                    .await;
                }
                if removal.send_unsubscribed {
                    deliver_roster_removal_presence(
                        &self.state,
                        user.id,
                        user.auth_generation,
                        contact.id,
                        contact.auth_generation,
                        &target_jid,
                        &unsubscribed,
                    )
                    .await;
                }
                if let Some(change) = removal.contact_change.as_ref() {
                    self.push_roster_change(contact.id, &contact.username, change, None)
                        .await?;
                }
            }
            self.push_roster_change(user.id, &user.username, &removal.owner_change, None)
                .await?;
        } else {
            let change = match self
                .state
                .roster_service()
                .upsert(
                    user.id,
                    user.auth_generation,
                    &parsed.contact,
                    parsed.name.as_deref(),
                    &parsed.groups,
                )
                .await?
            {
                RosterAuthorization::Authorized(change) => change,
                RosterAuthorization::Unauthorized => {
                    self.disconnect.cancel();
                    return Ok(Action::Send(iq_error(id, "not-authorized")));
                }
            };
            self.push_roster_change(user.id, &user.username, &change, None)
                .await?;
        }
        let owner_jid = format!("{}@{}", user.username, self.state.config.domain);
        Ok(Action::Send(iq_result_from(id, &owner_jid, "")))
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

fn roster_removal_presence(from: &str, to: &str, kind: &str) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind)
        .attr("id", uuid::Uuid::new_v4())
        .finish()
}

struct RosterSyncFlush {
    state: Arc<crate::state::AppState>,
    outbound: crate::outbound::OutboundSender,
    gate: Arc<RosterSyncGate>,
    disconnect: tokio_util::sync::CancellationToken,
    permit: RosterSyncPermit,
    snapshot_version: i64,
    initial_delta: Vec<String>,
    target: String,
}

async fn flush_roster_sync(request: RosterSyncFlush) {
    let RosterSyncFlush {
        state,
        outbound,
        gate,
        disconnect,
        permit,
        snapshot_version,
        initial_delta,
        target,
    } = request;
    async fn enqueue(outbound: &crate::outbound::OutboundSender, stanza: String) -> bool {
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
            state
                .metrics
                .post_accept_side_effect_failures_total
                .fetch_add(1, Ordering::Relaxed);
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
                        state
                            .metrics
                            .post_accept_side_effect_failures_total
                            .fetch_add(1, Ordering::Relaxed);
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
                state
                    .metrics
                    .post_accept_side_effect_failures_total
                    .fetch_add(1, Ordering::Relaxed);
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
                .and_then(|value| crate::jid::canonicalize_bare(value).ok())
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
    if let Ok(nodes) = state.cluster.lookup_nodes(target_bare).await {
        for node_id in nodes {
            if node_id != state.cluster.node_id {
                let _ = state
                    .cluster
                    .send_to_node_presence_subscription(
                        &node_id,
                        target_bare,
                        stanza,
                        false,
                        crate::cluster::ClusterPresenceAuthority {
                            owner_id,
                            owner_auth_generation,
                            recipient_id,
                            recipient_auth_generation,
                        },
                    )
                    .await;
            }
        }
    }
}

pub(crate) async fn deliver_roster_change(
    state: &crate::state::AppState,
    owner_id: uuid::Uuid,
    owner: &str,
    change: &RosterChange,
    participant_id: Option<&str>,
) -> Result<()> {
    let item = roster_change_item_element(change, None);
    let annotated = participant_id
        .map(|participant_id| roster_change_item_element(change, Some(participant_id)));
    let owner_jid = format!("{}@{}", owner, state.config.domain);
    for (target_jid, target) in state.session_entries_for(&owner_jid) {
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
                    state
                        .metrics
                        .post_accept_side_effect_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(owner = %owner_jid, target = %target_jid, version = change.version, ?error, "committed roster push did not enter the local resource queue; forcing a full resync");
                }
            }
            RosterPushDisposition::Overflow => {
                target.sender.disconnect_backpressured_transport();
                target.disconnect.cancel();
                state
                    .metrics
                    .post_accept_side_effect_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(owner = %owner_jid, target = %target_jid, version = change.version, "roster synchronization buffer overflowed; forcing a full resync");
            }
        }
    }
    // The immutable journal snapshot and exact committed version cross node
    // boundaries together; remote resources add their exact full-JID target.
    let push = roster_push_xml(&owner_jid, &owner_jid, change.version, item);
    let annotated_push = annotated
        .map(|annotated| roster_push_xml(&owner_jid, &owner_jid, change.version, annotated));
    match state.cluster.lookup_nodes(&owner_jid).await {
        Ok(nodes) => {
            for node_id in nodes {
                if node_id != state.cluster.node_id {
                    match state
                        .cluster
                        .send_to_node_roster(
                            &node_id,
                            &owner_jid,
                            owner_id,
                            change.version,
                            &push,
                            annotated_push.as_deref(),
                        )
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            state
                                .metrics
                                .post_accept_side_effect_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(owner = %owner_jid, remote_node = %node_id, version = change.version, "committed roster push was not accepted by the remote node; roster version recovery remains authoritative");
                        }
                        Err(error) => {
                            state
                                .metrics
                                .post_accept_side_effect_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(owner = %owner_jid, remote_node = %node_id, version = change.version, ?error, "committed roster push failed across the cluster; roster version recovery remains authoritative");
                        }
                    }
                }
            }
        }
        Err(error) => {
            state
                .metrics
                .post_accept_side_effect_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(owner = %owner_jid, version = change.version, ?error, "could not discover remote resources for a committed roster push; roster version recovery remains authoritative");
        }
    }
    Ok(())
}

fn roster_target_allowed(target: Option<&str>, username: &str, domain: &str) -> bool {
    target.is_none_or(|target| {
        crate::jid::CanonicalJid::parse_bare(target).is_ok_and(|jid| {
            jid.localpart() == Some(username)
                && jid.domainpart() == domain
                && jid.resourcepart().is_none()
        })
    })
}

fn roster_target_error(
    target: Option<&str>,
    username: &str,
    domain: &str,
    write: bool,
) -> Option<&'static str> {
    (!roster_target_allowed(target, username, domain)).then_some(if write {
        "forbidden"
    } else {
        "service-unavailable"
    })
}

fn validate_roster_get(query: Node<'_, '_>) -> std::result::Result<bool, &'static str> {
    if query
        .attributes()
        .any(|attribute| attribute.namespace().is_some() || attribute.name() != "ver")
        || has_non_whitespace_text(query)
    {
        return Err("bad-request");
    }
    let children = query
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if children.is_empty() {
        return Ok(false);
    }
    if children.len() != 1
        || children[0].tag_name().name() != "annotate"
        || children[0].tag_name().namespace() != Some(MIX_ROSTER_NS)
        || children[0].attributes().len() != 0
        || children[0].children().any(|node| node.is_element())
        || has_non_whitespace_text(children[0])
    {
        return Err("bad-request");
    }
    Ok(true)
}

fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .any(|text| !text.trim().is_empty())
}

fn roster_push_xml(from: &str, to: &str, version: i64, item: XmlElement) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "set")
        .attr("from", from)
        .attr("to", to)
        .attr("id", format!("roster-{}", stream_id()))
        .child(
            XmlElement::namespaced("query", "jabber:iq:roster")
                .attr("ver", version)
                .child(item),
        )
        .finish()
}

struct ParsedRosterSetItem {
    contact: String,
    name: Option<String>,
    groups: Vec<String>,
    remove: bool,
}

fn parse_roster_set_item(
    item: Node<'_, '_>,
) -> std::result::Result<ParsedRosterSetItem, &'static str> {
    if item.attributes().any(|attribute| {
        attribute.namespace().is_some()
            || !matches!(attribute.name(), "jid" | "name" | "subscription")
    }) || has_non_whitespace_text(item)
    {
        return Err("bad-request");
    }
    let jid = item.attribute("jid").ok_or("jid-malformed")?;
    if !valid_bare_jid(jid) {
        return Err("jid-malformed");
    }
    let contact = crate::jid::canonicalize_bare(jid)
        .expect("valid_bare_jid and canonicalize_bare use the same parser");
    let name = item.attribute("name");
    if name.is_some_and(|name| name.chars().count() > 128 || name.len() > 1_024) {
        return Err("not-acceptable");
    }
    let groups = parse_roster_groups(item)?;
    // RFC 6121 requires ignoring all client-supplied subscription values
    // except the special deletion token.
    let remove = item.attribute("subscription") == Some("remove");
    if remove && (name.is_some() || !groups.is_empty()) {
        return Err("bad-request");
    }
    Ok(ParsedRosterSetItem {
        contact,
        name: name.map(str::to_owned),
        groups,
        remove,
    })
}

fn parse_roster_groups(item: Node<'_, '_>) -> std::result::Result<Vec<String>, &'static str> {
    let mut seen = HashSet::new();
    let mut groups = Vec::new();
    let mut group_bytes = 0usize;
    for child in item.children().filter(|node| node.is_element()) {
        if child.tag_name().name() != "group"
            || child.tag_name().namespace() != Some("jabber:iq:roster")
            || child.attributes().len() != 0
            || child.children().any(|node| node.is_element())
        {
            return Err("bad-request");
        }
        let group = child.text().unwrap_or_default().to_owned();
        if group.trim().is_empty() || group.len() > 1_024 {
            return Err("not-acceptable");
        }
        if !seen.insert(group.clone()) {
            return Err("bad-request");
        }
        group_bytes = group_bytes.saturating_add(group.len());
        if groups.len() >= 64 || group_bytes > 16_384 {
            return Err("resource-constraint");
        }
        groups.push(group);
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn mix_roster_annotation_is_opt_in_and_carries_stable_id() {
        let plain = roster_item_xml("c@mix.example.test", None, "none", None, false, &[], None);
        assert_eq!(
            plain,
            "<item jid='c@mix.example.test' subscription='none'/>"
        );

        let annotated = roster_item_xml(
            "c@mix.example.test",
            Some("Channel"),
            "none",
            None,
            false,
            &[],
            Some("opaque-id"),
        );
        assert!(annotated.contains("urn:xmpp:mix:roster:0"));
        assert!(annotated.contains("participant-id='opaque-id'"));
        assert!(annotated.contains("name='Channel'"));
    }

    #[test]
    fn mix_roster_annotation_escapes_untrusted_values() {
        let item = roster_item_xml(
            "c@mix.example.test",
            Some("A&B"),
            "none",
            None,
            true,
            &["A <group>".to_owned()],
            Some("opaque'id"),
        );
        assert!(item.contains("name='A&amp;B'"));
        assert!(item.contains("participant-id='opaque&apos;id'"));
        assert!(item.contains("approved='true'"));
        assert!(item.contains("<group>A &lt;group&gt;</group>"));
    }

    #[test]
    fn roster_groups_and_client_owned_fields_follow_rfc_6121() {
        let document = Document::parse(
            "<item xmlns='jabber:iq:roster' jid='a@example.test' subscription='both'><group>Friends</group><group>仕事</group></item>",
        )
        .unwrap();
        let parsed = parse_roster_set_item(document.root_element()).unwrap();
        assert_eq!(parsed.groups, ["Friends".to_owned(), "仕事".to_owned()]);
        assert!(!parsed.remove, "non-remove subscription must be ignored");

        let duplicate = Document::parse(
            "<item xmlns='jabber:iq:roster' jid='a@example.test'><group>Friends</group><group>Friends</group></item>",
        )
        .unwrap();
        assert_eq!(
            parse_roster_set_item(duplicate.root_element()).err(),
            Some("bad-request")
        );

        let empty =
            Document::parse("<item xmlns='jabber:iq:roster' jid='a@example.test'><group/></item>")
                .unwrap();
        assert_eq!(
            parse_roster_set_item(empty.root_element()).err(),
            Some("not-acceptable")
        );
        let whitespace = Document::parse(
            "<item xmlns='jabber:iq:roster' jid='a@example.test'><group>   </group></item>",
        )
        .unwrap();
        assert_eq!(
            parse_roster_set_item(whitespace.root_element()).err(),
            Some("not-acceptable")
        );

        let long_name = format!(
            "<item xmlns='jabber:iq:roster' jid='a@example.test' name='{}'/>",
            "x".repeat(129)
        );
        let long_name = Document::parse(&long_name).unwrap();
        assert_eq!(
            parse_roster_set_item(long_name.root_element()).err(),
            Some("not-acceptable")
        );

        let long_group = format!(
            "<item xmlns='jabber:iq:roster' jid='a@example.test'><group>{}</group></item>",
            "x".repeat(1_025)
        );
        let long_group = Document::parse(&long_group).unwrap();
        assert_eq!(
            parse_roster_set_item(long_group.root_element()).err(),
            Some("not-acceptable")
        );

        let invalid = Document::parse(
            "<item xmlns='jabber:iq:roster' jid='a@example.test'><group><b/></group></item>",
        )
        .unwrap();
        assert_eq!(
            parse_roster_set_item(invalid.root_element()).err(),
            Some("bad-request")
        );
    }

    #[test]
    fn roster_targets_and_get_payload_are_strict() {
        assert!(roster_target_allowed(None, "alice", "example.test"));
        assert!(roster_target_allowed(
            Some("Alice@EXAMPLE.test"),
            "alice",
            "example.test"
        ));
        assert!(!roster_target_allowed(
            Some("bob@example.test"),
            "alice",
            "example.test"
        ));
        assert!(!roster_target_allowed(
            Some("alice@example.test/Phone"),
            "alice",
            "example.test"
        ));
        assert_eq!(
            roster_target_error(Some("bob@example.test"), "alice", "example.test", true),
            Some("forbidden")
        );
        assert_eq!(
            roster_target_error(Some("bob@example.test"), "alice", "example.test", false),
            Some("service-unavailable")
        );

        for (xml, expected) in [
            ("<query xmlns='jabber:iq:roster'/>", Ok(false)),
            ("<query xmlns='jabber:iq:roster' ver='opaque'/>", Ok(false)),
            (
                "<query xmlns='jabber:iq:roster'><annotate xmlns='urn:xmpp:mix:roster:0'/></query>",
                Ok(true),
            ),
            (
                "<query xmlns='jabber:iq:roster' extra='x'/>",
                Err("bad-request"),
            ),
            (
                "<query xmlns='jabber:iq:roster'><item jid='bob@example.test'/></query>",
                Err("bad-request"),
            ),
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(validate_roster_get(document.root_element()), expected);
        }
    }

    #[test]
    fn roster_push_uses_the_committed_snapshot_and_exact_target() {
        let change = RosterChange {
            version: 42,
            contact_jid: "bob@example.test".to_owned(),
            display_name: Some("B&B".to_owned()),
            subscription: Some("both".to_owned()),
            ask: None,
            groups: vec!["Friends".to_owned()],
            approved: true,
            removed: false,
        };
        let item = roster_change_item_element(&change, None);
        let push = roster_push_xml("alice@example.test", "alice@example.test/Phone", 42, item);
        assert!(push.contains("from='alice@example.test'"));
        assert!(push.contains("to='alice@example.test/Phone'"));
        assert!(push.contains("ver='42'"));
        assert!(push.contains("name='B&amp;B'"));
        assert!(push.contains("<group>Friends</group>"));
    }

    #[test]
    fn roster_output_round_trips_hostile_runtime_values_without_markup_injection() {
        let jid = "x'&<@example.test";
        let name = "name' /><injected xmlns='urn:evil'/>";
        let group = "<& already &amp; escaped-looking".to_owned();
        let participant = "p' /><injected/>";
        let item = roster_item_xml(
            jid,
            Some(name),
            "none",
            Some("subscribe"),
            true,
            std::slice::from_ref(&group),
            Some(participant),
        );
        let document = Document::parse(&item).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("jid"), Some(jid));
        assert_eq!(root.attribute("name"), Some(name));
        assert_eq!(root.children().filter(Node::is_element).count(), 2);
        let group_node = root
            .children()
            .find(|child| child.tag_name().name() == "group")
            .unwrap();
        assert_eq!(group_node.text(), Some(group.as_str()));
        let channel = root
            .children()
            .find(|child| child.tag_name().name() == "channel")
            .unwrap();
        assert_eq!(channel.attribute("participant-id"), Some(participant));
        assert!(document
            .descendants()
            .all(|node| !node.is_element() || node.tag_name().name() != "injected"));
    }
}
