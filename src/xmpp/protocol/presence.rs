use super::{Action, ProtocolSession};
use crate::services::presence::{
    LocalPresenceEffect, LocalSubscriptionRequest, PresenceMutation, PresencePolicyDenial,
    RemoteSubscriptionTransition,
};
use crate::services::privacy::PrivacyStanzaKind;
use crate::state::bare_jid;
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;
use roxmltree::Node;
use std::sync::{atomic::Ordering, Arc};

// Keep the live-session bound aligned with the durable XEP-0198 snapshot
// validator. An accepted directed presence must remain representable across
// suspend/resume so that the matching unavailable presence is not lost.

enum DirectedPresencePlan {
    None,
    Insert(String),
    Remove(String),
    RemoveBroadcastScope(String),
    AtCapacity,
}

enum SubscriptionMutationDisposition {
    Accepted(bool),
    Unauthorized,
    PolicyDenied(PresencePolicyDenial),
    Missing,
}

struct RemoteSubscriptionRequest<'a> {
    actor_id: uuid::Uuid,
    expected_auth_generation: i64,
    contact: &'a str,
    kind: &'a str,
    target_domain: &'a str,
    stanza: &'a str,
    bounce_to: &'a str,
}

impl ProtocolSession {
    pub(crate) async fn presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        if self.authenticated.is_none() {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        }
        let Some(from) = self.full_jid.clone() else {
            return Ok(Action::None);
        };
        let kind = root.attribute("type").unwrap_or("available");
        if let Some(raw_to) = root.attribute("to") {
            let target_jid = match crate::jid::CanonicalJid::parse(raw_to) {
                Ok(target) => target,
                Err(_) => return Ok(Action::Send(stanza_error(root, "modify", "jid-malformed"))),
            };
            let canonical_to = target_jid.to_string();
            let subscription_kind = matches!(
                kind,
                "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
            );
            let subscription_to = target_jid.bare();
            let to = if subscription_kind {
                subscription_to.as_str()
            } else {
                canonical_to.as_str()
            };
            let user = self.authenticated.as_ref().expect("authenticated session");
            if !subscription_kind {
                if self
                    .state
                    .presence_service()
                    .is_blocked_for_account(user.id, bare_jid(&from), to)
                    .await?
                {
                    return Ok(if kind == "error" {
                        Action::None
                    } else {
                        Action::Send(blocked_stanza_error(root))
                    });
                }
                let active_privacy = self
                    .privacy_active
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if self
                    .state
                    .privacy_service()
                    .denies(
                        user.id,
                        active_privacy.as_deref(),
                        to,
                        PrivacyStanzaKind::PresenceOut,
                    )
                    .await?
                {
                    return Ok(if kind == "error" {
                        Action::None
                    } else {
                        Action::Send(stanza_error(root, "cancel", "service-unavailable"))
                    });
                }
            }
            if let Some(action) = self.try_mix_presence(root, raw).await? {
                return Ok(action);
            }
            if target_jid.resourcepart().is_none()
                && target_jid.localpart().is_none()
                && target_jid.domainpart() == self.pubsub_domain()
            {
                return self.pubsub_presence(kind, &from).await;
            }
            if target_jid.domainpart() == self.muc_domain() {
                if kind == "available" {
                    let avatar_hash = self.state.presence_service().avatar_hash(user.id).await?;
                    let injected = inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref());
                    let document = roxmltree::Document::parse(&injected)?;
                    return self.muc_presence(document.root_element(), &injected).await;
                }
                return self.muc_presence(root, raw).await;
            }
            let target_domain = target_jid.domainpart();
            let remote_domain = (target_domain != self.state.config.domain
                && target_domain != self.muc_domain()
                && target_domain != self.upload_domain()
                && target_domain != self.pubsub_domain())
            .then_some(target_domain);
            if let Some(domain) = remote_domain {
                if !self.state.config.external_route_domain_allowed(domain) {
                    return Ok(Action::Send(stanza_error(
                        root,
                        "cancel",
                        "remote-server-not-found",
                    )));
                }
                let injected = if subscription_kind {
                    // Preserve an explicitly addressed remote resource so the
                    // authoritative receiving server can apply RFC 6121
                    // full-JID match/no-match rules. Roster state remains
                    // keyed by the contact's bare JID below.
                    stamped_subscription_presence(raw, bare_jid(&from), &canonical_to)
                } else if kind == "available" {
                    let avatar_hash = self.state.presence_service().avatar_hash(user.id).await?;
                    inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref())
                } else {
                    raw.to_owned()
                };
                let outbound = if subscription_kind {
                    injected
                } else {
                    set_from(&injected, &from)
                };
                let bounce_to = if subscription_kind {
                    bare_jid(&from).to_owned()
                } else {
                    from.to_owned()
                };
                let directed_presence_plan = self.plan_directed_presence(user, to, kind).await?;
                if matches!(&directed_presence_plan, DirectedPresencePlan::AtCapacity) {
                    return Ok(Action::Send(stanza_error(
                        root,
                        "wait",
                        "resource-constraint",
                    )));
                }
                if subscription_kind && !self.state.config.component_domain_configured(domain) {
                    match self
                        .update_remote_presence_subscription(RemoteSubscriptionRequest {
                            actor_id: user.id,
                            expected_auth_generation: user.auth_generation,
                            contact: subscription_to.as_str(),
                            kind,
                            target_domain: domain,
                            stanza: &outbound,
                            bounce_to: &bounce_to,
                        })
                        .await
                    {
                        Ok(SubscriptionMutationDisposition::Accepted(_)) => {}
                        Ok(SubscriptionMutationDisposition::Unauthorized) => {
                            self.disconnect.cancel();
                            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
                        }
                        Ok(SubscriptionMutationDisposition::PolicyDenied(reason)) => {
                            return Ok(Action::Send(subscription_policy_error(root, reason)));
                        }
                        Ok(SubscriptionMutationDisposition::Missing) => return Ok(Action::None),
                        Err(_) => {
                            return Ok(Action::Send(stanza_error(
                                root,
                                "wait",
                                "remote-server-timeout",
                            )));
                        }
                    }
                } else {
                    // External components are process-local routes rather than
                    // S2S peers. Pre-approvals and other suppressed transitions
                    // must not leak a stanza to the component.
                    let should_route = if subscription_kind {
                        match self
                            .update_component_presence_subscription(
                                user.id,
                                user.auth_generation,
                                subscription_to.as_str(),
                                kind,
                            )
                            .await?
                        {
                            SubscriptionMutationDisposition::Accepted(routed) => routed,
                            SubscriptionMutationDisposition::Unauthorized => {
                                self.disconnect.cancel();
                                return Ok(Action::Send(stanza_error(
                                    root,
                                    "auth",
                                    "not-authorized",
                                )));
                            }
                            SubscriptionMutationDisposition::PolicyDenied(reason) => {
                                return Ok(Action::Send(subscription_policy_error(root, reason)));
                            }
                            SubscriptionMutationDisposition::Missing => return Ok(Action::None),
                        }
                    } else {
                        true
                    };
                    if should_route
                        && !self
                            .state
                            .federation
                            .send(domain, outbound, Some(bounce_to))
                            .await
                    {
                        return Ok(Action::Send(stanza_error(
                            root,
                            "wait",
                            "remote-server-timeout",
                        )));
                    }
                }
                self.commit_directed_presence(directed_presence_plan);
                return Ok(Action::None);
            }
            let target_user = match target_jid.localpart() {
                Some(target_name) => {
                    self.state
                        .presence_service()
                        .find_enabled_user(target_name)
                        .await?
                }
                None => None,
            };
            if !subscription_kind {
                if let Some(target) = &target_user {
                    let target_bare = format!("{}@{}", target.username, self.state.config.domain);
                    if self
                        .state
                        .presence_service()
                        .is_blocked_for_account(target.id, &target_bare, &from)
                        .await?
                    {
                        return Ok(Action::None);
                    }
                }
            }
            // RFC 6121 presence probes are authorization checks performed by
            // the recipient's server.  Forwarding a client probe to the
            // target resource would delegate that check to clients and can
            // expose presence to an unsubscribed requester.
            if kind == "probe" {
                let target_bare = target_jid.bare();
                let probe_id = root.attribute("id");
                if let Some(target) = target_user {
                    let requester_bare = bare_jid(&from);
                    let authorized = self
                        .state
                        .presence_service()
                        .roster_subscription(target.id, requester_bare)
                        .await?
                        .is_some_and(|subscription| {
                            matches!(subscription.as_str(), "from" | "both")
                        });
                    if authorized {
                        if target_jid.resourcepart().is_some() {
                            self.answer_authorized_full_presence_probe(
                                &canonical_to,
                                &target_bare,
                                &from,
                                probe_id,
                            )
                            .await?;
                        } else {
                            let local_available = self
                                .state
                                .session_entries_for(&target_bare)
                                .into_iter()
                                .any(|(_, session)| session.available.load(Ordering::Acquire));
                            let delegated = self
                                .state
                                .cluster
                                .lookup_nodes(&target_bare)
                                .await?
                                .iter()
                                .any(|node_id| node_id != &self.state.cluster.node_id);
                            self.send_current_availability(&target_bare, &from).await;
                            if !local_available && !delegated {
                                let _ = self.outbound.try_send(presence_probe_status_response(
                                    &target_bare,
                                    &from,
                                    "unavailable",
                                    probe_id,
                                ));
                            }
                        }
                    } else if target_jid.resourcepart().is_some()
                        && self
                            .answer_directed_presence_probe(
                                &canonical_to,
                                &target_bare,
                                &from,
                                probe_id,
                            )
                            .await?
                    {
                        return Ok(Action::None);
                    } else {
                        let _ = self.outbound.try_send(unsubscribed_probe_response(
                            &target_bare,
                            &from,
                            probe_id,
                        ));
                    }
                } else {
                    let _ = self.outbound.try_send(unsubscribed_probe_response(
                        &target_bare,
                        &from,
                        probe_id,
                    ));
                }
                return Ok(Action::None);
            }
            let directed_presence_plan = self
                .plan_directed_presence(user, &canonical_to, kind)
                .await?;
            if matches!(&directed_presence_plan, DirectedPresencePlan::AtCapacity) {
                return Ok(Action::Send(stanza_error(
                    root,
                    "wait",
                    "resource-constraint",
                )));
            }
            let should_route = if matches!(
                kind,
                "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
            ) {
                if target_jid.resourcepart().is_some()
                    && kind != "subscribe"
                    && self.state.sessions_for(&canonical_to).is_empty()
                    && self
                        .state
                        .cluster
                        .lookup_nodes(&canonical_to)
                        .await
                        .map_or(true, |nodes| nodes.is_empty())
                {
                    return Ok(Action::None);
                }
                match self
                    .update_presence_subscription(
                        user.id,
                        &user.username,
                        user.auth_generation,
                        to,
                        kind,
                        raw,
                    )
                    .await
                {
                    Ok(SubscriptionMutationDisposition::Accepted(route)) => route,
                    Ok(SubscriptionMutationDisposition::Unauthorized) => {
                        self.disconnect.cancel();
                        return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
                    }
                    Ok(SubscriptionMutationDisposition::PolicyDenied(reason)) => {
                        return Ok(Action::Send(subscription_policy_error(root, reason)));
                    }
                    Ok(SubscriptionMutationDisposition::Missing) => false,
                    Err(error) => {
                        tracing::warn!(?error, actor_id = %user.id, %to, %kind, "presence subscription mutation failed before acceptance");
                        return Ok(Action::Send(stanza_error(
                            root,
                            "wait",
                            "internal-server-error",
                        )));
                    }
                }
            } else {
                true
            };
            if should_route {
                let injected = if subscription_kind {
                    stamped_subscription_presence(raw, bare_jid(&from), to)
                } else if kind == "available" {
                    let avatar_hash = self.state.presence_service().avatar_hash(user.id).await?;
                    inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref())
                } else {
                    raw.to_owned()
                };
                let rewritten = if subscription_kind {
                    injected
                } else {
                    set_from(&injected, &from)
                };
                let mut targets = self.state.session_entries_for(to);
                if target_jid.resourcepart().is_none() {
                    targets.retain(|(_, target)| target.available.load(Ordering::Relaxed));
                }
                let mut delivered = false;
                for (_, target) in targets {
                    if self
                        .state
                        .privacy_allows_session(&target, &from, PrivacyStanzaKind::PresenceIn)
                        .await?
                        && target.sender.try_send(rewritten.clone()).is_ok()
                    {
                        delivered = true;
                    }
                }
                if let Ok(nodes) = self.state.cluster.lookup_nodes(&canonical_to).await {
                    for node_id in nodes {
                        if node_id == self.state.cluster.node_id {
                            continue;
                        }
                        let accepted = if target_jid.resourcepart().is_none() {
                            self.state
                                .cluster
                                .send_to_node_available_presence(
                                    &node_id,
                                    &canonical_to,
                                    &rewritten,
                                )
                                .await
                                .unwrap_or(false)
                        } else {
                            self.state
                                .cluster
                                .send_to_node(&node_id, &canonical_to, &rewritten, false, None)
                                .await
                                .unwrap_or(false)
                        };
                        delivered |= accepted;
                    }
                }
                if delivered || kind == "unavailable" {
                    self.commit_directed_presence(directed_presence_plan);
                }
            }
        } else {
            // MIX presence is an account/resource epoch, not a best-effort
            // side effect. Serialize the database projection with the exact
            // in-memory availability/generation transition, then release the
            // per-resource gate before roster, federation and replay work.
            let mix_presence_epoch = Arc::clone(&self.mix_presence_gate).lock_owned().await;
            if !super::mix::mix_presence_route_is_current(
                &self.state,
                &from,
                self.connection_id,
                &self.mix_presence_gate,
                false,
            ) {
                return Ok(Action::None);
            }
            let advertised_mix_capability = self.advertised_mix_capability(root, &from);
            self.forward_presence_to_mix_channels(kind, advertised_mix_capability, raw)
                .await?;
            if matches!(kind, "available" | "unavailable") {
                // A broadcast transition supersedes every earlier directed
                // per-channel suppression for this resource.
                self.mix_presence_fallback_suppressed.clear();
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
                self.availability_generation.fetch_add(1, Ordering::AcqRel) + 1
            } else {
                self.availability_generation.load(Ordering::Acquire)
            };
            if let Some(available) = &self.available {
                available.store(now_available, Ordering::Release);
            }
            self.commit_caps_observation(root, &from);
            drop(mix_presence_epoch);
            let show = if kind == "available" {
                match child_text(root, "show") {
                    Some("away") => 2,
                    Some("chat") => 3,
                    Some("dnd") => 4,
                    Some("xa") => 5,
                    _ => 1,
                }
            } else {
                0
            };
            self.show.store(show, Ordering::Relaxed);
            let priority = if kind == "available" {
                child_text(root, "priority")
                    .and_then(|value| value.parse::<i16>().ok())
                    .filter(|value| (-128..=127).contains(value))
                    .unwrap_or(0)
            } else {
                0
            };
            self.priority.store(priority, Ordering::Relaxed);
            // XEP-0160 delivers the offline queue on the first available
            // presence whose priority is nonnegative. A resource is allowed
            // to announce priority -1 first and later raise it without an
            // intervening unavailable presence, so availability alone is not
            // sufficient to identify this transition.
            let newly_offline_eligible = offline_replay_became_eligible(
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
                Some(self.state.presence_service().replay_cutoff().await?)
            } else {
                None
            };
            let roster = self.state.blocking_service().roster(user.id).await?;
            let injected = if kind == "available" {
                let avatar_hash = self.state.presence_service().avatar_hash(user.id).await?;
                inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref())
            } else {
                raw.to_owned()
            };
            let rewritten = set_from(&injected, &from);
            *self
                .last_presence
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                (kind == "available").then(|| rewritten.clone());
            let account = format!("{}@{}", user.username, self.state.config.domain);
            let active_privacy = self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            for (jid, _, subscription, ask) in roster {
                if self
                    .state
                    .presence_service()
                    .outbound_denied(user.id, bare_jid(&from), active_privacy.as_deref(), &jid)
                    .await?
                {
                    continue;
                }
                let contact_jid = crate::jid::CanonicalJid::parse_bare(&jid).ok();
                let local_contact = match contact_jid.as_ref().and_then(|jid| jid.localpart()) {
                    Some(username)
                        if contact_jid
                            .as_ref()
                            .is_some_and(|jid| jid.domainpart() == self.state.config.domain) =>
                    {
                        self.state
                            .presence_service()
                            .find_enabled_user(username)
                            .await?
                    }
                    _ => None,
                };
                if let Some(contact) = local_contact.as_ref() {
                    let contact_bare = format!("{}@{}", contact.username, self.state.config.domain);
                    if self
                        .state
                        .presence_service()
                        .is_blocked_for_account(contact.id, &contact_bare, &from)
                        .await?
                    {
                        continue;
                    }
                }
                if should_resend_pending_outbound_subscription(first_available, ask.as_deref()) {
                    // RFC 6121 section 3.1.2 recommends re-sending every
                    // outstanding outbound subscription request when a
                    // resource sends initial presence. Roster state remains
                    // unchanged: this is delivery recovery, not a second
                    // subscription transition. Blocking/privacy checks above
                    // remain authoritative for both local and federated
                    // destinations.
                    let request = XmlElement::namespaced("presence", "jabber:client")
                        .attr("from", &account)
                        .attr("to", &jid)
                        .attr("type", "subscribe")
                        .finish();
                    if let Some(contact) = contact_jid.as_ref() {
                        if contact.domainpart() == self.state.config.domain {
                            let Some(local_contact) = local_contact.as_ref() else {
                                continue;
                            };
                            for (target_full, target) in self
                                .state
                                .session_entries_for(&jid)
                                .into_iter()
                                .filter(|(_, target)| {
                                    target.user_id == local_contact.id
                                        && target.auth_generation == local_contact.auth_generation
                                        && target.available.load(Ordering::Acquire)
                                })
                            {
                                if self
                                    .state
                                    .privacy_allows_session(
                                        &target,
                                        &account,
                                        PrivacyStanzaKind::PresenceIn,
                                    )
                                    .await?
                                {
                                    let _ = target.sender.try_send(set_to(&request, &target_full));
                                }
                            }
                            if let Ok(nodes) = self.state.cluster.lookup_nodes(&jid).await {
                                for node_id in nodes {
                                    if node_id != self.state.cluster.node_id {
                                        let _ = self
                                            .state
                                            .cluster
                                            .send_to_node_presence_subscription(
                                                &node_id,
                                                &jid,
                                                &request,
                                                false,
                                                crate::cluster::ClusterPresenceAuthority {
                                                    owner_id: user.id,
                                                    owner_auth_generation: user.auth_generation,
                                                    recipient_id: local_contact.id,
                                                    recipient_auth_generation: local_contact
                                                        .auth_generation,
                                                },
                                            )
                                            .await;
                                    }
                                }
                            }
                        } else if self
                            .state
                            .config
                            .external_route_domain_allowed(contact.domainpart())
                        {
                            let _ = self
                                .state
                                .federation
                                .send(contact.domainpart(), request, Some(account.clone()))
                                .await;
                        }
                    }
                }
                if matches!(subscription.as_str(), "from" | "both") {
                    self.remove_directed_presence_for_bare(&jid);
                    let delivery = set_to(&rewritten, &jid);
                    if let Ok(contact) = crate::jid::CanonicalJid::parse_bare(&jid) {
                        if contact.domainpart() == self.state.config.domain {
                            for (_, target) in self
                                .state
                                .session_entries_for(&jid)
                                .into_iter()
                                .filter(|(_, target)| target.available.load(Ordering::Relaxed))
                            {
                                if self
                                    .state
                                    .privacy_allows_session(
                                        &target,
                                        &from,
                                        PrivacyStanzaKind::PresenceIn,
                                    )
                                    .await?
                                {
                                    let _ = target.sender.try_send(delivery.clone());
                                }
                            }
                            if let Ok(nodes) = self.state.cluster.lookup_nodes(&jid).await {
                                for node_id in nodes {
                                    if node_id != self.state.cluster.node_id {
                                        let _ = self
                                            .state
                                            .cluster
                                            .send_to_node_available_presence(
                                                &node_id, &jid, &delivery,
                                            )
                                            .await;
                                    }
                                }
                            }
                        } else if self
                            .state
                            .config
                            .external_route_domain_allowed(contact.domainpart())
                        {
                            let _ = self
                                .state
                                .federation
                                .send(contact.domainpart(), delivery, Some(from.to_owned()))
                                .await;
                        }
                    }
                }
                if should_probe_contact_on_presence(first_available, &subscription) {
                    self.probe_contact_presence(&jid, &account).await;
                }
            }

            // RFC 6121 requires every available resource of the same account
            // to observe initial/subsequent presence. Unavailable presence is
            // also echoed to the resource that generated it.
            for (jid, target) in self.state.session_entries_for(&account) {
                if target.available.load(Ordering::Relaxed) || jid == from {
                    let _ = target.sender.try_send(set_to(&rewritten, &jid));
                }
            }
            let account_delivery = set_to(&rewritten, &account);
            if let Ok(nodes) = self.state.cluster.lookup_nodes(&account).await {
                for node_id in nodes {
                    if node_id != self.state.cluster.node_id {
                        let _ = self
                            .state
                            .cluster
                            .send_to_node_available_presence(&node_id, &account, &account_delivery)
                            .await;
                    }
                }
            }

            if kind == "unavailable" {
                self.broadcast_directed_unavailable(&rewritten, &from).await;
            }

            if first_available {
                for claim in self
                    .state
                    .presence_service()
                    .claim_service_messages(user.id)
                    .await?
                {
                    let subject = if claim.kind() == "motd" {
                        "Message of the Day"
                    } else {
                        "Welcome"
                    };
                    let notice = XmlElement::namespaced("message", "jabber:client")
                        .attr("from", &self.state.config.domain)
                        .attr("to", &from)
                        .attr("type", "headline")
                        .attr("id", uuid::Uuid::new_v4())
                        .child(XmlElement::new("subject").text(subject))
                        .child(XmlElement::new("body").text(claim.body()))
                        .finish();
                    self.outbound
                        .send(notice)
                        .await
                        .map_err(|_| anyhow::anyhow!("client delivery queue closed"))?;
                    if !self
                        .state
                        .presence_service()
                        .complete_service_message_claim(user.id, &claim)
                        .await?
                    {
                        tracing::warn!(
                            kind = %claim.kind(),
                            user_id = %user.id,
                            "service-message delivery lease changed after queue acceptance"
                        );
                    }
                }
                let state = self.state.clone();
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
                let generation = self.availability_generation.clone();
                let recipient_id = user.id;
                let full_jid = from.clone();
                let account = account.clone();
                let bind2_mam_catchup = self.bind2_mam_catchup;
                let include_offline = priority >= 0 && !bind2_mam_catchup;
                self.defer_after_transport("available-offline-replay", async move {
                    super::replay::replay_newly_available_resource(
                        state,
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
                let _ = self.pubsub_presence("available", &from).await?;
            } else if newly_offline_eligible && !self.bind2_mam_catchup {
                let state = self.state.clone();
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
                let generation = self.availability_generation.clone();
                let recipient_id = user.id;
                let full_jid = from.clone();
                let offline_replay_cutoff = offline_replay_cutoff
                    .expect("newly eligible legacy replay captured a database cutoff");
                self.defer_after_transport("nonnegative-offline-replay", async move {
                    super::replay::replay_newly_nonnegative_resource(
                        state,
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
        }
        Ok(Action::None)
    }

    async fn update_remote_presence_subscription(
        &self,
        request: RemoteSubscriptionRequest<'_>,
    ) -> Result<SubscriptionMutationDisposition> {
        let RemoteSubscriptionRequest {
            actor_id,
            expected_auth_generation,
            contact,
            kind,
            target_domain,
            stanza,
            bounce_to,
        } = request;
        let contact = crate::jid::canonicalize_bare(contact)?;
        let outcome = self
            .state
            .presence_service()
            .transition_remote_with_outbox(
                actor_id,
                expected_auth_generation,
                self.connection_id,
                &self.state.config.domain,
                &contact,
                kind,
                target_domain,
                stanza,
                Some(bounce_to),
                self.state.federation.outbox_policy(),
            )
            .await?;
        let transition = match outcome {
            PresenceMutation::Unauthorized => {
                return Ok(SubscriptionMutationDisposition::Unauthorized);
            }
            PresenceMutation::PolicyDenied(reason) => {
                return Ok(SubscriptionMutationDisposition::PolicyDenied(reason));
            }
            PresenceMutation::Missing => return Ok(SubscriptionMutationDisposition::Missing),
            PresenceMutation::Transition(transition) => transition,
        };
        if transition.routed {
            self.state.federation.wake_outbox();
        }
        self.finish_remote_presence_transition(&contact, transition)
            .await;
        Ok(SubscriptionMutationDisposition::Accepted(false))
    }

    async fn update_component_presence_subscription(
        &self,
        actor_id: uuid::Uuid,
        expected_auth_generation: i64,
        contact: &str,
        kind: &str,
    ) -> Result<SubscriptionMutationDisposition> {
        let contact = crate::jid::canonicalize_bare(contact)?;
        let outcome = self
            .state
            .presence_service()
            .transition_remote(
                actor_id,
                expected_auth_generation,
                self.connection_id,
                &self.state.config.domain,
                &contact,
                kind,
            )
            .await?;
        let transition = match outcome {
            PresenceMutation::Unauthorized => {
                return Ok(SubscriptionMutationDisposition::Unauthorized);
            }
            PresenceMutation::PolicyDenied(reason) => {
                return Ok(SubscriptionMutationDisposition::PolicyDenied(reason));
            }
            PresenceMutation::Missing => return Ok(SubscriptionMutationDisposition::Missing),
            PresenceMutation::Transition(transition) => transition,
        };
        let routed = transition.routed;
        self.finish_remote_presence_transition(&contact, transition)
            .await;
        Ok(SubscriptionMutationDisposition::Accepted(routed))
    }

    async fn finish_remote_presence_transition(
        &self,
        contact: &str,
        transition: RemoteSubscriptionTransition,
    ) {
        if let Some(change) = transition.change.as_ref() {
            if let Err(error) = self
                .push_roster_change(
                    transition.actor.id,
                    &transition.actor.username,
                    change,
                    None,
                )
                .await
            {
                tracing::warn!(
                    owner = %transition.actor.username,
                    version = change.version,
                    ?error,
                    "failed to deliver committed federated roster transition"
                );
            }
        }
        if matches!(transition.subscription.as_str(), "from" | "both") {
            self.remove_directed_presence_for_bare(contact);
        }
    }

    async fn update_presence_subscription(
        &self,
        actor_id: uuid::Uuid,
        actor_username: &str,
        expected_auth_generation: i64,
        target_jid: &str,
        kind: &str,
        raw: &str,
    ) -> Result<SubscriptionMutationDisposition> {
        let target_jid = crate::jid::CanonicalJid::parse_bare(target_jid)?;
        if target_jid.domainpart() != self.state.config.domain {
            return Ok(SubscriptionMutationDisposition::Missing);
        }
        let Some(target_name) = target_jid.localpart() else {
            return Ok(SubscriptionMutationDisposition::Missing);
        };
        let actor_jid = format!("{}@{}", actor_username, self.state.config.domain);
        let target_jid = format!("{}@{}", target_name, self.state.config.domain);
        let stamped_stanza = set_to(&set_from(raw, &actor_jid), &target_jid);
        let outcome = self
            .state
            .presence_service()
            .transition_local(LocalSubscriptionRequest {
                actor_id,
                expected_auth_generation,
                connection_id: self.connection_id,
                local_domain: &self.state.config.domain,
                target_username: target_name,
                kind,
                stanza: &stamped_stanza,
            })
            .await?;
        let transition = match outcome {
            PresenceMutation::Unauthorized => {
                return Ok(SubscriptionMutationDisposition::Unauthorized);
            }
            PresenceMutation::PolicyDenied(reason) => {
                return Ok(SubscriptionMutationDisposition::PolicyDenied(reason));
            }
            PresenceMutation::Missing => return Ok(SubscriptionMutationDisposition::Missing),
            PresenceMutation::Transition(transition) => transition,
        };
        let actor = transition.actor.clone();
        let target = transition.target.clone();
        let actor_jid = format!("{}@{}", actor.username, self.state.config.domain);
        let target_jid = format!("{}@{}", target.username, self.state.config.domain);
        let stamped_stanza = set_to(&set_from(raw, &actor_jid), &target_jid);

        // RFC 6121 requires the subscription notification to be delivered
        // before the resulting roster push.  Keep that ordering explicit here
        // instead of returning to the generic presence router (which cannot
        // distinguish available from roster-interested resources).
        match transition.effect {
            LocalPresenceEffect::AutoApproved => {
                let approved = XmlElement::namespaced("presence", "jabber:client")
                    .attr("from", &target_jid)
                    .attr("to", &actor_jid)
                    .attr("type", "subscribed")
                    .finish();
                let current = self.full_jid.as_deref();
                let active_privacy = self
                    .privacy_active
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if !self
                    .state
                    .privacy_service()
                    .denies(
                        actor.id,
                        active_privacy.as_deref(),
                        &target_jid,
                        PrivacyStanzaKind::PresenceIn,
                    )
                    .await?
                {
                    let _ = self.outbound.try_send(approved.clone());
                }
                for (jid, session) in self
                    .state
                    .session_entries_for(&actor_jid)
                    .into_iter()
                    .filter(|(_, session)| {
                        session.user_id == actor.id
                            && session.auth_generation == actor.auth_generation
                            && session.available.load(Ordering::Acquire)
                    })
                {
                    if current != Some(jid.as_str())
                        && self
                            .state
                            .privacy_allows_session(
                                &session,
                                &target_jid,
                                PrivacyStanzaKind::PresenceIn,
                            )
                            .await?
                    {
                        let _ = session.sender.try_send(approved.clone());
                    }
                }
                if let Ok(nodes) = self.state.cluster.lookup_nodes(&actor_jid).await {
                    for node_id in nodes {
                        if node_id != self.state.cluster.node_id {
                            let _ = self
                                .state
                                .cluster
                                .send_to_node_presence_subscription(
                                    &node_id,
                                    &actor_jid,
                                    &approved,
                                    false,
                                    crate::cluster::ClusterPresenceAuthority {
                                        owner_id: target.id,
                                        owner_auth_generation: target.auth_generation,
                                        recipient_id: actor.id,
                                        recipient_auth_generation: actor.auth_generation,
                                    },
                                )
                                .await;
                        }
                    }
                }
            }
            LocalPresenceEffect::Forward => {
                let mut targets = self.state.session_entries_for(&target_jid);
                // RFC 6121 subscription-related presence is delivered to
                // available resources independently of roster interest.
                // `roster_requested` gates roster pushes only; using it here
                // can drop the approval on the exact resource that just sent
                // the subscription request after reconnecting.
                targets.retain(|(_, session)| {
                    session.user_id == target.id
                        && session.auth_generation == target.auth_generation
                        && session.available.load(Ordering::Acquire)
                });
                for (target_full, session) in targets {
                    if self
                        .state
                        .privacy_allows_session(&session, &actor_jid, PrivacyStanzaKind::PresenceIn)
                        .await?
                    {
                        let _ = session
                            .sender
                            .try_send(set_to(&stamped_stanza, &target_full));
                    }
                }
                if let Ok(nodes) = self.state.cluster.lookup_nodes(&target_jid).await {
                    for node_id in nodes {
                        if node_id != self.state.cluster.node_id {
                            let _ = self
                                .state
                                .cluster
                                .send_to_node_presence_subscription(
                                    &node_id,
                                    &target_jid,
                                    &stamped_stanza,
                                    false,
                                    crate::cluster::ClusterPresenceAuthority {
                                        owner_id: actor.id,
                                        owner_auth_generation: actor.auth_generation,
                                        recipient_id: target.id,
                                        recipient_auth_generation: target.auth_generation,
                                    },
                                )
                                .await;
                        }
                    }
                }
            }
            LocalPresenceEffect::Suppressed => {}
        }

        if let Some(change) = transition.actor_change.as_ref() {
            if let Err(error) = self
                .push_roster_change(actor.id, &actor.username, change, None)
                .await
            {
                tracing::warn!(owner = %actor.username, version = change.version, ?error, "failed to deliver committed actor roster transition");
            }
        }
        if let Some(change) = transition.target_change.as_ref() {
            if let Err(error) = self
                .push_roster_change(target.id, &target.username, change, None)
                .await
            {
                tracing::warn!(owner = %target.username, version = change.version, ?error, "failed to deliver committed target roster transition");
            }
        }
        match transition.effect {
            LocalPresenceEffect::AutoApproved => {
                self.send_current_availability_exact(
                    &target_jid,
                    target.id,
                    target.auth_generation,
                    &actor_jid,
                    actor.id,
                    actor.auth_generation,
                )
                .await;
                return Ok(SubscriptionMutationDisposition::Accepted(false));
            }
            LocalPresenceEffect::Suppressed => {
                return Ok(SubscriptionMutationDisposition::Accepted(false));
            }
            LocalPresenceEffect::Forward => {}
        }
        if kind == "subscribe" && self.state.sessions_for(&target_jid).is_empty() {
            if let Err(error) =
                crate::xmpp::protocol::misc::send_push_notification(&self.state, target.id).await
            {
                tracing::warn!(target = %target.username, ?error, "failed to send post-commit subscription notification");
            }
        }
        if matches!(transition.actor_subscription.as_str(), "from" | "both") {
            self.remove_directed_presence_for_bare(&target_jid);
        }
        if kind == "subscribed" {
            self.send_current_availability_exact(
                &actor_jid,
                actor.id,
                actor.auth_generation,
                &target_jid,
                target.id,
                target.auth_generation,
            )
            .await;
        }
        // Subscription stanzas were routed above to preserve notification ->
        // roster-push ordering and exact interested-resource semantics.
        Ok(SubscriptionMutationDisposition::Accepted(false))
    }

    async fn plan_directed_presence(
        &self,
        user: &crate::services::authentication::AuthenticatedAccount,
        target: &str,
        kind: &str,
    ) -> Result<DirectedPresencePlan> {
        if kind == "unavailable" {
            return Ok(DirectedPresencePlan::Remove(target.to_owned()));
        }
        if kind != "available" {
            return Ok(DirectedPresencePlan::None);
        }
        let target_bare = crate::jid::canonical_bare_key(target)?;
        let receives_broadcast = self
            .available
            .as_ref()
            .is_some_and(|available| available.load(Ordering::Relaxed))
            && self
                .state
                .presence_service()
                .roster_subscription(user.id, &target_bare)
                .await?
                .is_some_and(|subscription| matches!(subscription.as_str(), "from" | "both"));
        if receives_broadcast {
            return Ok(DirectedPresencePlan::RemoveBroadcastScope(target_bare));
        }
        if self.directed_presence.contains(target) {
            return Ok(DirectedPresencePlan::None);
        }
        if directed_presence_capacity_reached(self.directed_presence.len(), false) {
            return Ok(DirectedPresencePlan::AtCapacity);
        }
        Ok(DirectedPresencePlan::Insert(target.to_owned()))
    }

    fn commit_directed_presence(&self, plan: DirectedPresencePlan) {
        match plan {
            DirectedPresencePlan::Insert(target) => {
                self.directed_presence.insert(target);
            }
            DirectedPresencePlan::Remove(target) => {
                self.directed_presence.remove(&target);
            }
            DirectedPresencePlan::RemoveBroadcastScope(target_bare) => {
                self.remove_directed_presence_for_bare(&target_bare);
            }
            DirectedPresencePlan::None | DirectedPresencePlan::AtCapacity => {}
        }
    }

    fn remove_directed_presence_for_bare(&self, target_bare: &str) {
        self.directed_presence
            .retain(|target| directed_presence_target_is_outside_bare_scope(target, target_bare));
    }

    async fn answer_directed_presence_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<bool> {
        let authorized =
            self.state
                .session_entries_for(owner_full)
                .into_iter()
                .any(|(_, owner)| {
                    owner
                        .directed_presence
                        .iter()
                        .any(|target| directed_recipient_matches(target.key(), requester))
                });
        if !authorized {
            return Ok(false);
        }
        self.answer_authorized_full_presence_probe(owner_full, owner_bare, requester, probe_id)
            .await?;
        Ok(true)
    }

    async fn answer_authorized_full_presence_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<()> {
        // RFC 6121 section 4.3.2 requires a full-JID probe response to
        // communicate only the availability fact.  Replaying last_presence
        // here would leak show/status/priority and arbitrary extensions.
        let requester_sessions = self.state.sessions_for(requester);
        let mut requester_allows = false;
        for requester_session in requester_sessions {
            if self
                .state
                .privacy_allows_session(
                    &requester_session,
                    owner_full,
                    PrivacyStanzaKind::PresenceIn,
                )
                .await?
            {
                requester_allows = true;
                break;
            }
        }
        if !requester_allows {
            return Ok(());
        }

        let owners = self.state.session_entries_for(owner_full);
        let mut available = false;
        let mut available_but_private = false;
        let mut original_presence_id = None;
        for (_, owner) in &owners {
            if !owner.available.load(Ordering::Acquire) {
                continue;
            }
            if self
                .state
                .privacy_allows_session(owner, requester, PrivacyStanzaKind::PresenceOut)
                .await?
            {
                available = true;
                if original_presence_id.is_none() {
                    original_presence_id = owner
                        .last_presence
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .as_deref()
                        .and_then(presence_id);
                }
            } else {
                available_but_private = true;
            }
        }
        if available {
            let _ = self.outbound.try_send(full_jid_probe_available_response(
                owner_full,
                requester,
                original_presence_id.as_deref(),
            ));
            return Ok(());
        }
        if available_but_private {
            return Ok(());
        }

        let owner_identity = crate::jid::CanonicalJid::parse(owner_full)
            .ok()
            .and_then(|jid| jid.localpart().map(str::to_owned));
        let recipient_identity = crate::jid::CanonicalJid::parse(requester)
            .ok()
            .and_then(|jid| jid.localpart().map(str::to_owned));
        let authority = match (owner_identity, recipient_identity) {
            (Some(owner), Some(recipient)) => self
                .state
                .presence_service()
                .find_enabled_user(&owner)
                .await?
                .zip(
                    self.state
                        .presence_service()
                        .find_enabled_user(&recipient)
                        .await?,
                )
                .map(
                    |(owner, recipient)| crate::cluster::ClusterPresenceAuthority {
                        owner_id: owner.id,
                        owner_auth_generation: owner.auth_generation,
                        recipient_id: recipient.id,
                        recipient_auth_generation: recipient.auth_generation,
                    },
                ),
            _ => None,
        };
        let mut delegated = false;
        for node_id in self.state.cluster.lookup_nodes(owner_full).await? {
            if node_id != self.state.cluster.node_id {
                if let Some(authority) = authority {
                    self.state
                        .cluster
                        .request_presence_probe_from_node(
                            &node_id, owner_full, requester, true, authority,
                        )
                        .await?;
                    delegated = true;
                }
            }
        }
        if !delegated {
            let _ = self.outbound.try_send(presence_probe_status_response(
                owner_bare,
                requester,
                "unavailable",
                probe_id,
            ));
        }
        Ok(())
    }

    async fn broadcast_directed_unavailable(&self, unavailable: &str, from: &str) {
        let targets = self
            .directed_presence
            .iter()
            .map(|target| target.key().clone())
            .collect::<Vec<_>>();
        self.directed_presence.clear();
        for target in targets {
            let delivery = set_to(unavailable, &target);
            let Ok(jid) = crate::jid::CanonicalJid::parse(&target) else {
                continue;
            };
            if jid.domainpart() == self.state.config.domain {
                let mut recipients = self.state.session_entries_for(&target);
                if jid.resourcepart().is_none() {
                    recipients.retain(|(_, session)| session.available.load(Ordering::Relaxed));
                }
                for (_, recipient) in recipients {
                    if self
                        .state
                        .privacy_allows_session(&recipient, from, PrivacyStanzaKind::PresenceIn)
                        .await
                        .unwrap_or(false)
                    {
                        let _ = recipient.sender.try_send(delivery.clone());
                    }
                }
            } else {
                let _ = self
                    .state
                    .federation
                    .send(jid.domainpart(), delivery, Some(from.to_owned()))
                    .await;
            }
        }
    }

    pub(crate) async fn send_current_availability(&self, owner: &str, recipient: &str) {
        self.send_current_availability_inner(owner, recipient, None, None, None, None)
            .await;
    }

    async fn send_current_availability_exact(
        &self,
        owner: &str,
        expected_owner_id: uuid::Uuid,
        expected_owner_auth_generation: i64,
        recipient: &str,
        expected_recipient_id: uuid::Uuid,
        expected_recipient_auth_generation: i64,
    ) {
        self.send_current_availability_inner(
            owner,
            recipient,
            Some(expected_owner_id),
            Some(expected_owner_auth_generation),
            Some(expected_recipient_id),
            Some(expected_recipient_auth_generation),
        )
        .await;
    }

    async fn send_current_availability_inner(
        &self,
        owner: &str,
        recipient: &str,
        expected_owner_id: Option<uuid::Uuid>,
        expected_owner_auth_generation: Option<i64>,
        expected_recipient_id: Option<uuid::Uuid>,
        expected_recipient_auth_generation: Option<i64>,
    ) {
        let Ok(owner_jid) = crate::jid::CanonicalJid::parse(owner) else {
            return;
        };
        let owner_bare = owner_jid.bare();
        let owner_full = owner_jid
            .resourcepart()
            .is_some()
            .then(|| owner_jid.to_string());
        let resolved_owner = if expected_owner_id.is_none() {
            match owner_jid.localpart() {
                Some(localpart) if owner_jid.domainpart() == self.state.config.domain => self
                    .state
                    .presence_service()
                    .find_enabled_user(localpart)
                    .await
                    .ok()
                    .flatten(),
                _ => None,
            }
        } else {
            None
        };
        let expected_owner_id = expected_owner_id.or_else(|| resolved_owner.as_ref().map(|a| a.id));
        let expected_owner_auth_generation = expected_owner_auth_generation
            .or_else(|| resolved_owner.as_ref().map(|a| a.auth_generation));
        let Ok(recipient_jid) = crate::jid::CanonicalJid::parse(recipient) else {
            return;
        };
        let resolved_recipient = if expected_recipient_id.is_none() {
            match recipient_jid.localpart() {
                Some(localpart) if recipient_jid.domainpart() == self.state.config.domain => self
                    .state
                    .presence_service()
                    .find_enabled_user(localpart)
                    .await
                    .ok()
                    .flatten(),
                _ => None,
            }
        } else {
            None
        };
        let expected_recipient_id =
            expected_recipient_id.or_else(|| resolved_recipient.as_ref().map(|a| a.id));
        let expected_recipient_auth_generation = expected_recipient_auth_generation
            .or_else(|| resolved_recipient.as_ref().map(|a| a.auth_generation));
        let (
            Some(expected_owner_id),
            Some(expected_owner_auth_generation),
            Some(expected_recipient_id),
            Some(expected_recipient_auth_generation),
        ) = (
            expected_owner_id,
            expected_owner_auth_generation,
            expected_recipient_id,
            expected_recipient_auth_generation,
        )
        else {
            return;
        };
        let authoritative_avatar_hash = {
            self.state
                .presence_service()
                .avatar_hash(expected_owner_id)
                .await
                .ok()
        };
        let Ok(recipient) = crate::jid::canonicalize(recipient) else {
            return;
        };
        let recipients = self
            .state
            .sessions_for(&recipient)
            .into_iter()
            .filter(|session| {
                session.user_id == expected_recipient_id
                    && session.auth_generation == expected_recipient_auth_generation
                    && session.available.load(Ordering::Acquire)
            })
            .collect::<Vec<_>>();
        for session in self.state.sessions.iter() {
            if !owner_full.as_ref().map_or_else(
                || {
                    crate::jid::canonical_bare_key(session.key())
                        .is_ok_and(|session_owner| session_owner == owner_bare)
                },
                |owner_full| session.key() == owner_full,
            ) || !session.value().routable.load(Ordering::Acquire)
                || session.value().user_id != expected_owner_id
                || session.value().auth_generation != expected_owner_auth_generation
                || !session.value().available.load(Ordering::Relaxed)
            {
                continue;
            }
            if !self
                .state
                .privacy_allows_session(session.value(), &recipient, PrivacyStanzaKind::PresenceOut)
                .await
                .unwrap_or(false)
            {
                continue;
            }
            let presence = session
                .value()
                .last_presence
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
                .map(|presence| {
                    let presence = authoritative_avatar_hash
                        .as_ref()
                        .and_then(|hash| {
                            let document = roxmltree::Document::parse(&presence).ok()?;
                            Some(inject_vcard_avatar_hash(
                                &presence,
                                document.root_element(),
                                hash.as_deref(),
                            ))
                        })
                        .unwrap_or(presence);
                    set_to(&presence, &recipient)
                })
                .unwrap_or_else(|| {
                    XmlElement::namespaced("presence", "jabber:client")
                        .attr("from", session.key())
                        .attr("to", &recipient)
                        .finish()
                });
            for recipient_session in &recipients {
                if self
                    .state
                    .privacy_allows_session(
                        recipient_session,
                        session.key(),
                        PrivacyStanzaKind::PresenceIn,
                    )
                    .await
                    .unwrap_or(false)
                {
                    let _ = recipient_session.sender.try_send(presence.clone());
                }
            }
        }
        let owner_lookup = owner_full.as_deref().unwrap_or(&owner_bare);
        let authority = crate::cluster::ClusterPresenceAuthority {
            owner_id: expected_owner_id,
            owner_auth_generation: expected_owner_auth_generation,
            recipient_id: expected_recipient_id,
            recipient_auth_generation: expected_recipient_auth_generation,
        };
        match self.state.cluster.lookup_nodes(owner_lookup).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.state.cluster.node_id {
                        continue;
                    }
                    if let Err(error) = self
                        .state
                        .cluster
                        .request_presence_probe_from_node(
                            &node_id,
                            owner_lookup,
                            &recipient,
                            owner_full.is_some(),
                            authority,
                        )
                        .await
                    {
                        self.state
                            .metrics
                            .cluster_presence_probe_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(?error, owner = %owner_lookup, %recipient, %node_id, "cross-node current-presence replay failed");
                    }
                }
            }
            Err(error) => {
                self.state
                    .metrics
                    .cluster_presence_probe_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(?error, owner = %owner_lookup, %recipient, "could not resolve current-presence owner nodes");
            }
        }
    }

    async fn probe_contact_presence(&self, contact: &str, requester_bare: &str) {
        let Ok(contact_jid) = crate::jid::CanonicalJid::parse_bare(contact) else {
            return;
        };
        if contact_jid.domainpart() == self.state.config.domain {
            self.send_current_availability(contact, requester_bare)
                .await;
            return;
        }
        if !self
            .state
            .config
            .external_route_domain_allowed(contact_jid.domainpart())
        {
            return;
        }
        let probe = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", requester_bare)
            .attr("to", contact)
            .attr("type", "probe")
            .finish();
        let _ = self
            .state
            .federation
            .send(
                contact_jid.domainpart(),
                probe,
                Some(requester_bare.to_owned()),
            )
            .await;
    }
}

fn should_resend_pending_outbound_subscription(first_available: bool, ask: Option<&str>) -> bool {
    northstar_presence_core::should_resend_pending_subscription(first_available, ask)
}

fn subscription_policy_error(root: Node<'_, '_>, reason: PresencePolicyDenial) -> String {
    match reason {
        PresencePolicyDenial::Blocking => blocked_stanza_error(root),
        PresencePolicyDenial::Privacy => stanza_error(root, "cancel", "service-unavailable"),
    }
}

pub(crate) fn directed_recipient_matches(authorized: &str, requester: &str) -> bool {
    northstar_presence_core::directed_recipient_matches(authorized, requester)
}

fn stamped_subscription_presence(raw: &str, from_bare: &str, to_bare: &str) -> String {
    set_to(&set_from(raw, from_bare), to_bare)
}

fn presence_id(raw: &str) -> Option<String> {
    let document = roxmltree::Document::parse(raw).ok()?;
    document
        .root_element()
        .attribute("id")
        .filter(|id| !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control))
        .map(str::to_owned)
}

fn full_jid_probe_available_response(
    owner_full: &str,
    requester: &str,
    original_presence_id: Option<&str>,
) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", owner_full)
        .attr("to", requester)
        .optional_attr("id", original_presence_id)
        .finish()
}

fn presence_probe_status_response(
    target_bare: &str,
    requester: &str,
    kind: &str,
    id: Option<&str>,
) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", target_bare)
        .attr("to", requester)
        .attr("type", kind)
        .optional_attr("id", id)
        .finish()
}

fn unsubscribed_probe_response(target_bare: &str, requester: &str, id: Option<&str>) -> String {
    presence_probe_status_response(target_bare, requester, "unsubscribed", id)
}

fn offline_replay_became_eligible(
    was_available: bool,
    previous_priority: i16,
    now_available: bool,
    priority: i16,
) -> bool {
    northstar_presence_core::offline_replay_became_eligible(
        was_available,
        previous_priority,
        now_available,
        priority,
    )
}

fn should_probe_contact_on_presence(first_available: bool, subscription: &str) -> bool {
    // RFC 6121 sections 4.2.2 and 4.3.1 tie automatic contact probes to the
    // start of a presence session. A subsequent status/show update must not
    // amplify into another roster-sized wave of probes.
    northstar_presence_core::should_probe_contact_on_presence(first_available, subscription)
}

fn directed_presence_capacity_reached(current: usize, already_present: bool) -> bool {
    northstar_presence_core::directed_presence_capacity_reached(current, already_present)
}

fn directed_presence_target_is_outside_bare_scope(target: &str, target_bare: &str) -> bool {
    northstar_presence_core::directed_presence_target_is_outside_bare_scope(target, target_bare)
}

#[cfg(test)]
mod tests {
    use super::{
        directed_presence_capacity_reached, directed_presence_target_is_outside_bare_scope,
        directed_recipient_matches, full_jid_probe_available_response,
        offline_replay_became_eligible, should_probe_contact_on_presence,
        should_resend_pending_outbound_subscription, stamped_subscription_presence,
        unsubscribed_probe_response,
    };

    #[test]
    fn offline_replay_starts_on_first_nonnegative_available_priority() {
        assert!(!offline_replay_became_eligible(false, 0, true, -1));
        assert!(offline_replay_became_eligible(true, -1, true, 0));
        assert!(offline_replay_became_eligible(false, 0, true, 0));
        assert!(!offline_replay_became_eligible(true, 0, true, 5));
        assert!(!offline_replay_became_eligible(true, -1, false, 0));
    }

    #[test]
    fn directed_presence_admission_matches_the_resume_snapshot_bound() {
        assert!(!directed_presence_capacity_reached(1_023, false));
        assert!(directed_presence_capacity_reached(1_024, false));
        assert!(!directed_presence_capacity_reached(1_024, true));
    }

    #[test]
    fn roster_broadcast_scope_removes_bare_and_full_directed_targets() {
        assert!(!directed_presence_target_is_outside_bare_scope(
            "Alice@BÜCHER.example/Phone",
            "alice@bücher.example",
        ));
        assert!(directed_presence_target_is_outside_bare_scope(
            "bob@example.test/Phone",
            "alice@example.test",
        ));
        assert!(!directed_presence_target_is_outside_bare_scope(
            "not a jid",
            "alice@example.test",
        ));
    }

    #[test]
    fn automatic_contact_probes_are_initial_presence_only() {
        assert!(should_probe_contact_on_presence(true, "to"));
        assert!(should_probe_contact_on_presence(true, "both"));
        assert!(!should_probe_contact_on_presence(false, "both"));
        assert!(!should_probe_contact_on_presence(true, "from"));
    }

    #[test]
    fn pending_outbound_subscriptions_are_recovered_on_initial_presence_only() {
        assert!(should_resend_pending_outbound_subscription(
            true,
            Some("subscribe")
        ));
        assert!(!should_resend_pending_outbound_subscription(
            false,
            Some("subscribe")
        ));
        assert!(!should_resend_pending_outbound_subscription(true, None));
    }

    #[test]
    fn directed_presence_authorization_is_bare_or_exact_resource_scoped() {
        assert!(directed_recipient_matches(
            "Alice@BÜCHER.example",
            "alice@bücher.example/Phone"
        ));
        assert!(directed_recipient_matches(
            "alice@example.test/Phone",
            "alice@example.test/Phone"
        ));
        assert!(!directed_recipient_matches(
            "alice@example.test/Phone",
            "alice@example.test/phone"
        ));
        assert!(!directed_recipient_matches(
            "alice@example.test/Phone",
            "alice@example.test/Tablet"
        ));
    }

    #[test]
    fn subscription_stamping_uses_bare_jids_and_preserves_extensions() {
        let stamped = stamped_subscription_presence(
            "<presence to='bob@example.test/Tablet' type='subscribe'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>",
            "alice@example.test",
            "bob@example.test",
        );
        assert!(stamped.contains("from='alice@example.test'"));
        assert!(stamped.contains("to='bob@example.test'"));
        assert!(!stamped.contains("Tablet"));
        assert!(stamped.contains("<nick xmlns='http://jabber.org/protocol/nick'>Alice</nick>"));
    }

    #[test]
    fn unauthorized_probe_response_does_not_expose_a_resource() {
        assert_eq!(
            unsubscribed_probe_response(
                "missing@example.test",
                "alice@example.test/Phone",
                Some("probe-1"),
            ),
            "<presence xmlns='jabber:client' from='missing@example.test' to='alice@example.test/Phone' type='unsubscribed' id='probe-1'/>"
        );
    }

    #[test]
    fn full_jid_probe_response_exposes_only_availability() {
        let response = full_jid_probe_available_response(
            "romeo@example.test/Phone",
            "alice@example.test/Tablet",
            Some("presence-1"),
        );
        assert_eq!(
            response,
            "<presence xmlns='jabber:client' from='romeo@example.test/Phone' to='alice@example.test/Tablet' id='presence-1'/>"
        );
        assert!(!response.contains("<show>"));
        assert!(!response.contains("<status>"));
        assert!(!response.contains("<priority>"));
    }
}
