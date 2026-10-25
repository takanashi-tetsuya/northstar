use super::{Action, ProtocolSession};
use crate::platform::jid_text::bare_jid;
use crate::services::presence::{
    LocalPresenceEffect, LocalSubscriptionRequest, PresenceMutation, PresencePolicyDenial,
    RemoteSubscriptionTransition,
};
use crate::services::privacy::PrivacyStanzaKind;
use crate::services::xml_util::*;
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
use roxmltree::Node;
use std::sync::{atomic::Ordering, Arc};

mod availability;
mod subscriptions;

#[cfg(test)]
use self::availability::{
    directed_presence_capacity_reached, directed_presence_target_is_outside_bare_scope,
    full_jid_probe_available_response,
};
use self::availability::{presence_probe_status_response, unsubscribed_probe_response};
use self::subscriptions::{
    should_resend_pending_outbound_subscription, stamped_subscription_presence,
    subscription_policy_error,
};

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
            let target_jid = match northstar_xmpp_types::jid::CanonicalJid::parse(raw_to) {
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
            let remote_domain = (target_domain != self.state.local_domain()
                && target_domain != self.muc_domain()
                && target_domain != self.upload_domain()
                && target_domain != self.pubsub_domain())
            .then_some(target_domain);
            if let Some(domain) = remote_domain {
                if !self.state.xmpp_external_route_domain_allowed(domain) {
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
                if subscription_kind && !self.state.xmpp_component_domain_configured(domain) {
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
                            .federation_outbox()
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
                    let target_bare = format!("{}@{}", target.username, self.state.local_domain());
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
                                .presence_probe_has_remote_owner(&target_bare)
                                .await?;
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
                    && !self
                        .state
                        .subscription_full_target_has_route(&canonical_to)
                        .await
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
                delivered |= self
                    .state
                    .route_directed_presence_remote(
                        &canonical_to,
                        &rewritten,
                        target_jid.resourcepart().is_none(),
                    )
                    .await;
                if delivered || kind == "unavailable" {
                    self.commit_directed_presence(directed_presence_plan);
                }
            }
        } else {
            // MIX presence is an account/resource epoch, not a best-effort
            // side effect. Serialize the database projection with the exact
            // in-memory availability/generation transition, then release the
            // per-resource gate before roster, federation and replay work.
            let mix_presence_epoch = Arc::clone(&self.presence.mix_presence_gate)
                .lock_owned()
                .await;
            if !super::mix::mix_presence_route_is_current(
                &self.state,
                &from,
                self.connection_id,
                &self.presence.mix_presence_gate,
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
            let account = format!("{}@{}", user.username, self.state.local_domain());
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
                let contact_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&jid).ok();
                let local_contact = match contact_jid.as_ref().and_then(|jid| jid.localpart()) {
                    Some(username)
                        if contact_jid
                            .as_ref()
                            .is_some_and(|jid| jid.domainpart() == self.state.local_domain()) =>
                    {
                        self.state
                            .presence_service()
                            .find_enabled_user(username)
                            .await?
                    }
                    _ => None,
                };
                if let Some(contact) = local_contact.as_ref() {
                    let contact_bare =
                        format!("{}@{}", contact.username, self.state.local_domain());
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
                        if contact.domainpart() == self.state.local_domain() {
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
                            self.state
                                .route_presence_subscription_remote(
                                    &jid,
                                    &request,
                                    crate::cluster::ClusterPresenceAuthority {
                                        owner_id: user.id,
                                        owner_auth_generation: user.auth_generation,
                                        recipient_id: local_contact.id,
                                        recipient_auth_generation: local_contact.auth_generation,
                                    },
                                )
                                .await;
                        } else if self
                            .state
                            .xmpp_external_route_domain_allowed(contact.domainpart())
                        {
                            let _ = self
                                .state
                                .federation_outbox()
                                .send(contact.domainpart(), request, Some(account.clone()))
                                .await;
                        }
                    }
                }
                if matches!(subscription.as_str(), "from" | "both") {
                    self.remove_directed_presence_for_bare(&jid);
                    let delivery = set_to(&rewritten, &jid);
                    if let Ok(contact) = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&jid) {
                        if contact.domainpart() == self.state.local_domain() {
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
                            self.state
                                .broadcast_available_presence_remote(&jid, &delivery)
                                .await;
                        } else if self
                            .state
                            .xmpp_external_route_domain_allowed(contact.domainpart())
                        {
                            let _ = self
                                .state
                                .federation_outbox()
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
            self.state
                .broadcast_available_presence_remote(&account, &account_delivery)
                .await;

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
                        .attr("from", self.state.local_domain())
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
                let replay_service = self.state.replay_service().clone();
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
                let account = account.clone();
                let bind2_mam_catchup = self.bind2_mam_catchup;
                let include_offline = priority >= 0 && !bind2_mam_catchup;
                self.defer_after_transport("available-offline-replay", async move {
                    super::replay::replay_newly_available_resource(
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
                let _ = self.pubsub_presence("available", &from).await?;
            } else if newly_offline_eligible && !self.bind2_mam_catchup {
                let replay_service = self.state.replay_service().clone();
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
                    super::replay::replay_newly_nonnegative_resource(
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
        }
        Ok(Action::None)
    }
}

pub(crate) fn directed_recipient_matches(authorized: &str, requester: &str) -> bool {
    northstar_presence_core::directed_recipient_matches(authorized, requester)
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

#[cfg(test)]
mod tests;
