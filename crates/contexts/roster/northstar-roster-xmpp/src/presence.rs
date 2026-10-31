//! RFC 6121 presence: directed presence, the broadcast of a resource's availability, probes and
//! subscriptions.

use anyhow::Result;
use northstar_roster_application::presence::{
    LocalPresenceEffect, LocalSubscriptionRequest, PresenceMutation, PresencePolicyDenial,
    PresenceRepository, PresenceService, RemoteSubscriptionTransition,
};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_core::PresenceAccount;
use northstar_xml_builder::rewrite::{set_from, set_to};
use northstar_xml_builder::stanza::{blocked_stanza_error, child_text, stanza_error};
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::CanonicalJid;
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
use std::future::Future;

use crate::blocking::BlockingSession;
use crate::privacy::PrivacySession;
use crate::roster::RosterSession;

mod availability;
mod avatar_update;
mod subscriptions;

pub use self::availability::{full_jid_probe_available_response, presence_probe_status_response};
pub use self::avatar_update::inject_vcard_avatar_hash;

use self::availability::{
    answer_directed_presence_probe, broadcast_directed_unavailable, commit_directed_presence,
    plan_directed_presence, probe_contact_presence, remove_directed_presence_for_bare,
    unsubscribed_probe_response,
};
#[cfg(test)]
use self::availability::{
    directed_presence_capacity_reached, directed_presence_target_is_outside_bare_scope,
};
use self::subscriptions::{
    should_resend_pending_outbound_subscription, stamped_subscription_presence,
    subscription_policy_error, update_component_presence_subscription,
    update_presence_subscription, update_remote_presence_subscription,
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

/// What a client session provides to the presence handlers, beyond its blocking, privacy and
/// roster capabilities. The fan-out over online sessions lives behind this trait until the
/// session context moves.
pub trait PresenceSession: BlockingSession + PrivacySession + RosterSession {
    /// The presence service, over the repository the composition root binds.
    fn presence_service(&self) -> &PresenceService<impl PresenceRepository>;
    /// Whether the session's resource is available.
    fn presence_is_available(&self) -> bool;
    /// Replaces the presence the session last broadcast.
    fn presence_set_last(&self, presence: Option<String>);
    /// Queues `stanza` to this session, dropping it when the queue is full.
    fn presence_try_send(&self, stanza: String);
    /// Queues `stanza` to this session, waiting for room.
    fn presence_send(&self, stanza: String) -> impl Future<Output = Result<()>> + Send;

    /// Whether the session sent directed presence to `target`.
    fn presence_directed_contains(&self, target: &str) -> bool;
    /// How many targets the session sent directed presence to.
    fn presence_directed_count(&self) -> usize;
    /// Records directed presence to `target`.
    fn presence_directed_insert(&self, target: String);
    /// Forgets directed presence to `target`.
    fn presence_directed_remove(&self, target: &str);
    /// Forgets directed presence to every target `keep` rejects.
    fn presence_directed_retain(&self, keep: impl Fn(&str) -> bool);
    /// Forgets every directed presence target and returns them.
    fn presence_directed_take(&self) -> Vec<String>;

    /// Whether stanzas may be routed to the external `domain`.
    fn presence_route_allowed(&self, domain: &str) -> bool;
    /// Whether `domain` is an external component of this server.
    fn presence_is_component_domain(&self, domain: &str) -> bool;
    /// Sends `stanza` towards the external `domain`. Returns whether it was accepted.
    fn presence_send_federated(
        &self,
        domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> impl Future<Output = bool> + Send;

    /// Delivers the directed presence `stanza` of `from` to `to` on this node, and to
    /// `canonical_to` on the others. A `bare_target` reaches only available resources. Returns
    /// whether a session accepted it.
    fn presence_deliver_directed(
        &self,
        to: &str,
        canonical_to: &str,
        from: &str,
        stanza: &str,
        bare_target: bool,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Delivers the subscription `stanza` of `owner` to the available resources of `recipient`,
    /// each addressed exactly, on this node and on the others.
    fn presence_deliver_subscription(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        stanza: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delivers the `approved` subscription of `owner` to the other available resources of
    /// `recipient`, the account of this session, on this node and on the others.
    fn presence_deliver_approval(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        approved: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delivers the broadcast `stanza` of `from` to the available resources of `contact`, a
    /// local account, on this node and on the others.
    fn presence_deliver_to_contact(
        &self,
        contact: &str,
        from: &str,
        stanza: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Echoes the broadcast `stanza` of the resource `from` to its own `account`, on this node
    /// and on the others.
    fn presence_echo_to_account(
        &self,
        account: &str,
        from: &str,
        stanza: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Delivers the unavailable `stanza` of `from` to the local directed-presence `target`. A
    /// `bare_target` reaches only available resources.
    fn presence_deliver_directed_unavailable(
        &self,
        target: &str,
        bare_target: bool,
        from: &str,
        stanza: &str,
    ) -> impl Future<Output = ()> + Send;

    /// Whether a resource of the local account `bare` is available on this node.
    fn presence_has_available_resource(&self, bare: &str) -> bool;
    /// Whether another node holds a resource of the local account `bare`.
    fn presence_probe_has_remote_owner(
        &self,
        bare: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Whether a local session of `owner_full` sent directed presence to `requester`.
    fn presence_directed_recipient(&self, owner_full: &str, requester: &str) -> bool;
    /// Answers a probe of `requester` for the resource `owner_full`, once it is authorized.
    fn presence_answer_full_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Sends the current availability of `owner` to `recipient`.
    fn presence_send_current(
        &self,
        owner: &str,
        recipient: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Sends the current availability of `owner` to `recipient`, for exactly these accounts.
    fn presence_send_current_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Whether another node routes the full JID.
    fn presence_full_target_routed(&self, full_jid: &str) -> impl Future<Output = bool> + Send;
    /// Tells the devices of an account without a session that something arrived.
    fn presence_notify_offline(
        &self,
        user_id: uuid::Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// The verdict on a directed presence before it is routed.
pub enum PresenceGate {
    /// The stanza goes on.
    Open,
    /// The stanza stops here, with this reply if there is one.
    Closed(Option<String>),
}

/// Evaluates blocking and privacy checks before directed presence is routed.
pub async fn directed_presence_gate<S: PresenceSession>(
    session: &S,
    root: Node<'_, '_>,
    target_jid: &CanonicalJid,
    kind: &str,
    from: &str,
) -> Result<PresenceGate> {
    let subscription_kind = matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    );
    if subscription_kind {
        return Ok(PresenceGate::Open);
    }
    let to = target_jid.to_string();
    let user = session.session_account().expect("authenticated session");
    if session
        .presence_service()
        .is_blocked_for_account(user.id, bare_jid(from), &to)
        .await?
    {
        return Ok(PresenceGate::Closed(if kind == "error" {
            None
        } else {
            Some(blocked_stanza_error(root))
        }));
    }
    let active_privacy = session.privacy_active_list();
    if session
        .privacy_service()
        .denies(
            user.id,
            active_privacy.as_deref(),
            &to,
            PrivacyStanzaKind::PresenceOut,
        )
        .await?
    {
        return Ok(PresenceGate::Closed(if kind == "error" {
            None
        } else {
            Some(stanza_error(root, "cancel", "service-unavailable"))
        }));
    }
    Ok(PresenceGate::Open)
}

/// Routes directed presence to remote domains, external components or local resources.
pub async fn route_directed_presence<S: PresenceSession>(
    session: &S,
    root: Node<'_, '_>,
    raw: &str,
    target_jid: &CanonicalJid,
    kind: &str,
    from: &str,
) -> Result<Option<String>> {
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
    let user = session.session_account().expect("authenticated session");
    let target_domain = target_jid.domainpart();
    let remote_domain = (target_domain != session.session_local_domain()
        && !session.roster_is_hosted_domain(target_domain))
    .then_some(target_domain);
    if let Some(domain) = remote_domain {
        if !session.presence_route_allowed(domain) {
            return Ok(Some(stanza_error(
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
            stamped_subscription_presence(raw, bare_jid(from), &canonical_to)
        } else if kind == "available" {
            let avatar_hash = session.presence_service().avatar_hash(user.id).await?;
            inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref())
        } else {
            raw.to_owned()
        };
        let outbound = if subscription_kind {
            injected
        } else {
            set_from(&injected, from)
        };
        let bounce_to = if subscription_kind {
            bare_jid(from).to_owned()
        } else {
            from.to_owned()
        };
        let directed_presence_plan = plan_directed_presence(session, &user, to, kind).await?;
        if matches!(&directed_presence_plan, DirectedPresencePlan::AtCapacity) {
            return Ok(Some(stanza_error(root, "wait", "resource-constraint")));
        }
        if subscription_kind && !session.presence_is_component_domain(domain) {
            match update_remote_presence_subscription(
                session,
                RemoteSubscriptionRequest {
                    actor_id: user.id,
                    expected_auth_generation: user.auth_generation,
                    contact: subscription_to.as_str(),
                    kind,
                    target_domain: domain,
                    stanza: &outbound,
                    bounce_to: &bounce_to,
                },
            )
            .await
            {
                Ok(SubscriptionMutationDisposition::Accepted(_)) => {}
                Ok(SubscriptionMutationDisposition::Unauthorized) => {
                    session.roster_disconnect();
                    return Ok(Some(stanza_error(root, "auth", "not-authorized")));
                }
                Ok(SubscriptionMutationDisposition::PolicyDenied(reason)) => {
                    return Ok(Some(subscription_policy_error(root, reason)));
                }
                Ok(SubscriptionMutationDisposition::Missing) => return Ok(None),
                Err(_) => {
                    return Ok(Some(stanza_error(root, "wait", "remote-server-timeout")));
                }
            }
        } else {
            // External components are process-local routes rather than
            // S2S peers. Pre-approvals and other suppressed transitions
            // must not leak a stanza to the component.
            let should_route = if subscription_kind {
                match update_component_presence_subscription(
                    session,
                    user.id,
                    user.auth_generation,
                    subscription_to.as_str(),
                    kind,
                )
                .await?
                {
                    SubscriptionMutationDisposition::Accepted(routed) => routed,
                    SubscriptionMutationDisposition::Unauthorized => {
                        session.roster_disconnect();
                        return Ok(Some(stanza_error(root, "auth", "not-authorized")));
                    }
                    SubscriptionMutationDisposition::PolicyDenied(reason) => {
                        return Ok(Some(subscription_policy_error(root, reason)));
                    }
                    SubscriptionMutationDisposition::Missing => return Ok(None),
                }
            } else {
                true
            };
            if should_route
                && !session
                    .presence_send_federated(domain, outbound, Some(bounce_to))
                    .await
            {
                return Ok(Some(stanza_error(root, "wait", "remote-server-timeout")));
            }
        }
        commit_directed_presence(session, directed_presence_plan);
        return Ok(None);
    }
    let target_user = match target_jid.localpart() {
        Some(target_name) => {
            session
                .presence_service()
                .find_enabled_user(target_name)
                .await?
        }
        None => None,
    };
    if !subscription_kind {
        if let Some(target) = &target_user {
            let target_bare = format!("{}@{}", target.username, session.session_local_domain());
            if session
                .presence_service()
                .is_blocked_for_account(target.id, &target_bare, from)
                .await?
            {
                return Ok(None);
            }
        }
    }
    // RFC 6121 presence probes are authorization checks performed by
    // the recipient's server. Forwarding a client probe to the
    // target resource would delegate that check to clients and can
    // expose presence to an unsubscribed requester.
    if kind == "probe" {
        let target_bare = target_jid.bare();
        let probe_id = root.attribute("id");
        if let Some(target) = target_user {
            let requester_bare = bare_jid(from);
            let authorized = session
                .presence_service()
                .roster_subscription(target.id, requester_bare)
                .await?
                .is_some_and(|subscription| matches!(subscription.as_str(), "from" | "both"));
            if authorized {
                if target_jid.resourcepart().is_some() {
                    session
                        .presence_answer_full_probe(&canonical_to, &target_bare, from, probe_id)
                        .await?;
                } else {
                    let local_available = session.presence_has_available_resource(&target_bare);
                    let delegated = session
                        .presence_probe_has_remote_owner(&target_bare)
                        .await?;
                    session.presence_send_current(&target_bare, from).await;
                    if !local_available && !delegated {
                        session.presence_try_send(presence_probe_status_response(
                            &target_bare,
                            from,
                            "unavailable",
                            probe_id,
                        ));
                    }
                }
            } else if target_jid.resourcepart().is_some()
                && answer_directed_presence_probe(
                    session,
                    &canonical_to,
                    &target_bare,
                    from,
                    probe_id,
                )
                .await?
            {
                return Ok(None);
            } else {
                session.presence_try_send(unsubscribed_probe_response(
                    &target_bare,
                    from,
                    probe_id,
                ));
            }
        } else {
            session.presence_try_send(unsubscribed_probe_response(&target_bare, from, probe_id));
        }
        return Ok(None);
    }
    let directed_presence_plan =
        plan_directed_presence(session, &user, &canonical_to, kind).await?;
    if matches!(&directed_presence_plan, DirectedPresencePlan::AtCapacity) {
        return Ok(Some(stanza_error(root, "wait", "resource-constraint")));
    }
    let should_route = if matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    ) {
        if target_jid.resourcepart().is_some()
            && kind != "subscribe"
            && session.privacy_local_resources(&canonical_to) == 0
            && !session.presence_full_target_routed(&canonical_to).await
        {
            return Ok(None);
        }
        match update_presence_subscription(
            session,
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
                session.roster_disconnect();
                return Ok(Some(stanza_error(root, "auth", "not-authorized")));
            }
            Ok(SubscriptionMutationDisposition::PolicyDenied(reason)) => {
                return Ok(Some(subscription_policy_error(root, reason)));
            }
            Ok(SubscriptionMutationDisposition::Missing) => false,
            Err(error) => {
                tracing::warn!(?error, actor_id = %user.id, %to, %kind, "presence subscription mutation failed before acceptance");
                return Ok(Some(stanza_error(root, "wait", "internal-server-error")));
            }
        }
    } else {
        true
    };
    if should_route {
        let injected = if subscription_kind {
            stamped_subscription_presence(raw, bare_jid(from), to)
        } else if kind == "available" {
            let avatar_hash = session.presence_service().avatar_hash(user.id).await?;
            inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref())
        } else {
            raw.to_owned()
        };
        let rewritten = if subscription_kind {
            injected
        } else {
            set_from(&injected, from)
        };
        let delivered = session
            .presence_deliver_directed(
                to,
                &canonical_to,
                from,
                &rewritten,
                target_jid.resourcepart().is_none(),
            )
            .await?;
        if delivered || kind == "unavailable" {
            commit_directed_presence(session, directed_presence_plan);
        }
    }
    Ok(None)
}

/// The numeric show value for an announced presence.
pub fn announced_show(root: Node<'_, '_>, kind: &str) -> u8 {
    if kind == "available" {
        match child_text(root, "show") {
            Some("away") => 2,
            Some("chat") => 3,
            Some("dnd") => 4,
            Some("xa") => 5,
            _ => 1,
        }
    } else {
        0
    }
}

/// The announced priority value for a presence stanza.
pub fn announced_priority(root: Node<'_, '_>, kind: &str) -> i16 {
    if kind == "available" {
        child_text(root, "priority")
            .and_then(|value| value.parse::<i16>().ok())
            .filter(|value| (-128..=127).contains(value))
            .unwrap_or(0)
    } else {
        0
    }
}

/// Broadcasts initial, status or unavailable presence to roster contacts, the account's other
/// resources and directed presence targets.
pub async fn broadcast_presence<S: PresenceSession>(
    session: &S,
    root: Node<'_, '_>,
    raw: &str,
    kind: &str,
    from: &str,
    first_available: bool,
) -> Result<()> {
    let user = session.session_account().expect("authenticated session");
    let roster = session.blocking_service().roster(user.id).await?;
    let injected = if kind == "available" {
        let avatar_hash = session.presence_service().avatar_hash(user.id).await?;
        inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref())
    } else {
        raw.to_owned()
    };
    let rewritten = set_from(&injected, from);
    session.presence_set_last((kind == "available").then(|| rewritten.clone()));
    let account = format!("{}@{}", user.username, session.session_local_domain());
    let active_privacy = session.privacy_active_list();
    for (jid, _, subscription, ask) in roster {
        if session
            .presence_service()
            .outbound_denied(user.id, bare_jid(from), active_privacy.as_deref(), &jid)
            .await?
        {
            continue;
        }
        let contact_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&jid).ok();
        let local_contact = match contact_jid.as_ref().and_then(|jid| jid.localpart()) {
            Some(username)
                if contact_jid
                    .as_ref()
                    .is_some_and(|jid| jid.domainpart() == session.session_local_domain()) =>
            {
                session
                    .presence_service()
                    .find_enabled_user(username)
                    .await?
            }
            _ => None,
        };
        if let Some(contact) = local_contact.as_ref() {
            let contact_bare = format!("{}@{}", contact.username, session.session_local_domain());
            if session
                .presence_service()
                .is_blocked_for_account(contact.id, &contact_bare, from)
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
                if contact.domainpart() == session.session_local_domain() {
                    let Some(local_contact) = local_contact.as_ref() else {
                        continue;
                    };
                    session
                        .presence_deliver_subscription(
                            &user,
                            local_contact,
                            &account,
                            &jid,
                            &request,
                        )
                        .await?;
                } else if session.presence_route_allowed(contact.domainpart()) {
                    let _ = session
                        .presence_send_federated(
                            contact.domainpart(),
                            request,
                            Some(account.clone()),
                        )
                        .await;
                }
            }
        }
        if matches!(subscription.as_str(), "from" | "both") {
            remove_directed_presence_for_bare(session, &jid);
            let delivery = set_to(&rewritten, &jid);
            if let Ok(contact) = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&jid) {
                if contact.domainpart() == session.session_local_domain() {
                    session
                        .presence_deliver_to_contact(&jid, from, &delivery)
                        .await?;
                } else if session.presence_route_allowed(contact.domainpart()) {
                    let _ = session
                        .presence_send_federated(
                            contact.domainpart(),
                            delivery,
                            Some(from.to_owned()),
                        )
                        .await;
                }
            }
        }
        if should_probe_contact_on_presence(first_available, &subscription) {
            probe_contact_presence(session, &jid, &account).await;
        }
    }

    // RFC 6121 requires every available resource of the same account
    // to observe initial/subsequent presence. Unavailable presence is
    // also echoed to the resource that generated it.
    session
        .presence_echo_to_account(&account, from, &rewritten)
        .await;

    if kind == "unavailable" {
        broadcast_directed_unavailable(session, &rewritten, from).await;
    }

    Ok(())
}

/// Delivers MOTD or welcome service messages to a newly available resource.
pub async fn deliver_service_messages<S: PresenceSession>(session: &S, from: &str) -> Result<()> {
    let user = session.session_account().expect("authenticated session");
    for claim in session
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
            .attr("from", session.session_local_domain())
            .attr("to", from)
            .attr("type", "headline")
            .attr("id", uuid::Uuid::new_v4())
            .child(XmlElement::new("subject").text(subject))
            .child(XmlElement::new("body").text(claim.body()))
            .finish();
        session.presence_send(notice).await?;
        if !session
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
    Ok(())
}

fn should_probe_contact_on_presence(first_available: bool, subscription: &str) -> bool {
    // RFC 6121 sections 4.2.2 and 4.3.1 tie automatic contact probes to the
    // start of a presence session. A subsequent status/show update must not
    // amplify into another roster-sized wave of probes.
    northstar_presence_core::should_probe_contact_on_presence(first_available, subscription)
}

#[cfg(test)]
mod tests;
