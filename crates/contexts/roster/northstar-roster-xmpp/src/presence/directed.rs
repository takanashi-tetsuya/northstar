use super::availability::{
    commit_directed_presence, plan_directed_presence, route_local_directed, send_address_withdrawal,
};
use super::probe_route::route_probe;
use super::subscription_route::{route_local_subscription, route_remote_subscription};
use super::subscriptions::stamped_subscription_presence;
use super::{inject_vcard_avatar_hash, PresenceSession};
use anyhow::Result;
use northstar_roster_application::presence::SubscriptionRoute;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_xml_builder::rewrite::set_from;
use northstar_xml_builder::stanza::{blocked_stanza_error, stanza_error};
use northstar_xmpp_types::jid::CanonicalJid;
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
use std::ops::ControlFlow;

// Keep the live-session bound aligned with the durable XEP-0198 snapshot
// validator. An accepted directed presence must remain representable across
// suspend/resume so that the matching unavailable presence is not lost.

pub(super) enum DirectedPresencePlan {
    None,
    Insert(String),
    Remove(String),
    AtCapacity,
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
    let hosted_service = session.roster_is_hosted_domain(target_domain);
    let subscription_route = subscription_kind.then(|| {
        SubscriptionRoute::resolve(
            session.session_local_domain(),
            target_domain,
            hosted_service,
            session.presence_is_component_domain(target_domain),
        )
    });
    let remote_domain = match subscription_route {
        Some(SubscriptionRoute::Hosted) => None,
        Some(SubscriptionRoute::Component | SubscriptionRoute::Federated) => Some(target_domain),
        None => (target_domain != session.session_local_domain() && !hosted_service)
            .then_some(target_domain),
    };
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
        // External peers own their resource identities. Federation and
        // component grants therefore keep the address scope on the wire.
        let directed_presence_plan = plan_directed_presence(session, to, kind);
        if matches!(&directed_presence_plan, DirectedPresencePlan::AtCapacity) {
            return Ok(Some(stanza_error(root, "wait", "resource-constraint")));
        }
        if let Some(route) = subscription_route {
            if let ControlFlow::Break(reply) = route_remote_subscription(
                session,
                root,
                &user,
                subscription_to.as_str(),
                kind,
                domain,
                route,
                &outbound,
                &bounce_to,
            )
            .await?
            {
                return Ok(reply);
            }
        } else {
            // Subscription kinds took the typed route above, so this branch
            // carries ordinary presence to a federated or component peer.
            let accepted = if kind == "unavailable" {
                send_address_withdrawal(session, domain, outbound, &bounce_to).await
            } else {
                session
                    .presence_send_federated(domain, outbound, Some(bounce_to))
                    .await
            };
            if !accepted {
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
        if let ControlFlow::Break(reply) =
            route_probe(session, root, target_jid, &canonical_to, from, target_user).await?
        {
            return Ok(reply);
        }
        return Ok(None);
    }
    let should_route = if matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    ) {
        match route_local_subscription(
            session,
            root,
            raw,
            target_jid,
            kind,
            to,
            &canonical_to,
            &user,
            target_user.as_ref(),
        )
        .await?
        {
            ControlFlow::Continue(routed) => routed,
            ControlFlow::Break(reply) => return Ok(reply),
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
        if subscription_kind {
            session
                .presence_deliver_directed(
                    to,
                    &canonical_to,
                    from,
                    &rewritten,
                    target_jid.resourcepart().is_none(),
                )
                .await?;
        } else if let Some(target) = target_user {
            if route_local_directed(session, &target, &canonical_to, &rewritten, kind).await? {
                return Ok(Some(stanza_error(root, "wait", "resource-constraint")));
            }
        }
    }
    Ok(None)
}
