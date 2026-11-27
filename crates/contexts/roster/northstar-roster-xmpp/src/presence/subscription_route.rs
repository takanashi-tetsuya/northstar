use super::subscriptions::{
    subscription_policy_error, update_presence_subscription, update_remote_presence_subscription,
};
use super::PresenceSession;
use anyhow::Result;
use northstar_roster_application::presence::{
    PresencePolicyDenial, SubscriptionOutboxAdmissionError, SubscriptionRoute,
};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_application::{
    CommunicationPolicyQuery, CommunicationPolicyReader, PolicyDirection, PolicySubject,
};
use northstar_roster_core::PresenceAccount;
use northstar_xml_builder::stanza::stanza_error;
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Node;
use std::ops::ControlFlow;

pub(super) enum SubscriptionMutationDisposition {
    Accepted(bool),
    Unauthorized,
    PolicyDenied(PresencePolicyDenial),
    Missing,
}

pub(super) struct RemoteSubscriptionRequest<'a> {
    pub(super) actor_id: uuid::Uuid,
    pub(super) expected_auth_generation: i64,
    pub(super) contact: &'a str,
    pub(super) kind: &'a str,
    pub(super) target_domain: &'a str,
    pub(super) stanza: &'a str,
    pub(super) bounce_to: &'a str,
}

pub(super) async fn subscription_reply_allowed<S: PresenceSession>(
    session: &S,
    recipient: &PresenceAccount,
    peer: &str,
) -> Result<bool> {
    let query = CommunicationPolicyQuery {
        account_id: recipient.id,
        expected_auth_generation: Some(recipient.auth_generation),
        subject: PolicySubject::Connection {
            connection_id: session.privacy_connection_id(),
            expects_active: session.privacy_active_list().is_some(),
        },
        peer: peer.to_owned(),
        kind: PrivacyStanzaKind::PresenceIn,
        direction: PolicyDirection::Inbound,
        check_owner_block: true,
        check_peer_block: true,
    };
    Ok(session
        .presence_service()
        .communication_policy()
        .read_communication_policy(&query)
        .await?
        .allows())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn route_remote_subscription<S: PresenceSession>(
    session: &S,
    root: Node<'_, '_>,
    user: &PresenceAccount,
    subscription_to: &str,
    kind: &str,
    domain: &str,
    route: SubscriptionRoute,
    outbound: &str,
    bounce_to: &str,
) -> Result<ControlFlow<Option<String>>> {
    match update_remote_presence_subscription(
        session,
        RemoteSubscriptionRequest {
            actor_id: user.id,
            expected_auth_generation: user.auth_generation,
            contact: subscription_to,
            kind,
            target_domain: domain,
            stanza: outbound,
            bounce_to,
        },
    )
    .await
    {
        Ok(SubscriptionMutationDisposition::Accepted(_)) => {}
        Ok(SubscriptionMutationDisposition::Unauthorized) => {
            session.roster_disconnect();
            return Ok(ControlFlow::Break(Some(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        }
        Ok(SubscriptionMutationDisposition::PolicyDenied(reason)) => {
            return Ok(ControlFlow::Break(Some(subscription_policy_error(
                root, reason,
            ))));
        }
        Ok(SubscriptionMutationDisposition::Missing) => return Ok(ControlFlow::Break(None)),
        Err(error)
            if route == SubscriptionRoute::Component
                && !error.is::<SubscriptionOutboxAdmissionError>() =>
        {
            return Err(error);
        }
        Err(_) => {
            return Ok(ControlFlow::Break(Some(stanza_error(
                root,
                "wait",
                "remote-server-timeout",
            ))));
        }
    }
    Ok(ControlFlow::Continue(()))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn route_local_subscription<S: PresenceSession>(
    session: &S,
    root: Node<'_, '_>,
    raw: &str,
    target_jid: &CanonicalJid,
    kind: &str,
    to: &str,
    canonical_to: &str,
    user: &PresenceAccount,
    target: Option<&PresenceAccount>,
) -> Result<ControlFlow<Option<String>, bool>> {
    let Some(target) = target else {
        return Ok(ControlFlow::Break(None));
    };
    if target_jid.resourcepart().is_some()
        && kind != "subscribe"
        && !session
            .presence_full_target_routed(canonical_to, target)
            .await
    {
        return Ok(ControlFlow::Break(None));
    }
    Ok(
        match update_presence_subscription(session, user, to, kind, raw, target).await {
            Ok(SubscriptionMutationDisposition::Accepted(route)) => ControlFlow::Continue(route),
            Ok(SubscriptionMutationDisposition::Unauthorized) => {
                session.roster_disconnect();
                ControlFlow::Break(Some(stanza_error(root, "auth", "not-authorized")))
            }
            Ok(SubscriptionMutationDisposition::PolicyDenied(reason)) => {
                ControlFlow::Break(Some(subscription_policy_error(root, reason)))
            }
            Ok(SubscriptionMutationDisposition::Missing) => ControlFlow::Continue(false),
            Err(error) => {
                tracing::warn!(?error, actor_id = %user.id, %to, %kind, "presence subscription mutation failed before acceptance");
                ControlFlow::Break(Some(stanza_error(root, "wait", "internal-server-error")))
            }
        },
    )
}
