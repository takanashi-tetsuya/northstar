use super::{ClusterAdapters, ClusterListenerDispatch, ClusterListenerMessagePolicy};
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_roster_application::notification_admission::{
    NotificationAdmission, NotificationHandoff, NotificationRecipient, NotificationSource,
};
use northstar_stream::local_routes::{session::OnlineSession, session_table::LocalSessionTable};
use northstar_xmpp_types::jid::CanonicalJid;
use std::sync::Arc;

pub(super) fn is_pubsub_event(document: &roxmltree::Document<'_>) -> bool {
    let message = document.root_element();
    message.tag_name().name() == "message"
        && message.attribute("type") == Some("headline")
        && message
            .children()
            .any(|child| child.has_tag_name(("http://jabber.org/protocol/pubsub#event", "event")))
}

pub(super) fn source<'a>(
    peer: &'a str,
    local_domain: &str,
    pubsub_event: bool,
) -> Option<NotificationSource<'a>> {
    if peer == format!("pubsub.{local_domain}") {
        return Some(NotificationSource::Service(peer));
    }
    if !pubsub_event {
        return None;
    }
    let publisher = CanonicalJid::parse_bare(peer).ok()?;
    (publisher.domainpart() == local_domain && publisher.localpart().is_some())
        .then_some(NotificationSource::PepPublisher(peer))
}

pub(super) async fn handoff<A: ClusterAdapters>(
    policy: &ClusterListenerMessagePolicy<A>,
    dispatch: &ClusterListenerDispatch<A>,
    jid: &str,
    session: &OnlineSession,
    source: NotificationSource<'_>,
    stanza: &str,
) -> NotificationHandoff {
    let active = session.privacy_active_snapshot();
    let recipient = NotificationRecipient {
        full_jid: jid,
        account_id: session.user_id,
        auth_generation: session.auth_generation,
        connection_id: session.connection_id,
        active_list: active.as_deref(),
    };
    match policy
        .notification
        .authorize_notification(recipient, source)
        .await
    {
        Ok(true) => {}
        Ok(false) => return NotificationHandoff::Suppressed,
        Err(error) => {
            tracing::warn!(?error, %jid, "clustered PubSub notification policy read failed");
            return NotificationHandoff::Retry;
        }
    }
    let route = ExactMessageRoute {
        full_jid: jid.to_owned(),
        account_id: session.user_id,
        auth_generation: session.auth_generation,
        connection_id: session.connection_id,
        node_id: None,
        priority: None,
        available: None,
    };
    let table = LocalSessionTable::new(Arc::clone(&dispatch.account_routes.sessions));
    if table.with_exact_message_route(&route, |current| {
        let selected = current
            .privacy_active
            .read()
            .unwrap_or_else(|error| error.into_inner());
        *selected == active && current.sender.try_send(stanza.to_owned()).is_ok()
    }) == Some(true)
    {
        NotificationHandoff::Accepted
    } else {
        NotificationHandoff::Retry
    }
}

#[cfg(test)]
mod tests;
