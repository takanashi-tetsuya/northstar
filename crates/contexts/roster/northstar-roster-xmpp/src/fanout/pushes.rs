use super::{RosterFanoutRoutes, BLOCKING_PUSH_TIMEOUT};
use northstar_xml_builder::rewrite::set_to;
use northstar_xml_builder::XmlElement;
use std::sync::atomic::Ordering;
use uuid::Uuid;

pub fn blocking_push_stanza(target: &str, payload: &str, id: Uuid) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("to", target)
        .attr("type", "set")
        .attr("id", format!("block-{}", id.as_u128()))
        .validated_fragment(payload)
        .expect("blocking payload was constructed structurally")
        .finish()
}

pub async fn push_blocklist_change(
    routes: &impl RosterFanoutRoutes,
    owner: &str,
    payload: &str,
    new_id: impl Fn() -> Uuid + Send + Sync,
) {
    for (jid, session) in routes.fanout_sessions(owner) {
        if !session.blocklist_requested.load(Ordering::Acquire) {
            continue;
        }
        let push = blocking_push_stanza(&jid, payload, new_id());
        match tokio::time::timeout(BLOCKING_PUSH_TIMEOUT, session.sender.send(push)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                // A committed block-list mutation must not be followed by
                // newer traffic on a resource which missed its ordered
                // push.  Disconnecting forces the client to query the
                // server-authoritative list again after reconnect.
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                routes.record_fanout_failure();
                tracing::warn!(%jid, ?error, "XEP-0191 blocklist push queue closed; disconnecting stale resource");
            }
            Err(_) => {
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                routes.record_fanout_failure();
                tracing::warn!(%jid, "timed out delivering XEP-0191 blocklist push; disconnecting stale resource");
            }
        }
    }
    match routes
        .remote_blocklist_push(owner, || blocking_push_stanza(owner, payload, new_id()))
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

pub async fn push_privacy_change(
    routes: &impl RosterFanoutRoutes,
    account: &str,
    name: &str,
    base: &str,
    current_connection: Uuid,
) -> Option<String> {
    let mut current_push = None;
    for (jid, session) in routes.fanout_sessions(account) {
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
            routes.record_fanout_failure();
            tracing::warn!(
                %jid,
                list = %name,
                ?error,
                "XEP-0016 privacy-list push queue was unavailable; disconnecting stale resource"
            );
        }
    }
    match routes.remote_privacy_push(account, base).await {
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
