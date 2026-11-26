use crate::SessionIdentity;
use anyhow::Result;
use northstar_roster_application::presence::ServiceMessageRoute;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::protocol::{
    ProtocolSession, SessionHost, SessionPresencePolicyHost, SessionRoutesHost,
};
use northstar_xml_builder::XmlElement;
use std::future::Future;
use std::sync::atomic::Ordering;

/// Delivers MOTD or welcome service messages to a newly available resource.
pub async fn deliver_service_messages<H: SessionHost>(
    session: &ProtocolSession<H>,
    from: &str,
) -> Result<()> {
    let Some(route) = session
        .roster_actor()
        .filter(|actor| actor.full_jid == from)
    else {
        return Ok(());
    };
    let service = SessionPresencePolicyHost::presence_service(session.host().as_ref());
    for claim in service.claim_service_messages(&route).await? {
        let route = claim.route();
        let subject = if claim.kind() == "motd" {
            "Message of the Day"
        } else {
            "Welcome"
        };
        let notice = XmlElement::namespaced("message", "jabber:client")
            .attr("from", session.session_local_domain())
            .attr("to", route.full_jid.as_str())
            .attr("type", "headline")
            .attr("id", session.roster_events().new_protocol_id())
            .child(XmlElement::new("subject").text(subject))
            .child(XmlElement::new("body").text(claim.body()))
            .finish();
        if !enqueue_notice(
            &session.outbound,
            notice,
            route,
            |jid| SessionRoutesHost::session_entries_for(session.host().as_ref(), jid),
            service.admit_service_message_claim(&claim),
        )
        .await?
        {
            continue;
        }
        if !service.complete_service_message_claim(&claim).await? {
            tracing::warn!(
                kind = %claim.kind(),
                user_id = %route.account_id,
                "service-message delivery lease changed after queue acceptance"
            );
        }
    }
    Ok(())
}

async fn enqueue_notice(
    outbound: &OutboundSender,
    notice: String,
    route: &ServiceMessageRoute,
    routes_for: impl Fn(&str) -> Vec<(String, OnlineSession)> + Send + Sync,
    admit: impl Future<Output = Result<bool>> + Send,
) -> Result<bool> {
    let is_current = || {
        routes_for(&route.full_jid)
            .into_iter()
            .any(|(jid, target)| {
                jid == route.full_jid
                    && target.user_id == route.account_id
                    && target.auth_generation == route.auth_generation
                    && target.connection_id == route.connection_id
                    && target.routable.load(Ordering::Acquire)
                    && !target.disconnect.is_cancelled()
            })
    };
    let mut admission = Ok(false);
    let queued = outbound
        .send_if_current(notice, is_current, async {
            admission = admit.await;
            matches!(admission, Ok(true))
        })
        .await;
    admission?;
    queued.map_err(|_| anyhow::anyhow!("client delivery queue closed"))
}

#[cfg(test)]
mod tests;
