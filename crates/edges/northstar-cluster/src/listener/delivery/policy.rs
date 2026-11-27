use super::{active_privacy_list, ClusterAdapters, ClusterListenerMessagePolicy};
use crate::delivery_contract::EXACT_MESSAGE_DELIVERY_VERSION;
use northstar_message_application::messaging::{
    MessageRepository, MessageService, ResourceStanzaPolicy,
};
use northstar_stream::local_routes::{session::OnlineSession, session_table::LocalSessionTable};
use northstar_stream::protocol::iq_visibility::LocalIqAdmission;
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use northstar_xmpp_types::jid_text::bare_jid;

pub(super) fn exact_iq_request(
    envelope: &serde_json::Value,
    target: &str,
    document: Option<&roxmltree::Document<'_>>,
) -> Option<(bool, bool)> {
    let check_only = envelope["exact_iq_check_only"].as_bool()?;
    let iq = document?.root_element();
    let request = match iq.attribute("type")? {
        "get" | "set" => true,
        "result" | "error" if !check_only => false,
        _ => return None,
    };
    (iq.tag_name().name() == "iq"
        && envelope["protocol_version"].as_str() == Some(EXACT_MESSAGE_DELIVERY_VERSION)
        && envelope["delivery"].is_null()
        && CanonicalJid::parse(target)
            .is_ok_and(|jid| jid.localpart().is_some() && jid.resourcepart().is_some())
        && iq
            .attribute("to")
            .and_then(|to| CanonicalJid::parse(to).ok())
            .is_some_and(|to| to.to_string() == target)
        && iq
            .attribute("from")
            .is_some_and(|from| CanonicalJid::parse(from).is_ok()))
    .then_some((request, check_only))
}

pub(super) async fn handoff_exact_iq<R: MessageRepository>(
    service: &MessageService<R>,
    table: &LocalSessionTable,
    (jid, session, peer): (&str, &OnlineSession, &str),
    request: bool,
    stanza: Option<&str>,
) -> bool {
    let result = async {
        let admission = LocalIqAdmission::capture(jid.to_owned(), session, peer, request)?;
        let allowed = service
            .allows_resource_stanza(admission.policy(), admission.requires_subscription())
            .await?;
        Ok::<_, anyhow::Error>(allowed && admission.handoff(table, stanza))
    }
    .await;
    match result {
        Ok(accepted) => accepted,
        Err(error) => {
            tracing::warn!(?error, %jid, "exact IQ policy lookup failed during clustered delivery");
            false
        }
    }
}

pub(super) async fn permits_direct_delivery<A: ClusterAdapters>(
    message_policy: &ClusterListenerMessagePolicy<A>,
    session: &OnlineSession,
    jid: &str,
    privacy_peer_kind: &Option<(String, PrivacyStanzaKind)>,
    server_push: bool,
    mix_capable_only: bool,
) -> bool {
    let Some((peer, kind)) = privacy_peer_kind.as_ref().filter(|_| !server_push) else {
        return true;
    };
    let active = active_privacy_list(&session.privacy_active);
    let allowed = if mix_capable_only || *kind == PrivacyStanzaKind::PresenceIn {
        message_policy
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                peer,
                *kind,
            )
            .await
    } else {
        message_policy
            .message
            .allows_resource_stanza(
                ResourceStanzaPolicy {
                    account: Some(bare_jid(jid)),
                    account_id: session.user_id,
                    auth_generation: Some(session.auth_generation),
                    connection_id: session.connection_id,
                    expects_active: active.is_some(),
                    peer,
                    kind: *kind,
                },
                false,
            )
            .await
    };
    match allowed {
        Ok(allowed) => allowed && active_privacy_list(&session.privacy_active) == active,
        Err(error) => {
            tracing::warn!(?error, %jid, "resource policy lookup failed during clustered delivery");
            false
        }
    }
}

#[cfg(test)]
mod tests;
