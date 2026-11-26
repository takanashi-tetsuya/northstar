use super::render::presence_probe_status_response;
use crate::FederatedPresenceHost;
use anyhow::Result;
use northstar_federation_core::wire::s2s_stanza_error;
use northstar_federation_core::FederationRoute;
use northstar_presence_core::directed_recipient_matches;
use northstar_roster_application::presence::PresenceAccount;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_xml_builder::rewrite::set_to;
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::{canonical_bare_key, CanonicalJid};
use roxmltree::{Document, Node};
use std::sync::atomic::Ordering;

pub(super) async fn route_inbound_presence_probe<H: FederatedPresenceHost>(
    state: &H,
    root: Node<'_, '_>,
    requester: &str,
    target_jid: &CanonicalJid,
    recipient: &PresenceAccount,
) -> Result<Option<String>> {
    let requester_bare = canonical_bare_key(requester)?;
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
    let roster_authorized = state
        .presence_service()
        .roster_subscription(recipient.id, &requester_bare)
        .await?
        .is_some_and(|subscription| matches!(subscription.as_str(), "from" | "both"));
    let directed_authorized = target_jid.resourcepart().is_some()
        && state
            .session_entries_for(&target_jid.to_string())
            .into_iter()
            .any(|(_, session)| {
                session
                    .directed_presence
                    .iter()
                    .any(|authorized| directed_recipient_matches(authorized.key(), requester))
            });
    if !roster_authorized && !directed_authorized {
        return Ok(Some(presence_probe_status_response(
            &recipient_bare,
            requester,
            "unsubscribed",
            root.attribute("id"),
        )));
    }

    let owner = if target_jid.resourcepart().is_some() {
        target_jid.to_string()
    } else {
        recipient_bare.clone()
    };
    let mut available = state.session_entries_for(&owner);
    available.retain(|(_, session)| session.available.load(Ordering::Relaxed));
    let mut privacy_allowed = Vec::with_capacity(available.len());
    for entry in available {
        if state
            .privacy_allows_session(&entry.1, requester, PrivacyStanzaKind::PresenceIn)
            .await?
            && state
                .privacy_allows_session(&entry.1, requester, PrivacyStanzaKind::PresenceOut)
                .await?
        {
            privacy_allowed.push(entry);
        }
    }
    let available = privacy_allowed;
    if available.is_empty() {
        return Ok(Some(presence_probe_status_response(
            &recipient_bare,
            requester,
            "unavailable",
            root.attribute("id"),
        )));
    }

    let requester_domain = CanonicalJid::parse(requester)
        .expect("validated federated probe sender")
        .domainpart()
        .to_owned();
    let full_target = target_jid.resourcepart().is_some();
    for (full_jid, session) in available {
        let last_presence = session
            .last_presence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let response = if full_target {
            // RFC 6121 section 4.3.2: a full-JID probe must expose only the
            // fact that this exact resource is available, never show/status,
            // priority, caps, OMEMO or another presence extension.
            let original_id = last_presence.as_deref().and_then(|presence| {
                let document = Document::parse(presence).ok()?;
                document
                    .root_element()
                    .attribute("id")
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control)
                    })
                    .map(str::to_owned)
            });
            XmlElement::new("presence")
                .attr("xmlns", "jabber:server")
                .attr("from", &full_jid)
                .attr("to", requester)
                .optional_attr("id", original_id.as_deref())
                .finish()
        } else {
            last_presence
                .map(|presence| set_to(&presence, requester))
                .unwrap_or_else(|| {
                    XmlElement::new("presence")
                        .attr("xmlns", "jabber:server")
                        .attr("from", &full_jid)
                        .attr("to", requester)
                        .finish()
                })
        };
        // RFC 6121 section 4.3.2.1 preserves each available resource's
        // original presence id.  The probe id is mirrored only for
        // unavailable/unsubscribed/error responses above.
        if !state
            .federation_outbox()
            .send(&requester_domain, response, None)
            .await
        {
            return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
        }
    }
    Ok(None)
}
