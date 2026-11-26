use crate::protocol::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_xml_builder::rewrite::set_from;
use northstar_xml_builder::stanza::{iq_error, stanza_error};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Node;
use std::ops::ControlFlow;

impl<H: SessionHost> ProtocolSession<H> {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn route_full_jid_iq(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        to: &str,
        target_jid: &CanonicalJid,
        kind: &str,
        id: &str,
        child: Option<Node<'_, '_>>,
        caps_disco_get: bool,
    ) -> Result<ControlFlow<Action>> {
        // RFC 6121 section 8.5.3.1 applies this presence-leak
        // protection to every IQ get/set addressed to an exact
        // full JID, not only to capability discovery.  The same
        // account is necessarily entitled to address its own
        // resources; other entities need a from/both subscription
        // or a directed-presence grant from the target resource.
        if matches!(kind, "get" | "set") {
            let Some(target_name) = target_jid.localpart() else {
                return Ok(ControlFlow::Break(Action::Send(stanza_error(
                    root,
                    "cancel",
                    "service-unavailable",
                ))));
            };
            let Some(target_user) = self
                .host
                .presence_service()
                .find_enabled_user(target_name)
                .await?
            else {
                return Ok(ControlFlow::Break(Action::Send(stanza_error(
                    root,
                    "cancel",
                    "service-unavailable",
                ))));
            };
            let requester = self.full_jid.as_deref().unwrap_or_default();
            let requester_bare = northstar_xmpp_types::jid::canonical_bare_key(requester)
                .expect("authenticated full JIDs are canonical");
            let same_account =
                requester_bare == format!("{}@{}", target_user.username, self.host.local_domain());
            let subscribed = self
                .host
                .presence_service()
                .roster_subscription(target_user.id, &requester_bare)
                .await?
                .is_some_and(|subscription| matches!(subscription.as_str(), "from" | "both"));
            let directed = self
                .host
                .session_entries_for(to)
                .into_iter()
                .any(|(_, session)| {
                    session.directed_presence.iter().any(|authorized| {
                        northstar_presence_core::directed_recipient_matches(
                            authorized.key(),
                            requester,
                        )
                    })
                });
            if !full_jid_iq_visible(same_account, subscribed, directed) {
                return Ok(ControlFlow::Break(Action::Send(stanza_error(
                    root,
                    "cancel",
                    "service-unavailable",
                ))));
            }
        }
        // RFC 6121 section 8.5.3.2.3 requires
        // service-unavailable when an IQ request targets a
        // missing exact resource. Its broad wording cannot make
        // an IQ response into a new request: RFC 6120 section
        // 8.2.3 says an entity MUST NOT respond to an IQ
        // result/error (and section 8.3.1 independently forbids
        // an error loop). Check this before a server-side
        // XEP-0115 cache can answer for a stale resource.
        let local_resource_matches = !self.host.session_entries_for(to).is_empty();
        let remote_resource_matches = self.host.personal_message_remote_resource_exists(to).await;
        if !local_resource_matches && !remote_resource_matches {
            return if missing_full_jid_iq_needs_error(kind) {
                Ok(ControlFlow::Break(Action::Send(stanza_error(
                    root,
                    "cancel",
                    "service-unavailable",
                ))))
            } else {
                Ok(ControlFlow::Break(Action::None))
            };
        }
        if caps_disco_get {
            if let Some(result) = super::super::caps::cached_disco_result(
                &*self.host,
                id,
                to,
                child.and_then(|child| child.attribute("node")),
            ) {
                return Ok(ControlFlow::Break(Action::Send(result)));
            }
        }
        let from = self.full_jid.as_deref().unwrap_or("");
        let rewritten = set_from(raw, from);
        let targets = self.host.session_entries_for(to);
        let mut delivered = false;
        for (_, target) in targets {
            if self
                .host
                .privacy_allows_session(&target, from, PrivacyStanzaKind::Iq)
                .await?
                && target.sender.try_send(rewritten.clone()).is_ok()
            {
                delivered = true;
                break;
            }
        }
        if !delivered {
            delivered = self
                .host
                .route_client_iq_to_remote_resource(to, &rewritten)
                .await;
        }
        if delivered {
            Ok(ControlFlow::Break(Action::None))
        } else if kind == "get" || kind == "set" {
            Ok(ControlFlow::Break(Action::Send(iq_error(
                id,
                "service-unavailable",
            ))))
        } else {
            Ok(ControlFlow::Break(Action::None))
        }
    }
}

pub(super) fn full_jid_iq_visible(same_account: bool, subscribed: bool, directed: bool) -> bool {
    same_account || subscribed || directed
}

pub(super) fn missing_full_jid_iq_needs_error(kind: &str) -> bool {
    matches!(kind, "get" | "set")
}
