use crate::protocol::iq_visibility::{LocalIqAdmission, RequesterFence};
use crate::protocol::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_auth_application::authentication::AuthenticatedAccount;
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader, PolicyDirection,
    PolicySubject,
};
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xml_builder::rewrite::set_from;
use northstar_xml_builder::stanza::{iq_error, stanza_error};
use northstar_xmpp_types::jid::CanonicalJid;
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;

impl<H: SessionHost> ProtocolSession<H> {
    pub(super) async fn authorize_outbound_user_iq(
        &self,
        user: &AuthenticatedAccount,
        from: &str,
        to: &str,
        target: &CanonicalJid,
    ) -> Result<CommunicationDecision> {
        let expects_active = self
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some();
        CommunicationPolicyReader::read_communication_policy(
            &*self.host,
            &CommunicationPolicyQuery {
                account_id: user.id,
                expected_auth_generation: Some(user.auth_generation),
                subject: PolicySubject::Connection {
                    connection_id: self.connection_id,
                    expects_active,
                },
                peer: to.to_owned(),
                kind: PrivacyStanzaKind::Iq,
                direction: PolicyDirection::Outbound,
                check_owner_block: target.bare() != bare_jid(from),
                check_peer_block: false,
            },
        )
        .await
    }

    pub(super) async fn route_full_jid_iq(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        to: &str,
        caps_disco_get: bool,
        jingle_error: Option<&str>,
    ) -> Result<Action> {
        let id = root.attribute("id").unwrap_or_default();
        let request = missing_full_jid_iq_needs_error(root.attribute("type").unwrap_or_default());
        let from = self.full_jid.as_deref().unwrap_or_default();
        let rewritten = set_from(raw, from);
        if let Some((jid, session)) = self.host.session_entries_for(to).into_iter().next() {
            let fence = self.authenticated.as_ref().map(|account| RequesterFence {
                account_id: account.id,
                auth_generation: account.auth_generation,
                connection_id: self.connection_id,
            });
            let admission = match fence {
                Some(fence) => {
                    LocalIqAdmission::capture_local(jid, &session, from, fence, request)?
                }
                None => LocalIqAdmission::capture(jid, &session, from, request)?,
            };
            if self.host.authorize_iq_resource(&admission).await? {
                if let Some(condition) = jingle_error {
                    return Ok(if self.host.local_iq_handoff(&admission, None) {
                        Action::Send(iq_error(id, condition))
                    } else {
                        rejected_handoff(id, request)
                    });
                }
                if caps_disco_get {
                    let node = root
                        .children()
                        .find(Node::is_element)
                        .and_then(|child| child.attribute("node"));
                    if let Some(result) =
                        super::super::caps::cached_disco_result(&*self.host, id, to, node)
                    {
                        return Ok(if self.host.local_iq_handoff(&admission, None) {
                            Action::Send(result)
                        } else {
                            rejected_handoff(id, request)
                        });
                    }
                }
                if self.host.local_iq_handoff(&admission, Some(&rewritten)) {
                    return Ok(Action::None);
                }
            }
            return Ok(rejected_handoff(id, request));
        }
        // The owning node can sample its live selector and directed recipients.
        // A failed exact handoff supplies no authority to try a replacement.
        if let Some(route) = self.host.capture_remote_iq_route(to).await? {
            if self
                .host
                .remote_iq_handoff(&route, &rewritten, jingle_error.is_some())
                .await
            {
                return match jingle_error {
                    Some(condition) if self.host.remote_iq_route_current(&route).await? => {
                        Ok(Action::Send(iq_error(id, condition)))
                    }
                    Some(_) => Ok(rejected_handoff(id, request)),
                    None => Ok(Action::None),
                };
            }
            return Ok(rejected_handoff(id, request));
        }
        Ok(if request {
            Action::Send(stanza_error(root, "cancel", "service-unavailable"))
        } else {
            Action::None
        })
    }
}

fn rejected_handoff(id: &str, request: bool) -> Action {
    if request {
        Action::Send(iq_error(id, "service-unavailable"))
    } else {
        Action::None
    }
}

pub(in crate::protocol) fn full_jid_iq_visible(
    same_account: bool,
    subscribed: bool,
    directed: bool,
) -> bool {
    same_account || subscribed || directed
}

pub(super) fn missing_full_jid_iq_needs_error(kind: &str) -> bool {
    matches!(kind, "get" | "set")
}

#[cfg(test)]
mod tests;
