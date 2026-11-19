//! XEP-0280 Carbons and XEP-0357 Push delivery settings.

use super::super::{Action, ProtocolSession};
use crate::protocol::{
    SessionHost, SessionIdentityHost, SessionMessageEffectsHost, SessionTelemetryHost,
};
use anyhow::Result;
use northstar_message_application::push::{
    PushEnableOutcome, PushResponseKind, PushResponseOutcome,
};
use northstar_xml_builder::rewrite::set_to;
use northstar_xml_builder::stanza::{iq_error, iq_error_from, iq_result_from, stanza_error};
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
use std::sync::atomic::Ordering;

impl<H: SessionHost> ProtocolSession<H> {
    pub fn set_carbons(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        control: Node<'_, '_>,
        enabled: bool,
    ) -> Result<Action> {
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let own_bare = bare_jid(full_jid);
        let addressed_error =
            |condition| Action::Send(set_to(&iq_error_from(id, own_bare, condition), full_jid));
        let parsed_control = match northstar_xep_0280::parse_control(control) {
            Ok(control) => control,
            Err(_) => return Ok(addressed_error("bad-request")),
        };
        if enabled != matches!(parsed_control, northstar_xep_0280::Control::Enable) {
            return Ok(addressed_error("bad-request"));
        }
        let valid_from = iq.attribute("from").is_none_or(|from| {
            northstar_xmpp_types::jid::canonicalize(from)
                .is_ok_and(|from| from.as_str() == full_jid)
        });
        let valid_to = iq.attribute("to").is_none_or(|to| {
            northstar_xmpp_types::jid::canonicalize(to).is_ok_and(|to| {
                to.as_str() == full_jid
                    || to.as_str() == own_bare
                    || to.as_str() == self.host.local_domain()
            })
        });
        if !valid_from || !valid_to {
            return Ok(addressed_error("not-allowed"));
        }
        if !self
            .host
            .set_local_carbons_for_connection(full_jid, self.connection_id, enabled)
        {
            // Never acknowledge a session-local capability unless the exact
            // bound route that fanout will inspect was updated. This also
            // closes a replacement/resumption race where the protocol actor
            // could otherwise mutate a detached Arc and return success.
            return Ok(addressed_error("service-unavailable"));
        };
        // The IQ handler and message fanout can run on different Tokio
        // tasks. Publish the per-resource selection before acknowledging the
        // control IQ so subsequent routing observes it.
        self.carbons.store(enabled, Ordering::Release);
        // XEP-0280 examples 4 and 7 require the account bare JID as the
        // responder and the enabling resource's full JID as the result
        // target. The connection itself is not a substitute for the wire
        // addressing because clients use it to reject forged IQ results.
        Ok(Action::Send(set_to(
            &iq_result_from(id, own_bare, ""),
            full_jid,
        )))
    }

    pub async fn enable_push(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        enable: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(stanza_error(iq, "auth", "not-authorized")));
        };
        let own_bare = format!("{}@{}", user.username, self.host.local_domain());
        if !northstar_xep_0357::iq_targets_own_account(iq, &own_bare) {
            return Ok(Action::Send(stanza_error(iq, "cancel", "not-allowed")));
        }
        let (request, options_node) = match northstar_xep_0357::parse_enable(enable) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Ok(Action::Send(stanza_error(
                    iq,
                    error.stanza_error_type(),
                    error.as_stanza_error_condition(),
                )))
            }
        };
        let options = options_node.map(|options| &raw[options.range()]);
        let service_jid = request.service_jid().to_string();
        let node = request.node_str().to_owned();
        match self
            .host
            .push_service()
            .enable(user.id, &service_jid, &node, options)
            .await?
        {
            PushEnableOutcome::Enabled => Ok(Action::Send(iq_result_from(id, &own_bare, ""))),
            PushEnableOutcome::QuotaExceeded => Ok(Action::Send(stanza_error(
                iq,
                "wait",
                "resource-constraint",
            ))),
            PushEnableOutcome::RateLimited => {
                self.host.push_subscription_telemetry().rate_limited();
                Ok(Action::Send(stanza_error(
                    iq,
                    "wait",
                    "resource-constraint",
                )))
            }
        }
    }

    pub async fn disable_push(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        disable: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(stanza_error(iq, "auth", "not-authorized")));
        };
        let own_bare = format!("{}@{}", user.username, self.host.local_domain());
        if !northstar_xep_0357::iq_targets_own_account(iq, &own_bare) {
            return Ok(Action::Send(stanza_error(iq, "cancel", "not-allowed")));
        }
        let request = match northstar_xep_0357::parse_disable(disable) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Ok(Action::Send(stanza_error(
                    iq,
                    error.stanza_error_type(),
                    error.as_stanza_error_condition(),
                )))
            }
        };
        let service_jid = request.service_jid.to_string();
        let node = request.node.map(northstar_xep_0357::PushNode::into_inner);
        self.host
            .push_service()
            .disable(user.id, &service_jid, node.as_deref())
            .await?;
        Ok(Action::Send(iq_result_from(id, &own_bare, "")))
    }
}

impl<H: SessionHost> ProtocolSession<H> {
    pub(crate) async fn handle_push_response(
        &self,
        id: &str,
        kind: &str,
        root: Node<'_, '_>,
    ) -> Result<bool> {
        let Some(from) = root.attribute("from").or(self.full_jid.as_deref()) else {
            return Ok(false);
        };
        handle_push_delivery_response(&*self.host, id, kind, from).await
    }

    pub async fn push_disable_message(
        &self,
        root: Node<'_, '_>,
        from: &str,
        to: &str,
    ) -> Result<bool> {
        handle_push_disable(&*self.host, root, from, to).await
    }
}

/// Consume a local or federated Push Service IQ response.  PostgreSQL is the
/// authority, so correlation remains correct across process restarts and
/// cluster nodes.
pub async fn handle_push_delivery_response<
    H: SessionIdentityHost + SessionMessageEffectsHost + SessionTelemetryHost,
>(
    state: &H,
    id: &str,
    kind: &str,
    from: &str,
) -> Result<bool> {
    if !state.xmpp_extension_enabled(northstar_xep_0357::XEP_ID) {
        return Ok(false);
    }
    let Some(request_id) = id
        .strip_prefix("push-")
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
    else {
        return Ok(false);
    };
    let Ok(sender) = northstar_xmpp_types::jid::canonical_bare_key(from) else {
        return Ok(false);
    };
    let response_kind = if kind == "result" {
        PushResponseKind::Success
    } else if kind == "error" {
        PushResponseKind::PermanentError
    } else {
        return Ok(false);
    };
    let outcome = state
        .push_service()
        .complete_response(request_id, &sender, response_kind)
        .await?;
    match outcome {
        PushResponseOutcome::Unknown | PushResponseOutcome::SenderMismatch => Ok(false),
        PushResponseOutcome::Completed => Ok(true),
        PushResponseOutcome::SubscriptionDisabled => {
            state.push_delivery_telemetry().failed();
            tracing::warn!(service = %sender, "push service rejected notifications repeatedly or permanently; subscription disabled");
            Ok(true)
        }
    }
}

pub async fn handle_push_disable<H: SessionIdentityHost + SessionMessageEffectsHost>(
    state: &H,
    root: Node<'_, '_>,
    from: &str,
    to: &str,
) -> Result<bool> {
    if !state.xmpp_extension_enabled(northstar_xep_0357::XEP_ID) {
        return Ok(false);
    }
    if !matches!(
        root.attribute("type").unwrap_or("normal"),
        "normal" | "headline"
    ) {
        return Ok(false);
    }
    let elements = root
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if elements.len() != 1 {
        return Ok(false);
    }
    let pubsub = elements[0];
    if pubsub.tag_name().name() != "pubsub"
        || pubsub.tag_name().namespace() != Some("http://jabber.org/protocol/pubsub")
        || pubsub
            .attributes()
            .any(|attribute| attribute.name() != "node")
        || pubsub.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Ok(false);
    }
    let Some(node) = pubsub
        .attribute("node")
        .filter(|node| northstar_xep_0357::PushNode::new((*node).to_owned()).is_ok())
    else {
        return Ok(false);
    };
    let affiliations = pubsub
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if affiliations.len() != 1 {
        return Ok(false);
    }
    let affiliation = affiliations[0];
    if affiliation.tag_name().name() != "affiliation"
        || affiliation.tag_name().namespace() != Some("http://jabber.org/protocol/pubsub")
        || affiliation.attribute("affiliation") != Some("none")
        || affiliation
            .attributes()
            .any(|attribute| !matches!(attribute.name(), "jid" | "affiliation"))
        || affiliation.children().any(|child| {
            child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Ok(false);
    }
    let Ok(target) = northstar_xmpp_types::jid::CanonicalJid::parse_bare(to) else {
        return Ok(false);
    };
    let target = target.bare();
    if affiliation.attribute("jid").is_none_or(|jid| {
        !northstar_xmpp_types::jid::canonical_bare_key(jid).is_ok_and(|jid| jid == target)
    }) {
        return Ok(false);
    }
    let target_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&target)?;
    if target_jid.domainpart() != state.local_domain() {
        return Ok(false);
    }
    let Some(target_username) = target_jid.localpart() else {
        return Ok(false);
    };
    let service = northstar_xmpp_types::jid::canonical_bare_key(from)?;
    if !state
        .push_service()
        .disable_from_service(target_username, &service, node)
        .await?
    {
        return Ok(false);
    }
    tracing::info!(%service, user = %target, %node, "push subscription disabled by service");
    Ok(true)
}
