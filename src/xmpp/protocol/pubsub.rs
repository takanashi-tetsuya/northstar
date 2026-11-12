use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_pubsub_core::PubSubNode;
use northstar_pubsub_xmpp::pubsub::PubSubHost;
use northstar_xml_builder::stanza::{iq_error_from, iq_result_from};
use roxmltree::Node;

pub(crate) use northstar_pubsub_xmpp::pubsub::{error_condition, pubsub_s2s_iq_error, PubSubReply};

pub(crate) fn service_disco_payload<S: PubSubHost>(state: &S) -> String {
    northstar_pubsub_xmpp::pubsub::service_disco_payload(state)
}

pub(crate) async fn federated_disco_info<S: PubSubHost>(
    state: &S,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<PubSubReply> {
    northstar_pubsub_xmpp::pubsub::federated_disco_info(state, requester, requested_node).await
}

pub(crate) async fn federated_disco_items<S: PubSubHost>(
    state: &S,
    requester: &str,
    request: Node<'_, '_>,
) -> Result<PubSubReply> {
    northstar_pubsub_xmpp::pubsub::federated_disco_items(state, requester, request).await
}

pub(crate) async fn handle_request<S: PubSubHost>(
    state: &S,
    requester: &str,
    kind: &str,
    child: Node<'_, '_>,
) -> Result<PubSubReply> {
    northstar_pubsub_xmpp::pubsub::handle_request(state, requester, kind, child).await
}

pub(crate) async fn handle_authorization_response<S: PubSubHost>(
    state: &S,
    requester: &str,
    message: Node<'_, '_>,
) -> Result<()> {
    northstar_pubsub_xmpp::pubsub::handle_authorization_response(state, requester, message).await
}

pub(crate) async fn node_metadata_form<S: PubSubHost>(
    state: &S,
    node: &PubSubNode,
) -> Result<String> {
    northstar_pubsub_xmpp::pubsub::node_metadata_form(state, node).await
}

/// The session handlers of pubsub.rs.
pub(crate) trait PubSubHandlers {
    async fn pubsub_iq_get(&self, id: &str, child: Node<'_, '_>) -> Result<Action>;

    async fn pubsub_iq_set(&self, id: &str, child: Node<'_, '_>, _to: &str) -> Result<Action>;

    async fn pubsub_owner_get(&self, id: &str, child: Node<'_, '_>) -> Result<Action>;

    async fn pubsub_owner_set(&self, id: &str, child: Node<'_, '_>) -> Result<Action>;

    async fn pubsub_request(&self, id: &str, kind: &str, child: Node<'_, '_>) -> Result<Action>;

    async fn pubsub_authorization_response(&self, root: Node<'_, '_>) -> Result<bool>;

    /// XEP-0060 `send_last_published_item=on_sub_and_presence` delivery.
    /// Presence addressed to the service is consumed by the service and is
    /// never routed to a similarly named local account.
    async fn pubsub_presence(&mut self, kind: &str, from: &str) -> Result<Action>;
}

impl<H: SessionHost + PubSubHost> PubSubHandlers for ProtocolSession<H> {
    async fn pubsub_iq_get(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "get", child).await
    }

    async fn pubsub_iq_set(&self, id: &str, child: Node<'_, '_>, _to: &str) -> Result<Action> {
        self.pubsub_request(id, "set", child).await
    }

    async fn pubsub_owner_get(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "get", child).await
    }

    async fn pubsub_owner_set(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "set", child).await
    }

    async fn pubsub_request(&self, id: &str, kind: &str, child: Node<'_, '_>) -> Result<Action> {
        let service = self.host().pubsub_domain();
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error_from(id, &service, "not-authorized")));
        };
        let reply = match handle_request(&**self.host(), full_jid, kind, child).await {
            Ok(reply) => reply,
            Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
                PubSubReply::Error("resource-constraint")
            }
            Err(error) => return Err(error),
        };
        Ok(match reply {
            PubSubReply::Result(payload) => Action::Send(iq_result_from(id, &service, &payload)),
            reply @ (PubSubReply::Error(_) | PubSubReply::ExtendedError(_)) => Action::Send(
                northstar_pubsub_xmpp::pubsub::pubsub_iq_error(id, &service, &reply),
            ),
        })
    }

    async fn pubsub_authorization_response(&self, root: Node<'_, '_>) -> Result<bool> {
        let Some(to) = root.attribute("to") else {
            return Ok(false);
        };
        if northstar_xmpp_types::jid::canonicalize_bare(to)
            .ok()
            .as_deref()
            != northstar_xmpp_types::jid::canonicalize_bare(&self.host().pubsub_domain())
                .ok()
                .as_deref()
        {
            return Ok(false);
        }
        let Some(requester) = self.full_jid.as_deref() else {
            return Ok(true);
        };
        handle_authorization_response(&**self.host(), requester, root).await?;
        Ok(true)
    }

    async fn pubsub_presence(&mut self, kind: &str, from: &str) -> Result<Action> {
        if kind != "available" {
            return Ok(Action::None);
        }
        let requester_full = northstar_xmpp_types::jid::canonicalize(from)?;
        let requester_id = self
            .authenticated
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PubSub presence requires an authenticated account"))?
            .id;
        let active_privacy_list = self
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let connection_id = self.connection_id;
        let state = self.host().clone();
        let outbound = self.outbound.clone();
        let show = match self.show.load(std::sync::atomic::Ordering::Relaxed) {
            2 => "away",
            3 => "chat",
            4 => "dnd",
            5 => "xa",
            _ => "online",
        };
        self.defer_after_transport("pubsub-last-item-replay", async move {
            if let Err(error) = H::replay_pubsub_last_items(
                state,
                outbound,
                requester_id,
                active_privacy_list,
                connection_id,
                requester_full,
                show,
            )
            .await
            {
                tracing::error!(
                    ?error,
                    "failed PubSub last-item replay on available presence"
                );
            }
        })?;
        Ok(Action::None)
    }
}
