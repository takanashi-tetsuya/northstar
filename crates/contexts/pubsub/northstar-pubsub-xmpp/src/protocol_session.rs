//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`, and the handlers the root's client IQ route table calls on
//! it.

use crate::pubsub::handle_authorization_response;
use crate::pubsub::handle_request;
use crate::pubsub::PubSubHost;
use crate::pubsub::PubSubReply;
use crate::vcard::VCardSession;
use crate::PubSubSessionHost;
use anyhow::Result;
use northstar_pubsub_application::private_storage::{
    PrivateStorageRepository, PrivateStorageService,
};
use northstar_pubsub_application::profile::ProfileAudienceSnapshot;
use northstar_pubsub_application::profile::{ProfileRepository, ProfileService};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::PepAudienceSnapshot;
use northstar_pubsub_core::{PepQuotas, PubSubAccount};
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use northstar_xml_builder::stanza::{iq_error_from, iq_result_from};
use roxmltree::Node;

// From src/xmpp/protocol/pep.rs.
impl<H: SessionHost + PubSubSessionHost> crate::pep::PepSession for ProtocolSession<H> {
    fn pep_account(&self) -> Option<PubSubAccount> {
        self.authenticated.as_ref().map(|user| PubSubAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn pep_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn pep_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn pep_local_domain(&self) -> &str {
        self.host().pubsub_local_domain()
    }

    fn pep_quotas(&self) -> PepQuotas {
        self.host().pep_account_quotas()
    }

    fn pep_pubsub_service(&self) -> &PubSubService<impl crate::PubSubRepositories> {
        self.host().pubsub_application_service()
    }

    fn pep_profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.host().profile_service()
    }

    fn pep_audience_routing(&self) -> &impl crate::pep::PepAudienceRouting {
        &**self.host()
    }

    fn pep_record_published(&self, count: u64) {
        self.host().pep_record_published(count);
    }

    fn pep_record_retracted(&self, count: u64) {
        self.host().pep_record_retracted(count);
    }

    fn pep_record_retrieved(&self) {
        self.host().pep_record_retrieved();
    }

    fn pep_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        self.host().refresh_avatar_presence(owner_bare, hash);
    }
}

/// The PEP handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait PepHandlers {
    async fn pep_get(&self, id: &str, iq: Node<'_, '_>, pubsub: Node<'_, '_>) -> Result<Action>;

    async fn pep_publish(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action>;

    async fn pep_owner_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action>;

    async fn pep_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action>;
}

impl<H: SessionHost + PubSubSessionHost> PepHandlers for ProtocolSession<H> {
    async fn pep_get(&self, id: &str, iq: Node<'_, '_>, pubsub: Node<'_, '_>) -> Result<Action> {
        crate::pep::pep_get(self, id, iq, pubsub)
            .await
            .map(Action::Send)
    }

    async fn pep_publish(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        crate::pep::pep_publish(self, id, iq, pubsub, raw)
            .await
            .map(Action::Send)
    }

    async fn pep_owner_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        crate::pep::pep_owner_get(self, id, iq, pubsub)
            .await
            .map(Action::Send)
    }

    async fn pep_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        crate::pep::pep_owner_set(self, id, iq, pubsub)
            .await
            .map(Action::Send)
    }
}

// From src/xmpp/protocol/private.rs.
impl<H: SessionHost + PubSubSessionHost> crate::private_xml::PrivateXmlSession
    for ProtocolSession<H>
{
    fn private_account(&self) -> Option<northstar_pubsub_core::PubSubAccount> {
        self.authenticated
            .as_ref()
            .map(|user| northstar_pubsub_core::PubSubAccount {
                id: user.id,
                username: user.username.clone(),
                auth_generation: user.auth_generation,
            })
    }

    fn private_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn private_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn private_local_domain(&self) -> &str {
        self.host().pubsub_local_domain()
    }

    fn private_storage_service(&self) -> &PrivateStorageService<impl PrivateStorageRepository> {
        self.host().private_storage_service()
    }

    fn private_pubsub_service(&self) -> &PubSubService<impl crate::PubSubRepositories> {
        self.host().pubsub_application_service()
    }

    fn private_pep_audience_messages(
        &self,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &PepAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        crate::pep::pep_audience_messages(&**self.host(), publisher_full_jid, node, event, audience)
    }
}

/// The private XML handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait PrivateXmlHandlers {
    async fn private_get(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn private_set(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action>;
}

impl<H: SessionHost + PubSubSessionHost> PrivateXmlHandlers for ProtocolSession<H> {
    async fn private_get(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        crate::private_xml::private_get(&*self, id, to, query)
            .await
            .map(Action::Send)
    }

    async fn private_set(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        crate::private_xml::private_set(&*self, id, to, query, raw)
            .await
            .map(Action::Send)
    }
}

// From src/xmpp/protocol/vcard.rs.
impl<H: SessionHost + PubSubSessionHost> VCardSession for ProtocolSession<H> {
    fn vcard_account(&self) -> Option<PubSubAccount> {
        self.authenticated.as_ref().map(|user| PubSubAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn vcard_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn vcard_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn vcard_local_domain(&self) -> &str {
        self.host().pubsub_local_domain()
    }

    fn vcard_pep_quotas(&self) -> PepQuotas {
        self.host().pep_account_quotas()
    }

    fn vcard_profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.host().profile_service()
    }

    fn vcard_profile_audience_messages(
        &self,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &ProfileAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        crate::pep::profile_audience_messages(
            &**self.host(),
            publisher_full_jid,
            node,
            event,
            audience,
        )
    }

    fn vcard_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        self.host().refresh_avatar_presence(owner_bare, hash);
    }
}

/// The vCard handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait VCardHandlers {
    async fn vcard_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action>;

    async fn vcard_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        vcard: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action>;
}

impl<H: SessionHost + PubSubSessionHost> VCardHandlers for ProtocolSession<H> {
    async fn vcard_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        crate::vcard::vcard_get(self, id, iq)
            .await
            .map(Action::Send)
    }

    async fn vcard_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        vcard: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        crate::vcard::vcard_set(self, id, iq, vcard, raw)
            .await
            .map(Action::Send)
    }
}

// From src/xmpp/protocol/pubsub.rs.
/// The PubSub handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait PubSubHandlers {
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
            reply @ (PubSubReply::Error(_) | PubSubReply::ExtendedError(_)) => {
                Action::Send(crate::pubsub::pubsub_iq_error(id, &service, &reply))
            }
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
