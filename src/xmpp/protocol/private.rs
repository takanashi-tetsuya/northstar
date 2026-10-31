use super::{Action, ProtocolSession};
use anyhow::Result;
use northstar_pubsub_application::private_storage::{
    PrivateStorageRepository, PrivateStorageService,
};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::PepAudienceSnapshot;
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) async fn private_get(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::private_xml::private_get(&*self, id, to, query)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn private_set(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::private_xml::private_set(&*self, id, to, query, raw)
            .await
            .map(Action::Send)
    }
}

impl northstar_pubsub_xmpp::private_xml::PrivateXmlSession for ProtocolSession {
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
        self.state.local_domain()
    }

    fn private_storage_service(&self) -> &PrivateStorageService<impl PrivateStorageRepository> {
        self.state.private_storage_service()
    }

    fn private_pubsub_service(
        &self,
    ) -> &PubSubService<impl northstar_pubsub_xmpp::PubSubRepositories> {
        self.state.pubsub_service()
    }

    fn private_pep_audience_messages(
        &self,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &PepAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        northstar_pubsub_xmpp::pep::pep_audience_messages(
            self.state.as_ref(),
            publisher_full_jid,
            node,
            event,
            audience,
        )
    }
}
