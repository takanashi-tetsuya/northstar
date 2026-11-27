use crate::messaging::{
    ExactMessageRoute, MessageRepository, MessageService, ResourceStanzaPolicy,
};
use anyhow::Result;
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid_text::bare_jid;
use uuid::Uuid;

impl<R: MessageRepository> MessageService<R> {
    pub async fn allows_carbon(
        &self,
        account: &str,
        account_id: Uuid,
        connection_id: Uuid,
        active_list: Option<&str>,
        peer: &str,
    ) -> Result<bool> {
        self.allows_resource_stanza(
            ResourceStanzaPolicy {
                account: Some(account),
                account_id,
                auth_generation: None,
                connection_id,
                expects_active: active_list.is_some(),
                peer,
                kind: PrivacyStanzaKind::Message,
            },
            false,
        )
        .await
    }

    pub async fn allows_carbon_on_route(
        &self,
        route: &ExactMessageRoute,
        active_list: Option<&str>,
        peer: &str,
    ) -> Result<bool> {
        self.allows_resource_stanza(
            ResourceStanzaPolicy {
                account: Some(bare_jid(&route.full_jid)),
                account_id: route.account_id,
                auth_generation: Some(route.auth_generation),
                connection_id: route.connection_id,
                expects_active: active_list.is_some(),
                peer,
                kind: PrivacyStanzaKind::Message,
            },
            false,
        )
        .await
    }
}
