use super::{MessageRepository, MessageService};
use anyhow::Result;
use northstar_xep_0016::PrivacyStanzaKind;
use std::future::Future;
use uuid::Uuid;

pub struct ResourceStanzaPolicy<'a> {
    pub account: Option<&'a str>,
    pub account_id: Uuid,
    pub auth_generation: Option<i64>,
    pub connection_id: Uuid,
    pub expects_active: bool,
    pub peer: &'a str,
    pub kind: PrivacyStanzaKind,
}

pub trait ResourcePolicyRepository: Send + Sync {
    fn allows_resource_stanza(
        &self,
        request: ResourceStanzaPolicy<'_>,
        require_subscription: bool,
    ) -> impl Future<Output = Result<bool>> + Send;
}

impl<R: MessageRepository> MessageService<R> {
    pub async fn allows_resource_stanza(
        &self,
        request: ResourceStanzaPolicy<'_>,
        require_subscription: bool,
    ) -> Result<bool> {
        self.repository
            .allows_resource_stanza(request, require_subscription)
            .await
    }
}
