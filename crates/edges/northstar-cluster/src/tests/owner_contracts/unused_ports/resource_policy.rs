use super::MessagePorts;
use anyhow::Result;
use northstar_message_application::messaging::{
    MessageRepository, ResourcePolicyRepository, ResourceStanzaPolicy,
};

impl ResourcePolicyRepository for MessagePorts {
    async fn allows_resource_stanza(
        &self,
        request: ResourceStanzaPolicy<'_>,
        require_subscription: bool,
    ) -> Result<bool> {
        assert!(request.auth_generation.is_some());
        if self
            .1
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|policy| policy.account != request.account_id)
        {
            return Ok(false);
        }
        let allowed = self
            .privacy_allows_session(
                request.account_id,
                request.connection_id,
                request.expects_active.then_some("active"),
                request.peer,
                request.kind,
            )
            .await?;
        Ok(allowed && !require_subscription)
    }
}
