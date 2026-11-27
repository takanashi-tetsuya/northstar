use super::Repository;
use anyhow::Result;
use northstar_message_application::messaging::{ResourcePolicyRepository, ResourceStanzaPolicy};

impl ResourcePolicyRepository for Repository {
    async fn allows_resource_stanza(&self, _: ResourceStanzaPolicy<'_>, _: bool) -> Result<bool> {
        panic!("unexpected resource policy lookup")
    }
}
