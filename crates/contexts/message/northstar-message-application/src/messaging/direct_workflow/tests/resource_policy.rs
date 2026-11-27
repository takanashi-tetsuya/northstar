use super::RecordingCommit;
use crate::messaging::{ResourcePolicyRepository, ResourceStanzaPolicy};
use anyhow::Result;

impl ResourcePolicyRepository for RecordingCommit {
    async fn allows_resource_stanza(&self, _: ResourceStanzaPolicy<'_>, _: bool) -> Result<bool> {
        panic!("unexpected resource policy lookup")
    }
}
