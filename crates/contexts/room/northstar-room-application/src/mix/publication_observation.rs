use super::*;
use crate::mix_service::PreparedMessage;

impl Observation {
    pub(crate) fn publication_request(
        &self,
        message: &PreparedMessage,
    ) -> Result<StoreRequest, Rejected> {
        self.issue_store_request(
            StoreCommand {
                channel_id: message.channel_id.as_uuid(),
                actor: message.actor.as_str().to_owned(),
                item_id: message.item_id,
                payload: String::new(),
                identity: message.identity.clone(),
                delivery_payload: message.children.clone(),
                visible_jid: None,
                encrypted: message.encrypted,
            },
            None,
        )
    }
}
