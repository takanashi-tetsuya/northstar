use super::{FederatedMixMutation, FederatedMixSuccess, MixEventPayloadRenderer};
use anyhow::Result;

#[derive(Debug, thiserror::Error)]
#[error("federated MIX IQ id reused with a different request")]
pub struct FederatedMixIqConflict;

#[derive(thiserror::Error)]
#[error("federated MIX mutation was already finalized")]
pub struct FederatedMixIqAlreadyFinalized(String);

impl FederatedMixIqAlreadyFinalized {
    pub fn new(response: String) -> Self {
        Self(response)
    }

    pub fn response(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for FederatedMixIqAlreadyFinalized {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FederatedMixIqAlreadyFinalized([redacted])")
    }
}

pub enum FederatedMixOutcome {
    Success(FederatedMixSuccess),
    Denied {
        error_type: &'static str,
        condition: &'static str,
    },
}

impl FederatedMixOutcome {
    pub fn render(
        &self,
        context: &FederatedMixMutation,
        payloads: &dyn MixEventPayloadRenderer,
    ) -> Result<String> {
        match self {
            Self::Success(success) => payloads.federated_iq_result(context, success),
            Self::Denied {
                error_type,
                condition,
            } => Ok(northstar_xml_builder::stanza::iq_error_to(
                &context.request_id,
                &context.addressed,
                &context.reply_to,
                error_type,
                condition,
            )),
        }
    }
}
