use super::{CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader};
use anyhow::Result;
use std::sync::Mutex;

/// Configurable test double that records each batch, including failed reads.
pub struct InMemoryCommunicationPolicyReader<F> {
    decide: F,
    batches: Mutex<Vec<Vec<CommunicationPolicyQuery>>>,
}

impl<F> InMemoryCommunicationPolicyReader<F>
where
    F: Fn(&CommunicationPolicyQuery) -> Result<CommunicationDecision> + Send + Sync,
{
    pub fn new(decide: F) -> Self {
        Self {
            decide,
            batches: Mutex::new(Vec::new()),
        }
    }

    pub fn batches(&self) -> Vec<Vec<CommunicationPolicyQuery>> {
        self.batches
            .lock()
            .expect("recorded policy batches")
            .clone()
    }
}

impl<F> CommunicationPolicyReader for InMemoryCommunicationPolicyReader<F>
where
    F: Fn(&CommunicationPolicyQuery) -> Result<CommunicationDecision> + Send + Sync,
{
    async fn read_communication_policies(
        &self,
        queries: &[CommunicationPolicyQuery],
    ) -> Result<Vec<CommunicationDecision>> {
        self.batches
            .lock()
            .expect("recorded policy batches")
            .push(queries.to_vec());
        queries.iter().map(&self.decide).collect()
    }
}
