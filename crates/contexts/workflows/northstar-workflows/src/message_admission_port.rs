//! The message context's admission port over the anti-abuse adapter.

use anyhow::Result;
use northstar_abuse_policy::admission_execution::{Effect, ReconcileResult};
use northstar_abuse_policy::admission_transaction::FinalizeDecision;
use northstar_abuse_policy::message_admission::{
    MessageAdmissionAcceptance, MessageAdmissionStart,
};
use northstar_abuse_policy::MessageAdmissionRequest;
use northstar_abuse_postgres::message_admission::PostgresMessageAdmissionRepository;
use northstar_message_application::message_admission::{
    witness::AdmissionWitness, MessageAdmissionRepository,
};

#[derive(Clone)]
pub struct AbuseMessageAdmissionPort(PostgresMessageAdmissionRepository);

impl AbuseMessageAdmissionPort {
    pub fn new(repository: PostgresMessageAdmissionRepository) -> Self {
        Self(repository)
    }
}

impl MessageAdmissionRepository for AbuseMessageAdmissionPort {
    async fn begin(
        &self,
        request: &MessageAdmissionRequest<'_>,
        witness: &AdmissionWitness,
    ) -> Result<MessageAdmissionStart> {
        self.0.begin(request, witness).await
    }
    async fn accept(
        &self,
        acceptance: &MessageAdmissionAcceptance<'_>,
        witness: &AdmissionWitness,
    ) -> Result<FinalizeDecision> {
        self.0.accept(acceptance, witness).await
    }
    async fn reconcile(&self, effect: &Effect) -> Result<ReconcileResult> {
        self.0.reconcile(effect).await
    }
}
