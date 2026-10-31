//! The message context's admission port over the anti-abuse adapter.

use crate::services::message_admission::{witness::AdmissionWitness, MessageAdmissionRepository};
use anyhow::Result;
use northstar_abuse_application::guard::{MessageAdmissionAcceptance, MessageAdmissionStart};
use northstar_abuse_policy::admission_execution::{Effect, ReconcileResult};
use northstar_abuse_policy::admission_transaction::FinalizeDecision;
use northstar_abuse_policy::MessageAdmissionRequest;
use northstar_abuse_postgres::message_admission::PostgresMessageAdmissionRepository;

impl MessageAdmissionRepository for PostgresMessageAdmissionRepository {
    async fn begin(
        &self,
        request: &MessageAdmissionRequest<'_>,
        witness: &AdmissionWitness,
    ) -> Result<MessageAdmissionStart> {
        PostgresMessageAdmissionRepository::begin(self, request, witness).await
    }
    async fn accept(
        &self,
        acceptance: &MessageAdmissionAcceptance<'_>,
        witness: &AdmissionWitness,
    ) -> Result<FinalizeDecision> {
        PostgresMessageAdmissionRepository::accept(self, acceptance, witness).await
    }
    async fn reconcile(&self, effect: &Effect) -> Result<ReconcileResult> {
        PostgresMessageAdmissionRepository::reconcile(self, effect).await
    }
}
