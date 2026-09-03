//! Admin Saga Orchestrator microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 9, 19.1).

use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SagaStatus {
    Running,
    Succeeded,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct SagaStep {
    pub name: String,
    pub target_service: String,
    pub completed: bool,
}

#[derive(Debug, Clone)]
pub struct SagaOperation {
    pub operation_id: Uuid,
    pub operation_type: String,
    pub steps: Vec<SagaStep>,
    pub current_step: usize,
    pub status: SagaStatus,
}

pub struct AdminOrchestratorService {
    operations: RwLock<HashMap<Uuid, SagaOperation>>,
    outbox: InMemoryOutbox,
}

impl Default for AdminOrchestratorService {
    fn default() -> Self {
        Self::new()
    }
}

impl AdminOrchestratorService {
    pub fn new() -> Self {
        Self {
            operations: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn start_operation(
        &self,
        operation_id: Uuid,
        operation_type: impl Into<String>,
        step_names: &[(&str, &str)],
    ) -> bool {
        let mut ops = self.operations.write().unwrap();
        if ops.contains_key(&operation_id) {
            return false; // Idempotent: already exists
        }

        let steps = step_names
            .iter()
            .map(|(name, svc)| SagaStep {
                name: (*name).to_string(),
                target_service: (*svc).to_string(),
                completed: false,
            })
            .collect();

        let op = SagaOperation {
            operation_id,
            operation_type: operation_type.into(),
            steps,
            current_step: 0,
            status: SagaStatus::Running,
        };

        let event = OutboxEvent::new(
            "operation",
            operation_id.to_string(),
            1,
            "admin.operation.started.v1",
            Vec::new(),
        );
        self.outbox.stage(event);

        ops.insert(operation_id, op);
        true
    }

    pub fn complete_step(&self, operation_id: Uuid, step_index: usize) -> bool {
        let mut ops = self.operations.write().unwrap();
        let Some(op) = ops.get_mut(&operation_id) else {
            return false;
        };

        if op.status != SagaStatus::Running || step_index != op.current_step {
            return false;
        }

        let total_steps = op.steps.len();
        if let Some(step) = op.steps.get_mut(step_index) {
            step.completed = true;
            op.current_step += 1;

            if op.current_step >= total_steps {
                op.status = SagaStatus::Succeeded;
                let event = OutboxEvent::new(
                    "operation",
                    operation_id.to_string(),
                    op.current_step as u64,
                    "admin.operation.succeeded.v1",
                    Vec::new(),
                );
                self.outbox.stage(event);
            } else {
                let event = OutboxEvent::new(
                    "operation",
                    operation_id.to_string(),
                    op.current_step as u64,
                    "admin.operation.step_completed.v1",
                    step.name.as_bytes().to_vec(),
                );
                self.outbox.stage(event);
            }
            true
        } else {
            false
        }
    }

    pub fn get_status(&self, operation_id: Uuid) -> Option<SagaStatus> {
        self.operations
            .read()
            .unwrap()
            .get(&operation_id)
            .map(|op| op.status.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_saga_lifecycle() {
        let orchestrator = AdminOrchestratorService::new();
        let op_id = Uuid::new_v4();

        // 1. Start user deletion saga
        let steps = [
            ("revoke_identity", "identity"),
            ("close_sessions", "session-directory"),
            ("erase_roster", "roster-authority"),
        ];

        assert!(orchestrator.start_operation(op_id, "user_account_erase", &steps));
        assert!(!orchestrator.start_operation(op_id, "user_account_erase", &steps)); // Idempotent

        assert_eq!(orchestrator.get_status(op_id), Some(SagaStatus::Running));

        // 2. Complete step 0
        assert!(orchestrator.complete_step(op_id, 0));
        assert_eq!(orchestrator.get_status(op_id), Some(SagaStatus::Running));

        // Step 0 again fails (already completed)
        assert!(!orchestrator.complete_step(op_id, 0));

        // 3. Complete remaining steps
        assert!(orchestrator.complete_step(op_id, 1));
        assert!(orchestrator.complete_step(op_id, 2));

        // Saga finished successfully
        assert_eq!(orchestrator.get_status(op_id), Some(SagaStatus::Succeeded));
    }
}
