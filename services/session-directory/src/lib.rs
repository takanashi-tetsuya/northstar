//! Session Directory and Resource Binding Authority microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 8, 19.1, 19.4).

use foundation_contracts::common::ErrorDetail;
use foundation_contracts::session::{
    BindSessionRequest, BindSessionResponse, CloseSessionRequest, CloseSessionResponse,
    ResolveTargetsRequest, ResolveTargetsResponse, ResumeFenceRequest, ResumeFenceResponse,
    SessionTarget,
};
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub account_id: String,
    pub full_jid: String,
    pub bare_jid: String,
    pub resource: String,
    pub edge_instance_id: String,
    pub connection_id: String,
    pub session_epoch: u64,
}

pub struct SessionDirectoryService {
    sessions: RwLock<HashMap<String, ActiveSession>>, // full_jid -> ActiveSession
    outbox: InMemoryOutbox,
}

impl Default for SessionDirectoryService {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionDirectoryService {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn bind_session(&self, req: BindSessionRequest) -> BindSessionResponse {
        let bare_jid = req.auth.canonical_jid.clone();
        let resource = if req.desired_resource.trim().is_empty() {
            Uuid::new_v4().simple().to_string()[..8].to_string()
        } else {
            req.desired_resource.trim().to_string()
        };

        let full_jid = format!("{bare_jid}/{resource}");
        let mut sessions = self.sessions.write().unwrap();

        // Calculate next monotonic epoch for this full_jid
        let session_epoch = if let Some(existing) = sessions.get(&full_jid) {
            existing.session_epoch + 1
        } else {
            1
        };

        let active = ActiveSession {
            account_id: req.auth.account_id.clone(),
            full_jid: full_jid.clone(),
            bare_jid: bare_jid.clone(),
            resource: resource.clone(),
            edge_instance_id: req.edge_instance_id.clone(),
            connection_id: req.connection_id.clone(),
            session_epoch,
        };

        // Transactional Outbox: stage session bound event
        let payload = serde_json::to_vec(&foundation_contracts::events::SessionBoundEventPayload {
            account_id: req.auth.account_id,
            full_jid: full_jid.clone(),
            edge_instance_id: req.edge_instance_id,
            connection_id: req.connection_id,
            session_epoch,
        })
        .unwrap_or_default();

        let event = OutboxEvent::new(
            "session",
            &full_jid,
            session_epoch,
            "session.bound.v1",
            payload,
        );
        self.outbox.stage(event);

        sessions.insert(full_jid.clone(), active);

        BindSessionResponse {
            success: true,
            full_jid,
            session_epoch,
            error: None,
        }
    }

    pub fn resume_fence(&self, req: ResumeFenceRequest) -> ResumeFenceResponse {
        let mut sessions = self.sessions.write().unwrap();
        let Some(existing) = sessions.get_mut(&req.full_jid) else {
            return ResumeFenceResponse {
                success: false,
                new_epoch: 0,
                error: Some(ErrorDetail::new("ITEM_NOT_FOUND", "Session does not exist")),
            };
        };

        // Fencing check: expected epoch must match exactly to prevent ABA split-brain
        if existing.session_epoch != req.expected_epoch {
            return ResumeFenceResponse {
                success: false,
                new_epoch: existing.session_epoch,
                error: Some(
                    ErrorDetail::new(
                        "CONFLICT",
                        "Session epoch conflict: fenced out by newer connection",
                    )
                    .with_version(existing.session_epoch),
                ),
            };
        }

        existing.session_epoch += 1;
        existing.edge_instance_id = req.new_edge_instance_id;
        existing.connection_id = req.new_connection_id;
        let new_epoch = existing.session_epoch;

        ResumeFenceResponse {
            success: true,
            new_epoch,
            error: None,
        }
    }

    pub fn resolve_targets(&self, req: ResolveTargetsRequest) -> ResolveTargetsResponse {
        let query = req.bare_or_full_jid.trim();
        let sessions = self.sessions.read().unwrap();

        let targets: Vec<SessionTarget> = if query.contains('/') {
            // Exact Full-JID lookup
            sessions
                .get(query)
                .map(|s| SessionTarget {
                    full_jid: s.full_jid.clone(),
                    edge_instance_id: s.edge_instance_id.clone(),
                    connection_id: s.connection_id.clone(),
                    session_epoch: s.session_epoch,
                })
                .into_iter()
                .collect()
        } else {
            // Bare JID lookup (fanout to all resources of the user)
            sessions
                .values()
                .filter(|s| s.bare_jid == query)
                .map(|s| SessionTarget {
                    full_jid: s.full_jid.clone(),
                    edge_instance_id: s.edge_instance_id.clone(),
                    connection_id: s.connection_id.clone(),
                    session_epoch: s.session_epoch,
                })
                .collect()
        };

        ResolveTargetsResponse { targets }
    }

    pub fn close_session(&self, req: CloseSessionRequest) -> CloseSessionResponse {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(existing) = sessions.get(&req.full_jid) {
            // Verify epoch before closing
            if existing.session_epoch == req.session_epoch {
                sessions.remove(&req.full_jid);

                let payload =
                    serde_json::to_vec(&foundation_contracts::events::SessionClosedEventPayload {
                        full_jid: req.full_jid.clone(),
                        session_epoch: req.session_epoch,
                        reason: req.reason,
                    })
                    .unwrap_or_default();

                let event = OutboxEvent::new(
                    "session",
                    &req.full_jid,
                    req.session_epoch,
                    "session.closed.v1",
                    payload,
                );
                self.outbox.stage(event);

                return CloseSessionResponse { success: true };
            }
        }
        CloseSessionResponse { success: false }
    }

    pub fn pending_outbox(&self) -> Vec<OutboxEvent> {
        self.outbox.pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundation_contracts::common::AuthContext;

    #[test]
    fn binding_resolution_and_fencing_lifecycle() {
        let directory = SessionDirectoryService::new();
        let auth = AuthContext::new("acc-1", "alice@example.com", 1, "local");

        // 1. Bind session
        let bind = directory.bind_session(BindSessionRequest {
            auth: auth.clone(),
            desired_resource: "laptop".to_string(),
            edge_instance_id: "edge-1".to_string(),
            connection_id: "conn-100".to_string(),
            trace: None,
        });

        assert!(bind.success);
        assert_eq!(bind.full_jid, "alice@example.com/laptop");
        assert_eq!(bind.session_epoch, 1);

        // 2. Resolve target
        let resolved = directory.resolve_targets(ResolveTargetsRequest {
            bare_or_full_jid: "alice@example.com".to_string(),
        });
        assert_eq!(resolved.targets.len(), 1);
        assert_eq!(resolved.targets[0].full_jid, "alice@example.com/laptop");
        assert_eq!(resolved.targets[0].edge_instance_id, "edge-1");

        // 3. Resume with outdated epoch is fenced out
        let stale_resume = directory.resume_fence(ResumeFenceRequest {
            full_jid: "alice@example.com/laptop".to_string(),
            expected_epoch: 999, // Stale!
            new_edge_instance_id: "edge-2".to_string(),
            new_connection_id: "conn-200".to_string(),
            trace: None,
        });
        assert!(!stale_resume.success);
        assert_eq!(stale_resume.error.unwrap().code, "CONFLICT");

        // 4. Resume with valid epoch succeeds and increments epoch
        let valid_resume = directory.resume_fence(ResumeFenceRequest {
            full_jid: "alice@example.com/laptop".to_string(),
            expected_epoch: 1,
            new_edge_instance_id: "edge-2".to_string(),
            new_connection_id: "conn-200".to_string(),
            trace: None,
        });
        assert!(valid_resume.success);
        assert_eq!(valid_resume.new_epoch, 2);

        // 5. Target now reflects edge-2 and connection-200
        let updated_resolved = directory.resolve_targets(ResolveTargetsRequest {
            bare_or_full_jid: "alice@example.com/laptop".to_string(),
        });
        assert_eq!(updated_resolved.targets[0].edge_instance_id, "edge-2");
        assert_eq!(updated_resolved.targets[0].connection_id, "conn-200");
    }
}
