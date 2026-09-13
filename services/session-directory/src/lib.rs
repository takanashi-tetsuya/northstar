//! Session Directory and Resource Binding Authority microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 8, 19.1, 19.4)
//! and `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, 2.2).

use chrono::Utc;
use foundation_contracts::adapters::common::ErrorDetail;
use foundation_contracts::adapters::session::{
    BindSessionRequest, BindSessionResponse, CloseSessionRequest, CloseSessionResponse,
    CommitResumeRequest, CommitResumeResponse, PrepareResumeRequest, PrepareResumeResponse,
    RenewLeaseRequest, RenewLeaseResponse, ResolveTargetsRequest, ResolveTargetsResponse,
    ResumeFenceRequest, ResumeFenceResponse, RevokeAccountSessionsRequest,
    RevokeAccountSessionsResponse, SessionTarget, ValidateAssertionRequest,
    ValidateAssertionResponse,
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
    pub credential_generation: u64,
    pub region_epoch: u64,
    pub route_incarnation: u64,
    pub lease_expires_at_unix_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct EpochRecord {
    pub last_epoch: u64,
    pub closed_at_ms: Option<u64>,
    pub route_incarnation: u64,
}

#[derive(Debug, Clone)]
struct PendingResume {
    full_jid: String,
    resume_token_hash: Vec<u8>,
    expected_session_epoch: u64,
    new_edge_instance_id: String,
    new_connection_id: String,
}

pub struct SessionDirectoryService {
    sessions: RwLock<HashMap<String, ActiveSession>>, // full_jid -> ActiveSession
    epoch_ledger: RwLock<HashMap<String, EpochRecord>>, // full_jid -> EpochRecord (persistent epoch tracking)
    pending_resumes: RwLock<HashMap<String, PendingResume>>, // opaque id -> one-use resume authority
    account_generations: RwLock<HashMap<String, u64>>,       // credential fence observed at bind
    outbox: InMemoryOutbox,
}

fn now_unix_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn error(code: &'static str, message: &'static str) -> ErrorDetail {
    ErrorDetail::new(code, message)
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
            epoch_ledger: RwLock::new(HashMap::new()),
            pending_resumes: RwLock::new(HashMap::new()),
            account_generations: RwLock::new(HashMap::new()),
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
        let mut ledger = self.epoch_ledger.write().unwrap();

        // Monotonic epoch allocation: survives session close/destruction
        let record = ledger.entry(full_jid.clone()).or_default();
        record.last_epoch += 1;
        record.route_incarnation = record.route_incarnation.saturating_add(1).max(1);
        record.closed_at_ms = None;
        let session_epoch = record.last_epoch;
        let route_incarnation = record.route_incarnation;
        let lease_expires_at_unix_ms = now_unix_ms().saturating_add(30_000);

        let active = ActiveSession {
            account_id: req.auth.account_id.clone(),
            full_jid: full_jid.clone(),
            bare_jid: bare_jid.clone(),
            resource: resource.clone(),
            edge_instance_id: req.edge_instance_id.clone(),
            connection_id: req.connection_id.clone(),
            session_epoch,
            credential_generation: req.auth.credential_generation,
            region_epoch: 1,
            route_incarnation,
            lease_expires_at_unix_ms,
        };

        self.account_generations
            .write()
            .unwrap()
            .insert(req.auth.account_id.clone(), req.auth.credential_generation);

        // Transactional Outbox: stage session bound event
        let payload = serde_json::to_vec(
            &foundation_contracts::adapters::events::SessionBoundEventPayload {
                account_id: req.auth.account_id,
                full_jid: full_jid.clone(),
                edge_instance_id: req.edge_instance_id,
                connection_id: req.connection_id,
                session_epoch,
            },
        )
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
            assertion: None,
            error: None,
        }
    }

    pub fn resume_fence(&self, req: ResumeFenceRequest) -> ResumeFenceResponse {
        let mut sessions = self.sessions.write().unwrap();
        let mut ledger = self.epoch_ledger.write().unwrap();

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

        if req.expected_region_epoch != 0 && existing.region_epoch != req.expected_region_epoch {
            return ResumeFenceResponse {
                success: false,
                new_epoch: existing.session_epoch,
                error: Some(error(
                    "FAILED_PRECONDITION",
                    "Session region epoch no longer matches",
                )),
            };
        }

        existing.session_epoch += 1;
        existing.edge_instance_id = req.new_edge_instance_id;
        existing.connection_id = req.new_connection_id;
        let new_epoch = existing.session_epoch;
        existing.route_incarnation = existing.route_incarnation.saturating_add(1);
        existing.lease_expires_at_unix_ms = now_unix_ms().saturating_add(30_000);

        if let Some(record) = ledger.get_mut(&req.full_jid) {
            record.last_epoch = new_epoch;
            record.route_incarnation = existing.route_incarnation;
        }

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
                    route_incarnation: s.route_incarnation,
                    expires_at_unix_ms: s.lease_expires_at_unix_ms,
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
                    route_incarnation: s.route_incarnation,
                    expires_at_unix_ms: s.lease_expires_at_unix_ms,
                })
                .collect()
        };

        ResolveTargetsResponse { targets }
    }

    pub fn close_session(&self, req: CloseSessionRequest) -> CloseSessionResponse {
        let mut sessions = self.sessions.write().unwrap();
        let mut ledger = self.epoch_ledger.write().unwrap();

        if let Some(existing) = sessions.get(&req.full_jid) {
            // Verify epoch before closing
            if existing.session_epoch == req.session_epoch
                && (req.expected_region_epoch == 0
                    || existing.region_epoch == req.expected_region_epoch)
            {
                sessions.remove(&req.full_jid);

                if let Some(record) = ledger.get_mut(&req.full_jid) {
                    record.closed_at_ms = Some(1); // mark tombstone
                }

                let payload = serde_json::to_vec(
                    &foundation_contracts::adapters::events::SessionClosedEventPayload {
                        full_jid: req.full_jid.clone(),
                        session_epoch: req.session_epoch,
                        reason: req.reason,
                    },
                )
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
        } else if let Some(record) = ledger.get(&req.full_jid) {
            // Closing an already closed session is idempotent for the exact
            // epoch.  A different epoch remains a failed precondition.
            if record.last_epoch == req.session_epoch {
                return CloseSessionResponse { success: true };
            }
        }
        CloseSessionResponse { success: false }
    }

    pub fn renew_lease(&self, req: RenewLeaseRequest) -> RenewLeaseResponse {
        let mut sessions = self.sessions.write().unwrap();
        let Some(session) = sessions.get_mut(&req.full_jid) else {
            return RenewLeaseResponse {
                success: false,
                session_epoch: 0,
                lease_expires_at_unix_ms: 0,
                error: Some(error("NOT_FOUND", "Session does not exist")),
            };
        };
        if session.session_epoch != req.expected_session_epoch {
            return RenewLeaseResponse {
                success: false,
                session_epoch: session.session_epoch,
                lease_expires_at_unix_ms: session.lease_expires_at_unix_ms,
                error: Some(error("FAILED_PRECONDITION", "Session epoch has changed")),
            };
        }
        if req.expected_region_epoch != 0 && session.region_epoch != req.expected_region_epoch {
            return RenewLeaseResponse {
                success: false,
                session_epoch: session.session_epoch,
                lease_expires_at_unix_ms: session.lease_expires_at_unix_ms,
                error: Some(error(
                    "FAILED_PRECONDITION",
                    "Session region epoch has changed",
                )),
            };
        }
        session.lease_expires_at_unix_ms =
            now_unix_ms().saturating_add(i64::from(req.lease_ttl_seconds).saturating_mul(1_000));
        RenewLeaseResponse {
            success: true,
            session_epoch: session.session_epoch,
            lease_expires_at_unix_ms: session.lease_expires_at_unix_ms,
            error: None,
        }
    }

    pub fn prepare_resume(&self, req: PrepareResumeRequest) -> PrepareResumeResponse {
        let sessions = self.sessions.read().unwrap();
        let Some(session) = sessions.get(&req.full_jid) else {
            return PrepareResumeResponse {
                success: false,
                resume_id: None,
                session_epoch: 0,
                error: Some(error("NOT_FOUND", "Session does not exist")),
            };
        };
        if session.session_epoch != req.expected_session_epoch {
            return PrepareResumeResponse {
                success: false,
                resume_id: None,
                session_epoch: session.session_epoch,
                error: Some(error("FAILED_PRECONDITION", "Session epoch has changed")),
            };
        }
        if req.resume_token_hash.is_empty() {
            return PrepareResumeResponse {
                success: false,
                resume_id: None,
                session_epoch: session.session_epoch,
                error: Some(error("UNAUTHENTICATED", "Resume token is invalid")),
            };
        }
        let resume_id = Uuid::new_v4().simple().to_string();
        self.pending_resumes.write().unwrap().insert(
            resume_id.clone(),
            PendingResume {
                full_jid: req.full_jid,
                resume_token_hash: req.resume_token_hash.expose_for_authorized_use().to_vec(),
                expected_session_epoch: req.expected_session_epoch,
                new_edge_instance_id: req.new_edge_instance_id,
                new_connection_id: req.new_connection_id,
            },
        );
        PrepareResumeResponse {
            success: true,
            resume_id: Some(foundation_security::OpaqueToken::new(resume_id)),
            session_epoch: session.session_epoch,
            error: None,
        }
    }

    pub fn commit_resume(&self, req: CommitResumeRequest) -> CommitResumeResponse {
        let resume_id = req.resume_id.expose_for_authorized_transport().to_owned();
        let Some(pending) = self.pending_resumes.write().unwrap().remove(&resume_id) else {
            return CommitResumeResponse {
                success: false,
                new_session_epoch: 0,
                error: Some(error(
                    "ABORTED",
                    "Resume authority is absent or already used",
                )),
            };
        };
        if pending.resume_token_hash.is_empty() {
            return CommitResumeResponse {
                success: false,
                new_session_epoch: 0,
                error: Some(error("UNAUTHENTICATED", "Resume token is invalid")),
            };
        }
        if pending.expected_session_epoch != req.expected_session_epoch {
            return CommitResumeResponse {
                success: false,
                new_session_epoch: pending.expected_session_epoch,
                error: Some(error("FAILED_PRECONDITION", "Resume epoch does not match")),
            };
        }
        let mut sessions = self.sessions.write().unwrap();
        let Some(session) = sessions.get_mut(&pending.full_jid) else {
            return CommitResumeResponse {
                success: false,
                new_session_epoch: 0,
                error: Some(error("NOT_FOUND", "Session does not exist")),
            };
        };
        if session.session_epoch != pending.expected_session_epoch {
            return CommitResumeResponse {
                success: false,
                new_session_epoch: session.session_epoch,
                error: Some(error("FAILED_PRECONDITION", "Session epoch has changed")),
            };
        }
        session.session_epoch = session.session_epoch.saturating_add(1);
        session.route_incarnation = session.route_incarnation.saturating_add(1);
        session.edge_instance_id = pending.new_edge_instance_id;
        session.connection_id = pending.new_connection_id;
        session.lease_expires_at_unix_ms = now_unix_ms().saturating_add(30_000);
        CommitResumeResponse {
            success: true,
            new_session_epoch: session.session_epoch,
            error: None,
        }
    }

    pub fn validate_assertion(&self, req: ValidateAssertionRequest) -> ValidateAssertionResponse {
        match req
            .assertion
            .validate_at(Utc::now(), &req.expected_audience)
        {
            Ok(()) => ValidateAssertionResponse {
                valid: true,
                error: None,
            },
            Err(_) => ValidateAssertionResponse {
                valid: false,
                error: Some(error("UNAUTHENTICATED", "Session assertion is invalid")),
            },
        }
    }

    pub fn revoke_account_sessions(
        &self,
        req: RevokeAccountSessionsRequest,
    ) -> RevokeAccountSessionsResponse {
        let current_generation = self
            .account_generations
            .read()
            .unwrap()
            .get(&req.account_id)
            .copied();
        let Some(current_generation) = current_generation else {
            return RevokeAccountSessionsResponse {
                success: false,
                revoked_count: 0,
                error: Some(error(
                    "NOT_FOUND",
                    "Account does not have an active session",
                )),
            };
        };
        if current_generation != req.expected_credential_generation {
            return RevokeAccountSessionsResponse {
                success: false,
                revoked_count: 0,
                error: Some(error(
                    "FAILED_PRECONDITION",
                    "Credential generation has changed",
                )),
            };
        }
        let mut sessions = self.sessions.write().unwrap();
        let affected: Vec<String> = sessions
            .values()
            .filter(|session| session.account_id == req.account_id)
            .map(|session| session.full_jid.clone())
            .collect();
        let revoked_count = affected.len() as u64;
        let mut ledger = self.epoch_ledger.write().unwrap();
        for full_jid in affected {
            if let Some(session) = sessions.remove(&full_jid) {
                if let Some(record) = ledger.get_mut(&full_jid) {
                    record.closed_at_ms = Some(now_unix_ms().max(0) as u64);
                    record.last_epoch = session.session_epoch;
                }
            }
        }
        RevokeAccountSessionsResponse {
            success: true,
            revoked_count,
            error: None,
        }
    }

    pub fn pending_outbox(&self) -> Vec<OutboxEvent> {
        self.outbox.pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundation_contracts::adapters::assertions::SessionAssertion;
    use foundation_contracts::adapters::common::AuthContext;

    #[test]
    fn binding_resolution_and_fencing_lifecycle() {
        let directory = SessionDirectoryService::new();
        let auth = AuthContext::new("acc-1", "alice@example.com", 1, "local");

        // 1. Bind session
        let bind = directory.bind_session(BindSessionRequest {
            auth: auth.clone(),
            auth_grant: None,
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
            trace: None,
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
            expected_region_epoch: 1,
            idempotency_key: None,
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
            expected_region_epoch: 1,
            idempotency_key: None,
            trace: None,
        });
        assert!(valid_resume.success);
        assert_eq!(valid_resume.new_epoch, 2);

        // 5. Target now reflects edge-2 and connection-200
        let updated_resolved = directory.resolve_targets(ResolveTargetsRequest {
            bare_or_full_jid: "alice@example.com/laptop".to_string(),
            trace: None,
        });
        assert_eq!(updated_resolved.targets[0].edge_instance_id, "edge-2");
        assert_eq!(updated_resolved.targets[0].connection_id, "conn-200");
    }

    #[test]
    fn epoch_persists_monotonically_across_session_close_and_rebind() {
        let directory = SessionDirectoryService::new();
        let auth = AuthContext::new("acc-1", "alice@example.com", 1, "local");

        // 1. Initial bind gives epoch 1
        let bind1 = directory.bind_session(BindSessionRequest {
            auth: auth.clone(),
            auth_grant: None,
            desired_resource: "mobile".to_string(),
            edge_instance_id: "edge-1".to_string(),
            connection_id: "conn-1".to_string(),
            trace: None,
        });
        assert_eq!(bind1.session_epoch, 1);

        // 2. Close session
        let close = directory.close_session(CloseSessionRequest {
            full_jid: "alice@example.com/mobile".to_string(),
            session_epoch: 1,
            reason: "client disconnect".to_string(),
            expected_region_epoch: 1,
            idempotency_key: None,
            trace: None,
        });
        assert!(close.success);

        // 3. Re-binding the SAME resource MUST receive epoch 2 (never resets to 1, preventing ABA)
        let bind2 = directory.bind_session(BindSessionRequest {
            auth,
            auth_grant: None,
            desired_resource: "mobile".to_string(),
            edge_instance_id: "edge-1".to_string(),
            connection_id: "conn-2".to_string(),
            trace: None,
        });
        assert_eq!(bind2.session_epoch, 2);
    }

    #[test]
    fn lease_and_route_metadata_are_fenced() {
        let directory = SessionDirectoryService::new();
        let auth = AuthContext::new("acc-lease", "lease@example.com", 7, "local");
        let bind = directory.bind_session(BindSessionRequest {
            auth,
            auth_grant: None,
            desired_resource: "desktop".to_owned(),
            edge_instance_id: "edge-1".to_owned(),
            connection_id: "conn-1".to_owned(),
            trace: None,
        });
        let target = directory
            .resolve_targets(ResolveTargetsRequest {
                bare_or_full_jid: bind.full_jid.clone(),
                trace: None,
            })
            .targets
            .pop()
            .expect("bound target");
        assert_eq!(target.route_incarnation, 1);
        assert!(target.expires_at_unix_ms > now_unix_ms());

        let renewed = directory.renew_lease(RenewLeaseRequest {
            full_jid: bind.full_jid.clone(),
            expected_session_epoch: bind.session_epoch,
            expected_region_epoch: 1,
            lease_ttl_seconds: 120,
            idempotency_key: None,
            trace: None,
        });
        assert!(renewed.success);
        assert!(renewed.lease_expires_at_unix_ms >= target.expires_at_unix_ms);

        let stale = directory.renew_lease(RenewLeaseRequest {
            full_jid: bind.full_jid,
            expected_session_epoch: 999,
            expected_region_epoch: 1,
            lease_ttl_seconds: 120,
            idempotency_key: None,
            trace: None,
        });
        assert!(!stale.success);
        assert_eq!(stale.error.unwrap().code, "FAILED_PRECONDITION");
    }

    #[test]
    fn resume_authority_is_single_use_and_fenced() {
        let directory = SessionDirectoryService::new();
        let bind = directory.bind_session(BindSessionRequest {
            auth: AuthContext::new("acc-resume", "resume@example.com", 1, "local"),
            auth_grant: None,
            desired_resource: "phone".to_owned(),
            edge_instance_id: "edge-1".to_owned(),
            connection_id: "conn-1".to_owned(),
            trace: None,
        });
        let prepared = directory.prepare_resume(PrepareResumeRequest {
            full_jid: bind.full_jid,
            resume_token_hash: foundation_security::SecretBytes::new(vec![0xabu8; 32]),
            expected_session_epoch: 1,
            new_edge_instance_id: "edge-2".to_owned(),
            new_connection_id: "conn-2".to_owned(),
            idempotency_key: None,
            trace: None,
        });
        assert!(prepared.success);
        let resume_id = prepared.resume_id.expect("opaque resume id");
        let committed = directory.commit_resume(CommitResumeRequest {
            resume_id: resume_id.clone(),
            expected_session_epoch: 1,
            idempotency_key: None,
            trace: None,
        });
        assert!(committed.success);
        assert_eq!(committed.new_session_epoch, 2);

        let replay = directory.commit_resume(CommitResumeRequest {
            resume_id,
            expected_session_epoch: 1,
            idempotency_key: None,
            trace: None,
        });
        assert!(!replay.success);
        assert_eq!(replay.error.unwrap().code, "ABORTED");
    }

    #[test]
    fn account_revocation_removes_all_resources_and_assertions_fail_closed() {
        let directory = SessionDirectoryService::new();
        let auth = AuthContext::new("acc-revoke", "revoke@example.com", 4, "local");
        for resource in ["desktop", "mobile"] {
            directory.bind_session(BindSessionRequest {
                auth: auth.clone(),
                auth_grant: None,
                desired_resource: resource.to_owned(),
                edge_instance_id: "edge-1".to_owned(),
                connection_id: format!("conn-{resource}"),
                trace: None,
            });
        }
        let revoked = directory.revoke_account_sessions(RevokeAccountSessionsRequest {
            account_id: "acc-revoke".to_owned(),
            expected_credential_generation: 4,
            idempotency_key: None,
            reason: "credential rotation".to_owned(),
            trace: None,
        });
        assert!(revoked.success);
        assert_eq!(revoked.revoked_count, 2);
        assert!(directory
            .resolve_targets(ResolveTargetsRequest {
                bare_or_full_jid: "revoke@example.com".to_owned(),
                trace: None,
            })
            .targets
            .is_empty());

        let now = Utc::now();
        let invalid = directory.validate_assertion(ValidateAssertionRequest {
            assertion: SessionAssertion {
                issuer: "identity".to_owned(),
                audience: "wrong-service".to_owned(),
                issued_at: now,
                not_before: now,
                expires_at: now + chrono::Duration::seconds(60),
                jwt_id: "jti".to_owned(),
                schema_version: 1,
                account_id: "acc-revoke".to_owned(),
                bare_jid: "revoke@example.com".to_owned(),
                full_jid: "revoke@example.com/desktop".to_owned(),
                connection_id: "conn-desktop".to_owned(),
                edge_instance_id: "edge-1".to_owned(),
                session_epoch: 1,
                credential_generation: 4,
                home_region: "local".to_owned(),
                region_epoch: 1,
                key_id: "key-1".to_owned(),
                algorithm: "Ed25519".to_owned(),
                signature: vec![1],
                scopes: vec!["xmpp:bind".to_owned()],
                roles: Vec::new(),
            },
            expected_audience: "session-directory".to_owned(),
            trace: None,
        });
        assert!(!invalid.valid);
        assert_eq!(invalid.error.unwrap().code, "UNAUTHENTICATED");
    }
}
