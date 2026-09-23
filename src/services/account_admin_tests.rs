use super::*;
use crate::services::{api_mutations::*, api_queries::ApiReadAuthority};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

fn admission() -> AdminMutationAdmission<'static> {
    AdminMutationAdmission {
        authority: ApiReadAuthority {
            user_id: Uuid::nil(),
            auth_generation: 0,
            session_token: "fixture",
        },
        idempotency: IdempotencyRequest {
            request_id: Uuid::nil(),
            actor_id: Some(Uuid::nil()),
            principal_scope: b"actor",
            capacity_scope: b"actor",
            target_scope: b"registration_closed",
            principal_kind: ApiPrincipalKind::Admin,
            method: "POST",
            route: "/api/v1/admin/registration",
            idempotency_key: "fixture-idempotency",
            request_fingerprint: [0; 32],
            ttl_seconds: 3600,
            lease_seconds: 180,
        },
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Committed,
    Replay,
    Rejected,
    Failed,
}
struct Repository {
    outcome: Outcome,
    mutations: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    current_closed: Arc<AtomicBool>,
    read_fails: Arc<AtomicBool>,
}
impl RegistrationAdminRepository for Repository {
    async fn set_registration(
        &self,
        _: AdminMutationAdmission<'_>,
        enabled: bool,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.mutations.fetch_add(1, Ordering::Relaxed);
        let response =
            StoredApiResponse::json(200, serde_json::json!({"open_registration":enabled}))?;
        Ok(match self.outcome {
            Outcome::Committed => ApiMutationOutcome::Committed(response),
            Outcome::Replay => ApiMutationOutcome::Replay(IdempotentResponse {
                request_id: Uuid::nil(),
                status: response.status,
                headers: response.headers,
                body: response.body,
            }),
            Outcome::Rejected => ApiMutationOutcome::Rejected(ApiMutationRejection::Forbidden),
            Outcome::Failed => anyhow::bail!("fixture mutation failed"),
        })
    }
    async fn current_registration_closed(&self) -> Result<bool> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        anyhow::ensure!(
            !self.read_fails.load(Ordering::Acquire),
            "fixture read failed"
        );
        Ok(self.current_closed.load(Ordering::Acquire))
    }
}
struct Cache {
    locked: bool,
    closed: Arc<AtomicBool>,
}
impl RegistrationCache for Cache {
    fn dependency_locked(&self) -> bool {
        self.locked
    }
    fn apply_current_closed(&self, closed: bool) {
        self.closed.store(closed || self.locked, Ordering::Release);
    }
}
fn registration(outcome: Outcome, locked: bool) -> RegistrationAdminService<Repository, Cache> {
    RegistrationAdminService::new(
        Repository {
            outcome,
            mutations: Arc::default(),
            reads: Arc::default(),
            current_closed: Arc::new(AtomicBool::new(true)),
            read_fails: Arc::default(),
        },
        Cache {
            locked,
            closed: Arc::default(),
        },
    )
}

#[tokio::test]
async fn registration_dependency_lock_precedes_repository_admission() {
    let service = registration(Outcome::Committed, true);
    assert!(matches!(
        service.set_registration(admission(), true).await.unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::Conflict(_))
    ));
    assert_eq!(service.repository.mutations.load(Ordering::Relaxed), 0);
    assert_eq!(service.repository.reads.load(Ordering::Relaxed), 0);
    // Closing remains permitted, and still refreshes the original flag.
    assert!(matches!(
        service.set_registration(admission(), false).await.unwrap(),
        ApiMutationOutcome::Committed(_)
    ));
    assert!(service.cache.closed.load(Ordering::Acquire));
}

#[tokio::test]
async fn committed_and_replayed_registration_refresh_current_durable_state() {
    for outcome in [Outcome::Committed, Outcome::Replay] {
        let service = registration(outcome, false);
        let result = service.set_registration(admission(), true).await.unwrap();
        let bytes = match result {
            ApiMutationOutcome::Committed(response) => response.body,
            ApiMutationOutcome::Replay(response) => response.body,
            _ => panic!("fixture must succeed"),
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["open_registration"],
            true
        );
        assert!(
            service.cache.closed.load(Ordering::Acquire),
            "current durable state wins over the old response"
        );
        service
            .repository
            .current_closed
            .store(false, Ordering::Release);
        service.set_registration(admission(), false).await.unwrap();
        assert!(!service.cache.closed.load(Ordering::Acquire));
        assert_eq!(service.repository.reads.load(Ordering::Relaxed), 2);
    }
}

#[tokio::test]
async fn failed_cache_refresh_preserves_committed_or_replayed_response() {
    for outcome in [Outcome::Committed, Outcome::Replay] {
        let service = registration(outcome, false);
        service.repository.read_fails.store(true, Ordering::Release);
        let result = service.set_registration(admission(), true).await.unwrap();
        assert!(matches!(
            result,
            ApiMutationOutcome::Committed(_) | ApiMutationOutcome::Replay(_)
        ));
        assert!(!service.cache.closed.load(Ordering::Acquire));
        assert_eq!(service.repository.reads.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn rejected_and_failed_mutations_do_not_refresh_registration_cache() {
    for outcome in [Outcome::Rejected, Outcome::Failed] {
        let service = registration(outcome, false);
        let result = service.set_registration(admission(), true).await;
        assert!(matches!(
            result,
            Err(_) | Ok(ApiMutationOutcome::Rejected(_))
        ));
        assert_eq!(service.repository.reads.load(Ordering::Relaxed), 0);
    }
}

struct NoAdmission;
impl AccountAdminRepository for NoAdmission {
    async fn update_user(
        &self,
        _: AdminMutationAdmission<'_>,
        _: Uuid,
        _: UserStatusPatch,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        panic!("invalid input reached admission")
    }
    async fn clear_offline_messages(
        &self,
        _: AdminMutationAdmission<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        panic!("unused fixture method")
    }
}
impl SessionAdminRepository for NoAdmission {
    async fn kick_session<L: AdminSessionLookup>(
        &self,
        _: AdminMutationAdmission<'_>,
        _: Uuid,
        _: &L,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        panic!("invalid input reached admission")
    }
}
impl AdminSessionLookup for NoAdmission {
    fn exact_connection(&self, _: Uuid) -> Option<SessionKickSnapshot> {
        panic!("invalid input read live sessions")
    }
}
#[tokio::test]
async fn empty_patch_and_nil_connection_fail_before_admission() {
    let accounts = AccountAdminService::new(NoAdmission);
    assert!(matches!(
        accounts
            .update_user(
                admission(),
                Uuid::new_v4(),
                UserStatusPatch {
                    disabled: None,
                    admin: None
                }
            )
            .await
            .unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::BadRequest("user patch is empty"))
    ));
    let sessions = SessionAdminService::new(NoAdmission, NoAdmission);
    assert!(matches!(
        sessions
            .kick_session(admission(), Uuid::nil())
            .await
            .unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::BadRequest(
            "connection id must not be nil"
        ))
    ));
}
