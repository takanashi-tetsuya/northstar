use super::*;
use northstar_operations_core::api_mutations::{ApiPrincipalKind, IdempotencyRequest};
use northstar_security::password_work::{self, PasswordWorkReservation};
use std::{
    future::Future,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

struct Repository<'a> {
    intent: &'a PowIntent,
    http_intent: &'a PowIntent,
    proof: &'a PowProof,
    actors: &'a [String],
    calls: Mutex<Vec<&'static str>>,
    reservation: Mutex<Option<PasswordWorkReservation>>,
    availability: Mutex<Option<HttpRegistrationAvailability>>,
    fail_http: AtomicBool,
}
impl Repository<'_> {
    fn check_policy(&self, policy: AccountPolicy) {
        assert!(policy.invitation_required, "complete registration policy");
        assert_eq!(
            policy.registration_rate_per_hour, 13,
            "complete registration policy"
        );
        assert_eq!(
            policy.scram_iterations, 8192,
            "complete registration policy"
        );
        assert!(!policy.scram_sha1_enabled, "complete registration policy");
    }
    fn check_request(&self, request: RegistrationRequest<'_>) {
        assert_eq!(request.username, "Alice", "original username");
        assert_eq!(
            request.password, "sentinel-registration-password",
            "original password"
        );
        assert_eq!(
            request.invitation_token,
            Some("invitation-sentinel"),
            "original invitation"
        );
        assert_eq!(request.proof, Some(self.proof), "complete proof");
        assert_eq!(request.subject, "registration:alice", "original subject");
        assert_eq!(request.actors, self.actors, "original actor order");
    }
}
impl AccountRepository for Repository<'_> {
    async fn register_http(
        &self,
        request: HttpRegistrationRequest<'_>,
        policy: AccountPolicy,
    ) -> Result<HttpRegistrationOutcome> {
        self.calls.lock().unwrap().push("HTTP registration");
        self.check_policy(policy);
        assert_eq!(request.intent, self.http_intent, "original HTTP intent");
        self.check_request(RegistrationRequest {
            username: request.username,
            password: request.password,
            invitation_token: request.invitation_token,
            proof: request.proof,
            intent: request.intent,
            subject: request.subject,
            actors: request.actors,
        });
        let idempotency = request.idempotency;
        assert_eq!(
            idempotency.request_id,
            Uuid::from_u128(11),
            "request identity"
        );
        assert_eq!(
            idempotency.actor_id,
            Some(Uuid::from_u128(12)),
            "actor identity"
        );
        assert_eq!(
            idempotency.principal_scope, b"original principal",
            "principal scope"
        );
        assert_eq!(
            idempotency.capacity_scope, b"original capacity",
            "capacity scope"
        );
        assert_eq!(idempotency.target_scope, b"original target", "target scope");
        assert_eq!(
            idempotency.principal_kind,
            ApiPrincipalKind::Anonymous,
            "principal kind"
        );
        assert_eq!(idempotency.method, "POST", "original method");
        assert_eq!(idempotency.route, "/api/v1/register", "original route");
        assert_eq!(
            idempotency.idempotency_key, "registration-idempotency",
            "idempotency key"
        );
        assert_eq!(
            idempotency.request_fingerprint, [37; 32],
            "body fingerprint"
        );
        assert_eq!(idempotency.ttl_seconds, 1234, "idempotency TTL");
        assert_eq!(idempotency.lease_seconds, 97, "lease duration");
        *self.availability.lock().unwrap() = Some(request.availability);
        if self.fail_http.load(Ordering::Acquire) {
            anyhow::bail!("HTTP repository sentinel");
        }
        Ok(HttpRegistrationOutcome::Created(
            b"{ \"username\": \"Alice\" }\n".to_vec(),
        ))
    }
    async fn verify_registration_guard(
        &self,
        _: RegistrationGuardRequest<'_>,
    ) -> Result<RegistrationGuardOutcome> {
        panic!("registration must remain one repository command")
    }
    async fn register(
        &self,
        request: RegistrationRequest<'_>,
        policy: AccountPolicy,
        password_work: PasswordWorkReservation,
    ) -> Result<RegistrationOutcome> {
        self.calls.lock().unwrap().push("XMPP registration");
        self.check_policy(policy);
        assert_eq!(request.intent, self.intent, "original XMPP intent");
        self.check_request(request);
        *self.reservation.lock().unwrap() = Some(password_work);
        Ok(RegistrationOutcome::Created(RegistrationAccount {
            username: "Alice".to_owned(),
        }))
    }
    async fn change_password(
        &self,
        _: PasswordChangeRequest<'_>,
        _: AccountPolicy,
    ) -> Result<PasswordChangeOutcome> {
        panic!("unexpected password change")
    }
    async fn quiesce_for_deletion(
        &self,
        _: DeletionQuiesceRequest<'_>,
    ) -> Result<DeletionQuiesceOutcome> {
        panic!("unexpected deletion")
    }
    async fn delete_quiesced(&self, _: Uuid) -> Result<Option<RemovedAccount>> {
        panic!("unexpected deletion")
    }
    async fn claim_deletion_recovery(&self, _: i64, _: i64) -> Result<Vec<DeletionRecoveryJob>> {
        panic!("unexpected recovery")
    }
    async fn release_deletion_recovery(&self, _: &DeletionRecoveryJob, _: &str) -> Result<bool> {
        panic!("unexpected recovery")
    }
}

#[test]
fn registration_waits_for_password_capacity_and_forwards_complete_http_command() {
    let intent = PowIntent::xmpp_registration(
        "Alice",
        "sentinel-registration-password",
        Some("invitation-sentinel"),
    );
    let proof = PowProof {
        challenge_id: Uuid::from_u128(10),
        nonce: "proof-sentinel".to_owned(),
    };
    let http_intent = PowIntent::new(
        northstar_abuse_policy::AbuseAction::Registration,
        "POST",
        "/api/v1/register",
        [37; 32],
    )
    .unwrap();
    let actors = vec!["ip:192.0.2.1".to_owned(), "account:alice".to_owned()];
    let service = AccountService::new(
        Repository {
            intent: &intent,
            http_intent: &http_intent,
            proof: &proof,
            actors: &actors,
            calls: Mutex::default(),
            reservation: Mutex::default(),
            availability: Mutex::default(),
            fail_http: AtomicBool::new(false),
        },
        true,
        13,
        8192,
        false,
    );
    let request = || RegistrationRequest {
        username: "Alice",
        password: "sentinel-registration-password",
        invitation_token: Some("invitation-sentinel"),
        proof: Some(&proof),
        intent: &intent,
        subject: "registration:alice",
        actors: &actors,
    };
    // This is the only password-work consumer in this test binary. Retain
    // every immediately available public reservation without spawning tasks.
    let mut context = Context::from_waker(Waker::noop());
    let mut held = Vec::new();
    loop {
        let mut reservation = Box::pin(password_work::reserve());
        match reservation.as_mut().poll(&mut context) {
            Poll::Ready(Ok(reservation)) => held.push(reservation),
            Poll::Ready(Err(error)) => panic!("reserve active capacity: {error}"),
            Poll::Pending => break,
        }
        assert!(
            held.len() < 128,
            "password work has bounded active capacity"
        );
    }
    assert!(!held.is_empty(), "active password capacity exists");
    let mut registration = Box::pin(service.register(request()));
    assert!(
        registration.as_mut().poll(&mut context).is_pending(),
        "CPU admission precedes persistence"
    );
    assert!(
        service.repository.calls.lock().unwrap().is_empty(),
        "CPU admission precedes persistence"
    );
    drop(held.pop().unwrap());
    let Poll::Ready(Ok(RegistrationOutcome::Created(account))) =
        registration.as_mut().poll(&mut context)
    else {
        panic!("released CPU capacity must admit registration");
    };
    assert_eq!(account.username, "Alice", "repository result preserved");
    drop(registration);
    assert_eq!(
        *service.repository.calls.lock().unwrap(),
        ["XMPP registration"],
        "one admitted repository call"
    );
    let mut next = Box::pin(password_work::reserve());
    assert!(
        next.as_mut().poll(&mut context).is_pending(),
        "repository owns the actual CPU reservation"
    );
    drop(service.repository.reservation.lock().unwrap().take());
    let Poll::Ready(Ok(released)) = next.as_mut().poll(&mut context) else {
        panic!("repository drop releases CPU capacity");
    };
    drop(released);
    drop(next);
    drop(held);

    let mut admitted = Vec::new();
    loop {
        match password_work::admit() {
            Ok(admission) => admitted.push(admission),
            Err(error) => {
                assert!(error.is_overloaded(), "hard admission rejection");
                break;
            }
        }
        assert!(
            admitted.len() < 128,
            "password work has bounded total capacity"
        );
    }
    let mut overloaded = Box::pin(service.register(request()));
    assert!(
        matches!(
            overloaded.as_mut().poll(&mut context),
            Poll::Ready(Ok(RegistrationOutcome::PasswordWorkOverloaded))
        ),
        "overload preserved as immediate retryable outcome"
    );
    drop(overloaded);
    assert_eq!(
        *service.repository.calls.lock().unwrap(),
        ["XMPP registration"],
        "overload never reaches persistence"
    );

    let closed = Arc::new(AtomicBool::new(false));
    let http_request = || HttpRegistrationRequest {
        idempotency: IdempotencyRequest {
            request_id: Uuid::from_u128(11),
            actor_id: Some(Uuid::from_u128(12)),
            principal_scope: b"original principal",
            capacity_scope: b"original capacity",
            target_scope: b"original target",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: "registration-idempotency",
            request_fingerprint: [37; 32],
            ttl_seconds: 1234,
            lease_seconds: 97,
        },
        username: "Alice",
        password: "sentinel-registration-password",
        invitation_token: Some("invitation-sentinel"),
        proof: Some(&proof),
        intent: &http_intent,
        subject: "registration:alice",
        actors: &actors,
        availability: HttpRegistrationAvailability::new(closed.clone(), false, true),
    };
    // HTTP persistence owns admission; even an exhausted public password
    // queue must not prevent forwarding the complete idempotent command.
    let mut http = Box::pin(service.register_http(http_request()));
    let Poll::Ready(Ok(HttpRegistrationOutcome::Created(bytes))) = http.as_mut().poll(&mut context)
    else {
        panic!("HTTP command must delegate directly to its repository");
    };
    assert_eq!(
        bytes, b"{ \"username\": \"Alice\" }\n",
        "exact repository response bytes"
    );
    drop(http);
    assert_eq!(
        *service.repository.calls.lock().unwrap(),
        ["XMPP registration", "HTTP registration"],
        "HTTP delegation at full password capacity"
    );
    let availability = service
        .repository
        .availability
        .lock()
        .unwrap()
        .take()
        .unwrap();
    assert!(!availability.is_closed(), "original availability");
    assert!(
        availability.requires_invitation(),
        "original invitation policy"
    );
    closed.store(true, Ordering::Release);
    assert!(availability.is_closed(), "same live availability flag");
    assert!(
        !availability.requires_invitation(),
        "same live availability flag"
    );
    service.repository.fail_http.store(true, Ordering::Release);
    let mut failed_http = Box::pin(service.register_http(http_request()));
    let Poll::Ready(Err(error)) = failed_http.as_mut().poll(&mut context) else {
        panic!("repository failure must propagate");
    };
    assert_eq!(
        error.to_string(),
        "HTTP repository sentinel",
        "original repository failure"
    );
    assert_eq!(
        *service.repository.calls.lock().unwrap(),
        [
            "XMPP registration",
            "HTTP registration",
            "HTTP registration"
        ],
        "one repository call per HTTP command"
    );
    drop(admitted);
}
