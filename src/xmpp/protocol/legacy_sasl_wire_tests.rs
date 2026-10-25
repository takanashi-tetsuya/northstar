use super::{
    begin_owned_session_cleanup, claim_session_cleanup, client_stream_limits_feature,
    drop_requires_local_quiesce, durable_delivery_managed_by_sm, legacy_sasl_auth,
    legacy_sasl_payload, resource_bind_deadline_for, unauthenticated_timed_out_for, Action,
    PostActionHandle, PostActionSupervisor, PostActionTelemetry, ResumePayload,
    SessionCleanupOwnership, SessionTerminationSignals, StreamLimits,
};
use roxmltree::Document;

#[test]
fn durable_ownership_is_marked_before_polling_and_survives_cancellation() {
    use std::future::Future;
    let mut ownership = super::LiveSessionOwnership::default();
    assert!(!ownership.may_own());
    let polled = std::cell::Cell::new(false);
    let mut attempt = Box::pin(ownership.attempt(async {
        polled.set(true);
        std::future::pending::<()>().await;
    }));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(attempt.as_mut().poll(&mut context).is_pending());
    drop(attempt);
    assert!(polled.get());
    assert!(
        ownership.may_own(),
        "cancelled replies cannot prove that no lease committed"
    );
}

#[tokio::test]
async fn failed_and_retried_ownership_attempts_never_reset_durable_cleanup_evidence() {
    let mut ownership = super::LiveSessionOwnership::default();
    let result = ownership
        .attempt(async { Err::<(), _>("unknown commit outcome") })
        .await;
    assert!(result.is_err());
    assert!(ownership.may_own());
    // The same marker wraps binding, SM creation and resume claims. A
    // rejected retry cannot clear an earlier possibly committed lease.
    let rejected = ownership.attempt(async { false }).await;
    assert!(!rejected);
    assert!(ownership.may_own());
    ownership.attempt(async {}).await;
    assert!(ownership.may_own());
}

fn document(xml: &str) -> Document<'_> {
    Document::parse(xml).unwrap()
}

#[test]
fn durable_counted_stanza_uses_transport_ownership_without_stream_management() {
    let stanza = "<message xmlns='jabber:client' to='bob@example.test'/>";
    assert!(!durable_delivery_managed_by_sm(false, stanza, true));
    assert!(durable_delivery_managed_by_sm(true, stanza, true));
    assert!(!durable_delivery_managed_by_sm(true, stanza, false));
    assert!(!durable_delivery_managed_by_sm(
        true,
        "<a xmlns='urn:xmpp:sm:3' h='1'/>",
        true
    ));
}

#[test]
fn accepts_only_the_bounded_legacy_sasl_wire_shape() {
    let auth = document(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGFsaWNlAHNlY3JldA==</auth>",
    );
    let (mechanism, payload) = legacy_sasl_auth(auth.root_element()).unwrap();
    assert_eq!(mechanism, "PLAIN");
    assert_eq!(
        payload.as_ref().map(|payload| payload.as_str()),
        Some("AGFsaWNlAHNlY3JldA==")
    );
    let response =
        document("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>Y2xpZW50LWZpbmFs</response>");
    assert_eq!(
        legacy_sasl_payload(response.root_element())
            .as_ref()
            .map(|payload| payload.as_str()),
        Some("Y2xpZW50LWZpbmFs")
    );
}

#[test]
fn cancelled_finalizer_after_claim_still_requires_drop_quiesce() {
    // lifecycle=1 models cancellation immediately after finalize won its
    // 0→1 CAS but before SessionCleanupService::quiesce returned.
    assert!(drop_requires_local_quiesce(false, 1));
    assert!(drop_requires_local_quiesce(false, 0));
    assert!(!drop_requires_local_quiesce(true, 1));
    // State 2 belongs exclusively to the exact SM claimant.
    assert!(!drop_requires_local_quiesce(false, 2));
}

#[test]
fn external_disconnect_revokes_sm_resume_but_transport_loss_preserves_it() {
    let transport_loss = tokio_util::sync::CancellationToken::new();
    assert!(begin_owned_session_cleanup(&transport_loss, true));
    assert!(transport_loss.is_cancelled());

    let revoked = tokio_util::sync::CancellationToken::new();
    revoked.cancel(); // Revocation arrived while the transport was still active.
    assert!(!begin_owned_session_cleanup(&revoked, true));

    let nonresumable = tokio_util::sync::CancellationToken::new();
    assert!(!begin_owned_session_cleanup(&nonresumable, false));

    // An exact SM takeover owns the old lifecycle even though it also
    // cancels the old transport; that finalizer must not plan another SM
    // suspension or revoke the replacement's lease.
    let superseded = std::sync::atomic::AtomicU8::new(2);
    assert_eq!(
        claim_session_cleanup(&superseded),
        SessionCleanupOwnership::SupersededBySm
    );
}

#[tokio::test]
async fn termination_signals_keep_revocation_and_backpressure_distinct() {
    let policy_revoke = tokio_util::sync::CancellationToken::new();
    let backpressure = tokio_util::sync::CancellationToken::new();
    let signals = SessionTerminationSignals {
        policy_revoke: policy_revoke.clone(),
        backpressure: backpressure.clone(),
    };
    assert!(!signals.is_revoked());
    assert!(!signals.is_backpressured());

    backpressure.cancel();
    signals.backpressured().await;
    assert!(signals.is_backpressured());
    assert!(!signals.is_revoked());

    policy_revoke.cancel();
    signals.revoked().await;
    assert!(signals.is_revoked());
    assert!(signals.is_backpressured());
}

#[test]
fn distinguishes_an_omitted_initial_response_from_explicit_empty_data() {
    for mechanism in ["PLAIN", "SCRAM-SHA-256"] {
        let omitted_xml =
            format!("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{mechanism}'/>");
        let omitted = document(&omitted_xml);
        let (parsed_mechanism, payload) = legacy_sasl_auth(omitted.root_element()).unwrap();
        assert_eq!(parsed_mechanism, mechanism);
        assert!(payload.is_none());

        let explicit_empty_xml = format!(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{mechanism}'>=</auth>"
        );
        let explicit_empty = document(&explicit_empty_xml);
        let (parsed_mechanism, payload) = legacy_sasl_auth(explicit_empty.root_element()).unwrap();
        assert_eq!(parsed_mechanism, mechanism);
        assert_eq!(payload.as_ref().map(|payload| payload.as_str()), Some("="));
    }
}

#[test]
fn rejects_sasl_attribute_and_child_smuggling() {
    for xml in [
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>AA==</auth>",
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN' extra='x'>AA==</auth>",
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'><response>AA==</response></auth>",
        "<auth xmlns='urn:evil' mechanism='PLAIN'>AA==</auth>",
    ] {
        let document = document(xml);
        assert!(
            legacy_sasl_auth(document.root_element()).is_none(),
            "accepted {xml}"
        );
    }
    for xml in [
        "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl' extra='x'>AA==</response>",
        "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><x/>AA==</response>",
    ] {
        let document = document(xml);
        assert!(
            legacy_sasl_payload(document.root_element()).is_none(),
            "accepted {xml}"
        );
    }
}

#[test]
fn resource_bind_deadline_applies_only_to_authenticated_unbound_streams() {
    let authenticated_at = std::time::Instant::now();
    assert_eq!(
        resource_bind_deadline_for(true, false, Some(authenticated_at), 30),
        Some(authenticated_at + std::time::Duration::from_secs(30))
    );
    assert_eq!(
        resource_bind_deadline_for(false, false, Some(authenticated_at), 30),
        None
    );
    // SASL2 Bind 2 and successful inline SM resume reach this state.
    assert_eq!(
        resource_bind_deadline_for(true, true, Some(authenticated_at), 30),
        None
    );
    assert_eq!(resource_bind_deadline_for(true, false, None, 30), None);
}

#[test]
fn unauthenticated_deadline_is_inclusive_and_stops_after_authentication() {
    let connected_at = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(30);
    assert!(!unauthenticated_timed_out_for(
        false,
        connected_at,
        timeout,
        connected_at + timeout - std::time::Duration::from_nanos(1),
    ));
    assert!(unauthenticated_timed_out_for(
        false,
        connected_at,
        timeout,
        connected_at + timeout,
    ));
    assert!(!unauthenticated_timed_out_for(
        true,
        connected_at,
        timeout,
        connected_at + timeout + std::time::Duration::from_secs(1),
    ));
    assert!(!unauthenticated_timed_out_for(
        false,
        connected_at,
        timeout,
        connected_at - std::time::Duration::from_secs(1),
    ));
    assert!(unauthenticated_timed_out_for(
        false,
        connected_at,
        std::time::Duration::from_secs(5),
        connected_at + std::time::Duration::from_secs(5),
    ));
}

#[test]
fn stream_limits_use_transport_supplied_policy() {
    let limits = Some(StreamLimits {
        max_bytes: 1024 * 1024,
        negotiation_idle: std::time::Duration::from_secs(15),
        authenticated_idle: std::time::Duration::from_secs(300),
    });
    assert_eq!(
        client_stream_limits_feature(limits, false),
        "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>1048576</max-bytes><idle-seconds>15</idle-seconds></limits>"
    );
    assert_eq!(
        client_stream_limits_feature(limits, true),
        "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>1048576</max-bytes><idle-seconds>300</idle-seconds></limits>"
    );
    assert_eq!(client_stream_limits_feature(None, true), "");
    let custom = StreamLimits {
        max_bytes: 128,
        negotiation_idle: std::time::Duration::from_secs(2),
        authenticated_idle: std::time::Duration::from_secs(7),
    };
    assert!(client_stream_limits_feature(Some(custom), false)
        .contains("<idle-seconds>2</idle-seconds>"));
    assert!(
        client_stream_limits_feature(Some(custom), true).contains("<idle-seconds>7</idle-seconds>")
    );
}

fn resume_test_governor(
    max_bytes: usize,
) -> (
    std::sync::Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    std::sync::Arc<crate::services::sm_capacity::SmCapacityMetrics>,
) {
    let metrics = std::sync::Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
    let governor = crate::services::sm_capacity::SmMemoryGovernor::new(
        max_bytes,
        600,
        8,
        600,
        std::sync::Arc::clone(&metrics),
    )
    .unwrap();
    (governor, metrics)
}

fn replay_source(
    bytes: usize,
) -> std::collections::VecDeque<crate::xmpp::outbound::SmUnackedStanza> {
    std::collections::VecDeque::from([crate::xmpp::outbound::SmUnackedStanza::plain(
        "x".repeat(bytes),
    )])
}

fn resume_payload(
    governor: &std::sync::Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    source: &std::collections::VecDeque<crate::xmpp::outbound::SmUnackedStanza>,
) -> anyhow::Result<ResumePayload> {
    let mut control = String::with_capacity(64);
    control.push_str("<resumed xmlns='urn:xmpp:sm:3'/>");
    ResumePayload::from_sm_unacked(governor, control, Vec::new(), source, false)
}

#[test]
fn simultaneous_resume_actions_share_the_global_transient_budget() {
    let (governor, metrics) = resume_test_governor(900);
    let source = replay_source(320);
    let first = resume_payload(&governor, &source).unwrap();
    let second = resume_payload(&governor, &source).unwrap();
    assert!(resume_payload(&governor, &source).is_err());
    assert!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            <= 900
    );
    drop(first);
    let replacement = resume_payload(&governor, &source).unwrap();
    drop(second);
    drop(replacement);
    assert_eq!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn dropping_resume_action_releases_every_transport_clone_reservation() {
    let (governor, metrics) = resume_test_governor(900);
    let action = Action::Resume(resume_payload(&governor, &replay_source(320)).unwrap());
    assert!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    drop(action);
    assert_eq!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn transport_failure_drops_resume_capacity_with_the_failed_action() {
    fn fail_transport(action: Action) -> Result<(), ()> {
        let Action::Resume(payload) = action else {
            return Ok(());
        };
        let parts = payload.into_transport_parts();
        let _capacity_held_through_failed_write = parts.transient_capacity;
        Err(())
    }

    let (governor, metrics) = resume_test_governor(900);
    let action = Action::Resume(resume_payload(&governor, &replay_source(320)).unwrap());
    assert!(fail_transport(action).is_err());
    assert_eq!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn post_transport_resume_publication_cannot_run_while_replay_is_pending() {
    let metrics = northstar_telemetry::metrics::Metrics::default();
    let telemetry = PostActionTelemetry::new(
        &metrics.post_action_tasks_started_total,
        &metrics.post_action_tasks_completed_total,
        &metrics.post_action_tasks_panicked_total,
        &metrics.post_action_tasks_aborted_total,
        &metrics.post_action_capacity_rejections_total,
    );
    let published = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_published = std::sync::Arc::clone(&published);
    let mut supervisor = PostActionSupervisor::default();
    supervisor
        .defer(
            "resume-route-publication",
            async move {
                task_published.store(true, std::sync::atomic::Ordering::Release);
            },
            &telemetry,
        )
        .unwrap();

    tokio::task::yield_now().await;
    assert!(!published.load(std::sync::atomic::Ordering::Acquire));
    supervisor.start(&telemetry);
    assert_eq!(
        metrics
            .post_action_tasks_started_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !published.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    supervisor.reap(&telemetry);
}

#[tokio::test]
async fn external_recovery_task_waits_for_current_transport_action() {
    let metrics = northstar_telemetry::metrics::Metrics::default();
    let telemetry = PostActionTelemetry::new(
        &metrics.post_action_tasks_started_total,
        &metrics.post_action_tasks_completed_total,
        &metrics.post_action_tasks_panicked_total,
        &metrics.post_action_tasks_aborted_total,
        &metrics.post_action_capacity_rejections_total,
    );
    let handle = PostActionHandle::default();
    handle.begin_action();
    let (published, receiver) = tokio::sync::oneshot::channel();
    handle
        .defer_recovery(
            "recovered-offline-test",
            async move {
                let _ = published.send(());
            },
            &telemetry,
        )
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(
        metrics
            .post_action_tasks_started_total
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    handle.start(&telemetry);
    tokio::time::timeout(std::time::Duration::from_secs(1), receiver)
        .await
        .expect("recovery task should start after transport")
        .expect("task should publish after transport");
    assert_eq!(
        metrics
            .post_action_tasks_started_total
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
}
