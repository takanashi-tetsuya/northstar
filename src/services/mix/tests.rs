use super::*;
use sqlx::postgres::PgPoolOptions;

#[test]
fn outbox_background_budget_scales_with_the_configured_primary_pool() {
    // A one-connection configuration has no spare foreground slot, so it
    // retains a single durable worker. At two connections, the listener
    // stress profile gets one background worker and one foreground slot.
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            1
        ),
        1
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            2
        ),
        1
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            3
        ),
        2
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            17
        ),
        16
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            32
        ),
        16
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            u32::MAX
        ),
        16
    );
}

#[tokio::test]
async fn delivery_wake_retains_commits_and_listener_gap_transitions() {
    let broker =
        MixDeliveryWakeBroker::new("northstar_wake_test".to_owned()).expect("test schema is valid");
    let mut receiver = broker.subscribe();
    let initial = broker.generation();

    // Publish before the worker installs its `changed()` future. A
    // retained watch value must resolve immediately instead of losing the
    // edge as `Notify::notify_one()` could.
    broker.publish_local_commit();
    assert_eq!(broker.generation(), initial.wrapping_add(1));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), receiver.changed(),)
            .await
            .expect("retained local delivery wake must not wait")
    );

    // A listener reconnect is deliberately a wake even when no payload
    // was observed: a notification can have committed during the gap.
    broker.publish_listener_transition();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), receiver.changed(),)
            .await
            .expect("listener-gap transition must wake a durable probe")
    );

    let before_foreign = broker.generation();
    assert!(!broker.accept_committed_notification("other_schema"));
    assert_eq!(broker.generation(), before_foreign);
    assert!(broker.accept_committed_notification("northstar_wake_test"));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), receiver.changed(),)
            .await
            .expect("schema-matched PostgreSQL wake must be retained")
    );
}

#[test]
fn delivery_wake_generation_is_monotonic_under_concurrent_publishers() {
    let broker =
        MixDeliveryWakeBroker::new("northstar_wake_test".to_owned()).expect("test schema is valid");
    let publishers = 128_u64;
    std::thread::scope(|scope| {
        for _ in 0..publishers {
            let broker = Arc::clone(&broker);
            scope.spawn(move || broker.publish_local_commit());
        }
    });
    assert_eq!(broker.generation(), publishers);
}

#[tokio::test]
async fn delivery_admission_gate_is_clone_shared_and_fifo() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/northstar_gate_unit_test")
        .expect("a lazy test pool does not connect");
    let service = MixService::new_with_test_keyrings(pool);
    let first = service.clone();
    let second = service.clone();
    assert!(Arc::ptr_eq(
        &service.delivery_admission,
        &first.delivery_admission
    ));

    let held = service.delivery_admission_guard().await;
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
    let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();
    let first_ready = ready_tx.clone();
    let first_order = order_tx.clone();
    let first_waiter = tokio::spawn(async move {
        first_ready.send(()).expect("test receiver remains open");
        let _guard = first.delivery_admission_guard().await;
        first_order.send(1_u8).expect("test receiver remains open");
    });
    ready_rx.recv().await.expect("first waiter started");
    tokio::task::yield_now().await;

    let second_waiter = tokio::spawn(async move {
        ready_tx.send(()).expect("test receiver remains open");
        let _guard = second.delivery_admission_guard().await;
        order_tx.send(2_u8).expect("test receiver remains open");
    });
    ready_rx.recv().await.expect("second waiter started");
    tokio::task::yield_now().await;
    drop(held);

    assert_eq!(order_rx.recv().await, Some(1));
    assert_eq!(order_rx.recv().await, Some(2));
    first_waiter.await.expect("first waiter completed");
    second_waiter.await.expect("second waiter completed");
}

#[tokio::test]
async fn outbox_db_admission_gate_is_clone_shared_and_fifo() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/northstar_outbox_gate_unit_test")
        .expect("a lazy test pool does not connect");
    // A two-connection primary pool leaves one foreground connection and
    // therefore gives this outbox gate exactly one FIFO permit.
    let service = MixService::new(
        crate::db::mix_repository::PostgresMixRepository::new(pool),
        crate::services::abuse::test_mix_message_content_keyring(),
        crate::services::abuse::test_mix_retraction_content_keyring(),
        2,
        "public".to_owned(),
    )
    .expect("test MIX service schema is valid");
    assert_eq!(service.outbox_background_budget(), 1);
    assert_eq!(service.outbox_db_admission.available_permits(), 1);
    let first = service.clone();
    let second = service.clone();
    assert!(service
        .outbox_db_admission
        .shares_with(&first.outbox_db_admission));

    let held = service.outbox_db_admission_guard().await;
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
    let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();
    let first_ready = ready_tx.clone();
    let first_order = order_tx.clone();
    let first_waiter = tokio::spawn(async move {
        first_ready.send(()).expect("test receiver remains open");
        let _guard = first.outbox_db_admission_guard().await;
        first_order.send(1_u8).expect("test receiver remains open");
    });
    ready_rx.recv().await.expect("first waiter started");
    tokio::task::yield_now().await;

    let second_waiter = tokio::spawn(async move {
        ready_tx.send(()).expect("test receiver remains open");
        let _guard = second.outbox_db_admission_guard().await;
        order_tx.send(2_u8).expect("test receiver remains open");
    });
    ready_rx.recv().await.expect("second waiter started");
    tokio::task::yield_now().await;
    drop(held);

    assert_eq!(order_rx.recv().await, Some(1));
    assert_eq!(order_rx.recv().await, Some(2));
    first_waiter.await.expect("first waiter completed");
    second_waiter.await.expect("second waiter completed");
}

#[tokio::test]
async fn outbox_db_admission_permits_match_the_service_budget() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/northstar_outbox_gate_budget_unit_test")
        .expect("a lazy test pool does not connect");
    let service = MixService::new(
        crate::db::mix_repository::PostgresMixRepository::new(pool),
        crate::services::abuse::test_mix_message_content_keyring(),
        crate::services::abuse::test_mix_retraction_content_keyring(),
        3,
        "public".to_owned(),
    )
    .expect("test MIX service schema is valid");
    assert_eq!(service.outbox_background_budget(), 2);
    assert_eq!(service.outbox_db_admission.available_permits(), 2);
}

#[tokio::test]
async fn pam_capacity_admission_gate_is_clone_shared_and_fifo() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/northstar_pam_gate_unit_test")
        .expect("a lazy test pool does not connect");
    let service = MixService::new_with_test_keyrings(pool);
    let first = service.clone();
    let second = service.clone();
    assert!(Arc::ptr_eq(
        &service.pam_capacity_admission,
        &first.pam_capacity_admission
    ));

    let held = service.pam_capacity_admission_guard().await;
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
    let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();
    let first_ready = ready_tx.clone();
    let first_order = order_tx.clone();
    let first_waiter = tokio::spawn(async move {
        first_ready.send(()).expect("test receiver remains open");
        let _guard = first.pam_capacity_admission_guard().await;
        first_order.send(1_u8).expect("test receiver remains open");
    });
    ready_rx.recv().await.expect("first waiter started");
    tokio::task::yield_now().await;

    let second_waiter = tokio::spawn(async move {
        ready_tx.send(()).expect("test receiver remains open");
        let _guard = second.pam_capacity_admission_guard().await;
        order_tx.send(2_u8).expect("test receiver remains open");
    });
    ready_rx.recv().await.expect("second waiter started");
    tokio::task::yield_now().await;
    drop(held);

    assert_eq!(order_rx.recv().await, Some(1));
    assert_eq!(order_rx.recv().await, Some(2));
    first_waiter.await.expect("first waiter completed");
    second_waiter.await.expect("second waiter completed");
}

fn channel() -> MixChannel {
    MixChannel {
        id: Uuid::new_v4(),
        revision: 0,
        service_domain: "mix.example.test".to_owned(),
        localpart: "security".to_owned(),
        creator_jid: "owner@example.test".to_owned(),
        name: Some("</value><evil xmlns='urn:evil'>name</evil><value>".to_owned()),
        description: Some("description & <tag>\u{202e}".to_owned()),
        contacts: vec!["contact@example.test".to_owned()],
        access_model: "open".to_owned(),
        jid_visibility: "visible".to_owned(),
        nick_required: false,
        max_participants: 100,
        max_events: 1_000,
        allow_private_messages: true,
        allow_participant_invites: true,
        allow_user_message_retraction: true,
        administrator_retraction_rights: "administrators".to_owned(),
        enforce_registered_nick: false,
    }
}

fn assert_no_injected_element(xml: &str, expected_text: &str) {
    let document = roxmltree::Document::parse(xml).expect("builder output must parse");
    assert!(document
        .descendants()
        .filter(|node| node.is_element())
        .all(|node| node.tag_name().name() != "evil"));
    assert!(document
        .descendants()
        .filter_map(|node| node.text())
        .any(|text| text == expected_text));
}

#[test]
fn info_and_config_payloads_escape_untrusted_text_and_namespaces() {
    let channel = channel();
    let info = render_info_payload(&channel);
    assert_no_injected_element(&info, "</value><evil xmlns='urn:evil'>name</evil><value>");
    let document = roxmltree::Document::parse(&info).unwrap();
    assert_eq!(
        document.root_element().tag_name().namespace(),
        Some("jabber:x:data")
    );

    let malicious = "</value><evil xmlns='urn:evil'>owner</evil><value>".to_owned();
    let owners = BTreeSet::from([malicious.clone()]);
    let administrators = BTreeSet::from(["admin&<@example.test".to_owned()]);
    let config = render_config_payload(&channel, &malicious, &owners, &administrators);
    assert_no_injected_element(&config, &malicious);
    let config_document = roxmltree::Document::parse(&config).unwrap();
    assert_eq!(
        config_document.root_element().tag_name().namespace(),
        Some("jabber:x:data")
    );
}

#[test]
fn participant_and_access_payloads_cannot_inject_siblings() {
    let channel = channel();
    let participant = MixParticipant {
        participant_id: Uuid::new_v4(),
        jid: "</jid><evil xmlns='urn:evil'>jid</evil><jid>".to_owned(),
        nick: Some("</nick><evil xmlns='urn:evil'>nick</evil><nick>".to_owned()),
    };
    let payload =
        render_participant_payload(&channel, &participant, &MixParticipantPreference::default());
    assert_no_injected_element(&payload, &participant.jid);
    let document = roxmltree::Document::parse(&payload).unwrap();
    assert_eq!(
        document.root_element().tag_name().namespace(),
        Some("urn:xmpp:mix:core:1")
    );

    let pattern = "</jid><evil xmlns='urn:evil'>domain</evil><jid>";
    let access = render_access_payload(pattern);
    assert_no_injected_element(&access, pattern);
    assert_eq!(
        roxmltree::Document::parse(&access)
            .unwrap()
            .root_element()
            .tag_name()
            .namespace(),
        Some("urn:xmpp:mix:admin:0")
    );
}
