use super::*;

#[tokio::test]
async fn exact_iq_admission_only_checks_one_resource_and_leaves_the_queue_empty() {
    let fixture = DirectDeliveryFixture::new();
    let mut output = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    fixture
        .mix_caps
        .sessions
        .get(ORIGINAL_JID)
        .unwrap()
        .directed_presence
        .insert("alice@remote.test".to_owned());
    let stanza = format!(
        "<iq type='get' id='req' from='alice@remote.test/Work' to='{ORIGINAL_JID}'><query/></iq>"
    );
    let envelope = serde_json::json!({
        "target": ORIGINAL_JID,
        "stanza": stanza,
        "protocol_version": EXACT_MESSAGE_DELIVERY_VERSION,
        "expected_user_id": ORIGINAL,
        "expected_auth_generation": 1,
        "expected_connections": { (ORIGINAL_JID): ORIGINAL },
        "exact_iq_check_only": true,
    });
    let (accepted, _, _) = fixture
        .dispatch
        .test_direct_message_delivery(
            &fixture.admission,
            &fixture.policy,
            &fixture.mix_caps,
            &envelope,
        )
        .await;
    assert_eq!(accepted, 1);
    assert_eq!(*fixture.message_ports.0.lock().unwrap(), [ORIGINAL]);
    assert!(output.try_recv().is_err());
}
