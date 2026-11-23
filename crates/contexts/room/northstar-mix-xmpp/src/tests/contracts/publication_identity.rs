use super::*;

#[tokio::test]
async fn channel_archive_identity_is_rendered_once_by_locked_admission() {
    for observed in [false, true] {
        let context = Context::new(1);
        *context.state.publisher_visibility.lock().unwrap() =
            ["visible", "hidden", "visible"].into();
        let host = Arc::new(Host {
            context: context.clone(),
            relay: MixIqRelayIndex::new(),
        });
        let observer = Observer {
            state: context.state.clone(),
            present: observed,
            reject: false,
        };
        let raw = "<message type='groupchat' id='message' to='room@mix.local.test'><body>ordinary</body><origin-id xmlns='urn:xmpp:sid:0' id='origin'/></message>";
        assert!(process_channel_message(
            &host,
            "bob@local.test",
            "bob@local.test/phone",
            raw,
            Some(&observer)
        )
        .await
        .unwrap()
        .is_none());
        let writes = context.state.publisher_writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert!(!writes[0].payload.contains("<jid>"));
        assert!(writes[0].payload.contains("<nick>Locked Bob</nick>"));
        assert!(writes[0].payload.contains("<body>ordinary</body>"));
        assert_eq!(
            context
                .state
                .publisher_visibility
                .lock()
                .unwrap()
                .pop_front(),
            Some("visible")
        );
        assert_eq!(
            context.state.calls(),
            vec![
                Call::Frame(MixFrameStage::Policy),
                Call::Channel("mix.local.test".into(), "room".into()),
                Call::Register,
                Call::Replay(observed),
                Call::Member(Uuid::from_u128(93), "bob@local.test".into()),
                Call::Frame(MixFrameStage::Admission),
                Call::Store(observed),
            ]
        );
    }
}

#[tokio::test]
async fn unbound_or_reassigned_claims_dead_letter_without_archive_or_routing() {
    for (address, archive) in [
        ("legacy@local.test", true),
        ("reassigned@local.test", true),
        ("legacy@local.test", false),
        ("reassigned@local.test", false),
    ] {
        let context = Context::new(1);
        let mut delivery = row(archive);
        delivery.recipient_jid = address.into();
        if !archive {
            delivery.stanza = "<message><control/></message>".into();
        }
        let source = delivery.source;
        let work = outbox::OwnedAttempt::new(attempt_from_row(delivery));
        process_mix_outbox_work(
            context.clone(),
            MixOutboxWork::Delivery(work),
            CancellationToken::new(),
        )
        .await
        .1
        .unwrap();
        let mut calls = context.state.calls();
        assert!(
            matches!(calls.pop(), Some(Call::Settle(actual, _, mix_worker::SettlementCommand::DeadLetter { reason, .. }))
            if actual == source && reason == "account-unavailable")
        );
        assert!(
            calls.iter().all(|call| matches!(call, Call::User(..))),
            "unexpected effects: {calls:?}"
        );
    }
}
