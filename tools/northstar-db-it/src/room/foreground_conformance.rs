use northstar_abuse_application::guard::{
    test_mix_message_content_keyring, test_mix_retraction_content_keyring,
};
use northstar_room_application::{
    mix::*,
    mix_service::{MixBusinessReplay, MixPublisherIdentity, MixService, StoreEventOutcome},
};
use northstar_room_core::mix::{Ingress, Replay, ReplayIdentity, StoreCommand};
use northstar_room_postgres::mix as db;
use northstar_workflows::room_effects::{PostgresMixRepository, WorkflowRoomEffects};
use uuid::Uuid;

async fn prepare(
    service: &MixService<PostgresMixRepository>,
    channel: Uuid,
    item: Uuid,
    semantics: &[u8],
    publisher_identity: &MixPublisherIdentity,
) -> (Observation, StoreRequest) {
    let identity = ReplayIdentity {
        client_id: "foreground-origin".into(),
        canonical_semantics: semantics.to_vec(),
    };
    let prepared = service
        .prepare_mix_foreground(Ingress {
            channel_id: channel,
            channel_jid: "foreground@mix.local.test".into(),
            actor_bare: "sender@remote.test".into(),
            actor_full: "sender@remote.test/phone".into(),
            children: "<body>foreground</body>".into(),
            encrypted: true,
            identity: Some(identity.clone()),
        })
        .unwrap();
    let observation = Observation::new(prepared);
    let replay = observation.replay_request().unwrap().unwrap();
    assert_eq!(
        service
            .lookup_mix_message_replay_observed(&replay)
            .await
            .unwrap(),
        MixBusinessReplay::Miss
    );
    let request = observation
        .store_request(
            StoreCommand {
                channel_id: channel,
                actor: "sender@remote.test".into(),
                item_id: item,
                payload: "<body>archive input</body>".into(),
                identity: Some(identity),
                delivery_payload: "<body>foreground</body>".into(),
                visible_jid: Some("sender@remote.test".into()),
                encrypted: true,
            },
            publisher_identity.clone(),
        )
        .unwrap();
    (observation, request)
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn foreground_receipts_bind_durable_projection_and_authenticate_replay_after_rollback() {
    let pool = crate::support::operation_mutation_pool().await;
    let payloads = northstar_room_application::mix_service::MixPayloads;
    let (created, _) = db::create_mix_channel(
        &WorkflowRoomEffects,
        &pool,
        "mix.local.test",
        Some("foreground"),
        "sender@remote.test",
        100,
        &payloads,
        None,
    )
    .await
    .unwrap();
    let db::CreateChannelOutcome::Created(channel) = created else {
        panic!("fixture channel was not created");
    };
    let nodes = vec![db::NODE_MESSAGES.to_owned()];
    let joined = db::join_mix_channel(
        &WorkflowRoomEffects,
        &pool,
        channel,
        db::JoinMixRequest {
            actor_jid: "sender@remote.test",
            nick: Some("Sender"),
            nodes: &nodes,
            pam_user_id: None,
            invitation: None,
            preference: None,
            anonymous_profile: false,
        },
        &payloads,
        None,
    )
    .await
    .unwrap();
    assert!(matches!(joined, db::JoinChannelOutcome::Joined { .. }));
    let db::JoinChannelOutcome::Joined { participant, .. } = joined else {
        unreachable!("the sender joined above");
    };
    let channel_state = db::mix_channel_by_id(&pool, channel)
        .await
        .unwrap()
        .unwrap();
    let publisher_identity = MixPublisherIdentity::from_state(&channel_state, &participant);
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let service = MixService::new(
        PostgresMixRepository::new(pool.clone()),
        test_mix_message_content_keyring(),
        test_mix_retraction_content_keyring(),
        4,
        schema,
    )
    .unwrap();
    let original = Uuid::from_u128(0x573_153401);
    let (stored_observation, stored_request) = prepare(
        &service,
        channel,
        original,
        b"original semantics",
        &publisher_identity,
    )
    .await;
    let (replay_observation, replay_request) = prepare(
        &service,
        channel,
        Uuid::from_u128(0x573_153402),
        b"original semantics",
        &publisher_identity,
    )
    .await;
    let (conflict_observation, conflict_request) = prepare(
        &service,
        channel,
        Uuid::from_u128(0x573_153403),
        b"changed semantics",
        &publisher_identity,
    )
    .await;
    let admission = service
        .store_mix_message_observed(&stored_request)
        .await
        .unwrap();
    assert_eq!(admission.outcome, StoreEventOutcome::Stored(original));
    let Knowledge::ReceiptKnown(stored) = stored_observation.snapshot().knowledge else {
        panic!("stored message has no acknowledged COMMIT");
    };
    assert_eq!(stored.authoritative_id, original);
    assert_eq!(stored.channel_id, channel);
    let projection = stored
        .projection
        .as_ref()
        .expect("subscribed recipient must have durable projection");
    assert_eq!(projection.channel_jid, "foreground@mix.local.test");
    assert_eq!(projection.authoritative_stanza_id, Some(original));
    assert!(projection.archive && projection.encrypted);
    let mut observer = pool.acquire().await.unwrap();
    let payload: String = sqlx::query_scalar("SELECT payload FROM mix_events WHERE id=$1")
        .bind(stored.storage_id)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    assert_eq!(payload, stored_request.command().payload);
    let encrypted: bool =
        sqlx::query_scalar("SELECT encrypted FROM mix_delivery_events WHERE event_id=$1")
            .bind(projection.event_id)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert!(
        encrypted,
        "the durable delivery event keeps the encryption flag"
    );
    for recipient in &projection.recipients {
        let row: (Uuid, Uuid, String, i64) = sqlx::query_as("SELECT event_id,recipient_participant_id,recipient_jid,delivery_sequence FROM mix_delivery_recipients WHERE delivery_id=$1")
            .bind(recipient.delivery_id).fetch_one(&mut *observer).await.unwrap();
        assert_eq!(
            row,
            (
                projection.event_id,
                recipient.participant.participant_id,
                recipient.participant.jid.clone(),
                recipient.sequence
            )
        );
    }
    assert_eq!(projection.recipients.len(), admission.recipients.len());
    assert_eq!(stored_observation.snapshot().wake, Wake::Invoked);
    drop(observer);
    for (label, observation, request, expected, classified) in [
        (
            "authenticated replay",
            replay_observation,
            replay_request,
            StoreEventOutcome::Replay(original),
            Replay::Replay(original),
        ),
        (
            "semantic conflict",
            conflict_observation,
            conflict_request,
            StoreEventOutcome::Conflict,
            Replay::Conflict,
        ),
    ] {
        assert_eq!(
            service
                .store_mix_message_observed(&request)
                .await
                .unwrap()
                .outcome,
            expected,
            "{label}"
        );
        let snapshot = observation.snapshot();
        assert_eq!(
            snapshot.knowledge,
            Knowledge::NoCommitRequested,
            "{label}: existing evidence is returned after rollback"
        );
        assert_eq!(
            snapshot.existing.raw.as_ref().unwrap().authoritative_id,
            original,
            "{label}"
        );
        assert_eq!(snapshot.existing.authenticated, Some(classified), "{label}");
        assert_eq!(snapshot.wake, Wake::Unavailable, "{label}");
        let prepared = service
            .prepare_mix_foreground(observation.ingress().clone())
            .unwrap();
        let read_observation = Observation::new(prepared);
        let read = read_observation.replay_request().unwrap().unwrap();
        assert_eq!(
            service
                .lookup_mix_message_replay_observed(&read)
                .await
                .unwrap(),
            classified,
            "{label}: preflight classification"
        );
        let read_snapshot = read_observation.snapshot();
        assert_eq!(
            read_snapshot
                .replay
                .existing
                .raw
                .as_ref()
                .unwrap()
                .authoritative_id,
            original,
            "{label}: raw read evidence"
        );
        assert_eq!(
            read_snapshot.replay.existing.authenticated,
            Some(classified),
            "{label}: authenticated read evidence"
        );
    }
    // Removing the last subscriber keeps archive persistence but creates no
    // empty delivery event or invented recipient sequence facts.
    sqlx::query("DELETE FROM mix_subscriptions WHERE channel_id=$1")
        .bind(channel)
        .execute(&pool)
        .await
        .unwrap();
    let prepared = service
        .prepare_mix_foreground(Ingress {
            identity: None,
            ..stored_observation.ingress().clone()
        })
        .unwrap();
    let observation = Observation::new(prepared);
    let request = observation
        .store_request(
            StoreCommand {
                item_id: Uuid::from_u128(0x573_153404),
                identity: None,
                ..stored_request.command().clone()
            },
            publisher_identity,
        )
        .unwrap();
    assert!(matches!(
        service
            .store_mix_message_observed(&request)
            .await
            .unwrap()
            .outcome,
        StoreEventOutcome::Stored(_)
    ));
    let Knowledge::ReceiptKnown(empty) = observation.snapshot().knowledge else {
        panic!("empty audience lost its archive receipt");
    };
    assert!(
        empty.projection.is_none(),
        "empty audience has no delivery event"
    );
    sqlx::query("DELETE FROM mix_delivery_recipients WHERE event_id IN (SELECT event_id FROM mix_delivery_events WHERE channel_id=$1)")
        .bind(channel).execute(&pool).await.unwrap();
    db::reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mix_channels WHERE id=$1")
        .bind(channel)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
