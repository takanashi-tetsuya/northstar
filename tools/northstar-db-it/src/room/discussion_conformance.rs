use northstar_room_application::{discussion::*, RoomApplication};
use northstar_room_core::{
    MucActorAuthority, MucActorPrincipal, MucDiscussion, MucDiscussionAdmission,
};
use northstar_workflows::room_effects::PostgresMucRepository;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn discussion_receipts_preserve_all_stored_and_replay_commit_exits() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_140001);
    let room = Uuid::from_u128(0x573_140002);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'discussion-receipt','test-only')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let epoch: Uuid = sqlx::query_scalar("INSERT INTO muc_rooms(id,localpart,owner_id,occupant_id_secret) VALUES($1,'discussion-receipt',$2,$3) RETURNING room_epoch")
        .bind(room).bind(user).bind(vec![8_u8; 32]).fetch_one(&pool).await.unwrap();
    let application =
        RoomApplication::new(PostgresMucRepository::new(pool.clone()), "example.test");
    let command = MucDiscussion {
        id: Uuid::nil(),
        room_id: room,
        actor_scope: "discussion-receipt@example.test".into(),
        origin_id: None,
        sender_jid: "discussion-receipt@example.test/phone".into(),
        nick: "Receipt".into(),
        stanza: "<message id='original'><body>receipt</body></message>".into(),
        encrypted: true,
        archive: true,
        retention_days: 30,
        authority: MucActorAuthority {
            clustered: false,
            expected_room_epoch: epoch,
            principal: MucActorPrincipal::Local {
                user_id: user,
                local_domain: "example.test".into(),
            },
            actor_scope: "discussion-receipt@example.test".into(),
            full_jid: "discussion-receipt@example.test/phone".into(),
            nick: "Receipt".into(),
            occupant_incarnation: Uuid::nil(),
            connection_uuid: Uuid::nil(),
            expected_role: "participant".into(),
            expected_affiliation: "none".into(),
            cluster_target: None,
        },
    };
    for (index, label, origin, archive, expected_id) in [
        (0, "archive without origin", None, true, 0),
        (1, "archive with origin", Some("archive-origin"), true, 1),
        (2, "archived replay", Some("archive-origin"), true, 1),
        (
            3,
            "admission without archive",
            Some("admission-origin"),
            false,
            3,
        ),
        (4, "unarchived replay", Some("admission-origin"), false, 3),
        (5, "volatile commit", None, false, 5),
    ] {
        let id = Uuid::from_u128(0x573_140010 + index);
        let expected_id = Uuid::from_u128(0x573_140010 + expected_id);
        let expected = if index == 2 || index == 4 {
            MucDiscussionAdmission::Replay(expected_id)
        } else {
            MucDiscussionAdmission::Stored(id)
        };
        let prepared = application.prepare_discussion(MucDiscussion {
            id,
            origin_id: origin.map(str::to_owned),
            archive,
            ..command.clone()
        });
        let observation = Observation::new(prepared);
        let request = observation.request().unwrap();
        let completion = application
            .admit_discussion_observed(&request)
            .await
            .unwrap();
        assert_eq!(completion.outcome(), expected, "{label}");
        let snapshot = observation.snapshot();
        let Knowledge::ReceiptKnown(fact) = snapshot.knowledge else {
            panic!("{label}: missing acknowledged COMMIT");
        };
        assert_eq!(
            fact.outcome(),
            expected,
            "{label}: unchanged receipt identity"
        );
        assert_eq!(
            snapshot.returned,
            Some(Returned::Outcome(expected)),
            "{label}"
        );
        assert_eq!(
            completion.into_fanout(&observation).unwrap().is_some(),
            matches!(expected, MucDiscussionAdmission::Stored(_)),
            "{label}"
        );
        let mut observer = pool.acquire().await.unwrap();
        let saved: Option<(String, String, String, bool)> =
            sqlx::query_as("SELECT sender_jid,nick,stanza,encrypted FROM muc_messages WHERE id=$1")
                .bind(expected_id)
                .fetch_optional(&mut *observer)
                .await
                .unwrap();
        if archive {
            assert_eq!(
                saved,
                Some((
                    command.sender_jid.clone(),
                    command.nick.clone(),
                    command.stanza.clone(),
                    true
                )),
                "{label}: committed bound inputs"
            );
        } else {
            assert!(saved.is_none(), "{label}: no archive projection");
        }
        if let Some(origin) = origin {
            let stored: Uuid = sqlx::query_scalar(
                "SELECT stanza_id FROM muc_origin_admissions WHERE room_id=$1 AND origin_id=$2",
            )
            .bind(room)
            .bind(origin)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
            assert_eq!(stored, expected_id, "{label}: original dedupe identity");
        }
    }
    // The new origin admission is inserted before the duplicate archive ID
    // fails. Neither that admission nor a positive receipt may survive.
    let prepared = application.prepare_discussion(MucDiscussion {
        id: Uuid::from_u128(0x573_140010),
        origin_id: Some("rolled-back-origin".into()),
        ..command
    });
    let observation = Observation::new(prepared);
    let request = observation.request().unwrap();
    assert!(application
        .admit_discussion_observed(&request)
        .await
        .is_err());
    assert_eq!(
        observation.snapshot().knowledge,
        Knowledge::NoCommitRequested
    );
    assert_eq!(observation.snapshot().returned, Some(Returned::Error));
    let mut observer = pool.acquire().await.unwrap();
    let partial: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM muc_origin_admissions WHERE room_id=$1 AND origin_id='rolled-back-origin')")
        .bind(room).fetch_one(&mut *observer).await.unwrap();
    assert!(
        !partial,
        "failed archive insertion rolls back its admission"
    );
    drop(observer);
    sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
        .bind(room)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
