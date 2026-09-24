use super::*;
use crate::db;

fn query(page: super::super::MamRsmPage, max: i64) -> super::super::MamArchiveQuery {
    super::super::MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page,
        max,
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mix_mam_snapshot_filters_cursors_and_metadata_are_consistent() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let payloads = crate::services::mix::MixPayloads;

    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}@example.test");
    let localpart = format!("mam-{}", &suffix[..16]);
    let (outcome, _) = create_mix_channel(
        &pool,
        "mix.example.test",
        Some(&localpart),
        &owner,
        100,
        &payloads,
        None,
    )
    .await
    .unwrap();
    let CreateChannelOutcome::Created(channel_id) = outcome else {
        panic!("unique MIX MAM test channel was not created");
    };
    let first = Uuid::parse_str("00000000-0000-0000-0000-000000000101").unwrap();
    let second = Uuid::parse_str("00000000-0000-0000-0000-000000000102").unwrap();
    let third = Uuid::parse_str("00000000-0000-0000-0000-000000000103").unwrap();
    let fourth = Uuid::parse_str("00000000-0000-0000-0000-000000000104").unwrap();
    for (id, storage_id, publisher, second_offset) in [
        (first, Uuid::new_v4(), "alice@example.test", 1_i64),
        (second, Uuid::new_v4(), "bob@example.test", 2),
        (third, Uuid::new_v4(), "alice@example.test", 3),
        (fourth, Uuid::new_v4(), "bob@example.test", 4),
    ] {
        sqlx::query(
            "INSERT INTO mix_events
                 (id, channel_id, node, item_id, publisher_jid, payload, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6,
                         TIMESTAMPTZ '2026-01-01 00:00:00Z' + ($7 * INTERVAL '1 second'))",
        )
        .bind(storage_id)
        .bind(channel_id)
        .bind(NODE_MESSAGES)
        .bind(id.to_string())
        .bind(publisher)
        .bind(format!("<message id='{id}'/>"))
        .bind(second_offset)
        .execute(&pool)
        .await
        .unwrap();
    }

    let first_page = mix_mam_page(
        &pool,
        channel_id,
        &query(super::super::MamRsmPage::First, 2),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        first_page
            .events
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(first_page.total, 4);
    assert_eq!(first_page.first_index, 0);
    assert!(!first_page.complete);

    let after = mix_mam_page(
        &pool,
        channel_id,
        &query(super::super::MamRsmPage::After(second), 2),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        after
            .events
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>(),
        vec![third, fourth]
    );
    assert_eq!(after.first_index, 2);
    assert!(after.complete);

    let mut filtered = query(super::super::MamRsmPage::Last, 1);
    filtered.with_jid = Some("bob@example.test".to_owned());
    let filtered = mix_mam_page(&pool, channel_id, &filtered)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(filtered.total, 2);
    assert_eq!(filtered.first_index, 1);
    assert_eq!(filtered.events[0].id, fourth);

    let mut filtered_cursor = query(super::super::MamRsmPage::After(first), 10);
    filtered_cursor.with_jid = Some("bob@example.test".to_owned());
    let filtered_cursor = mix_mam_page(&pool, channel_id, &filtered_cursor)
        .await
        .unwrap()
        .expect("the cursor exists in the archive's visible scope");
    assert_eq!(
        filtered_cursor
            .events
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>(),
        vec![second, fourth]
    );
    assert_eq!(filtered_cursor.total, 2);
    assert!(filtered_cursor.complete);

    let viewer_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,username,password_hash)
             VALUES($1,$2,'mix-mam-test-only')",
    )
    .bind(viewer_id)
    .bind(format!("viewer-{}", &suffix[..12]))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
        .bind(viewer_id)
        .bind("bob@example.test")
        .execute(&pool)
        .await
        .unwrap();
    let visible = mix_mam_page_visible(
        &pool,
        channel_id,
        viewer_id,
        &query(super::super::MamRsmPage::First, 10),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(visible.total, 2);
    assert_eq!(
        visible
            .events
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>(),
        vec![first, third]
    );
    assert!(
        mix_mam_page_visible(
            &pool,
            channel_id,
            viewer_id,
            &query(super::super::MamRsmPage::After(second), 10),
        )
        .await
        .unwrap()
        .is_none(),
        "a blocked MIX publisher cannot be used as a cursor oracle"
    );

    let zero = mix_mam_page(
        &pool,
        channel_id,
        &query(super::super::MamRsmPage::First, 0),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(zero.events.is_empty());
    assert_eq!(zero.total, 4);
    assert!(!zero.complete);

    let missing = mix_mam_page(
        &pool,
        channel_id,
        &query(super::super::MamRsmPage::Before(Uuid::new_v4()), 10),
    )
    .await
    .unwrap();
    assert!(missing.is_none());

    let boundaries = mix_mam_boundaries(&pool, channel_id).await.unwrap();
    assert_eq!(boundaries.0.unwrap().id, first);
    assert_eq!(boundaries.1.unwrap().id, fourth);

    sqlx::query("DELETE FROM mix_channels WHERE id = $1")
        .bind(channel_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mix_anon_misc_permissions_are_atomic_and_private() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let payloads = crate::services::mix::MixPayloads;

    let suffix = Uuid::new_v4().simple().to_string();
    let owner_user_id = Uuid::new_v4();
    let owner_username = format!("owner-{suffix}");
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(owner_user_id)
        .bind(&owner_username)
        .execute(&pool)
        .await
        .unwrap();
    let owner = format!("{owner_username}@example.test");
    let guest = format!("guest-{suffix}@example.test");
    let localpart = format!("family-{}", &suffix[..16]);
    let (created, _) = create_mix_channel(
        &pool,
        "mix.example.test",
        Some(&localpart),
        &owner,
        100,
        &payloads,
        None,
    )
    .await
    .unwrap();
    let CreateChannelOutcome::Created(channel_id) = created else {
        panic!("MIX family test channel was not created")
    };
    let channel = mix_channel_by_id(&pool, channel_id).await.unwrap().unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT discoverable FROM mix_channels WHERE id = $1")
            .bind(channel_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    assert!(channel.allow_private_messages);
    assert_eq!(channel.administrator_retraction_rights, "owners");

    let owner_preference = MixParticipantPreference {
        jid_visibility: "prefer not".to_owned(),
        ..MixParticipantPreference::default()
    };
    let owner_join = join_mix_channel(
        &pool,
        channel_id,
        JoinMixRequest {
            actor_jid: &owner,
            nick: Some("Owner"),
            nodes: &[NODE_MESSAGES.to_owned(), NODE_AVATAR_METADATA.to_owned()],
            pam_user_id: Some(owner_user_id),
            invitation: None,
            preference: Some(&owner_preference),
            anonymous_profile: false,
        },
        &payloads,
        None,
    )
    .await
    .unwrap();
    let JoinChannelOutcome::Joined {
        participant: owner_participant,
        ..
    } = owner_join
    else {
        panic!("owner did not join")
    };
    let guest_preference = MixParticipantPreference {
        private_messages: "block".to_owned(),
        ..MixParticipantPreference::default()
    };
    let guest_join = join_mix_channel(
        &pool,
        channel_id,
        JoinMixRequest {
            actor_jid: &guest,
            nick: Some("Guest"),
            nodes: &[NODE_MESSAGES.to_owned()],
            pam_user_id: None,
            invitation: None,
            preference: Some(&guest_preference),
            anonymous_profile: false,
        },
        &payloads,
        None,
    )
    .await
    .unwrap();
    let JoinChannelOutcome::Joined {
        participant: guest_participant,
        ..
    } = guest_join
    else {
        panic!("guest did not join")
    };
    let registration = register_mix_nick(
        &pool,
        "mix.example.test",
        &owner,
        "Owner Registered",
        &payloads,
        None,
    )
    .await
    .unwrap();
    let RegisterMixNickOutcome::Registered {
        nick: registered_nick,
    } = registration
    else {
        panic!("unique registered nick unexpectedly conflicted")
    };
    assert_eq!(registered_nick, "Owner Registered");
    let participant_nick: Option<String> = sqlx::query_scalar(
        "SELECT nick FROM mix_participants WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(owner_participant.participant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(participant_nick.as_deref(), Some("Owner Registered"));
    let preference_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
               FROM mix_participant_preferences
              WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(owner_participant.participant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        MixParticipantPreference {
            jid_visibility: preference_row.get("jid_visibility"),
            private_messages: preference_row.get("private_messages"),
            vcard: preference_row.get("vcard"),
            share_presence: preference_row.get("share_presence"),
        },
        owner_preference
    );
    let pam_nick: Option<String> = sqlx::query_scalar(
        "SELECT nick FROM mix_pam_memberships
              WHERE user_id=$1 AND channel_jid=$2 AND participant_id=$3",
    )
    .bind(owner_user_id)
    .bind(channel.jid())
    .bind(owner_participant.participant_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pam_nick.as_deref(), Some("Owner Registered"));
    let participant_projection: String = sqlx::query_scalar(
        "SELECT payload FROM mix_events
              WHERE channel_id=$1 AND node=$2 AND item_id=$3",
    )
    .bind(channel_id)
    .bind(NODE_PARTICIPANTS)
    .bind(owner_participant.participant_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(participant_projection.contains("Owner Registered"));
    assert!(!participant_projection.contains(">Owner<"));
    assert!(
        mix_private_message_recipient(&pool, channel_id, &owner, guest_participant.participant_id,)
            .await
            .unwrap()
            .is_none(),
        "recipient private-message preference must fail closed"
    );
    let mut allowed_guest = guest_preference;
    allowed_guest.private_messages = "allow".to_owned();
    update_mix_participant_preference(&pool, channel_id, &guest, &allowed_guest, &payloads, None)
        .await
        .unwrap()
        .unwrap();
    assert!(mix_private_message_recipient(
        &pool,
        channel_id,
        &owner,
        guest_participant.participant_id,
    )
    .await
    .unwrap()
    .is_some());
    assert_eq!(
        mix_jid_map_entries(&pool, channel_id, &owner, 10)
            .await
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    assert!(mix_jid_map_entries(&pool, channel_id, &guest, 10)
        .await
        .unwrap()
        .is_none());
    assert!(publish_mix_avatar(
        &pool,
        channel_id,
        &owner,
        NODE_AVATAR_METADATA,
        "avatar",
        "<metadata xmlns='urn:xmpp:avatar:metadata'/>",
        &payloads,
        None,
    )
    .await
    .unwrap());
    assert!(!publish_mix_avatar(
        &pool,
        channel_id,
        &guest,
        NODE_AVATAR_METADATA,
        "attacker",
        "<metadata xmlns='urn:xmpp:avatar:metadata'/>",
        &payloads,
        None,
    )
    .await
    .unwrap());

    let target_id = Uuid::new_v4();
    let message_admission = store_mix_message(
        &pool,
        channel_id,
        &owner,
        &target_id.to_string(),
        "<message><body>remove me</body></message>",
        None,
        "<body>remove me</body>",
        None,
        false,
        &payloads,
    )
    .await
    .unwrap();
    assert!(matches!(
        message_admission.outcome,
        StoreEventOutcome::Stored(_)
    ));
    assert_eq!(
        message_admission
            .recipients
            .iter()
            .map(|participant| participant.jid.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([owner.as_str(), guest.as_str()]),
        "the channel-locked message admission must return its exact committed audience"
    );
    let retraction_id = Uuid::new_v4();
    let retraction_admission = retract_mix_message(
        &pool,
        channel_id,
        &owner,
        target_id,
        retraction_id,
        "<message><retracted xmlns='urn:xmpp:mix:misc:0'/></message>",
        "<message><retract xmlns='urn:xmpp:mix:misc:0'/></message>",
        None,
        None,
        &payloads,
    )
    .await
    .unwrap();
    assert_eq!(
        retraction_admission.outcome,
        RetractMixMessageOutcome::Retracted
    );
    assert_eq!(
        retraction_admission
            .recipients
            .iter()
            .map(|participant| participant.jid.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([owner.as_str(), guest.as_str()]),
        "the retraction and its audience must share one transaction"
    );
    let stored: String = sqlx::query_scalar(
        "SELECT payload FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .bind(target_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stored.contains("retracted"));

    // A subscription change and message admission must serialize on the
    // channel row. Hold an admission open after persisting its event and
    // audience, then prove the public unsubscribe operation cannot commit
    // until that admission commits. This catches the former
    // participant-only lock, under which an unsubscribe could overtake a
    // message after its audience was read but before it committed.
    let mut admission = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *admission)
        .await
        .unwrap();
    let concurrent_message_id = Uuid::new_v4();
    assert!(store_mix_event_tx(
        &mut admission,
        &channel,
        NODE_MESSAGES,
        &concurrent_message_id.to_string(),
        Some(&owner_participant),
        "<message><body>before unsubscribe</body></message>",
    )
    .await
    .unwrap()
    .is_some());
    let admitted_audience = mix_subscribers_tx(&mut admission, channel_id, NODE_MESSAGES)
        .await
        .unwrap();
    let concurrent_pool = pool.clone();
    let concurrent_guest = guest.clone();
    let concurrent_payloads = payloads.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut concurrent_unsubscribe = tokio::spawn(async move {
        let _ = started_tx.send(());
        update_mix_subscriptions(
            &concurrent_pool,
            channel_id,
            &concurrent_guest,
            &[],
            &[NODE_MESSAGES.to_owned()],
            &concurrent_payloads,
            None,
        )
        .await
    });
    started_rx.await.expect("unsubscribe task did not start");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(150),
            &mut concurrent_unsubscribe,
        )
        .await
        .is_err(),
        "subscription mutation bypassed the channel admission lock"
    );
    admission.commit().await.unwrap();
    assert_eq!(
        admitted_audience
            .iter()
            .map(|participant| participant.jid.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([owner.as_str(), guest.as_str()]),
        "the admission committed before unsubscribe and must retain that exact audience"
    );
    let unsubscribe_outcome =
        tokio::time::timeout(std::time::Duration::from_secs(5), concurrent_unsubscribe)
            .await
            .expect("unsubscribe remained blocked after message admission committed")
            .expect("unsubscribe task panicked")
            .unwrap()
            .expect("participant disappeared during serialized unsubscribe");
    assert!(
        !unsubscribe_outcome
            .subscriptions
            .iter()
            .any(|node| node == NODE_MESSAGES),
        "serialized unsubscribe did not remove the messages node"
    );
    let post_unsubscribe = store_mix_message(
        &pool,
        channel_id,
        &owner,
        &Uuid::new_v4().to_string(),
        "<message><body>after unsubscribe</body></message>",
        None,
        "<body>after unsubscribe</body>",
        None,
        false,
        &payloads,
    )
    .await
    .unwrap();
    assert_eq!(
        post_unsubscribe
            .recipients
            .iter()
            .map(|participant| participant.jid.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([owner.as_str()]),
        "message admission must use the audience committed after a serialized unsubscribe"
    );

    assert!(mix_channel_discoverable_to(&pool, &channel, &owner)
        .await
        .unwrap());
    assert!(mix_channel_discoverable_to(&pool, &channel, &guest)
        .await
        .unwrap());
    assert_eq!(owner_participant.jid, owner);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn federated_mutation_result_and_outbox_share_the_authority_transaction() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let payloads = crate::services::mix::MixPayloads;
    let suffix = Uuid::new_v4().simple().to_string();
    let localpart = format!("atomic-{}", &suffix[..16]);
    let actor = format!("owner-{suffix}@remote.example.test");
    let request_id = format!("create-{suffix}");
    let digest = Sha256::digest(b"exact-federated-create").into();
    let mut context = FederatedMixMutation {
        authenticated_domain: "remote.example.test".to_owned(),
        actor_jid: format!("{actor}/device"),
        request_id: request_id.clone(),
        request_digest: digest,
        addressed: "mix.example.test".to_owned(),
        reply_to: format!("{actor}/device"),
        policy: super::super::S2sOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 0,
            max_bytes: 1_048_576,
            max_per_domain: 100,
        },
    };

    assert!(create_mix_channel(
        &pool,
        "mix.example.test",
        Some(&localpart),
        &actor,
        100,
        &payloads,
        Some(&context),
    )
    .await
    .is_err());
    assert!(mix_channel(&pool, "mix.example.test", &localpart)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        federated_mix_iq_replay(
            &pool,
            &context.authenticated_domain,
            &context.actor_jid,
            &request_id,
            &digest,
        )
        .await
        .unwrap(),
        FederatedMixIqReplay::Miss,
        "outbox capacity rejection must roll back authority and result journal"
    );

    context.policy.max_rows = 100_000;
    let (created, _) = create_mix_channel(
        &pool,
        "mix.example.test",
        Some(&localpart),
        &actor,
        100,
        &payloads,
        Some(&context),
    )
    .await
    .unwrap();
    assert!(matches!(created, CreateChannelOutcome::Created(_)));
    let exact = federated_mix_iq_replay(
        &pool,
        &context.authenticated_domain,
        &context.actor_jid,
        &request_id,
        &digest,
    )
    .await
    .unwrap();
    let FederatedMixIqReplay::Replay(response) = exact else {
        panic!("committed mutation lost its exact result")
    };
    assert!(response.contains("type=\"result\""));
    assert!(response.contains(&format!("channel=\"{localpart}\"")));
    assert!(
        create_mix_channel(
            &pool,
            "mix.example.test",
            Some(&localpart),
            &actor,
            100,
            &payloads,
            Some(&context),
        )
        .await
        .is_err(),
        "an exact retry must stop at the durable result fence"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mix_channels WHERE service_domain=$1 AND localpart=$2",
    )
    .bind("mix.example.test")
    .bind(&localpart)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "replay must not execute the business mutation twice"
    );
}
