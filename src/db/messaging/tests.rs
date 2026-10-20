use super::*;
use std::time::Duration;

async fn downgrade_personal_evidence(pool: &PgPool, identity_value: &str, payload: &str) {
    sqlx::query(
        "UPDATE personal_message_admissions
                SET payload_key_id=NULL,payload_mac=NULL,payload_digest=$2
              WHERE identity_value=$1",
    )
    .bind(identity_value)
    .bind(Sha256::digest(payload.as_bytes()).to_vec())
    .execute(pool)
    .await
    .unwrap();
}

async fn assert_personal_evidence_is_keyed(pool: &PgPool, identity_value: &str) {
    let row: (Option<String>, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT payload_key_id,payload_mac,payload_digest
               FROM personal_message_admissions WHERE identity_value=$1",
    )
    .bind(identity_value)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(row.0.is_some());
    assert_eq!(row.1.as_deref().map(|value| value.len()), Some(32));
    assert_eq!(row.2, None);
}

#[test]
fn durable_results_do_not_expose_repository_row_ids() {
    assert_eq!(
        map_history_outcome(
            db::PersonalHistoryAdmission::Stored(vec![Uuid::new_v4()]),
            true,
            MessagePostCommit::WakeFederationOutbox,
        )
        .unwrap(),
        DurableAdmissionOutcome::Stored {
            archive_written: true,
            post_commit: MessagePostCommit::WakeFederationOutbox,
        }
    );
    assert_eq!(
        map_history_outcome(
            db::PersonalHistoryAdmission::Replay(vec![]),
            false,
            MessagePostCommit::WakeFederationOutbox,
        )
        .unwrap(),
        DurableAdmissionOutcome::Replay
    );
}

#[test]
fn only_explicit_full_normal_messages_receive_resource_affinity() {
    assert_eq!(
        durable_target_full_jid(
            "<message to='alice@example.test/Phone'><body>normal</body></message>"
        )
        .unwrap()
        .as_deref(),
        Some("alice@example.test/Phone")
    );
    for stanza in [
        "<message to='alice@example.test'><body>bare</body></message>",
        "<message type='chat' to='alice@example.test/Phone'><body>fallback</body></message>",
        "<message><body>implicit self</body></message>",
    ] {
        assert_eq!(durable_target_full_jid(stanza).unwrap(), None);
    }
}

#[test]
fn durable_recipient_authority_is_canonical_and_local() {
    assert!(
        validate_local_recipient_authority_for_domain("alice@example.test", "example.test").is_ok()
    );
    assert!(
        validate_local_recipient_authority_for_domain("alice@evil.test", "example.test").is_err()
    );
    assert!(
        validate_local_recipient_authority_for_domain("Alice@example.test", "example.test")
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn members_only_invite_is_one_replay_safe_transaction() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("message_invite_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let marker = Uuid::new_v4().simple().to_string();
    let sender_id = Uuid::new_v4();
    let recipient_id = Uuid::new_v4();
    let failure_recipient_id = Uuid::new_v4();
    let quota_recipient_id = Uuid::new_v4();
    let concurrent_recipient_id = Uuid::new_v4();
    for (id, username) in [
        (sender_id, format!("sender-{}", &marker[..8])),
        (recipient_id, format!("recipient-{}", &marker[..8])),
        (failure_recipient_id, format!("failure-{}", &marker[..8])),
        (quota_recipient_id, format!("quota-{}", &marker[..8])),
        (
            concurrent_recipient_id,
            format!("concurrent-{}", &marker[..8]),
        ),
    ] {
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(id)
            .bind(username)
            .execute(&pool)
            .await
            .unwrap();
    }
    let sender = format!("sender-{}@local.test/Phone", &marker[..8]);
    let recipient = format!("recipient-{}@local.test", &marker[..8]);
    let failure_recipient = format!("failure-{}@local.test", &marker[..8]);
    let quota_recipient = format!("quota-{}@local.test", &marker[..8]);
    let concurrent_recipient = format!("concurrent-{}@local.test", &marker[..8]);
    let (room, _) = db::get_or_create_muc_room(
        &pool,
        &format!("invite-{}", &marker[..8]),
        sender_id,
        &sender,
    )
    .await
    .unwrap();
    let (failure_room, _) = db::get_or_create_muc_room(
        &pool,
        &format!("invite-failure-{}", &marker[..8]),
        sender_id,
        &sender,
    )
    .await
    .unwrap();
    let (quota_room, _) = db::get_or_create_muc_room(
        &pool,
        &format!("invite-quota-{}", &marker[..8]),
        sender_id,
        &sender,
    )
    .await
    .unwrap();
    let (concurrent_room, _) = db::get_or_create_muc_room(
        &pool,
        &format!("invite-concurrent-{}", &marker[..8]),
        sender_id,
        &sender,
    )
    .await
    .unwrap();
    let service = MessageService::new(
        PostgresMessageRepository::new(
            pool.clone(),
            crate::services::abuse::test_personal_message_content_keyring(),
            "local.test",
            100,
            8_000_000,
            30,
        ),
        false,
    );

    let delivery_id = Uuid::new_v4();
    let sender_archive_id = Uuid::new_v4();
    let recipient_archive_id = Uuid::new_v4();
    let payload = format!("<message id='invite-{marker}'/>");
    let sender_archive = format!("<message to='{recipient}'><body>invite</body></message>");
    let recipient_archive = format!("<message from='{sender}'><body>invite</body></message>");
    let delayed = format!(
        "<message from='{sender}' to='{recipient}'><body>invite</body><delay xmlns='urn:xmpp:delay'/></message>"
    );
    let writes = [
        ArchiveWrite {
            id: sender_archive_id,
            owner_id: sender_id,
            peer_jid: &recipient,
            stanza: &sender_archive,
            encrypted: true,
            stanza_id: Some("invite-client-id"),
        },
        ArchiveWrite {
            id: recipient_archive_id,
            owner_id: recipient_id,
            peer_jid: &sender,
            stanza: &recipient_archive,
            encrypted: true,
            stanza_id: Some("invite-client-id"),
        },
    ];
    let request = LocalMucInviteAdmission {
        local_actor_id: sender_id,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &recipient,
            value: "origin-invite-success",
            payload: &payload,
        }),
        archives: &writes,
        delivery_id,
        recipient_id,
        recipient_bare_jid: &recipient,
        sender_jid: &sender,
        stanza: &delayed,
        encrypted: true,
        mam_backed: true,
        room_id: room.id,
        cluster_authority: None,
    };
    assert_eq!(
        service.admit_local_muc_invite(&request).await.unwrap(),
        DurableMucInviteOutcome::Stored {
            id: delivery_id,
            affiliation_changed: true,
            live_claim_id: None,
        }
    );
    let committed: (i64, i64, i64, i64, bool) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 AND affiliation='member'),
                 (SELECT COUNT(*) FROM message_archive WHERE id IN ($3,$4)),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-invite-success'),
                 (SELECT COUNT(*) FROM offline_messages WHERE id=$5),
                 (SELECT mam_backed FROM offline_messages WHERE id=$5)",
    )
    .bind(room.id)
    .bind(recipient_id)
    .bind(sender_archive_id)
    .bind(recipient_archive_id)
    .bind(delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(committed, (1, 2, 1, 1, true));
    let admission_plaintext_marker: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM personal_message_admissions AS admission
              WHERE row_to_json(admission)::TEXT LIKE '%' || $1 || '%'",
    )
    .bind(&marker)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        admission_plaintext_marker, 0,
        "a database dump of the admission table must not contain the original stanza marker"
    );

    downgrade_personal_evidence(&pool, "origin-invite-success", &payload).await;
    assert_eq!(
        service.admit_local_muc_invite(&request).await.unwrap(),
        DurableMucInviteOutcome::Replay { id: delivery_id }
    );
    assert_personal_evidence_is_keyed(&pool, "origin-invite-success").await;
    let replay_counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM message_archive WHERE id IN ($1,$2)),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-invite-success'),
                 (SELECT COUNT(*) FROM offline_messages WHERE id=$3)",
    )
    .bind(sender_archive_id)
    .bind(recipient_archive_id)
    .bind(delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replay_counts, (2, 1, 1));
    sqlx::query(
        "UPDATE personal_message_admissions
                SET payload_mac=decode(repeat('cc',32),'hex')
              WHERE identity_value='origin-invite-success'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        service
            .admit_local_muc_invite(&request)
            .await
            .unwrap_err()
            .to_string()
            .contains("conflicting personal history identity"),
        "a known key ID with a changed MAC must fail closed"
    );
    downgrade_personal_evidence(&pool, "origin-invite-success", &payload).await;
    assert_eq!(
        service.admit_local_muc_invite(&request).await.unwrap(),
        DurableMucInviteOutcome::Replay { id: delivery_id }
    );
    assert_personal_evidence_is_keyed(&pool, "origin-invite-success").await;
    sqlx::query(
        "UPDATE personal_message_admissions
                SET payload_key_id='BBBBBBBBBBBBBBBB'
              WHERE identity_value='origin-invite-success'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(service
        .admit_local_muc_invite(&request)
        .await
        .unwrap_err()
        .to_string()
        .contains("conflicting personal history identity"));
    assert!(
        sqlx::query(
            "UPDATE personal_message_admissions
                SET payload_key_id=NULL,payload_digest=NULL
              WHERE identity_value='origin-invite-success'",
        )
        .execute(&pool)
        .await
        .is_err(),
        "partial content evidence must fail the database constraint"
    );

    // Bind 2 receives the recipient projection from MAM. The transient
    // queue row is acknowledged without sending a second wire copy.
    let (outbound, mut receiver) = tokio::sync::mpsc::channel(1);
    let outbound = crate::xmpp::outbound::OutboundSender::new(outbound);
    assert_eq!(
        db::deliver_bind2_offline(&pool, recipient_id, 30, &outbound, None)
            .await
            .unwrap(),
        0
    );
    assert!(receiver.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    // A MAM write failure rolls back the origin identity, membership and
    // durable queue projection together.
    sqlx::query(
        "CREATE FUNCTION fail_invite_archive() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced invite archive failure'; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER fail_invite_archive BEFORE INSERT ON message_archive FOR EACH ROW EXECUTE FUNCTION fail_invite_archive()")
        .execute(&pool)
        .await
        .unwrap();
    let failure_delivery_id = Uuid::new_v4();
    let failure_archive_id = Uuid::new_v4();
    let failure_stanza = format!("<message from='{sender}' to='{failure_recipient}'/>");
    let failure_writes = [ArchiveWrite {
        id: failure_archive_id,
        owner_id: failure_recipient_id,
        peer_jid: &sender,
        stanza: &failure_stanza,
        encrypted: true,
        stanza_id: None,
    }];
    let failure_request = LocalMucInviteAdmission {
        local_actor_id: sender_id,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &failure_recipient,
            value: "origin-invite-failure",
            payload: &failure_stanza,
        }),
        archives: &failure_writes,
        delivery_id: failure_delivery_id,
        recipient_id: failure_recipient_id,
        recipient_bare_jid: &failure_recipient,
        sender_jid: &sender,
        stanza: &failure_stanza,
        encrypted: true,
        mam_backed: true,
        room_id: failure_room.id,
        cluster_authority: None,
    };
    assert!(service
        .admit_local_muc_invite(&failure_request)
        .await
        .is_err());
    let failed_halves: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND user_id=$2),
                 (SELECT COUNT(*) FROM message_archive WHERE id=$3),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-invite-failure'),
                 (SELECT COUNT(*) FROM offline_messages WHERE id=$4)",
    )
    .bind(failure_room.id)
    .bind(failure_recipient_id)
    .bind(failure_archive_id)
    .bind(failure_delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(failed_halves, (0, 0, 0, 0));
    sqlx::query("DROP TRIGGER fail_invite_archive ON message_archive")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION fail_invite_archive()")
        .execute(&pool)
        .await
        .unwrap();

    // Capacity rejection is typed for the stanza layer and leaves no MAM
    // or affiliation prefix committed.
    let quota_service = MessageService::new(
        PostgresMessageRepository::new(
            pool.clone(),
            crate::services::abuse::test_personal_message_content_keyring(),
            "local.test",
            1,
            8_000_000,
            30,
        ),
        false,
    );
    sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed) VALUES($1,$2,$3,'<message/>',TRUE,FALSE)")
        .bind(Uuid::new_v4())
        .bind(quota_recipient_id)
        .bind(&sender)
        .execute(&pool)
        .await
        .unwrap();
    let quota_delivery_id = Uuid::new_v4();
    let quota_archive_id = Uuid::new_v4();
    let quota_stanza = format!("<message from='{sender}' to='{quota_recipient}'/>");
    let quota_writes = [ArchiveWrite {
        id: quota_archive_id,
        owner_id: quota_recipient_id,
        peer_jid: &sender,
        stanza: &quota_stanza,
        encrypted: true,
        stanza_id: None,
    }];
    let quota_request = LocalMucInviteAdmission {
        local_actor_id: sender_id,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &quota_recipient,
            value: "origin-invite-quota",
            payload: &quota_stanza,
        }),
        archives: &quota_writes,
        delivery_id: quota_delivery_id,
        recipient_id: quota_recipient_id,
        recipient_bare_jid: &quota_recipient,
        sender_jid: &sender,
        stanza: &quota_stanza,
        encrypted: true,
        mam_backed: true,
        room_id: quota_room.id,
        cluster_authority: None,
    };
    assert_eq!(
        quota_service
            .admit_local_muc_invite(&quota_request)
            .await
            .unwrap(),
        DurableMucInviteOutcome::QuotaExceeded
    );
    let quota_halves: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND user_id=$2),
                 (SELECT COUNT(*) FROM message_archive WHERE id=$3),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-invite-quota'),
                 (SELECT COUNT(*) FROM offline_messages WHERE id=$4)",
    )
    .bind(quota_room.id)
    .bind(quota_recipient_id)
    .bind(quota_archive_id)
    .bind(quota_delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(quota_halves, (0, 0, 0, 0));

    // A combined invite and an ordinary durable message for the same
    // account must complete under the shared lock ordering rather than
    // deadlocking while each holds a different prefix lock.
    let concurrent_invite_id = Uuid::new_v4();
    let concurrent_message_id = Uuid::new_v4();
    let concurrent_invite_archive = Uuid::new_v4();
    let concurrent_message_archive = Uuid::new_v4();
    let concurrent_invite_stanza =
        format!("<message from='{sender}' to='{concurrent_recipient}' id='invite'/>");
    let concurrent_message_stanza =
        format!("<message from='{sender}' to='{concurrent_recipient}' id='message'/>");
    let invite_writes = [ArchiveWrite {
        id: concurrent_invite_archive,
        owner_id: concurrent_recipient_id,
        peer_jid: &sender,
        stanza: &concurrent_invite_stanza,
        encrypted: true,
        stanza_id: None,
    }];
    let message_writes = [ArchiveWrite {
        id: concurrent_message_archive,
        owner_id: concurrent_recipient_id,
        peer_jid: &sender,
        stanza: &concurrent_message_stanza,
        encrypted: true,
        stanza_id: None,
    }];
    let concurrent_invite = LocalMucInviteAdmission {
        local_actor_id: sender_id,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &concurrent_recipient,
            value: "origin-concurrent-invite",
            payload: &concurrent_invite_stanza,
        }),
        archives: &invite_writes,
        delivery_id: concurrent_invite_id,
        recipient_id: concurrent_recipient_id,
        recipient_bare_jid: &concurrent_recipient,
        sender_jid: &sender,
        stanza: &concurrent_invite_stanza,
        encrypted: true,
        mam_backed: true,
        room_id: concurrent_room.id,
        cluster_authority: None,
    };
    let concurrent_message = ValidatedPersonalMessage {
        local_actor_id: Some(sender_id),
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &concurrent_recipient,
            value: "origin-concurrent-message",
            payload: &concurrent_message_stanza,
        }),
        archives: &message_writes,
        destination: PersonalMessageDestination::Local(LocalDelivery {
            delivery_id: concurrent_message_id,
            recipient_id: concurrent_recipient_id,
            recipient_bare_jid: &concurrent_recipient,
            sender_jid: &sender,
            stanza: &concurrent_message_stanza,
            encrypted: true,
            mam_backed: true,
        }),
    };
    let (invite_result, message_result) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            service.admit_local_muc_invite(&concurrent_invite),
            service.admit_personal_message(&concurrent_message)
        )
    })
    .await
    .expect("invite and normal C2S admission deadlocked");
    assert!(matches!(
        invite_result.unwrap(),
        DurableMucInviteOutcome::Stored { .. }
    ));
    assert!(matches!(
        message_result.unwrap(),
        DurableAdmissionOutcome::Stored { .. }
    ));
    downgrade_personal_evidence(
        &pool,
        "origin-concurrent-message",
        &concurrent_message_stanza,
    )
    .await;
    assert_eq!(
        service
            .admit_personal_message(&concurrent_message)
            .await
            .unwrap(),
        DurableAdmissionOutcome::Replay
    );
    assert_personal_evidence_is_keyed(&pool, "origin-concurrent-message").await;

    // The federated form uses the same personal identity transaction, but
    // projects recovery into S2S instead of the local offline queue.
    let remote_target = format!("invitee-{}@remote.test", &marker[..8]);
    let remote_stanza = format!(
        "<message from='{sender}' to='{remote_target}' id='remote-invite'><body>invite</body></message>"
    );
    let remote_archive_id = Uuid::new_v4();
    let remote_archive =
        format!("<message from='{sender}' to='{remote_target}'><body>invite</body></message>");
    let remote_writes = [ArchiveWrite {
        id: remote_archive_id,
        owner_id: sender_id,
        peer_jid: &remote_target,
        stanza: &remote_archive,
        encrypted: true,
        stanza_id: Some("remote-invite"),
    }];
    let outbox_policy = db::S2sOutboxPolicy {
        ttl_seconds: 300,
        max_rows: 10_000,
        max_bytes: 64 * 1_048_576,
        max_per_domain: 10_000,
    };
    let remote_request = RemoteMucInviteAdmission {
        local_actor_id: sender_id,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &remote_target,
            value: "origin-remote-invite",
            payload: &remote_stanza,
        }),
        archives: &remote_writes,
        room_id: room.id,
        invitee_bare_jid: &remote_target,
        target_domain: "remote.test",
        stanza: &remote_stanza,
        bounce_to: Some(&sender),
        outbox_policy: outbox_policy.into(),
        cluster_authority: None,
    };
    assert_eq!(
        service
            .admit_remote_muc_invite(&remote_request)
            .await
            .unwrap(),
        RemoteMucInviteAdmissionOutcome::Stored
    );
    let remote_halves: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 AND affiliation='member'),
                 (SELECT COUNT(*) FROM message_archive WHERE id=$3),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-remote-invite'),
                 (SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test')",
    )
    .bind(room.id)
    .bind(&remote_target)
    .bind(remote_archive_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remote_halves, (1, 1, 1, 1));
    downgrade_personal_evidence(&pool, "origin-remote-invite", &remote_stanza).await;
    assert_eq!(
        service
            .admit_remote_muc_invite(&remote_request)
            .await
            .unwrap(),
        RemoteMucInviteAdmissionOutcome::Replay
    );
    assert_personal_evidence_is_keyed(&pool, "origin-remote-invite").await;
    let remote_replay_counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM message_archive WHERE id=$1),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-remote-invite'),
                 (SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test')",
    )
    .bind(remote_archive_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remote_replay_counts, (1, 1, 1));

    let changed_remote_stanza = format!(
        "<message from='{sender}' to='{remote_target}' id='remote-invite'><body>changed</body></message>"
    );
    let changed_remote = RemoteMucInviteAdmission {
        local_actor_id: sender_id,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &remote_target,
            value: "origin-remote-invite",
            payload: &changed_remote_stanza,
        }),
        archives: &remote_writes,
        room_id: room.id,
        invitee_bare_jid: &remote_target,
        target_domain: "remote.test",
        stanza: &changed_remote_stanza,
        bounce_to: Some(&sender),
        outbox_policy: outbox_policy.into(),
        cluster_authority: None,
    };
    assert_eq!(
        service
            .admit_remote_muc_invite(&changed_remote)
            .await
            .unwrap(),
        RemoteMucInviteAdmissionOutcome::Conflict
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    // Without an origin-id there is no protocol-safe exact-retry key.
    // Two identical sends are retained as two user actions instead of
    // being guessed into one message by a payload hash.
    let no_identity_target = format!("repeat-{}@repeat.remote.test", &marker[..8]);
    let no_identity_stanza =
        format!("<message from='{sender}' to='{no_identity_target}'><body>same</body></message>");
    let no_identity_request = RemoteMucInviteAdmission {
        local_actor_id: sender_id,
        identity: None,
        archives: &[],
        room_id: room.id,
        invitee_bare_jid: &no_identity_target,
        target_domain: "repeat.remote.test",
        stanza: &no_identity_stanza,
        bounce_to: Some(&sender),
        outbox_policy: outbox_policy.into(),
        cluster_authority: None,
    };
    for _ in 0..2 {
        assert_eq!(
            service
                .admit_remote_muc_invite(&no_identity_request)
                .await
                .unwrap(),
            RemoteMucInviteAdmissionOutcome::Stored
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='repeat.remote.test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        2
    );

    // An outbox failure must not leave a sender MAM row, origin identity
    // or federated affiliation behind.
    sqlx::query(
        "CREATE FUNCTION fail_remote_invite_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced remote invite outbox failure'; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER fail_remote_invite_outbox BEFORE INSERT ON s2s_outbox FOR EACH ROW EXECUTE FUNCTION fail_remote_invite_outbox()")
        .execute(&pool)
        .await
        .unwrap();
    let failed_remote_target = format!("failed-{}@failure.remote.test", &marker[..8]);
    let failed_remote_stanza = format!("<message from='{sender}' to='{failed_remote_target}'/>");
    let failed_remote_archive_id = Uuid::new_v4();
    let failed_remote_writes = [ArchiveWrite {
        id: failed_remote_archive_id,
        owner_id: sender_id,
        peer_jid: &failed_remote_target,
        stanza: &failed_remote_stanza,
        encrypted: true,
        stanza_id: None,
    }];
    let failed_remote = RemoteMucInviteAdmission {
        local_actor_id: sender_id,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &failed_remote_target,
            value: "origin-remote-failure",
            payload: &failed_remote_stanza,
        }),
        archives: &failed_remote_writes,
        room_id: room.id,
        invitee_bare_jid: &failed_remote_target,
        target_domain: "failure.remote.test",
        stanza: &failed_remote_stanza,
        bounce_to: Some(&sender),
        outbox_policy: outbox_policy.into(),
        cluster_authority: None,
    };
    assert!(service
        .admit_remote_muc_invite(&failed_remote)
        .await
        .is_err());
    let failed_remote_halves: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2),
                 (SELECT COUNT(*) FROM message_archive WHERE id=$3),
                 (SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-remote-failure'),
                 (SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='failure.remote.test')",
    )
    .bind(room.id)
    .bind(&failed_remote_target)
    .bind(failed_remote_archive_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(failed_remote_halves, (0, 0, 0, 0));
    sqlx::query("DROP TRIGGER fail_remote_invite_outbox ON s2s_outbox")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION fail_remote_invite_outbox()")
        .execute(&pool)
        .await
        .unwrap();

    // Both the legacy repository admission and the combined personal
    // admission acquire outbox before room, so concurrent calls cannot
    // deadlock by holding opposite prefixes.
    let concurrent_remote_stanza =
        format!("<message from='{sender}' to='{remote_target}' id='combined-concurrent'/>",);
    let legacy_remote_stanza =
        format!("<message from='{sender}' to='{remote_target}' id='legacy-concurrent'/>",);
    let concurrent_remote_archive_id = Uuid::new_v4();
    let concurrent_remote_writes = [ArchiveWrite {
        id: concurrent_remote_archive_id,
        owner_id: sender_id,
        peer_jid: &remote_target,
        stanza: &concurrent_remote_stanza,
        encrypted: true,
        stanza_id: None,
    }];
    let concurrent_remote = RemoteMucInviteAdmission {
        local_actor_id: sender_id,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: &sender,
            actor_scope: &sender,
            target_scope: &remote_target,
            value: "origin-remote-concurrent",
            payload: &concurrent_remote_stanza,
        }),
        archives: &concurrent_remote_writes,
        room_id: room.id,
        invitee_bare_jid: &remote_target,
        target_domain: "remote.test",
        stanza: &concurrent_remote_stanza,
        bounce_to: Some(&sender),
        outbox_policy: outbox_policy.into(),
        cluster_authority: None,
    };
    let (combined_remote_result, legacy_remote_result) =
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                service.admit_remote_muc_invite(&concurrent_remote),
                db::admit_federated_muc_invite(
                    &pool,
                    room.id,
                    &remote_target,
                    "remote.test",
                    &legacy_remote_stanza,
                    Some(&sender),
                    outbox_policy,
                    None,
                )
            )
        })
        .await
        .expect("combined and legacy federated invite admission deadlocked");
    assert_eq!(
        combined_remote_result.unwrap(),
        RemoteMucInviteAdmissionOutcome::Stored
    );
    assert!(legacy_remote_result.unwrap());

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
